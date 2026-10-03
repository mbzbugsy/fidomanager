//! M2 complete-transaction authority. There is no reusable parent-side PUAT cache.
use crate::{
    AdmissionError, DiscoverySupervisor, MonotonicClock, ProcessWorkerLauncher,
    SensitiveWorkflowGate, SystemMonotonicClock, WorkerEndpoint, WorkflowAdmission,
    WorkflowCompletion, WorkflowReleaseEvidence,
};
use fido_auth::{AcquisitionBinding, AcquisitionId, AuthenticationEvidence, GrantKind};
pub use fido_core::DeviceHandle;
use fido_core::{ExecutionQuiescence, RecoveryAdmission, SensitiveWorkflowKind};
use fido_native_ui::{PinCompletion, PromptController, PromptOutcome, PromptRequest};
use fido_worker_protocol::{
    CancellationId, RequestBudgetMs, WORKER_PROTOCOL_VERSION, WorkerRequest, WorkerRequestEnvelope,
    WorkerRequestId, WorkerResponse,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Sender},
    },
    time::{Duration, Instant},
};

pub use fido_auth::AuthenticationStatus as Status;
pub use fido_native_ui::PinCompletion as NativePinCompletion;
pub use fido_native_ui::PromptRequest as NativePinRequest;
pub type NativeController = Arc<Mutex<PromptController>>;

/// Deliberately contains no grant/acquisition/worker identity, token or PIN.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticationResult {
    pub status: Status,
    pub grant_kind: Option<GrantKind>,
    pub attached_puat_cleared: bool,
    pub worker_quiescent: bool,
    pub prompt_torn_down: bool,
}

pub struct AuthenticationAuthority {
    gate: Mutex<SensitiveWorkflowGate>,
    controller: NativeController,
    pub epoch: Arc<AtomicU64>,
    next_acquisition: AtomicU64,
    clock: SystemMonotonicClock,
}
pub struct AuthenticationReservation {
    admission: WorkflowAdmission,
    prompt: PromptRequest,
    prompt_outcome: mpsc::Receiver<PromptOutcome>,
    acquisition: AcquisitionId,
    epoch: u64,
}

impl Default for AuthenticationAuthority {
    fn default() -> Self {
        Self {
            gate: Mutex::new(SensitiveWorkflowGate::default()),
            controller: Arc::new(Mutex::new(PromptController::default())),
            epoch: Arc::new(AtomicU64::new(1)),
            next_acquisition: AtomicU64::new(1),
            clock: SystemMonotonicClock::new(),
        }
    }
}

impl AuthenticationAuthority {
    pub fn revoke(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
    pub fn reserve(&self) -> Result<AuthenticationReservation, AdmissionError> {
        let mut gate = self
            .gate
            .try_lock()
            .map_err(|_| AdmissionError::OperationInProgress)?;
        let admission = gate.try_begin(
            SensitiveWorkflowKind::CredentialInspection,
            self.clock.now(),
        )?;
        let acquisition = self
            .next_acquisition
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .map(AcquisitionId)
            .map_err(|_| AdmissionError::WorkflowIdExhausted)?;
        let (prompt, prompt_outcome) = self
            .controller
            .lock()
            .map_err(|_| AdmissionError::RecoveryBarrier)?
            .request(
                admission.workflow_id(),
                Instant::now(),
                Duration::from_secs(fido_auth::PROMPT_LIFETIME_SECS),
            )
            .map_err(|_| AdmissionError::OperationInProgress)?;
        Ok(AuthenticationReservation {
            admission,
            prompt,
            prompt_outcome,
            acquisition,
            epoch: self.epoch.load(Ordering::SeqCst),
        })
    }

    pub fn cancel_unpresented(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        reservation: AuthenticationReservation,
    ) {
        let binding = reservation.prompt.binding();
        let quiescent = supervisor.retire_authentication() == ExecutionQuiescence::Quiescent;
        let torn_down = self.controller.lock().is_ok_and(|mut c| {
            let _ = c.revoke(PromptOutcome::Cancelled(binding));
            c.did_teardown(binding, Instant::now()).is_ok()
        });
        if torn_down && quiescent {
            if let Ok(mut gate) = self.gate.lock() {
                let _ = gate.finish(
                    &reservation.admission,
                    WorkflowCompletion::Rejected,
                    WorkflowReleaseEvidence {
                        execution_quiescence: ExecutionQuiescence::Quiescent,
                        recovery_admission: RecoveryAdmission::Open,
                    },
                    self.clock.now(),
                );
            }
        }
    }

    /// Owned backend-only reservation, trusted native presenter and opaque registered device.
    /// Caller must exclusively borrow the canonical supervisor for the WHOLE transaction. M3
    /// adds a named worker inspection operation at validate, not a general authenticated CTAP API.
    pub fn validate(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        handle: DeviceHandle,
        reservation: AuthenticationReservation,
        present: impl FnOnce(
            PromptRequest,
            NativeController,
            Sender<PinCompletion>,
            Option<u8>,
            Arc<AtomicU64>,
            u64,
        ) -> Result<(), &'static str>,
    ) -> AuthenticationResult {
        let AuthenticationReservation {
            admission,
            prompt,
            prompt_outcome,
            acquisition,
            epoch,
        } = reservation;
        let prompt_binding = prompt.binding();
        let mut prompt = Some(prompt);
        let mut presented = false;
        let mut result = AuthenticationResult {
            status: Status::Unsupported,
            grant_kind: None,
            attached_puat_cleared: false,
            worker_quiescent: false,
            prompt_torn_down: false,
        };
        let target = supervisor.resolve_handle(handle);
        let transaction = (|| -> Result<AuthenticationEvidence, Status> {
            if self.epoch.load(Ordering::SeqCst) != epoch {
                return Err(Status::Revoked);
            }
            let target = target.ok_or(Status::StaleAcquisition)?;
            let coordinator = supervisor.coordinator.as_mut().ok_or(Status::Unsupported)?;
            let binding = AcquisitionBinding {
                worker_generation: coordinator.worker_generation().0,
                device_generation: target.device_generation,
                workflow_id: admission.workflow_id(),
                prompt_instance_id: prompt_binding.prompt_instance_id,
                acquisition_id: acquisition,
            };
            coordinator
                .endpoint
                .set_revocation(Arc::clone(&self.epoch), epoch);
            let request_id = coordinator
                .take_request_id()
                .map_err(|_| Status::Unsupported)?;
            let prepare = envelope(
                binding,
                request_id,
                WorkerRequest::PrepareAuthentication {
                    device_id: target.worker_device_id,
                    binding,
                },
            );
            let response = coordinator
                .endpoint
                .exchange(prepare)
                .map_err(|_| Status::Uncertain)?;
            if response.device_generation != Some(binding.device_generation)
                || response.evidence.mutation_outcome.is_some()
                || response.evidence.execution_quiescence != ExecutionQuiescence::Quiescent
            {
                return Err(Status::Uncertain);
            }
            let (kind, retries) = match response.response {
                WorkerResponse::AuthenticationPrepared {
                    binding: echoed,
                    grant_kind,
                    pin_retries,
                } if echoed == binding => (grant_kind, pin_retries),
                _ => return Err(Status::Unsupported),
            };
            result.grant_kind = Some(kind);
            eprintln!(
                "[authentication] prepared grant={kind:?} pin_retries={retries:?} acquisition={} worker_generation={} device_generation={}",
                binding.acquisition_id.0, binding.worker_generation, binding.device_generation.0
            );
            let (tx, rx) = mpsc::channel();
            let request = prompt.take().ok_or(Status::Uncertain)?;
            present(
                request,
                Arc::clone(&self.controller),
                tx,
                retries,
                Arc::clone(&self.epoch),
                epoch,
            )
            .map_err(|_| Status::Cancelled)?;
            presented = true;
            let completion = rx
                .recv_timeout(Duration::from_secs(fido_auth::PROMPT_LIFETIME_SECS + 2))
                .map_err(|_| Status::TimedOut)?;
            if completion.binding != prompt_binding {
                return Err(Status::StaleAcquisition);
            }
            let acknowledged = prompt_outcome.try_recv().map_err(|_| Status::Uncertain)?;
            result.prompt_torn_down = !matches!(acknowledged, PromptOutcome::OwnerLost(_));
            if !result.prompt_torn_down || acknowledged != completion.outcome {
                return Err(Status::Uncertain);
            }
            if self.epoch.load(Ordering::SeqCst) != epoch {
                return Err(Status::Revoked);
            }
            if !matches!(completion.outcome, PromptOutcome::Approved(_)) {
                return Err(match completion.outcome {
                    PromptOutcome::TimedOut(_) => Status::TimedOut,
                    PromptOutcome::Shutdown(_) | PromptOutcome::ParentLost(_) => Status::Revoked,
                    _ => Status::Cancelled,
                });
            }
            let pin = completion.pin.ok_or(Status::InvalidSecret)?;
            let request_id = coordinator
                .take_request_id()
                .map_err(|_| Status::Uncertain)?;
            #[cfg(unix)]
            coordinator
                .endpoint
                .submit_secret(binding, request_id, pin)
                .map_err(|_| Status::Uncertain)?;
            #[cfg(not(unix))]
            {
                drop(pin);
                return Err(Status::Unsupported);
            }
            let response = coordinator
                .endpoint
                .exchange(envelope(
                    binding,
                    request_id,
                    WorkerRequest::ValidateAuthentication { binding },
                ))
                .map_err(|_| Status::Uncertain)?;
            if self.epoch.load(Ordering::SeqCst) != epoch {
                return Err(Status::Uncertain);
            }
            if response.device_generation != Some(binding.device_generation)
                || response.evidence.mutation_outcome.is_some()
                || response.evidence.execution_quiescence != ExecutionQuiescence::Quiescent
            {
                return Err(Status::Uncertain);
            }
            match response.response {
                WorkerResponse::AuthenticationValidated { evidence }
                    if evidence.binding == binding && evidence.kind == kind =>
                {
                    Ok(evidence)
                }
                _ => Err(Status::Uncertain),
            }
        })();
        match transaction {
            Ok(evidence) => {
                result.status = evidence.status;
                result.attached_puat_cleared = evidence.attached_puat_cleared;
            }
            Err(status) => result.status = status,
        }
        // Retire on EVERY path. The native device was consumed on success; cleanup failure,
        // cancellation and uncertainty also discard the process. No replacement opens here.
        result.worker_quiescent =
            supervisor.retire_authentication() == ExecutionQuiescence::Quiescent;
        if !result.prompt_torn_down {
            // Only a prompt that was never presented may be acknowledged locally.
            if !presented {
                if let Ok(mut c) = self.controller.lock() {
                    let _ = c.revoke(PromptOutcome::PresentationFailed(prompt_binding));
                    result.prompt_torn_down =
                        c.did_teardown(prompt_binding, Instant::now()).is_ok();
                }
            } else if self.controller.lock().is_ok_and(|c| !c.is_active()) {
                result.prompt_torn_down = true;
            }
        }
        if !result.worker_quiescent {
            result.status = Status::Uncertain;
        }
        // Admission remains held indefinitely if teardown/reap cannot be proven. A subsequent
        // renderer/native start cannot bypass that barrier; operator must resolve authority loss.
        if result.prompt_torn_down && result.worker_quiescent {
            let completion = match result.status {
                Status::Validated => WorkflowCompletion::Succeeded,
                Status::TimedOut => WorkflowCompletion::TimedOut,
                Status::Cancelled | Status::Revoked => WorkflowCompletion::Cancelled,
                _ => WorkflowCompletion::Rejected,
            };
            if let Ok(mut gate) = self.gate.lock() {
                let _ = gate.finish(
                    &admission,
                    completion,
                    WorkflowReleaseEvidence {
                        execution_quiescence: ExecutionQuiescence::Quiescent,
                        recovery_admission: RecoveryAdmission::Open,
                    },
                    self.clock.now(),
                );
            }
        }
        result
    }
}

fn envelope(binding: AcquisitionBinding, id: u64, request: WorkerRequest) -> WorkerRequestEnvelope {
    WorkerRequestEnvelope {
        protocol_version: WORKER_PROTOCOL_VERSION,
        request_id: WorkerRequestId(id),
        cancellation_id: CancellationId(id),
        operation_class: request.operation_class(),
        worker_generation: crate::WorkerGeneration(binding.worker_generation),
        device_generation: Some(binding.device_generation),
        budget_ms: RequestBudgetMs(fido_auth::AUTH_NATIVE_BUDGET_MS),
        request,
    }
}

#[cfg(all(feature = "native-pin", target_os = "macos"))]
pub use fido_native_ui::macos_pin::{
    install_lifecycle, present, shutdown as shutdown_native_prompt,
};

/// Trusted main-thread presentation failure; no sheet was created, so teardown is vacuous.
pub fn presentation_failed(
    request_binding: fido_native_ui::PromptBinding,
    controller: NativeController,
    reply: Sender<NativePinCompletion>,
) {
    if let Ok(mut c) = controller.lock() {
        let outcome = PromptOutcome::PresentationFailed(request_binding);
        let _ = c.revoke(outcome);
        if c.did_teardown(request_binding, Instant::now()).is_ok() {
            let _ = reply.send(PinCompletion {
                binding: request_binding,
                outcome,
                pin: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_has_zero_queue_and_bound_prompt_identity() {
        let a = AuthenticationAuthority::default();
        let r = a.reserve().unwrap_or_else(|_| panic!("reserve"));
        assert_eq!(r.prompt.binding().workflow_id, r.admission.workflow_id());
        assert!(matches!(
            a.reserve(),
            Err(AdmissionError::OperationInProgress)
        ));
        a.revoke();
        assert_ne!(a.epoch.load(Ordering::SeqCst), r.epoch);
    }
}
