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
#[derive(Debug)]
pub struct AuthenticationResult {
    pub inventory: Option<fido_core::inventory::OwnedInventory>,
    pub inspection_error: Option<fido_worker_protocol::InspectionError>,
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
        let setup = (|| {
            let acquisition = self
                .next_acquisition
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
                .map(AcquisitionId)
                .map_err(|_| (AdmissionError::WorkflowIdExhausted, RecoveryAdmission::Open))?;
            let mut controller = self
                .controller
                .lock()
                .map_err(|_| (AdmissionError::RecoveryBarrier, RecoveryAdmission::Barrier))?;
            let (prompt, prompt_outcome) = controller
                .request(
                    admission.workflow_id(),
                    Instant::now(),
                    Duration::from_secs(fido_auth::PROMPT_LIFETIME_SECS),
                )
                .map_err(|_| {
                    // request() creates no new active prompt on Err. An existing prompt cannot be
                    // torn down by this failed reservation, so retain a separate recovery barrier.
                    let recovery = if controller.is_active() {
                        RecoveryAdmission::Barrier
                    } else {
                        RecoveryAdmission::Open
                    };
                    (AdmissionError::OperationInProgress, recovery)
                })?;
            Ok((acquisition, prompt, prompt_outcome))
        })();
        let (acquisition, prompt, prompt_outcome) = match setup {
            Ok(setup) => setup,
            Err((error, recovery_admission)) => {
                // No worker/native call or new sheet has started. Release exactly this admission
                // as an internal failure; controller uncertainty may still block recovery.
                gate.finish(
                    &admission,
                    WorkflowCompletion::Failed,
                    WorkflowReleaseEvidence {
                        execution_quiescence: ExecutionQuiescence::Quiescent,
                        recovery_admission,
                    },
                    self.clock.now(),
                )
                .map_err(|_| AdmissionError::RecoveryBarrier)?;
                return Err(error);
            }
        };
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
        self.run(supervisor, handle, reservation, false, present)
    }

    pub fn inspect(
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
        self.run(supervisor, handle, reservation, true, present)
    }

    fn run(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        handle: DeviceHandle,
        reservation: AuthenticationReservation,
        inspect: bool,
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
            inventory: None,
            inspection_error: None,
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
                WorkerResponse::Error { code } => {
                    if inspect {
                        result.inspection_error = Some(match code {
                            fido_worker_protocol::WorkerErrorCode::DeviceAbsent => {
                                fido_worker_protocol::InspectionError::DeviceAbsent
                            }
                            fido_worker_protocol::WorkerErrorCode::DeviceBusy => {
                                fido_worker_protocol::InspectionError::Busy
                            }
                            fido_worker_protocol::WorkerErrorCode::AccessDenied => {
                                fido_worker_protocol::InspectionError::AccessDenied
                            }
                            fido_worker_protocol::WorkerErrorCode::DeadlineExpired => {
                                fido_worker_protocol::InspectionError::TimedOut
                            }
                            fido_worker_protocol::WorkerErrorCode::MalformedDeviceData => {
                                fido_worker_protocol::InspectionError::Malformed
                            }
                            fido_worker_protocol::WorkerErrorCode::UnsupportedDevice => {
                                fido_worker_protocol::InspectionError::Unsupported
                            }
                            _ => fido_worker_protocol::InspectionError::NativeFailure,
                        });
                    }
                    return Err(Status::Unsupported);
                }
                _ => return Err(Status::Unsupported),
            };
            result.grant_kind = Some(kind);
            eprintln!("[authentication] prepared grant={kind:?}");
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
                    if inspect {
                        WorkerRequest::InspectCredentials { binding }
                    } else {
                        WorkerRequest::ValidateAuthentication { binding }
                    },
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
            if inspect {
                match response.response {
                    WorkerResponse::CredentialsInspected {
                        evidence,
                        inventory,
                        error,
                    } if evidence.binding == binding && evidence.kind == kind => {
                        if !evidence.attached_puat_cleared {
                            return Err(Status::CleanupFailed);
                        }
                        result.inspection_error = error;
                        if evidence.status == Status::Validated && error.is_none() {
                            let inventory = inventory
                                .filter(|i| i.within_bounds())
                                .ok_or(Status::Uncertain)?;
                            result.inventory = Some(inventory);
                        } else if inventory.is_some() {
                            return Err(Status::Uncertain);
                        }
                        Ok(evidence)
                    }
                    _ => Err(Status::Uncertain),
                }
            } else {
                validate_authentication_evidence(response.response, binding, kind)
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
        if !result.worker_quiescent || !result.prompt_torn_down {
            result.inventory = None;
            result.status = Status::Uncertain;
        } else if self.epoch.load(Ordering::SeqCst) != epoch {
            result.inventory = None;
            result.status = Status::Revoked;
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

fn validate_authentication_evidence(
    response: WorkerResponse,
    binding: AcquisitionBinding,
    kind: GrantKind,
) -> Result<AuthenticationEvidence, Status> {
    match response {
        WorkerResponse::AuthenticationValidated { evidence }
            if evidence.binding == binding && evidence.kind == kind =>
        {
            // Enforce cleanup independently of the worker, even for otherwise exact evidence.
            if evidence.status == Status::Validated && !evidence.attached_puat_cleared {
                Err(Status::CleanupFailed)
            } else {
                Ok(evidence)
            }
        }
        _ => Err(Status::Uncertain),
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
    use fido_core::{DeviceGeneration, PromptInstanceId, WorkflowId};

    #[test]
    fn reservation_unwinds_acquisition_exhaustion_before_any_prompt() {
        let a = AuthenticationAuthority::default();
        a.next_acquisition.store(u64::MAX, Ordering::SeqCst);
        assert!(matches!(
            a.reserve(),
            Err(AdmissionError::WorkflowIdExhausted)
        ));
        assert!(!a.gate.lock().unwrap_or_else(|_| panic!("gate")).is_active());
        assert!(
            !a.controller
                .lock()
                .unwrap_or_else(|_| panic!("controller"))
                .is_active()
        );
        // Repair only the synthetic test exhaustion. There was no native authority to reuse.
        a.next_acquisition.store(1, Ordering::SeqCst);
        assert!(a.reserve().is_ok());
    }

    #[test]
    fn reservation_unwinds_prompt_request_failure_without_new_controller_state() {
        let a = AuthenticationAuthority::default();
        a.controller
            .lock()
            .unwrap_or_else(|_| panic!("controller"))
            .shutdown();
        assert!(matches!(
            a.reserve(),
            Err(AdmissionError::OperationInProgress)
        ));
        assert!(!a.gate.lock().unwrap_or_else(|_| panic!("gate")).is_active());
        let mut controller = a.controller.lock().unwrap_or_else(|_| panic!("controller"));
        assert!(!controller.is_active());
        // Restore the synthetic shutdown only in this test, then prove the gate was not orphaned.
        *controller = PromptController::default();
        drop(controller);
        assert!(a.reserve().is_ok());
    }

    #[test]
    fn reservation_unwinds_without_tearing_down_an_existing_prompt() {
        let a = AuthenticationAuthority::default();
        let (existing, outcome) = a
            .controller
            .lock()
            .unwrap_or_else(|_| panic!("controller"))
            .request(
                WorkflowId::from_raw(99),
                Instant::now(),
                Duration::from_secs(30),
            )
            .unwrap_or_else(|_| panic!("prompt"));
        assert!(matches!(
            a.reserve(),
            Err(AdmissionError::OperationInProgress)
        ));
        let gate = a.gate.lock().unwrap_or_else(|_| panic!("gate"));
        assert!(!gate.is_active());
        assert_eq!(gate.recovery_admission(), RecoveryAdmission::Barrier);
        drop(gate);
        assert!(
            a.controller
                .lock()
                .unwrap_or_else(|_| panic!("controller"))
                .is_active()
        );
        assert!(outcome.try_recv().is_err());
        assert!(matches!(a.reserve(), Err(AdmissionError::RecoveryBarrier)));
        a.controller
            .lock()
            .unwrap_or_else(|_| panic!("controller"))
            .did_teardown(existing.binding(), Instant::now())
            .unwrap_or_else(|_| panic!("teardown"));
    }

    #[test]
    fn reservation_unwinds_poisoned_controller_but_retains_recovery_barrier() {
        let a = AuthenticationAuthority::default();
        let controller = Arc::clone(&a.controller);
        let poisoned = std::thread::spawn(move || {
            let _held = controller.lock().unwrap_or_else(|_| panic!("controller"));
            panic!("synthetic controller poisoning");
        });
        assert!(poisoned.join().is_err());
        assert!(matches!(a.reserve(), Err(AdmissionError::RecoveryBarrier)));
        let gate = a.gate.lock().unwrap_or_else(|_| panic!("gate"));
        assert!(!gate.is_active());
        assert_eq!(gate.recovery_admission(), RecoveryAdmission::Barrier);
        drop(gate);
        assert!(matches!(a.reserve(), Err(AdmissionError::RecoveryBarrier)));
    }

    #[test]
    fn parent_rejects_validated_evidence_without_attached_puat_cleanup() {
        let binding = AcquisitionBinding {
            worker_generation: 1,
            device_generation: DeviceGeneration(1),
            workflow_id: WorkflowId::from_raw(1),
            prompt_instance_id: PromptInstanceId::from_raw(1),
            acquisition_id: AcquisitionId(1),
        };
        let evidence = AuthenticationEvidence {
            binding,
            kind: GrantKind::CredMan,
            status: Status::Validated,
            attached_puat_cleared: false,
        };
        assert_eq!(
            validate_authentication_evidence(
                WorkerResponse::AuthenticationValidated { evidence },
                binding,
                evidence.kind
            ),
            Err(Status::CleanupFailed)
        );
        let cleaned = AuthenticationEvidence {
            attached_puat_cleared: true,
            ..evidence
        };
        assert_eq!(
            validate_authentication_evidence(
                WorkerResponse::AuthenticationValidated { evidence: cleaned },
                binding,
                cleaned.kind
            ),
            Ok(cleaned)
        );
        let other = AcquisitionBinding {
            acquisition_id: AcquisitionId(2),
            ..binding
        };
        assert_eq!(
            validate_authentication_evidence(
                WorkerResponse::AuthenticationValidated { evidence },
                other,
                evidence.kind
            ),
            Err(Status::Uncertain)
        );
    }

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
