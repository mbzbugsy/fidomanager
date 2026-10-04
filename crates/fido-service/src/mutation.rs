//! Trusted PIN mutation orchestration built on the shared intent/permit and durable journal.
//! The renderer cannot enter this path. Native execution belongs exclusively to the child worker.
use crate::{
    AdmissionError, CompletionError, DiscoverySupervisor, MonotonicClock, ProcessWorkerLauncher,
    RegisteredDeviceTarget, WorkerEndpoint, WorkerGeneration, WorkflowCompletion,
    WorkflowReleaseEvidence,
    authentication::{AuthenticationAuthority, AuthenticationReservation},
    recovery::{JournalError, JournalPhase, PinOperation, Resolution},
};
use fido_core::{DeviceHandle, ExecutionQuiescence, RecoveryAdmission, SensitiveWorkflowKind};
use fido_native_ui::{PromptBinding, PromptOutcome, PromptRequest};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const INTENT_VERSION: u8 = 1;
pub const PERMIT_TTL: Duration = Duration::from_secs(10);

/// Backend-owned immutable description of WHAT and WHICH exact target, never the secret value.
/// Not serde/Clone/Copy and no public constructor or mutable fields.
pub struct OperationIntent {
    operation: PinOperation,
    handle: DeviceHandle,
    target: RegisteredDeviceTarget,
    worker: WorkerGeneration,
    binding: PromptBinding,
    nonce: [u8; 16],
    created_ms: u64,
    expires_ms: u64,
    expires_at: Instant,
    epoch: u64,
    authority_epoch: Arc<AtomicU64>,
}
impl OperationIntent {
    pub fn operation(&self) -> PinOperation {
        self.operation
    }
    pub fn binding(&self) -> PromptBinding {
        self.binding
    }
    /// Fixed, versioned, big-endian encoding; no strings/paths/secrets. Used for native description
    /// binding only, never persisted. Any future field addition requires a version change.
    pub fn canonical(&self) -> Vec<u8> {
        let mut bytes = b"FidoManager operation intent\0".to_vec();
        bytes.push(INTENT_VERSION);
        bytes.push(match self.operation {
            PinOperation::SetPin => 1,
            PinOperation::ChangePin => 2,
        });
        bytes.extend(self.nonce);
        bytes.extend(self.handle.as_raw().to_be_bytes());
        bytes.extend(self.target.worker_device_id.0.to_be_bytes());
        bytes.extend(self.target.device_generation.0.to_be_bytes());
        bytes.extend(self.worker.0.to_be_bytes());
        bytes.extend(self.binding.workflow_id.as_raw().to_be_bytes());
        bytes.extend(self.binding.prompt_instance_id.as_raw().to_be_bytes());
        bytes.extend(self.created_ms.to_be_bytes());
        bytes.extend(self.expires_ms.to_be_bytes());
        bytes.extend(self.epoch.to_be_bytes());
        bytes
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical()).into()
    }
}

/// Trusted native approval mints this exact-intent capability. No public constructor, serde,
/// Clone/Copy or secret. Owned consumption plus reservation-held digest enforces one-shot use.
///
/// ```compile_fail
/// fn duplicate(permit: &fido_service::mutation::OperationPermit) {
///     let _replay: fido_service::mutation::OperationPermit = permit.clone();
/// }
/// ```
/// ```compile_fail
/// fn serialize(permit: &fido_service::mutation::OperationPermit) {
///     let _ = serde_json::to_string(permit);
/// }
/// ```
/// ```compile_fail
/// let _ = fido_service::mutation::OperationPermit { digest: [0; 32], expires_at: std::time::Instant::now() };
/// ```
pub struct OperationPermit {
    digest: [u8; 32],
    expires_at: Instant,
}

pub struct MutationReservation {
    reservation: AuthenticationReservation,
    intent: OperationIntent,
    approved: Option<[u8; 32]>,
    consumed: bool,
    pending: bool,
}
impl MutationReservation {
    pub fn intent(&self) -> &OperationIntent {
        &self.intent
    }
    pub fn prompt(&self) -> &PromptRequest {
        &self.reservation.prompt
    }
}

pub struct RecoveryReservation {
    reservation: AuthenticationReservation,
    authority_epoch: Arc<AtomicU64>,
}
impl RecoveryReservation {
    pub fn prompt(&self) -> &PromptRequest {
        &self.reservation.prompt
    }
}

#[derive(Debug, Error)]
pub enum MutationError {
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Completion(#[from] CompletionError),
    #[error("approval or exact target is stale, expired, replayed or revoked")]
    InvalidPermit,
    #[error("native teardown/quiescence is not established")]
    NotQuiescent,
}

/// Produced only after the durable marker, consumed only by dispatch below. No public constructor.
struct PinMutationDispatchPermit {
    binding: fido_auth::mutation::PinMutationBinding,
    epoch: u64,
    expires_at: Instant,
}
#[derive(Debug)]
pub struct PinWorkflowResult {
    pub outcome: fido_core::MutationOutcome,
    pub rejection: Option<fido_auth::mutation::PinRejection>,
    pub worker_quiescent: bool,
    pub prompt_torn_down: bool,
    pub recovery_required: bool,
    pub cancelled: bool,
}

impl AuthenticationAuthority {
    /// Trusted backend entry only. The canonical supervisor stays exclusively borrowed throughout.
    pub fn mutate_pin(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        mut r: MutationReservation,
        present: impl FnOnce(
            PromptRequest,
            crate::authentication::NativeController,
            std::sync::mpsc::Sender<fido_native_ui::MutationCompletion>,
            PinOperation,
            Option<u8>,
            Arc<AtomicU64>,
            u64,
        ) -> Result<(), &'static str>,
    ) -> PinWorkflowResult {
        use fido_auth::{AcquisitionBinding, mutation::PinMutationBinding};
        use fido_core::MutationOutcome;
        use fido_worker_protocol::{WorkerRequest, WorkerResponse};
        let binding = PinMutationBinding {
            operation: r.intent.operation,
            session: AcquisitionBinding {
                worker_generation: r.intent.worker.0,
                device_generation: r.intent.target.device_generation,
                workflow_id: r.intent.binding.workflow_id,
                prompt_instance_id: r.intent.binding.prompt_instance_id,
                acquisition_id: r.reservation.acquisition,
            },
            intent_digest: r.intent.digest(),
        };
        let mut result = PinWorkflowResult {
            outcome: MutationOutcome::NotDispatched,
            rejection: None,
            worker_quiescent: false,
            prompt_torn_down: false,
            recovery_required: true,
            cancelled: false,
        };
        let mut presented = false;
        let transaction = (|| -> Result<(), MutationError> {
            if self.epoch.load(Ordering::SeqCst) != r.intent.epoch {
                return Err(MutationError::InvalidPermit);
            }
            let coordinator = supervisor
                .coordinator
                .as_mut()
                .ok_or(MutationError::InvalidPermit)?;
            coordinator
                .endpoint
                .set_revocation(Arc::clone(&self.epoch), r.intent.epoch);
            let id = coordinator
                .take_request_id()
                .map_err(|_| MutationError::InvalidPermit)?;
            let response = coordinator
                .endpoint
                .exchange(mutation_envelope(
                    binding,
                    id,
                    WorkerRequest::PreparePinMutation {
                        device_id: r.intent.target.worker_device_id,
                        binding,
                    },
                ))
                .map_err(|_| MutationError::InvalidPermit)?;
            if response.device_generation != Some(binding.session.device_generation)
                || response.evidence.execution_quiescence != ExecutionQuiescence::Quiescent
                || response.evidence.mutation_outcome.is_some()
            {
                return Err(MutationError::InvalidPermit);
            }
            let retries = match response.response {
                WorkerResponse::PinMutationPrepared {
                    binding: echoed,
                    pin_retries,
                } if echoed == binding
                    && (binding.operation == PinOperation::SetPin && pin_retries.is_none()
                        || binding.operation == PinOperation::ChangePin
                            && pin_retries.is_some_and(|n| (1..=8).contains(&n))) =>
                {
                    pin_retries
                }
                _ => return Err(MutationError::InvalidPermit),
            };
            let (tx, rx) = std::sync::mpsc::channel();
            // Once the presenter accepts ownership, only its native teardown can release admission.
            present(
                r.reservation.prompt.clone(),
                Arc::clone(&self.controller),
                tx,
                binding.operation,
                retries,
                Arc::clone(&self.epoch),
                r.intent.epoch,
            )
            .map_err(|_| MutationError::InvalidPermit)?;
            presented = true;
            let completion = rx
                .recv_timeout(Duration::from_secs(fido_auth::PROMPT_LIFETIME_SECS + 2))
                .map_err(|_| MutationError::InvalidPermit)?;
            if completion.binding != r.intent.binding
                || completion.outcome.binding() != r.intent.binding
            {
                return Err(MutationError::InvalidPermit);
            }
            result.cancelled = !matches!(completion.outcome, PromptOutcome::Approved(_));
            let secrets = completion.secrets.ok_or(MutationError::InvalidPermit)?;
            if secrets.operation() != binding.operation {
                return Err(MutationError::InvalidPermit);
            }
            let permit = self.approve_pin_intent(&mut r)?;
            let dispatch_expiry = permit.expires_at;
            self.write_pending(&mut r, &permit)?;
            self.mark_dispatch_capable(supervisor, &mut r, permit)?;
            result.outcome = MutationOutcome::OutcomeUnknown;
            let dispatch = PinMutationDispatchPermit {
                binding,
                epoch: r.intent.epoch,
                expires_at: dispatch_expiry,
            };
            let native = self.dispatch_pin(supervisor, &r, dispatch, secrets)?;
            // No post-marker host path is advertised as NotDispatched; retain recovery protection.
            if native.outcome != MutationOutcome::NotDispatched {
                result.outcome = native.outcome;
                result.rejection = native.rejection;
            }
            Ok(())
        })();
        let _ = transaction;
        // If the marker was published during a failing handoff, no later abort erases uncertainty.
        let phase = self
            .recovery
            .lock()
            .ok()
            .and_then(|j| j.as_ref().and_then(|j| j.phase()));
        if phase == Some(JournalPhase::DispatchCapable)
            && result.outcome == MutationOutcome::NotDispatched
        {
            result.outcome = MutationOutcome::OutcomeUnknown;
        }
        result.worker_quiescent =
            supervisor.retire_authentication() == ExecutionQuiescence::Quiescent;
        if !presented {
            if let Ok(mut c) = self.controller.lock() {
                let _ = c.revoke(PromptOutcome::PresentationFailed(r.intent.binding));
                let _ = c.did_teardown(r.intent.binding, Instant::now());
            }
        }
        result.prompt_torn_down = self.controller.lock().is_ok_and(|c| !c.is_active());
        if result.worker_quiescent && result.prompt_torn_down {
            let resolution = match result.outcome {
                MutationOutcome::ConfirmedSuccessful => Some(Resolution::ConfirmedSuccessful),
                MutationOutcome::Rejected => Some(Resolution::Rejected),
                MutationOutcome::NotDispatched if r.pending => Some(Resolution::NotDispatched),
                _ => None,
            };
            if let Some(resolution) = resolution {
                let _ = self.resolve_pin_result(&r, resolution);
            }
            let completion = if result.cancelled {
                WorkflowCompletion::Cancelled
            } else if result.outcome == MutationOutcome::ConfirmedSuccessful {
                WorkflowCompletion::Succeeded
            } else {
                WorkflowCompletion::Rejected
            };
            let _ = self.finish_pin_foundation(r, completion, ExecutionQuiescence::Quiescent);
        }
        result.recovery_required = self.recovery_admission() != fido_core::RecoveryAdmission::Open;
        result
    }
    fn dispatch_pin(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        r: &MutationReservation,
        permit: PinMutationDispatchPermit,
        secrets: fido_auth::mutation::PinMutationSecrets,
    ) -> Result<fido_auth::mutation::PinMutationResult, MutationError> {
        use fido_worker_protocol::{WorkerRequest, WorkerResponse};
        // Ownership consumes the handoff on every attempt. Target/generation remains under the
        // exclusive supervisor borrow; endpoint revocation also guards transport and waiting.
        if self.epoch.load(Ordering::SeqCst) != permit.epoch
            || Instant::now() >= permit.expires_at
            || permit.binding.intent_digest != r.intent.digest()
            || supervisor.resolve_handle(r.intent.handle) != Some(r.intent.target)
            || supervisor.status().worker_generation != Some(r.intent.worker)
        {
            return Err(MutationError::InvalidPermit);
        }
        let c = supervisor
            .coordinator
            .as_mut()
            .ok_or(MutationError::InvalidPermit)?;
        let id = c
            .take_request_id()
            .map_err(|_| MutationError::InvalidPermit)?;
        #[cfg(unix)]
        c.endpoint
            .submit_mutation_secret(permit.binding, id, secrets)
            .map_err(|_| MutationError::InvalidPermit)?;
        #[cfg(not(unix))]
        {
            drop(secrets);
            return Err(MutationError::InvalidPermit);
        }
        let response = c
            .endpoint
            .exchange(mutation_envelope(
                permit.binding,
                id,
                WorkerRequest::ExecutePinMutation {
                    binding: permit.binding,
                },
            ))
            .map_err(|_| MutationError::InvalidPermit)?;
        match response.response {
            WorkerResponse::PinMutationCompleted { binding, result }
                if binding == permit.binding
                    && response.device_generation == Some(binding.session.device_generation)
                    && response.evidence.execution_quiescence == ExecutionQuiescence::Quiescent
                    && result.valid_for(binding.operation)
                    && response.evidence.mutation_outcome == Some(result.outcome) =>
            {
                Ok(result)
            }
            _ => Err(MutationError::InvalidPermit),
        }
    }
    fn resolve_pin_result(
        &self,
        r: &MutationReservation,
        resolution: Resolution,
    ) -> Result<(), MutationError> {
        let mut gate = self.gate.lock().map_err(|_| MutationError::InvalidPermit)?;
        if !gate.matches(&r.reservation.admission) {
            return Err(MutationError::InvalidPermit);
        }
        let mut slot = self
            .recovery
            .lock()
            .map_err(|_| JournalError::Unavailable)?;
        let journal = slot.as_mut().ok_or(JournalError::Unavailable)?;
        let result = journal.resolve(resolution);
        gate.set_persistent_barrier(journal.admission() == RecoveryAdmission::Barrier);
        result?;
        Ok(())
    }
    pub fn sensitive_blocked(&self) -> bool {
        self.recovery_admission() == RecoveryAdmission::Barrier
    }
    pub fn recovery_admission(&self) -> RecoveryAdmission {
        self.gate
            .lock()
            .map_or(RecoveryAdmission::Barrier, |g| g.recovery_admission())
    }
    /// Only a valid, unresolved dispatch record can offer acknowledgement. Poisoned storage
    /// exposes informational failure only; it cannot be acknowledged away.
    pub fn recoverable_pin_operation(&self) -> Option<PinOperation> {
        self.recovery
            .lock()
            .ok()?
            .as_ref()
            .filter(|j| j.can_acknowledge())?
            .operation()
    }

    pub fn acknowledge_pin_recovery(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        present: impl FnOnce(
            PromptRequest,
            crate::authentication::NativeController,
            std::sync::mpsc::Sender<fido_native_ui::MutationCompletion>,
            PinOperation,
            Arc<AtomicU64>,
            u64,
        ) -> Result<(), &'static str>,
    ) -> Result<(), MutationError> {
        let operation = self
            .recoverable_pin_operation()
            .ok_or(MutationError::InvalidPermit)?;
        let mut r = self.reserve_recovery()?;
        let binding = r.reservation.prompt.binding();
        let quiescence = supervisor.retire_authentication();
        if quiescence != ExecutionQuiescence::Quiescent {
            return Err(MutationError::NotQuiescent);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let presented = present(
            r.reservation.prompt.clone(),
            Arc::clone(&self.controller),
            tx,
            operation,
            Arc::clone(&self.epoch),
            r.reservation.epoch,
        )
        .is_ok();
        let approved = presented
            && rx
                .recv_timeout(Duration::from_secs(fido_auth::PROMPT_LIFETIME_SECS + 2))
                .is_ok_and(|c| {
                    c.binding == binding
                        && c.outcome == PromptOutcome::Approved(binding)
                        && c.secrets.is_none()
                });
        if !presented {
            if let Ok(mut c) = self.controller.lock() {
                let _ = c.revoke(PromptOutcome::PresentationFailed(binding));
                let _ = c.did_teardown(binding, Instant::now());
            }
        }
        if approved {
            match self.resolve_recovery(&mut r, Resolution::AcknowledgedUnknown, quiescence) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let _ = self.finish_recovery_foundation(
                        r,
                        WorkflowCompletion::Rejected,
                        quiescence,
                    );
                    return Err(e);
                }
            }
        }
        self.finish_recovery_foundation(r, WorkflowCompletion::Cancelled, quiescence)?;
        Err(MutationError::InvalidPermit)
    }

    /// Requires an exclusive borrow of the canonical supervisor, as inspection does. The handle
    /// comes from trusted backend selection, never a display handle or renderer mutation command.
    pub fn reserve_pin_intent<C: MonotonicClock + Clone>(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher, C>,
        handle: DeviceHandle,
        operation: PinOperation,
    ) -> Result<MutationReservation, MutationError> {
        let target = supervisor
            .resolve_handle(handle)
            .ok_or(MutationError::InvalidPermit)?;
        let worker = supervisor
            .status()
            .worker_generation
            .ok_or(MutationError::InvalidPermit)?;
        self.reserve_pin_target(handle, target, worker, operation)
    }

    fn reserve_pin_target(
        &self,
        handle: DeviceHandle,
        target: RegisteredDeviceTarget,
        worker: WorkerGeneration,
        operation: PinOperation,
    ) -> Result<MutationReservation, MutationError> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| MutationError::InvalidPermit)?;
        let created_at = Instant::now();
        let created_ms = self.clock.now().as_millis();
        let expires_at = created_at
            .checked_add(Duration::from_secs(fido_auth::PROMPT_LIFETIME_SECS))
            .ok_or(MutationError::InvalidPermit)?;
        let expires_ms = created_ms
            .checked_add(fido_auth::PROMPT_LIFETIME_SECS * 1000)
            .ok_or(MutationError::InvalidPermit)?;
        let reservation = self.reserve_sensitive(match operation {
            PinOperation::SetPin => SensitiveWorkflowKind::SetPin,
            PinOperation::ChangePin => SensitiveWorkflowKind::ChangePin,
        })?;
        let intent = OperationIntent {
            operation,
            handle,
            target,
            worker,
            binding: reservation.prompt.binding(),
            nonce,
            created_ms,
            expires_ms,
            expires_at: expires_at.min(reservation.prompt.deadline()),
            epoch: reservation.epoch,
            authority_epoch: Arc::clone(&self.epoch),
        };
        Ok(MutationReservation {
            reservation,
            intent,
            approved: None,
            consumed: false,
            pending: false,
        })
    }

    /// Polls the authority-owned teardown channel. Callers cannot supply an approval flag or
    /// synthesize an outcome; only the registered trusted native host resolves the controller.
    pub fn approve_pin_intent(
        &self,
        reservation: &mut MutationReservation,
    ) -> Result<OperationPermit, MutationError> {
        self.approve_at(reservation, Instant::now())
    }
    fn approve_at(
        &self,
        r: &mut MutationReservation,
        now: Instant,
    ) -> Result<OperationPermit, MutationError> {
        let gate = self.gate.lock().map_err(|_| MutationError::InvalidPermit)?;
        if !gate.matches(&r.reservation.admission)
            || r.intent.binding != r.reservation.prompt.binding()
            || r.intent.binding.workflow_id != r.reservation.admission.workflow_id()
            || self
                .controller
                .lock()
                .map_err(|_| MutationError::InvalidPermit)?
                .is_active()
            || gate.recovery_admission() != RecoveryAdmission::Open
            || r.approved.is_some()
            || r.consumed
            || now >= r.intent.expires_at
            || !Arc::ptr_eq(&self.epoch, &r.intent.authority_epoch)
            || self.epoch.load(Ordering::SeqCst) != r.intent.epoch
            || r.reservation.prompt_outcome.try_recv().ok()
                != Some(PromptOutcome::Approved(r.intent.binding))
        {
            return Err(MutationError::InvalidPermit);
        }
        let expires_at = now
            .checked_add(PERMIT_TTL)
            .ok_or(MutationError::InvalidPermit)?
            .min(r.intent.expires_at);
        let digest = r.intent.digest();
        r.approved = Some(digest);
        Ok(OperationPermit { digest, expires_at })
    }

    pub fn write_pending(
        &self,
        r: &mut MutationReservation,
        permit: &OperationPermit,
    ) -> Result<(), MutationError> {
        let mut gate = self.gate.lock().map_err(|_| MutationError::InvalidPermit)?;
        self.validate_permit(&gate, r, permit, Instant::now())?;
        if r.pending {
            return Err(MutationError::InvalidPermit);
        }
        let mut slot = self
            .recovery
            .lock()
            .map_err(|_| JournalError::Unavailable)?;
        let journal = slot.as_mut().ok_or(JournalError::Unavailable)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JournalError::Unavailable)?
            .as_secs();
        let result = journal.pending(r.intent.operation, timestamp);
        gate.set_persistent_barrier(journal.admission() == RecoveryAdmission::Barrier);
        result?;
        r.pending = true;
        Ok(())
    }

    /// Final exact target validation, single-use consumption and durable journal transition share
    /// the global gate lock and exclusive supervisor borrow. Returns no worker request, dispatch
    /// permit, callback or executable operation. Only mutate_pin's private typed continuation
    /// preserves the exclusive supervisor ownership and epoch/expiry checks through handoff.
    pub fn mark_dispatch_capable<C: MonotonicClock + Clone>(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher, C>,
        r: &mut MutationReservation,
        permit: OperationPermit,
    ) -> Result<(), MutationError> {
        let target = supervisor.resolve_handle(r.intent.handle);
        let worker = supervisor.status().worker_generation;
        self.consume_at(r, permit, target, worker, Instant::now())
    }
    fn consume_at(
        &self,
        r: &mut MutationReservation,
        permit: OperationPermit,
        target: Option<RegisteredDeviceTarget>,
        worker: Option<WorkerGeneration>,
        now: Instant,
    ) -> Result<(), MutationError> {
        let mut gate = self.gate.lock().map_err(|_| MutationError::InvalidPermit)?;
        // On ANY attempt the owned permit is lost. The reservation cannot mint or consume another.
        let valid = self.validate_permit(&gate, r, &permit, now).is_ok()
            && r.pending
            && target == Some(r.intent.target)
            && worker == Some(r.intent.worker);
        r.approved = None;
        r.consumed = true;
        if !valid {
            return Err(MutationError::InvalidPermit);
        }
        let mut slot = self
            .recovery
            .lock()
            .map_err(|_| JournalError::Unavailable)?;
        let journal = slot.as_mut().ok_or(JournalError::Unavailable)?;
        let result = journal.dispatch_capable(r.intent.operation);
        gate.set_persistent_barrier(journal.admission() == RecoveryAdmission::Barrier);
        result?;
        // Lifecycle can change during disk sync; retain the marker/barrier but return no authority.
        if self.epoch.load(Ordering::SeqCst) != r.intent.epoch
            || Instant::now() >= permit.expires_at
        {
            return Err(MutationError::InvalidPermit);
        }
        Ok(())
    }
    fn validate_permit(
        &self,
        gate: &crate::SensitiveWorkflowGate,
        r: &MutationReservation,
        permit: &OperationPermit,
        now: Instant,
    ) -> Result<(), MutationError> {
        if !gate.matches(&r.reservation.admission)
            || r.intent.binding != r.reservation.prompt.binding()
            || r.intent.binding.workflow_id != r.reservation.admission.workflow_id()
            || self
                .controller
                .lock()
                .map_err(|_| MutationError::InvalidPermit)?
                .is_active()
            || gate.recovery_admission() != RecoveryAdmission::Open
            || !Arc::ptr_eq(&self.epoch, &r.intent.authority_epoch)
            || self.epoch.load(Ordering::SeqCst) != r.intent.epoch
            || r.consumed
            || now >= permit.expires_at
            || now >= r.intent.expires_at
            || r.approved != Some(permit.digest)
            || permit.digest != r.intent.digest()
        {
            return Err(MutationError::InvalidPermit);
        }
        Ok(())
    }

    /// Release only after the registered prompt is closed and execution is independently proven
    /// quiescent. A durable dispatch-capable record remains a barrier on every completion.
    pub fn finish_pin_foundation(
        &self,
        r: MutationReservation,
        completion: WorkflowCompletion,
        quiescence: ExecutionQuiescence,
    ) -> Result<(), MutationError> {
        if !Arc::ptr_eq(&self.epoch, &r.intent.authority_epoch) {
            return Err(MutationError::InvalidPermit);
        }
        self.finish_sensitive(r.reservation, completion, quiescence)
    }
    fn finish_sensitive(
        &self,
        r: AuthenticationReservation,
        completion: WorkflowCompletion,
        quiescence: ExecutionQuiescence,
    ) -> Result<(), MutationError> {
        let mut gate = self.gate.lock().map_err(|_| MutationError::InvalidPermit)?;
        if self
            .controller
            .lock()
            .map_err(|_| MutationError::NotQuiescent)?
            .is_active()
            || quiescence != ExecutionQuiescence::Quiescent
        {
            return Err(MutationError::NotQuiescent);
        }
        let recovery_admission = gate.recovery_admission();
        gate.finish(
            &r.admission,
            completion,
            WorkflowReleaseEvidence {
                execution_quiescence: quiescence,
                recovery_admission,
            },
            self.clock.now(),
        )?;
        Ok(())
    }

    pub fn reserve_recovery(&self) -> Result<RecoveryReservation, MutationError> {
        Ok(RecoveryReservation {
            reservation: self.reserve_sensitive(SensitiveWorkflowKind::Recovery)?,
            authority_epoch: Arc::clone(&self.epoch),
        })
    }

    pub fn finish_recovery_foundation(
        &self,
        r: RecoveryReservation,
        completion: WorkflowCompletion,
        quiescence: ExecutionQuiescence,
    ) -> Result<(), MutationError> {
        if !Arc::ptr_eq(&self.epoch, &r.authority_epoch) {
            return Err(MutationError::InvalidPermit);
        }
        self.finish_sensitive(r.reservation, completion, quiescence)
    }

    /// A rejected clearance retains the reservation so trusted code can finish/cancel the
    /// quiescent workflow without clearing its incident barrier. Approval remains one-shot.
    /// Native recovery may deliberately acknowledge uncertainty or resolve a Pending-only
    /// incident as NotDispatched. No automatic probing or passive read implementation. A corrupt
    /// journal cannot be cleared by this primitive. Remaining-retry display belongs to the future
    /// explicit verification workflow, which is not implemented here.
    pub fn resolve_recovery(
        &self,
        r: &mut RecoveryReservation,
        resolution: Resolution,
        quiescence: ExecutionQuiescence,
    ) -> Result<(), MutationError> {
        let mut gate = self.gate.lock().map_err(|_| MutationError::InvalidPermit)?;
        let binding = r.reservation.prompt.binding();
        if !Arc::ptr_eq(&self.epoch, &r.authority_epoch)
            || Instant::now() >= r.reservation.prompt.deadline()
            || !gate.matches(&r.reservation.admission)
            || self.epoch.load(Ordering::SeqCst) != r.reservation.epoch
            || self
                .controller
                .lock()
                .map_err(|_| MutationError::NotQuiescent)?
                .is_active()
            || quiescence != ExecutionQuiescence::Quiescent
            || r.reservation.prompt_outcome.try_recv().ok()
                != Some(PromptOutcome::Approved(binding))
        {
            return Err(MutationError::InvalidPermit);
        }
        let mut slot = self
            .recovery
            .lock()
            .map_err(|_| JournalError::Unavailable)?;
        let journal = slot.as_mut().ok_or(JournalError::Unavailable)?;
        // This recovery path only supports native acknowledgement, not fabricated adapter success.
        if !matches!(
            (journal.phase(), resolution),
            (Some(JournalPhase::Pending), Resolution::NotDispatched)
                | (
                    Some(JournalPhase::DispatchCapable),
                    Resolution::AcknowledgedUnknown
                )
        ) {
            return Err(MutationError::InvalidPermit);
        }
        let result = journal.resolve(resolution);
        gate.set_persistent_barrier(journal.admission() == RecoveryAdmission::Barrier);
        result?;
        let recovery_admission = gate.recovery_admission();
        gate.finish(
            &r.reservation.admission,
            WorkflowCompletion::Succeeded,
            WorkflowReleaseEvidence {
                execution_quiescence: quiescence,
                recovery_admission,
            },
            self.clock.now(),
        )?;
        Ok(())
    }
}

fn mutation_envelope(
    binding: fido_auth::mutation::PinMutationBinding,
    id: u64,
    request: fido_worker_protocol::WorkerRequest,
) -> fido_worker_protocol::WorkerRequestEnvelope {
    fido_worker_protocol::WorkerRequestEnvelope {
        protocol_version: fido_worker_protocol::WORKER_PROTOCOL_VERSION,
        request_id: fido_worker_protocol::WorkerRequestId(id),
        cancellation_id: fido_worker_protocol::CancellationId(id),
        operation_class: request.operation_class(),
        worker_generation: WorkerGeneration(binding.session.worker_generation),
        device_generation: Some(binding.session.device_generation),
        budget_ms: fido_worker_protocol::RequestBudgetMs(fido_auth::AUTH_NATIVE_BUDGET_MS),
        request,
    }
}

/// Backend capability policy, never inferred from renderer summaries.
pub fn native_pin_operation(device: &fido_core::DeviceSnapshot) -> Option<PinOperation> {
    if device.read_status != fido_core::DeviceReadStatus::Ready {
        return None;
    }
    fido_auth::mutation::available_operation(
        &device.versions,
        device.options.iter().map(|o| (o.name.as_str(), o.enabled)),
    )
}
pub use fido_native_ui::MutationCompletion;
#[cfg(all(feature = "native-pin", target_os = "macos"))]
pub use fido_native_ui::macos_pin::{present_mutation, present_recovery};

/// Failure before any sheet exists has vacuous native teardown, acknowledged by the controller.
pub fn presentation_failed(
    binding: fido_native_ui::PromptBinding,
    controller: crate::authentication::NativeController,
    reply: std::sync::mpsc::Sender<MutationCompletion>,
) {
    if let Ok(mut c) = controller.lock() {
        let outcome = PromptOutcome::PresentationFailed(binding);
        let _ = c.revoke(outcome);
        if c.did_teardown(binding, Instant::now()).is_ok() {
            let _ = reply.send(MutationCompletion {
                binding,
                outcome,
                secrets: None,
            });
        }
    }
}
pub fn activity_outcome(
    operation: PinOperation,
    result: &PinWorkflowResult,
) -> crate::activity::ActivityOutcome {
    use crate::activity::ActivityOutcome;
    use fido_core::MutationOutcome;
    match result.outcome {
        MutationOutcome::ConfirmedSuccessful if result.recovery_required => {
            ActivityOutcome::Success(match operation {
                PinOperation::SetPin => {
                    "PIN was set. Further security key operations are blocked because the result could not be saved safely."
                }
                PinOperation::ChangePin => {
                    "PIN was changed. Further security key operations are blocked because the result could not be saved safely."
                }
            })
        }
        MutationOutcome::ConfirmedSuccessful => ActivityOutcome::Success(match operation {
            PinOperation::SetPin => "PIN was set.",
            PinOperation::ChangePin => "PIN was changed.",
        }),
        MutationOutcome::Rejected if operation == PinOperation::SetPin => {
            ActivityOutcome::Issue("PIN was not set: the security key rejected the operation.")
        }
        MutationOutcome::Rejected => ActivityOutcome::Issue(match result.rejection {
            Some(fido_auth::mutation::PinRejection::WrongCurrentPin) => {
                "PIN was not changed: the current PIN was rejected. No automatic retry was made."
            }
            Some(fido_auth::mutation::PinRejection::PinPolicy) => {
                "PIN was not changed: the security key rejected the new PIN policy."
            }
            _ => "PIN was not changed: the security key rejected the operation.",
        }),
        MutationOutcome::OutcomeUnknown => ActivityOutcome::Issue(
            "The PIN operation may have reached the security key, but the result could not be confirmed. Do not try again automatically. Review the uncertain operation from the Security key menu.",
        ),
        MutationOutcome::NotDispatched if result.recovery_required => ActivityOutcome::Issue(
            "PIN operation did not start. Further security key operations are blocked because preparation could not be saved safely.",
        ),
        MutationOutcome::NotDispatched if result.cancelled => ActivityOutcome::Cancelled,
        _ => ActivityOutcome::Issue("PIN operation did not start. No PIN change was attempted."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::tests::MemoryStorage;
    use fido_core::{DeviceGeneration, PromptInstanceId, WorkflowId};
    use fido_worker_protocol::WorkerDeviceId;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn authority() -> AuthenticationAuthority {
        let a = AuthenticationAuthority::awaiting_recovery_startup();
        a.initialize_recovery(Box::new(MemoryStorage::default()))
            .unwrap_or_else(|_| panic!("journal"));
        a
    }
    fn reserve(
        a: &AuthenticationAuthority,
        operation: PinOperation,
    ) -> Result<MutationReservation, MutationError> {
        a.reserve_pin_target(
            DeviceHandle::from_raw(1),
            RegisteredDeviceTarget {
                worker_device_id: WorkerDeviceId(2),
                device_generation: DeviceGeneration(3),
            },
            WorkerGeneration(4),
            operation,
        )
    }
    fn native_teardown(a: &AuthenticationAuthority, binding: PromptBinding, approved: bool) {
        let mut controller = a.controller.lock().unwrap_or_else(|_| panic!("controller"));
        let outcome = if approved {
            PromptOutcome::Approved(binding)
        } else {
            PromptOutcome::Cancelled(binding)
        };
        controller
            .resolve(outcome, Instant::now())
            .unwrap_or_else(|_| panic!("resolve"));
        controller
            .did_teardown(binding, Instant::now())
            .unwrap_or_else(|_| panic!("teardown"));
    }
    fn ready(
        a: &AuthenticationAuthority,
    ) -> Result<(MutationReservation, OperationPermit), MutationError> {
        let mut r = reserve(a, PinOperation::ChangePin)?;
        native_teardown(a, r.intent.binding, true);
        let p = a.approve_pin_intent(&mut r)?;
        a.write_pending(&mut r, &p)?;
        Ok((r, p))
    }
    fn consume(
        a: &AuthenticationAuthority,
        r: &mut MutationReservation,
        p: OperationPermit,
    ) -> Result<(), MutationError> {
        let target = r.intent.target;
        let worker = r.intent.worker;
        a.consume_at(r, p, Some(target), Some(worker), Instant::now())
    }
    #[test]
    fn one_gate_and_prompt_domain_across_inspection_set_change_and_recovery() -> TestResult {
        for first in [
            SensitiveWorkflowKind::CredentialInspection,
            SensitiveWorkflowKind::SetPin,
            SensitiveWorkflowKind::ChangePin,
            SensitiveWorkflowKind::Recovery,
        ] {
            let a = authority();
            let r = a.reserve_sensitive(first)?;
            for next in [
                SensitiveWorkflowKind::CredentialInspection,
                SensitiveWorkflowKind::SetPin,
                SensitiveWorkflowKind::ChangePin,
                SensitiveWorkflowKind::Recovery,
            ] {
                assert!(matches!(
                    a.reserve_sensitive(next),
                    Err(AdmissionError::OperationInProgress)
                ));
            }
            native_teardown(&a, r.prompt.binding(), false);
            a.finish_sensitive(
                r,
                WorkflowCompletion::Cancelled,
                ExecutionQuiescence::Quiescent,
            )?;
            assert!(a.reserve().is_ok());
        }
        Ok(())
    }
    #[test]
    fn shared_cooldown_counts_different_workflow_kinds() -> TestResult {
        let a = authority();
        for kind in [
            SensitiveWorkflowKind::CredentialInspection,
            SensitiveWorkflowKind::SetPin,
            SensitiveWorkflowKind::ChangePin,
        ] {
            let r = a.reserve_sensitive(kind)?;
            native_teardown(&a, r.prompt.binding(), false);
            a.finish_sensitive(
                r,
                WorkflowCompletion::Cancelled,
                ExecutionQuiescence::Quiescent,
            )?;
        }
        assert!(matches!(a.reserve(), Err(AdmissionError::CoolingDown)));
        Ok(())
    }
    #[test]
    fn prompt_teardown_and_execution_quiescence_remain_required() -> TestResult {
        let a = authority();
        let r = reserve(&a, PinOperation::SetPin)?;
        assert!(
            a.finish_pin_foundation(
                r,
                WorkflowCompletion::Failed,
                ExecutionQuiescence::Quiescent
            )
            .is_err()
        );
        assert!(matches!(
            a.reserve(),
            Err(AdmissionError::OperationInProgress)
        ));
        let a = authority();
        let r = reserve(&a, PinOperation::SetPin)?;
        native_teardown(&a, r.intent.binding, true);
        assert!(
            a.finish_pin_foundation(r, WorkflowCompletion::Failed, ExecutionQuiescence::Active)
                .is_err()
        );
        assert!(matches!(
            a.reserve(),
            Err(AdmissionError::OperationInProgress)
        ));
        Ok(())
    }
    #[test]
    fn intent_canonical_binding_detects_every_approved_dimension() -> TestResult {
        for field in 0..11 {
            let a = authority();
            let (mut r, p) = ready(&a)?;
            let before = r.intent.canonical();
            assert_eq!(r.intent.digest(), p.digest);
            match field {
                0 => r.intent.operation = PinOperation::SetPin,
                1 => r.intent.handle = DeviceHandle::from_raw(99),
                2 => r.intent.target.worker_device_id = WorkerDeviceId(99),
                3 => r.intent.target.device_generation = DeviceGeneration(99),
                4 => r.intent.worker = WorkerGeneration(99),
                5 => r.intent.binding.workflow_id = WorkflowId::from_raw(99),
                6 => r.intent.binding.prompt_instance_id = PromptInstanceId::from_raw(99),
                7 => r.intent.created_ms += 1,
                8 => r.intent.expires_ms += 1,
                9 => r.intent.epoch += 1,
                _ => r.intent.nonce[0] ^= 1,
            }
            assert_ne!(r.intent.canonical(), before);
            assert!(consume(&a, &mut r, p).is_err());
        }
        Ok(())
    }
    #[test]
    fn exact_device_generation_worker_and_target_changes_invalidate_permits() -> TestResult {
        for field in 0..5 {
            let a = authority();
            let (mut r, p) = ready(&a)?;
            let mut target = Some(r.intent.target);
            let mut worker = Some(r.intent.worker);
            match field {
                0 => target.as_mut().ok_or("target")?.device_generation = DeviceGeneration(99),
                1 => target.as_mut().ok_or("target")?.worker_device_id = WorkerDeviceId(99),
                2 => worker = Some(WorkerGeneration(99)),
                3 => target = None,
                _ => worker = None,
            }
            assert!(
                a.consume_at(&mut r, p, target, worker, Instant::now())
                    .is_err()
            );
            assert_eq!(
                a.recovery
                    .lock()
                    .map_err(|_| "journal")?
                    .as_ref()
                    .ok_or("journal")?
                    .phase(),
                Some(JournalPhase::Pending)
            );
        }
        Ok(())
    }
    #[test]
    fn approval_requires_bound_native_teardown_not_a_supplied_boolean() -> TestResult {
        let a = authority();
        let mut r = reserve(&a, PinOperation::SetPin)?;
        assert!(a.approve_pin_intent(&mut r).is_err());
        let wrong = PromptBinding {
            workflow_id: r.intent.binding.workflow_id,
            prompt_instance_id: PromptInstanceId::from_raw(99),
        };
        assert!(
            a.controller
                .lock()
                .map_err(|_| "controller")?
                .resolve(PromptOutcome::Approved(wrong), Instant::now())
                .is_err()
        );
        a.controller
            .lock()
            .map_err(|_| "controller")?
            .resolve(PromptOutcome::Approved(r.intent.binding), Instant::now())?;
        assert!(a.approve_pin_intent(&mut r).is_err());
        a.controller
            .lock()
            .map_err(|_| "controller")?
            .did_teardown(r.intent.binding, Instant::now())?;
        assert!(a.approve_pin_intent(&mut r).is_ok());
        assert!(a.approve_pin_intent(&mut r).is_err());
        Ok(())
    }
    #[test]
    fn cancellation_and_lifecycle_epoch_revoke_approval() -> TestResult {
        let a = authority();
        let mut r = reserve(&a, PinOperation::SetPin)?;
        native_teardown(&a, r.intent.binding, false);
        assert!(a.approve_pin_intent(&mut r).is_err());
        for _ in ["cancel", "lock", "sleep", "session switch", "owner loss"] {
            let a = authority();
            let (mut r, p) = ready(&a)?;
            a.revoke();
            assert!(consume(&a, &mut r, p).is_err());
        }
        Ok(())
    }
    #[test]
    fn expiry_is_inclusive_for_intent_and_permit() -> TestResult {
        let a = authority();
        let mut r = reserve(&a, PinOperation::SetPin)?;
        native_teardown(&a, r.intent.binding, true);
        let deadline = r.intent.expires_at;
        assert!(a.approve_at(&mut r, deadline).is_err());
        let a = authority();
        let (mut r, p) = ready(&a)?;
        let deadline = p.expires_at;
        let target = r.intent.target;
        let worker = r.intent.worker;
        assert!(
            a.consume_at(&mut r, p, Some(target), Some(worker), deadline)
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn permit_is_one_shot_even_if_replayed_internally() -> TestResult {
        let a = authority();
        let (mut r, p) = ready(&a)?;
        // Module-private adversarial duplication simulates a replay unavailable to real callers.
        let replay = OperationPermit {
            digest: p.digest,
            expires_at: p.expires_at,
        };
        consume(&a, &mut r, p)?;
        assert!(consume(&a, &mut r, replay).is_err());
        assert!(a.approve_pin_intent(&mut r).is_err());
        Ok(())
    }
    #[test]
    fn stale_permit_cannot_authorize_successor_or_other_authority() -> TestResult {
        let a = authority();
        let (r, p) = ready(&a)?;
        a.finish_pin_foundation(
            r,
            WorkflowCompletion::Succeeded,
            ExecutionQuiescence::Quiescent,
        )?;
        let mut successor = reserve(&a, PinOperation::ChangePin)?;
        native_teardown(&a, successor.intent.binding, true);
        let own = a.approve_pin_intent(&mut successor)?;
        assert_ne!(p.digest, own.digest);
        assert!(consume(&a, &mut successor, p).is_err());
        let a = authority();
        let b = authority();
        let (mut r, p) = ready(&a)?;
        assert!(consume(&b, &mut r, p).is_err());
        Ok(())
    }
    #[test]
    fn durable_barrier_survives_ordinary_completion_revocation_and_reinitialization() -> TestResult
    {
        let disk = MemoryStorage::default();
        let a = AuthenticationAuthority::awaiting_recovery_startup();
        a.initialize_recovery(Box::new(disk.clone()))?;
        let (mut r, p) = ready(&a)?;
        consume(&a, &mut r, p)?;
        a.finish_pin_foundation(
            r,
            WorkflowCompletion::Succeeded,
            ExecutionQuiescence::Quiescent,
        )?;
        a.revoke(); // reconnect/lifecycle does not clear the persistent latch
        assert!(
            a.initialize_recovery(Box::new(MemoryStorage::default()))
                .is_err()
        );
        let restarted = AuthenticationAuthority::awaiting_recovery_startup();
        restarted.initialize_recovery(Box::new(disk))?;
        for authority in [&a, &restarted] {
            assert!(matches!(
                authority.reserve(),
                Err(AdmissionError::RecoveryBarrier)
            ));
            assert!(matches!(
                reserve(authority, PinOperation::SetPin),
                Err(MutationError::Admission(AdmissionError::RecoveryBarrier))
            ));
            assert!(matches!(
                reserve(authority, PinOperation::ChangePin),
                Err(MutationError::Admission(AdmissionError::RecoveryBarrier))
            ));
        }
        let mut recovery = restarted.reserve_recovery()?;
        native_teardown(&restarted, recovery.prompt().binding(), true);
        restarted.resolve_recovery(
            &mut recovery,
            Resolution::AcknowledgedUnknown,
            ExecutionQuiescence::Quiescent,
        )?;
        assert!(restarted.reserve().is_ok());
        Ok(())
    }
    #[test]
    fn pending_restart_requires_no_dispatch_claim_and_can_resolve_deliberately() -> TestResult {
        let disk = MemoryStorage::default();
        let a = AuthenticationAuthority::awaiting_recovery_startup();
        a.initialize_recovery(Box::new(disk.clone()))?;
        let (r, _) = ready(&a)?;
        a.finish_pin_foundation(
            r,
            WorkflowCompletion::Succeeded,
            ExecutionQuiescence::Quiescent,
        )?;
        let restarted = AuthenticationAuthority::awaiting_recovery_startup();
        restarted.initialize_recovery(Box::new(disk.clone()))?;
        let mut recovery = restarted.reserve_recovery()?;
        native_teardown(&restarted, recovery.prompt().binding(), true);
        restarted.resolve_recovery(
            &mut recovery,
            Resolution::NotDispatched,
            ExecutionQuiescence::Quiescent,
        )?;
        let after = AuthenticationAuthority::awaiting_recovery_startup();
        after.initialize_recovery(Box::new(disk))?;
        assert!(after.reserve().is_ok());
        Ok(())
    }
    #[test]
    fn no_storage_corrupt_storage_and_storage_failure_fail_closed() -> TestResult {
        let a = AuthenticationAuthority::awaiting_recovery_startup();
        assert!(matches!(a.reserve(), Err(AdmissionError::RecoveryBarrier)));
        for failure in [1, 2] {
            let disk = MemoryStorage::default();
            let a = AuthenticationAuthority::awaiting_recovery_startup();
            a.initialize_recovery(Box::new(disk.clone()))?;
            let (mut r, p) = ready(&a)?;
            disk.0.lock().map_err(|_| "disk")?.failure = failure;
            assert!(consume(&a, &mut r, p).is_err());
            a.finish_pin_foundation(
                r,
                WorkflowCompletion::Failed,
                ExecutionQuiescence::Quiescent,
            )?;
            assert!(matches!(a.reserve(), Err(AdmissionError::RecoveryBarrier)));
        }
        let disk = MemoryStorage::default();
        disk.0.lock().map_err(|_| "disk")?.bytes = Some(b"malformed".to_vec());
        let a = AuthenticationAuthority::awaiting_recovery_startup();
        a.initialize_recovery(Box::new(disk))?;
        assert!(matches!(a.reserve(), Err(AdmissionError::RecoveryBarrier)));
        Ok(())
    }
    #[test]
    fn lifecycle_revocation_during_sync_cannot_authorize_a_transition() -> TestResult {
        struct RevokeOnSync {
            disk: MemoryStorage,
            epoch: Arc<AtomicU64>,
            writes: usize,
        }
        impl crate::recovery::JournalStorage for RevokeOnSync {
            fn read(&mut self) -> std::io::Result<Option<Vec<u8>>> {
                crate::recovery::JournalStorage::read(&mut self.disk)
            }
            fn replace_durable(&mut self, bytes: &[u8]) -> std::io::Result<()> {
                self.writes += 1;
                if self.writes == 2 {
                    self.epoch.fetch_add(1, Ordering::SeqCst);
                }
                crate::recovery::JournalStorage::replace_durable(&mut self.disk, bytes)
            }
        }
        let a = AuthenticationAuthority::awaiting_recovery_startup();
        a.initialize_recovery(Box::new(RevokeOnSync {
            disk: MemoryStorage::default(),
            epoch: Arc::clone(&a.epoch),
            writes: 0,
        }))?;
        let (mut r, p) = ready(&a)?;
        assert!(consume(&a, &mut r, p).is_err());
        assert_eq!(
            a.recovery
                .lock()
                .map_err(|_| "journal")?
                .as_ref()
                .ok_or("journal")?
                .admission(),
            RecoveryAdmission::Barrier
        );
        Ok(())
    }
    #[test]
    fn changed_reservation_workflow_or_prompt_cannot_consume_old_approval() -> TestResult {
        for change_prompt in [false, true] {
            let a = authority();
            let (mut r, p) = ready(&a)?;
            if change_prompt {
                let (prompt, _) = a.controller.lock().map_err(|_| "controller")?.request(
                    r.reservation.admission.workflow_id(),
                    Instant::now(),
                    Duration::from_secs(30),
                )?;
                let binding = prompt.binding();
                r.reservation.prompt = prompt;
                native_teardown(&a, binding, true);
            } else {
                r.reservation.admission.workflow_id = WorkflowId::from_raw(99);
            }
            assert!(consume(&a, &mut r, p).is_err());
        }
        Ok(())
    }

    #[test]
    fn pending_write_failure_blocks_consumption_and_ordinary_admission() -> TestResult {
        let disk = MemoryStorage::default();
        let a = AuthenticationAuthority::default();
        a.initialize_recovery(Box::new(disk.clone()))?;
        let mut r = reserve(&a, PinOperation::SetPin)?;
        native_teardown(&a, r.intent.binding, true);
        let p = a.approve_pin_intent(&mut r)?;
        disk.0.lock().map_err(|_| "disk")?.failure = 1;
        assert!(a.write_pending(&mut r, &p).is_err());
        assert!(consume(&a, &mut r, p).is_err());
        a.finish_pin_foundation(
            r,
            WorkflowCompletion::Failed,
            ExecutionQuiescence::Quiescent,
        )?;
        assert!(matches!(a.reserve(), Err(AdmissionError::RecoveryBarrier)));
        Ok(())
    }

    #[test]
    fn recovery_requires_native_approval_quiescence_and_durable_resolution() -> TestResult {
        for failure in 0..4 {
            let disk = MemoryStorage::default();
            let a = AuthenticationAuthority::default();
            a.initialize_recovery(Box::new(disk.clone()))?;
            let (mut r, p) = ready(&a)?;
            consume(&a, &mut r, p)?;
            a.finish_pin_foundation(
                r,
                WorkflowCompletion::Succeeded,
                ExecutionQuiescence::Quiescent,
            )?;
            let mut recovery = a.reserve_recovery()?;
            native_teardown(&a, recovery.prompt().binding(), failure != 0);
            let quiescence = if failure == 1 {
                ExecutionQuiescence::Active
            } else {
                ExecutionQuiescence::Quiescent
            };
            if failure == 2 {
                disk.0.lock().map_err(|_| "disk")?.failure = 2;
            }
            let resolution = if failure == 3 {
                Resolution::ConfirmedSuccessful
            } else {
                Resolution::AcknowledgedUnknown
            };
            assert!(
                a.resolve_recovery(&mut recovery, resolution, quiescence)
                    .is_err()
            );
            assert_eq!(
                a.gate.lock().map_err(|_| "gate")?.recovery_admission(),
                RecoveryAdmission::Barrier
            );
            // After independent quiescence proof, failure can release exclusion without
            // clearing admission. No restart is needed to admit another deliberate Recovery.
            a.finish_recovery_foundation(
                recovery,
                WorkflowCompletion::Failed,
                ExecutionQuiescence::Quiescent,
            )?;
            assert!(matches!(a.reserve(), Err(AdmissionError::RecoveryBarrier)));
            assert!(a.reserve_recovery().is_ok());
        }
        Ok(())
    }

    #[test]
    fn ordinary_finish_evidence_cannot_clear_persistent_gate_latch() -> TestResult {
        let mut gate = crate::SensitiveWorkflowGate::default();
        let r = gate.try_begin(
            SensitiveWorkflowKind::CredentialInspection,
            crate::MonotonicMillis::from_millis(0),
        )?;
        gate.set_persistent_barrier(true);
        gate.finish(
            &r,
            WorkflowCompletion::Succeeded,
            WorkflowReleaseEvidence {
                execution_quiescence: ExecutionQuiescence::Quiescent,
                recovery_admission: RecoveryAdmission::Open,
            },
            crate::MonotonicMillis::from_millis(1),
        )?;
        assert_eq!(gate.recovery_admission(), RecoveryAdmission::Barrier);
        Ok(())
    }
}
