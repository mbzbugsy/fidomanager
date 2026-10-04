//! Non-dispatching PIN intent/permit foundation. One authority owns inspection, mutation and
//! recovery reservations. No worker operation or native PIN-mutation presenter is installed.
use crate::{
    AdmissionError, CompletionError, DiscoverySupervisor, MonotonicClock, ProcessWorkerLauncher,
    RegisteredDeviceTarget, WorkerGeneration, WorkflowCompletion, WorkflowReleaseEvidence,
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

impl AuthenticationAuthority {
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
    /// permit, callback or executable operation. Future dispatch requires a separately reviewed
    /// continuation preserving these locks/epoch checks through its actual handoff.
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

    /// Future native recovery may deliberately acknowledge uncertainty or resolve a Pending-only
    /// incident as NotDispatched. No automatic probing or passive read implementation. A corrupt
    /// journal cannot be cleared by this primitive. Remaining-retry display belongs to the future
    /// explicit verification workflow, which is not implemented here.
    pub fn resolve_recovery(
        &self,
        r: RecoveryReservation,
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
        // This foundation only supports native acknowledgement, not fabricated adapter success.
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
        let recovery = restarted.reserve_recovery()?;
        native_teardown(&restarted, recovery.prompt().binding(), true);
        restarted.resolve_recovery(
            recovery,
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
        let recovery = restarted.reserve_recovery()?;
        native_teardown(&restarted, recovery.prompt().binding(), true);
        restarted.resolve_recovery(
            recovery,
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
            let recovery = a.reserve_recovery()?;
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
                a.resolve_recovery(recovery, resolution, quiescence)
                    .is_err()
            );
            assert_eq!(
                a.gate.lock().map_err(|_| "gate")?.recovery_admission(),
                RecoveryAdmission::Barrier
            );
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
