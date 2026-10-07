//! M5 credential-deletion authority foundation.
//!
//! Production credential-deletion authority: exact current inventory identity, immutable intent,
//! trusted-native approval, durable Pending -> DispatchCapable transition, one-shot worker
//! dispatch, conservative outcome classification, worker quiescence and recovery barrier.
//! Renderer input never supplies raw credential identity or approval evidence.

use crate::{
    AdmissionError, CompletionError, DiscoverySupervisor, MonotonicClock, ProcessWorkerLauncher,
    RegisteredDeviceTarget, WorkerEndpoint, WorkerGeneration, WorkflowCompletion,
    WorkflowReleaseEvidence,
    authentication::{AuthenticationAuthority, AuthenticationReservation, NativeController},
    inspection::{ExactCredentialTarget, InspectionStore, InventoryDevice},
    recovery::{JournalError, Resolution},
};
use fido_core::{DeviceHandle, ExecutionQuiescence, RecoveryAdmission, SensitiveWorkflowKind};
use fido_native_ui::{PinCompletion, PromptBinding, PromptOutcome, PromptRequest};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const DELETE_INTENT_VERSION: u8 = 1;
pub const DELETE_PERMIT_TTL: Duration = Duration::from_secs(10);
/// Avoid starting a durable transition with an approval about to expire. Fsync can still exceed
/// this margin; the post-sync expiry check remains mandatory.
pub const DELETE_PERSISTENCE_LIFETIME_MARGIN: Duration = Duration::from_secs(1);

/// Backend-owned immutable description of one exact enumerated credential.
///
/// Owns inspection selection and freshly resolved candidate addressing. The worker must prove
/// the exact credential again on its current native session; presentation continuity is not authority.
///
/// The type has no public constructor, no mutable fields, no serde, and no Clone/Copy.
pub struct DeleteCredentialIntent {
    target: ExactCredentialTarget,
    native_handle: DeviceHandle,
    native_target: RegisteredDeviceTarget,
    worker: WorkerGeneration,
    binding: PromptBinding,
    nonce: [u8; 16],
    created_ms: u64,
    expires_ms: u64,
    expires_at: Instant,
    lifecycle_epoch: u64,
    authority_epoch: Arc<AtomicU64>,
}

impl DeleteCredentialIntent {
    pub fn binding(&self) -> PromptBinding {
        self.binding
    }

    pub fn device(&self) -> InventoryDevice {
        self.target.device()
    }

    pub fn rp_text(&self) -> &str {
        self.target.rp_text()
    }

    pub fn user_name(&self) -> Option<&str> {
        self.target.user_name()
    }

    pub fn display_name(&self) -> Option<&str> {
        self.target.display_name()
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical()).into()
    }

    pub fn presentation(&self) -> DeleteCredentialPresentation {
        DeleteCredentialPresentation {
            authenticator: self.target.authenticator().to_owned(),
            rp_id: self.target.rp_text().to_owned(),
            user_name: self.target.user_name().map(ToOwned::to_owned),
            display_name: self.target.display_name().map(ToOwned::to_owned),
            credential_fingerprint: crate::inspection::credential_fingerprint(
                self.target.credential_id(),
            ),
            inventory_incomplete: self.target.completeness()
                == fido_core::inventory::Completeness::Incomplete,
        }
    }

    /// Fixed, versioned, length-delimited representation of the exact approved target and the
    /// presentation derived from that same target. No native handle, path, secret, or renderer
    /// value is accepted here.
    fn canonical(&self) -> Vec<u8> {
        fn bytes(out: &mut Vec<u8>, value: &[u8]) {
            let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
            out.extend(len.to_be_bytes());
            out.extend(value);
        }
        fn optional(out: &mut Vec<u8>, value: Option<&[u8]>) {
            match value {
                Some(value) => {
                    out.push(1);
                    bytes(out, value);
                }
                None => out.push(0),
            }
        }

        let mut out = b"FidoManager delete credential intent\0".to_vec();
        out.push(DELETE_INTENT_VERSION);
        out.extend(self.nonce);

        let device = self.target.device();
        bytes(&mut out, device.handle.as_wire().as_bytes());
        out.extend(device.generation.0.to_be_bytes());
        out.extend(self.native_handle.as_raw().to_be_bytes());
        out.extend(self.native_target.worker_device_id.0.to_be_bytes());
        out.extend(self.native_target.device_generation.0.to_be_bytes());
        out.extend(self.worker.0.to_be_bytes());
        bytes(&mut out, self.target.epoch().as_wire().as_bytes());
        bytes(&mut out, self.target.handle().as_wire().as_bytes());
        bytes(&mut out, self.target.authenticator().as_bytes());
        out.push(match self.target.completeness() {
            fido_core::inventory::Completeness::Complete => 1,
            fido_core::inventory::Completeness::Incomplete => 2,
            fido_core::inventory::Completeness::Inconsistent => 3,
        });

        out.extend(self.target.rp_hash());
        bytes(&mut out, self.target.credential_id());
        optional(&mut out, self.target.user_id());

        bytes(&mut out, self.target.rp_text().as_bytes());
        optional(&mut out, self.target.user_name().map(str::as_bytes));
        optional(&mut out, self.target.display_name().map(str::as_bytes));

        out.extend(self.binding.workflow_id.as_raw().to_be_bytes());
        out.extend(self.binding.prompt_instance_id.as_raw().to_be_bytes());
        out.extend(self.created_ms.to_be_bytes());
        out.extend(self.expires_ms.to_be_bytes());
        out.extend(self.lifecycle_epoch.to_be_bytes());
        out
    }
}

/// One native approval for one exact deletion intent. It cannot be cloned, serialized, retargeted
/// or used to dispatch by this module.
///
/// ```compile_fail
/// fn replay(p: &fido_service::deletion::DeleteCredentialPermit) {
///     let _copy = (*p).clone();
/// }
/// ```
///
/// ```compile_fail
/// fn serialize(p: &fido_service::deletion::DeleteCredentialPermit) {
///     let _ = serde_json::to_string(p);
/// }
/// ```
pub struct DeleteCredentialPermit {
    digest: [u8; 32],
    expires_at: Instant,
}

struct DeleteCredentialReservation {
    reservation: AuthenticationReservation,
    intent: DeleteCredentialIntent,
    approved: Option<[u8; 32]>,
    consumed: bool,
    pending: bool,
}

/// Backend-private authority produced only after a successfully synced DispatchCapable journal
/// transition. Ownership is consumed by the one native deletion attempt.
struct CredentialDeletionDispatchPermit {
    durable: crate::recovery::DurableCredentialDeletionDispatch,
    binding: fido_auth::deletion::DeleteCredentialBinding,
    lifecycle_epoch: u64,
    expires_at: Instant,
}

#[cfg(test)]
impl DeleteCredentialReservation {
    pub fn intent(&self) -> &DeleteCredentialIntent {
        &self.intent
    }
}

/// Trusted-native presentation derived only from the immutable exact deletion intent.
/// No renderer input or native addressing appears here.
pub struct DeleteCredentialPresentation {
    authenticator: String,
    rp_id: String,
    user_name: Option<String>,
    display_name: Option<String>,
    credential_fingerprint: String,
    inventory_incomplete: bool,
}
impl DeleteCredentialPresentation {
    pub fn authenticator(&self) -> &str {
        &self.authenticator
    }
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    pub fn user_name(&self) -> Option<&str> {
        self.user_name.as_deref()
    }
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
    pub fn consequence(&self) -> &'static str {
        "Deleting this credential permanently removes this passkey from the authenticator. You may lose access to the account unless another sign-in method is available."
    }
    pub fn credential_fingerprint(&self) -> &str {
        &self.credential_fingerprint
    }
    pub fn inventory_incomplete(&self) -> bool {
        self.inventory_incomplete
    }
    pub fn inventory_warning(&self) -> Option<&'static str> {
        self.inventory_incomplete.then_some("Some credentials could not be read. This inventory is incomplete; confirm the selected credential using its RP, account names, and fingerprint.")
    }
}

#[derive(Debug)]
pub struct DeleteCredentialWorkflowResult {
    pub outcome: fido_core::MutationOutcome,
    pub rejection: Option<fido_auth::deletion::DeleteCredentialRejection>,
    pub worker_quiescent: bool,
    pub prompt_torn_down: bool,
    pub recovery_required: bool,
    pub cancelled: bool,
}

#[derive(Debug, Error)]
pub enum DeleteCredentialError {
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Completion(#[from] CompletionError),
    #[error("deletion approval is stale, expired, replayed or revoked")]
    InvalidPermit,
    #[error("native teardown/quiescence is not established")]
    NotQuiescent,
}

/// Trusted information from the durable incident. The journal deliberately stores no credential
/// or physical-key identity, so recovery must not imply that it can identify a reconnected key.
pub struct DeletionRecoveryPresentation {
    created_unix_secs: u64,
}
impl DeletionRecoveryPresentation {
    pub fn created_unix_secs(&self) -> u64 {
        self.created_unix_secs
    }
    pub fn explanation(&self) -> &'static str {
        "The credential may or may not have been deleted. The incident record does not identify a reconnected authenticator or credential. Acknowledgement preserves the unknown result and allows future operations. Inspect the authenticator again before another credential mutation. No deletion will be retried."
    }
}

pub use fido_auth::deletion::DeleteCredentialRejection;
pub use fido_native_ui::DeletionRecoveryCompletion;
pub use fido_native_ui::deletion_description;
#[cfg(all(feature = "native-pin", target_os = "macos"))]
pub use fido_native_ui::macos_pin::{present_deletion, present_deletion_recovery};

pub fn recovery_presentation_failed(
    binding: PromptBinding,
    controller: NativeController,
    reply: std::sync::mpsc::Sender<DeletionRecoveryCompletion>,
) {
    let outcome = PromptOutcome::PresentationFailed(binding);
    if let Ok(mut c) = controller.lock() {
        let _ = c.revoke(outcome);
        let _ = c.did_teardown(binding, Instant::now());
    }
    let _ = reply.send(DeletionRecoveryCompletion { binding, outcome });
}

pub fn deletion_presentation_failed(
    binding: PromptBinding,
    controller: NativeController,
    reply: std::sync::mpsc::Sender<PinCompletion>,
) {
    let outcome = PromptOutcome::PresentationFailed(binding);
    if let Ok(mut c) = controller.lock() {
        let _ = c.revoke(outcome);
        let _ = c.did_teardown(binding, Instant::now());
    }
    let _ = reply.send(PinCompletion {
        binding,
        outcome,
        pin: None,
    });
}

impl AuthenticationAuthority {
    /// Application-owned deletion-only recovery; no generic renderer acknowledgement primitive.
    pub fn acknowledge_deletion_recovery(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        inspection: &mut InspectionStore,
        present: impl FnOnce(
            PromptRequest,
            NativeController,
            std::sync::mpsc::Sender<DeletionRecoveryCompletion>,
            DeletionRecoveryPresentation,
            Arc<AtomicU64>,
            u64,
        ) -> Result<(), &'static str>,
    ) -> Result<(), crate::mutation::MutationError> {
        use crate::{mutation::MutationError, recovery::RecoverableOperation};
        if self.recoverable_operation() != Some(RecoverableOperation::DeleteCredential) {
            return Err(MutationError::InvalidPermit);
        }
        let mut r = self.reserve_recovery()?;
        let binding = r.reservation.prompt.binding();
        let quiescence = supervisor.retire_authentication();
        if quiescence != ExecutionQuiescence::Quiescent {
            return Err(MutationError::NotQuiescent);
        }
        // Also clear old cards on restart acknowledgement. No cached selection may be reused.
        inspection.clear();
        let presentation = self.recovery.lock().ok().and_then(|slot| {
            let journal = slot.as_ref()?;
            (journal.recoverable_operation() == Some(RecoverableOperation::DeleteCredential))
                .then_some(DeletionRecoveryPresentation {
                    created_unix_secs: journal.incident_created_unix_secs()?,
                })
        });
        let (tx, rx) = std::sync::mpsc::channel();
        let presented = presentation.is_some_and(|presentation| {
            present(
                r.reservation.prompt.clone(),
                Arc::clone(&self.controller),
                tx.clone(),
                presentation,
                Arc::clone(&self.epoch),
                r.reservation.epoch,
            )
            .is_ok()
        });
        if !presented {
            recovery_presentation_failed(binding, Arc::clone(&self.controller), tx.clone());
        }
        drop(tx);
        let approved = presented
            && rx
                .recv_timeout(Duration::from_secs(fido_auth::PROMPT_LIFETIME_SECS + 2))
                .is_ok_and(|c| {
                    c.binding == binding && c.outcome == PromptOutcome::Approved(binding)
                });
        if approved {
            match self.resolve_recovery(
                &mut r,
                crate::mutation::RecoveryFamily::Deletion,
                Resolution::AcknowledgedUnknown,
                quiescence,
            ) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    let _ = self.finish_recovery_foundation(
                        r,
                        WorkflowCompletion::Rejected,
                        quiescence,
                    );
                    return Err(error);
                }
            }
        }
        self.finish_recovery_foundation(r, WorkflowCompletion::Cancelled, quiescence)?;
        Err(MutationError::InvalidPermit)
    }

    /// Execute one credential-deletion workflow through the killable worker. The renderer cannot
    /// enter this path directly: target identity, native presentation, approval, durable authority
    /// and worker addressing are all backend-owned.
    pub fn delete_credential(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        inspection: &mut InspectionStore,
        target: ExactCredentialTarget,
        present: impl FnOnce(
            PromptRequest,
            NativeController,
            std::sync::mpsc::Sender<PinCompletion>,
            DeleteCredentialPresentation,
            u8,
            Arc<AtomicU64>,
            u64,
        ) -> Result<(), &'static str>,
    ) -> Result<DeleteCredentialWorkflowResult, DeleteCredentialError> {
        use fido_core::MutationOutcome;
        use fido_worker_protocol::{WorkerRequest, WorkerResponse};

        let mut reservation = self.reserve_delete_credential(supervisor, inspection, target)?;
        let binding = delete_binding(&reservation);
        let mut result = DeleteCredentialWorkflowResult {
            outcome: MutationOutcome::NotDispatched,
            rejection: None,
            worker_quiescent: false,
            prompt_torn_down: false,
            recovery_required: true,
            cancelled: false,
        };
        let mut presented = false;

        let transaction = (|| -> Result<(), DeleteCredentialError> {
            if self.epoch.load(Ordering::SeqCst) != reservation.intent.lifecycle_epoch
                || !inspection.matches_exact_target(&reservation.intent.target)
                || inspection.current_candidate(&reservation.intent.target)
                    != Some((
                        reservation.intent.native_handle,
                        reservation.intent.native_target.device_generation,
                        reservation.intent.worker,
                    ))
            {
                return Err(DeleteCredentialError::InvalidPermit);
            }

            let coordinator = supervisor
                .coordinator
                .as_mut()
                .ok_or(DeleteCredentialError::InvalidPermit)?;
            coordinator
                .endpoint
                .set_revocation(Arc::clone(&self.epoch), reservation.intent.lifecycle_epoch);
            let request_id = coordinator
                .take_request_id()
                .map_err(|_| DeleteCredentialError::InvalidPermit)?;
            let response = coordinator
                .endpoint
                .exchange(delete_envelope(
                    binding,
                    request_id,
                    WorkerRequest::PrepareCredentialDeletion {
                        device_id: reservation.intent.native_target.worker_device_id,
                        binding,
                    },
                ))
                .map_err(|_| DeleteCredentialError::InvalidPermit)?;

            if response.device_generation != Some(binding.session.device_generation)
                || response.evidence.execution_quiescence != ExecutionQuiescence::Quiescent
                || response.evidence.mutation_outcome.is_some()
            {
                return Err(DeleteCredentialError::InvalidPermit);
            }

            let retries = match response.response {
                WorkerResponse::CredentialDeletionPrepared {
                    binding: echoed,
                    grant_kind,
                    pin_retries,
                } if echoed == binding
                    && matches!(
                        grant_kind,
                        fido_auth::GrantKind::CredMan | fido_auth::GrantKind::LegacyUnscoped
                    )
                    && (1..=8).contains(&pin_retries) =>
                {
                    pin_retries
                }
                _ => return Err(DeleteCredentialError::InvalidPermit),
            };

            let (reply, completion) = std::sync::mpsc::channel();
            present(
                reservation.reservation.prompt.clone(),
                Arc::clone(&self.controller),
                reply,
                reservation.intent.presentation(),
                retries,
                Arc::clone(&self.epoch),
                reservation.intent.lifecycle_epoch,
            )
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;
            presented = true;

            let completion = completion
                .recv_timeout(Duration::from_secs(fido_auth::PROMPT_LIFETIME_SECS + 2))
                .map_err(|_| DeleteCredentialError::InvalidPermit)?;
            if completion.binding != reservation.intent.binding
                || completion.outcome.binding() != reservation.intent.binding
            {
                return Err(DeleteCredentialError::InvalidPermit);
            }
            result.cancelled = !matches!(completion.outcome, PromptOutcome::Approved(_));
            if result.cancelled {
                return Err(DeleteCredentialError::InvalidPermit);
            }
            let pin = completion.pin.ok_or(DeleteCredentialError::InvalidPermit)?;

            let permit = self.approve_delete_credential(&mut reservation)?;

            // Read-only proof of the exact credential on the CURRENT prepared native session,
            // BEFORE any durable record. Every failure here is a provable "no DeleteCredential
            // was ever sent": no Pending, no DispatchCapable, no recovery barrier.
            let proof = self.prove_delete(supervisor, inspection, &reservation, &permit, pin)?;
            match proof.outcome {
                fido_auth::deletion::DeleteProofOutcome::Proved => {}
                fido_auth::deletion::DeleteProofOutcome::Rejected => {
                    result.outcome = MutationOutcome::Rejected;
                    result.rejection = proof.rejection;
                    return Ok(());
                }
                fido_auth::deletion::DeleteProofOutcome::NotProved => return Ok(()),
            }

            self.write_delete_pending(&mut reservation, &permit)?;
            let dispatch = self.mark_delete_dispatch_capable(
                supervisor,
                inspection,
                &mut reservation,
                permit,
            )?;

            // From this point a lost worker/response is never advertised as NotDispatched: the
            // only remaining native step is the one real delete.
            result.outcome = MutationOutcome::OutcomeUnknown;
            let native = self.dispatch_delete(supervisor, inspection, &reservation, dispatch)?;
            if native.outcome != MutationOutcome::NotDispatched {
                result.outcome = native.outcome;
                result.rejection = native.rejection;
            }
            Ok(())
        })();
        let _ = transaction;

        // A durable dispatch-capable marker dominates any host-side pre-result classification.
        let phase = self
            .recovery
            .lock()
            .ok()
            .and_then(|journal| journal.as_ref().and_then(|journal| journal.phase()));
        if phase == Some(crate::recovery::JournalPhase::DispatchCapable)
            && result.outcome == MutationOutcome::NotDispatched
        {
            result.outcome = MutationOutcome::OutcomeUnknown;
        }

        result.worker_quiescent =
            supervisor.retire_authentication() == ExecutionQuiescence::Quiescent;
        if !presented {
            if let Ok(mut controller) = self.controller.lock() {
                let _ = controller.revoke(PromptOutcome::PresentationFailed(
                    reservation.intent.binding,
                ));
                let _ = controller.did_teardown(reservation.intent.binding, Instant::now());
            }
        }
        result.prompt_torn_down = self.controller.lock().is_ok_and(|c| !c.is_active());
        if matches!(
            result.outcome,
            MutationOutcome::ConfirmedSuccessful | MutationOutcome::OutcomeUnknown
        ) || matches!(
            result.rejection,
            Some(
                fido_auth::deletion::DeleteCredentialRejection::CredentialAbsent
                    | fido_auth::deletion::DeleteCredentialRejection::CredentialMismatch
            )
        ) {
            // The card no longer describes the authenticator.
            inspection.invalidate(reservation.intent.device());
        }
        if result.worker_quiescent {
            inspection.proven_retirement(reservation.intent.worker);
        } else {
            inspection.clear();
        }

        if result.worker_quiescent && result.prompt_torn_down {
            // Only a record this workflow wrote can be resolved by it. A proof-stage failure wrote
            // nothing, so there is nothing to resolve and no barrier to clear.
            let resolution = match result.outcome {
                _ if !reservation.pending => None,
                MutationOutcome::ConfirmedSuccessful => Some(Resolution::ConfirmedSuccessful),
                MutationOutcome::Rejected => Some(Resolution::Rejected),
                MutationOutcome::NotDispatched => Some(Resolution::NotDispatched),
                _ => None,
            };
            if let Some(resolution) = resolution {
                let _ = self.resolve_delete_result(&reservation, resolution);
            }

            let completion = if result.cancelled {
                WorkflowCompletion::Cancelled
            } else if result.outcome == MutationOutcome::ConfirmedSuccessful {
                WorkflowCompletion::Succeeded
            } else {
                WorkflowCompletion::Rejected
            };
            let _ = self.finish_delete_foundation(
                reservation,
                completion,
                ExecutionQuiescence::Quiescent,
            );
        }

        result.recovery_required = self.recovery_admission() != RecoveryAdmission::Open;
        Ok(result)
    }

    /// Read-only proof step. Sends the PIN over the protected secret frame together with the exact
    /// immutable identity, and requires a typed result bound to this workflow. Runs strictly before
    /// `write_delete_pending`; the worker keeps the proven session for the one `dispatch_delete`.
    fn prove_delete(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        inspection: &InspectionStore,
        reservation: &DeleteCredentialReservation,
        permit: &DeleteCredentialPermit,
        pin: fido_auth::PinSecret,
    ) -> Result<fido_auth::deletion::DeleteProofResult, DeleteCredentialError> {
        use fido_worker_protocol::{WorkerRequest, WorkerResponse};

        {
            let gate = self
                .gate
                .lock()
                .map_err(|_| DeleteCredentialError::InvalidPermit)?;
            self.validate_delete_permit_with_gate(&gate, reservation, permit, Instant::now())?;
        }
        // Do not spend a PIN attempt on an approval that can no longer reach durable dispatch.
        if !persistence_lifetime_available(permit.expires_at, Instant::now())
            || supervisor.resolve_handle(reservation.intent.native_handle)
                != Some(reservation.intent.native_target)
            || supervisor.status().worker_generation != Some(reservation.intent.worker)
            || !inspection.matches_exact_target(&reservation.intent.target)
            || inspection.current_candidate(&reservation.intent.target)
                != Some((
                    reservation.intent.native_handle,
                    reservation.intent.native_target.device_generation,
                    reservation.intent.worker,
                ))
        {
            return Err(DeleteCredentialError::InvalidPermit);
        }

        let binding = delete_binding(reservation);
        let coordinator = supervisor
            .coordinator
            .as_mut()
            .ok_or(DeleteCredentialError::InvalidPermit)?;
        let request_id = coordinator
            .take_request_id()
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;

        #[cfg(unix)]
        coordinator
            .endpoint
            .submit_secret(binding.session, request_id, pin)
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;
        #[cfg(not(unix))]
        {
            drop(pin);
            return Err(DeleteCredentialError::InvalidPermit);
        }

        let response = coordinator
            .endpoint
            .exchange(delete_envelope(
                binding,
                request_id,
                WorkerRequest::ProveCredentialDeletion {
                    binding,
                    target: deletion_identity(&reservation.intent.target),
                },
            ))
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;

        match response.response {
            WorkerResponse::CredentialDeletionProved {
                binding: echoed,
                result,
            } if echoed == binding
                && response.device_generation == Some(binding.session.device_generation)
                && response.evidence.execution_quiescence == ExecutionQuiescence::Quiescent
                && response.evidence.mutation_outcome.is_none()
                && result.valid() =>
            {
                Ok(result)
            }
            _ => Err(DeleteCredentialError::InvalidPermit),
        }
    }

    fn dispatch_delete(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        inspection: &InspectionStore,
        reservation: &DeleteCredentialReservation,
        permit: CredentialDeletionDispatchPermit,
    ) -> Result<fido_auth::deletion::DeleteCredentialResult, DeleteCredentialError> {
        use fido_worker_protocol::{WorkerRequest, WorkerResponse};

        self.validate_delete_dispatch(supervisor, inspection, reservation, &permit)?;
        let coordinator = supervisor
            .coordinator
            .as_mut()
            .ok_or(DeleteCredentialError::InvalidPermit)?;
        let request_id = coordinator
            .take_request_id()
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;

        // No secret frame: the PIN already lives only inside the worker's proven session.
        let response = coordinator
            .endpoint
            .exchange(delete_envelope(
                permit.binding,
                request_id,
                WorkerRequest::ExecuteCredentialDeletion {
                    binding: permit.binding,
                    target: deletion_identity(&reservation.intent.target),
                },
            ))
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;

        match response.response {
            WorkerResponse::CredentialDeletionCompleted { binding, result }
                if binding == permit.binding
                    && response.device_generation == Some(binding.session.device_generation)
                    && response.evidence.execution_quiescence == ExecutionQuiescence::Quiescent
                    && result.valid()
                    && response.evidence.mutation_outcome == Some(result.outcome) =>
            {
                Ok(result)
            }
            _ => Err(DeleteCredentialError::InvalidPermit),
        }
    }

    /// Reserve one exact current credential for a future deletion workflow.
    ///
    /// `target` can only be produced by `InspectionStore::resolve_for_mutation`; it is an owned
    /// current-epoch identity, not native operation authority. No worker/native mutation occurs.
    fn reserve_delete_credential(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>,
        inspection: &InspectionStore,
        target: ExactCredentialTarget,
    ) -> Result<DeleteCredentialReservation, DeleteCredentialError> {
        // Acquire the sensitive gate BEFORE resolving any current native candidate.
        let reservation = self.reserve_sensitive(SensitiveWorkflowKind::DeleteCredential)?;
        let candidate = (|| {
            let (handle, generation, worker) = inspection.current_candidate(&target)?;
            let native = supervisor.resolve_handle(handle)?;
            (supervisor.status().worker_generation == Some(worker)
                && native.device_generation == generation)
                .then_some((handle, native, worker))
        })();
        let Some((handle, native, worker)) = candidate else {
            self.cancel_unpresented(supervisor, reservation);
            return Err(DeleteCredentialError::InvalidPermit);
        };
        // No reservation escapes the high-level orchestrator. Setup failure tears down explicitly.
        self.reserve_delete_target(target, handle, native, worker, reservation)
    }

    fn reserve_delete_target(
        &self,
        target: ExactCredentialTarget,
        native_handle: DeviceHandle,
        native_target: RegisteredDeviceTarget,
        worker: WorkerGeneration,
        reservation: AuthenticationReservation,
    ) -> Result<DeleteCredentialReservation, DeleteCredentialError> {
        let setup = (|| {
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).map_err(|_| DeleteCredentialError::InvalidPermit)?;
            let created_ms = self.clock.now().as_millis();
            let expires_ms = created_ms
                .checked_add(fido_auth::PROMPT_LIFETIME_SECS * 1000)
                .ok_or(DeleteCredentialError::InvalidPermit)?;
            Ok::<_, DeleteCredentialError>((nonce, created_ms, expires_ms))
        })();
        let (nonce, created_ms, expires_ms) = match setup {
            Ok(values) => values,
            Err(error) => {
                let binding = reservation.prompt.binding();
                if let Ok(mut c) = self.controller.lock() {
                    let _ = c.revoke(PromptOutcome::Cancelled(binding));
                    let _ = c.did_teardown(binding, Instant::now());
                }
                let _ = self.finish_sensitive(
                    reservation,
                    WorkflowCompletion::Cancelled,
                    ExecutionQuiescence::Quiescent,
                );
                return Err(error);
            }
        };
        let intent = DeleteCredentialIntent {
            target,
            native_handle,
            native_target,
            worker,
            binding: reservation.prompt.binding(),
            nonce,
            created_ms,
            expires_ms,
            expires_at: reservation.prompt.deadline(),
            lifecycle_epoch: reservation.epoch,
            authority_epoch: Arc::clone(&self.epoch),
        };
        Ok(DeleteCredentialReservation {
            reservation,
            intent,
            approved: None,
            consumed: false,
            pending: false,
        })
    }

    /// Mint at most one short-lived exact-intent permit after trusted native approval has torn down.
    /// Only the orchestrator may consume this permit into durable dispatch authority.
    fn approve_delete_credential(
        &self,
        reservation: &mut DeleteCredentialReservation,
    ) -> Result<DeleteCredentialPermit, DeleteCredentialError> {
        self.approve_delete_at(reservation, Instant::now())
    }

    fn approve_delete_at(
        &self,
        r: &mut DeleteCredentialReservation,
        now: Instant,
    ) -> Result<DeleteCredentialPermit, DeleteCredentialError> {
        let gate = self
            .gate
            .lock()
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;
        if !gate.matches(&r.reservation.admission)
            || r.intent.binding != r.reservation.prompt.binding()
            || r.intent.binding.workflow_id != r.reservation.admission.workflow_id()
            || self
                .controller
                .lock()
                .map_err(|_| DeleteCredentialError::InvalidPermit)?
                .is_active()
            || gate.recovery_admission() != RecoveryAdmission::Open
            || r.approved.is_some()
            || r.consumed
            || now >= r.intent.expires_at
            || !Arc::ptr_eq(&self.epoch, &r.intent.authority_epoch)
            || self.epoch.load(Ordering::SeqCst) != r.intent.lifecycle_epoch
            || r.reservation.prompt_outcome.try_recv().ok()
                != Some(PromptOutcome::Approved(r.intent.binding))
        {
            return Err(DeleteCredentialError::InvalidPermit);
        }

        let expires_at = now
            .checked_add(DELETE_PERMIT_TTL)
            .ok_or(DeleteCredentialError::InvalidPermit)?
            .min(r.intent.expires_at);
        let digest = r.intent.digest();
        r.approved = Some(digest);
        Ok(DeleteCredentialPermit { digest, expires_at })
    }

    fn write_delete_pending(
        &self,
        r: &mut DeleteCredentialReservation,
        permit: &DeleteCredentialPermit,
    ) -> Result<(), DeleteCredentialError> {
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;
        self.validate_delete_permit_with_gate(&gate, r, permit, Instant::now())?;
        if r.pending || !persistence_lifetime_available(permit.expires_at, Instant::now()) {
            return Err(DeleteCredentialError::InvalidPermit);
        }
        let mut slot = self
            .recovery
            .lock()
            .map_err(|_| JournalError::Unavailable)?;
        let journal = slot.as_mut().ok_or(JournalError::Unavailable)?;
        if !persistence_lifetime_available(permit.expires_at, Instant::now()) {
            return Err(DeleteCredentialError::InvalidPermit);
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JournalError::Unavailable)?
            .as_secs();
        let result = journal.pending_credential_deletion(timestamp);
        gate.set_persistent_barrier(journal.admission() == RecoveryAdmission::Barrier);
        result?;
        r.pending = true;
        Ok(())
    }

    fn mark_delete_dispatch_capable<C: MonotonicClock + Clone>(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher, C>,
        inspection: &InspectionStore,
        r: &mut DeleteCredentialReservation,
        permit: DeleteCredentialPermit,
    ) -> Result<CredentialDeletionDispatchPermit, DeleteCredentialError> {
        let current_target = supervisor.resolve_handle(r.intent.native_handle);
        let worker = supervisor.status().worker_generation;
        let inspection_matches = inspection.matches_exact_target(&r.intent.target)
            && inspection.current_candidate(&r.intent.target)
                == Some((
                    r.intent.native_handle,
                    r.intent.native_target.device_generation,
                    r.intent.worker,
                ));
        self.consume_delete_at(
            r,
            permit,
            current_target,
            worker,
            inspection_matches,
            Instant::now(),
        )
    }

    fn consume_delete_at(
        &self,
        r: &mut DeleteCredentialReservation,
        permit: DeleteCredentialPermit,
        current_target: Option<RegisteredDeviceTarget>,
        worker: Option<WorkerGeneration>,
        inspection_matches: bool,
        now: Instant,
    ) -> Result<CredentialDeletionDispatchPermit, DeleteCredentialError> {
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;
        let now = now.max(Instant::now());
        let valid = self
            .validate_delete_permit_with_gate(&gate, r, &permit, now)
            .is_ok()
            && persistence_lifetime_available(permit.expires_at, now)
            && r.pending
            && !r.consumed
            && inspection_matches
            && current_target == Some(r.intent.native_target)
            && worker == Some(r.intent.worker);
        // Any consumption attempt destroys the approval, even when validation fails.
        r.approved = None;
        r.consumed = true;
        if !valid {
            return Err(DeleteCredentialError::InvalidPermit);
        }

        let mut slot = self
            .recovery
            .lock()
            .map_err(|_| JournalError::Unavailable)?;
        let journal = slot.as_mut().ok_or(JournalError::Unavailable)?;
        if !persistence_lifetime_available(permit.expires_at, Instant::now()) {
            return Err(DeleteCredentialError::InvalidPermit);
        }
        let durable = journal.dispatch_capable_credential_deletion();
        gate.set_persistent_barrier(journal.admission() == RecoveryAdmission::Barrier);
        let durable = durable?;

        // Revocation/expiry during durable sync retains the barrier but mints no native authority.
        if self.epoch.load(Ordering::SeqCst) != r.intent.lifecycle_epoch
            || Instant::now() >= permit.expires_at
        {
            return Err(DeleteCredentialError::InvalidPermit);
        }

        Ok(CredentialDeletionDispatchPermit {
            durable,
            binding: delete_binding(r),
            lifecycle_epoch: r.intent.lifecycle_epoch,
            expires_at: permit.expires_at,
        })
    }

    fn validate_delete_dispatch<C: MonotonicClock + Clone>(
        &self,
        supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher, C>,
        inspection: &InspectionStore,
        r: &DeleteCredentialReservation,
        permit: &CredentialDeletionDispatchPermit,
    ) -> Result<(), DeleteCredentialError> {
        let gate = self
            .gate
            .lock()
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;
        let slot = self
            .recovery
            .lock()
            .map_err(|_| JournalError::Unavailable)?;
        let journal = slot.as_ref().ok_or(JournalError::Unavailable)?;
        let now = Instant::now();

        if !gate.matches(&r.reservation.admission)
            || gate.recovery_admission() != RecoveryAdmission::Barrier
            || !r.pending
            || !r.consumed
            || r.approved.is_some()
            || !journal.matches_credential_deletion_dispatch(&permit.durable)
            || !journal.has_unresolved_credential_deletion()
            || self
                .controller
                .lock()
                .map_err(|_| DeleteCredentialError::InvalidPermit)?
                .is_active()
            || !Arc::ptr_eq(&self.epoch, &r.intent.authority_epoch)
            || self.epoch.load(Ordering::SeqCst) != permit.lifecycle_epoch
            || permit.lifecycle_epoch != r.intent.lifecycle_epoch
            || now >= permit.expires_at
            || now >= r.intent.expires_at
            || permit.binding != delete_binding(r)
            || supervisor.resolve_handle(r.intent.native_handle) != Some(r.intent.native_target)
            || supervisor.status().worker_generation != Some(r.intent.worker)
            || !inspection.matches_exact_target(&r.intent.target)
            || inspection.current_candidate(&r.intent.target)
                != Some((
                    r.intent.native_handle,
                    r.intent.native_target.device_generation,
                    r.intent.worker,
                ))
        {
            return Err(DeleteCredentialError::InvalidPermit);
        }
        Ok(())
    }

    fn resolve_delete_result(
        &self,
        r: &DeleteCredentialReservation,
        resolution: Resolution,
    ) -> Result<(), DeleteCredentialError> {
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;
        if !gate.matches(&r.reservation.admission) {
            return Err(DeleteCredentialError::InvalidPermit);
        }
        let mut slot = self
            .recovery
            .lock()
            .map_err(|_| JournalError::Unavailable)?;
        let journal = slot.as_mut().ok_or(JournalError::Unavailable)?;
        if !journal.has_unresolved_credential_deletion() {
            return Err(DeleteCredentialError::InvalidPermit);
        }
        let result = journal.resolve(resolution);
        gate.set_persistent_barrier(journal.admission() == RecoveryAdmission::Barrier);
        result?;
        Ok(())
    }

    /// Release this foundation workflow only after native prompt teardown and independently proven
    /// worker quiescence. Durable deletion incidents may keep RecoveryAdmission blocked.
    fn finish_delete_foundation(
        &self,
        r: DeleteCredentialReservation,
        completion: WorkflowCompletion,
        quiescence: ExecutionQuiescence,
    ) -> Result<(), DeleteCredentialError> {
        if !Arc::ptr_eq(&self.epoch, &r.intent.authority_epoch) {
            return Err(DeleteCredentialError::InvalidPermit);
        }
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;
        if self
            .controller
            .lock()
            .map_err(|_| DeleteCredentialError::NotQuiescent)?
            .is_active()
            || quiescence != ExecutionQuiescence::Quiescent
        {
            return Err(DeleteCredentialError::NotQuiescent);
        }
        let recovery_admission = gate.recovery_admission();
        gate.finish(
            &r.reservation.admission,
            completion,
            WorkflowReleaseEvidence {
                execution_quiescence: quiescence,
                recovery_admission,
            },
            self.clock.now(),
        )?;
        Ok(())
    }

    /// Dispatch consumes the permit by value and compares this binding while holding
    /// the gate and freshly revalidating the exact inspection epoch plus native worker/device.
    fn validate_delete_permit_with_gate(
        &self,
        gate: &crate::SensitiveWorkflowGate,
        r: &DeleteCredentialReservation,
        permit: &DeleteCredentialPermit,
        now: Instant,
    ) -> Result<(), DeleteCredentialError> {
        let now = now.max(Instant::now());
        if !gate.matches(&r.reservation.admission)
            || gate.recovery_admission() != RecoveryAdmission::Open
            || r.approved != Some(permit.digest)
            || r.consumed
            || permit.digest != r.intent.digest()
            || now >= permit.expires_at
            || now >= r.intent.expires_at
            || !Arc::ptr_eq(&self.epoch, &r.intent.authority_epoch)
            || self.epoch.load(Ordering::SeqCst) != r.intent.lifecycle_epoch
            || self
                .controller
                .lock()
                .map_err(|_| DeleteCredentialError::InvalidPermit)?
                .is_active()
        {
            return Err(DeleteCredentialError::InvalidPermit);
        }
        Ok(())
    }

    #[cfg(test)]
    fn validate_delete_permit(
        &self,
        r: &DeleteCredentialReservation,
        permit: &DeleteCredentialPermit,
        now: Instant,
    ) -> Result<(), DeleteCredentialError> {
        let gate = self
            .gate
            .lock()
            .map_err(|_| DeleteCredentialError::InvalidPermit)?;
        self.validate_delete_permit_with_gate(&gate, r, permit, now)
    }
}

fn deletion_identity(target: &ExactCredentialTarget) -> fido_core::inventory::DeletionIdentity {
    fido_core::inventory::DeletionIdentity {
        rp_hash: *target.rp_hash(),
        rp_text: target.rp_text().to_owned(),
        credential_id: target.credential_id().to_vec(),
        user_id: target.user_id().map(ToOwned::to_owned),
    }
}

fn persistence_lifetime_available(expires: Instant, now: Instant) -> bool {
    expires
        .checked_duration_since(now)
        .is_some_and(|left| left >= DELETE_PERSISTENCE_LIFETIME_MARGIN)
}

fn delete_envelope(
    binding: fido_auth::deletion::DeleteCredentialBinding,
    request_id: u64,
    request: fido_worker_protocol::WorkerRequest,
) -> fido_worker_protocol::WorkerRequestEnvelope {
    fido_worker_protocol::WorkerRequestEnvelope {
        protocol_version: fido_worker_protocol::WORKER_PROTOCOL_VERSION,
        request_id: fido_worker_protocol::WorkerRequestId(request_id),
        cancellation_id: fido_worker_protocol::CancellationId(request_id),
        operation_class: request.operation_class(),
        worker_generation: WorkerGeneration(binding.session.worker_generation),
        device_generation: Some(binding.session.device_generation),
        budget_ms: fido_worker_protocol::RequestBudgetMs(fido_auth::AUTH_NATIVE_BUDGET_MS),
        request,
    }
}

fn delete_binding(
    reservation: &DeleteCredentialReservation,
) -> fido_auth::deletion::DeleteCredentialBinding {
    fido_auth::deletion::DeleteCredentialBinding {
        session: fido_auth::AcquisitionBinding {
            worker_generation: reservation.intent.worker.0,
            device_generation: reservation.intent.native_target.device_generation,
            workflow_id: reservation.intent.binding.workflow_id,
            prompt_instance_id: reservation.intent.binding.prompt_instance_id,
            acquisition_id: reservation.reservation.acquisition,
        },
        intent_digest: reservation.intent.digest(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WorkerGeneration, inspection::InspectionStore, recovery::tests::MemoryStorage};
    use fido_core::{
        DeviceGeneration, DeviceHandle, DeviceReadStatus, DeviceSnapshot, ViewFreshness,
        inventory::{OwnedCredential, OwnedInventory, OwnedRp},
    };
    use sha2::{Digest, Sha256};
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(
        DeleteCredentialPermit:
            Clone,
            Copy,
            std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned
    );
    assert_not_impl_any!(
        DeleteCredentialIntent:
            Clone,
            Copy,
            serde::Serialize,
            serde::de::DeserializeOwned
    );

    // Exact deletion authority and identity can be neither copied, formatted nor serialized.
    assert_not_impl_any!(
        CredentialDeletionDispatchPermit:
            Clone,
            Copy,
            std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned
    );
    assert_not_impl_any!(
        ExactCredentialTarget:
            Clone,
            Copy,
            std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned
    );

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_authority() -> AuthenticationAuthority {
        let authority = AuthenticationAuthority::awaiting_recovery_startup();
        authority
            .initialize_recovery(Box::new(MemoryStorage::default()))
            .unwrap_or_else(|_| panic!("journal"));
        authority
    }

    fn device(raw: u128, generation: u64, connection: u8) -> DeviceSnapshot {
        DeviceSnapshot {
            verification_history_id: Some([connection; 32]),
            handle: DeviceHandle::from_raw(raw),
            generation: DeviceGeneration(generation),
            vendor_id: 1,
            product_id: 2,
            manufacturer: Some("Thetis".into()),
            product: Some("Test key".into()),
            aaguid: None,
            versions: vec!["FIDO_2_1".into()],
            extensions: Vec::new(),
            transports: vec!["usb".into()],
            options: Vec::new(),
            max_message_size: None,
            firmware_version: None,
            read_status: DeviceReadStatus::Ready,
            freshness: ViewFreshness::Fresh,
        }
    }

    fn target(
        id: Vec<u8>,
        user_id: Option<Vec<u8>>,
    ) -> Result<ExactCredentialTarget, &'static str> {
        let mut store = InspectionStore::default();
        let devices = store
            .reconcile_connected(&[device(1, 1, 1)], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        store
            .replace(
                devices[0],
                WorkerGeneration(1),
                "Test key".into(),
                OwnedInventory {
                    metadata_existing: 1,
                    rps: vec![OwnedRp {
                        hash: Sha256::digest(b"example.com").into(),
                        verified_text: Some("example.com".into()),
                        issue: None,
                        credentials: vec![OwnedCredential {
                            id,
                            user_id,
                            user_name: Some("person@example.com".into()),
                            display_name: Some("Person".into()),
                        }],
                    }],
                },
            )
            .map_err(|_| "replace")?;
        let snapshot = store.snapshot_for(devices[0]).ok_or("snapshot")?;
        let handle = &snapshot.rps[0].credentials[0].handle;
        store
            .resolve_for_mutation(
                devices[0].handle,
                devices[0].generation,
                &snapshot.epoch,
                handle,
            )
            .ok_or("target")
    }

    fn reserve(
        authority: &AuthenticationAuthority,
        target: ExactCredentialTarget,
    ) -> Result<DeleteCredentialReservation, DeleteCredentialError> {
        authority.reserve_delete_target(
            target,
            DeviceHandle::from_raw(1),
            RegisteredDeviceTarget {
                worker_device_id: fido_worker_protocol::WorkerDeviceId(1),
                device_generation: DeviceGeneration(1),
            },
            WorkerGeneration(1),
            authority.reserve_sensitive(SensitiveWorkflowKind::DeleteCredential)?,
        )
    }

    fn native_teardown(
        authority: &AuthenticationAuthority,
        binding: PromptBinding,
        approved: bool,
    ) {
        let mut controller = authority
            .controller
            .lock()
            .unwrap_or_else(|_| panic!("controller"));
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

    #[test]
    fn persistence_margin_boundary_is_inclusive_and_expiry_fails_closed() {
        let now = Instant::now();
        let edge = now + DELETE_PERSISTENCE_LIFETIME_MARGIN;
        assert!(persistence_lifetime_available(edge, now));
        assert!(persistence_lifetime_available(
            edge + Duration::from_nanos(1),
            now
        ));
        assert!(!persistence_lifetime_available(
            edge - Duration::from_nanos(1),
            now
        ));
        assert!(!persistence_lifetime_available(now, now));
        assert!(!persistence_lifetime_available(
            now - Duration::from_nanos(1),
            now
        ));
    }

    #[test]
    fn dispatch_transition_rechecks_worker_native_target_epoch_and_margin() -> TestResult {
        for scenario in 0..5 {
            let authority = test_authority();
            let mut r = reserve(&authority, target(vec![1], Some(vec![2]))?)?;
            native_teardown(&authority, r.intent.binding(), true);
            let mut permit = authority.approve_delete_credential(&mut r)?;
            authority.write_delete_pending(&mut r, &permit)?;
            let mut current = r.intent.native_target;
            let worker = if scenario == 0 {
                WorkerGeneration(2)
            } else {
                r.intent.worker
            };
            if scenario == 1 {
                current.worker_device_id = fido_worker_protocol::WorkerDeviceId(2);
            }
            if scenario == 2 {
                current.device_generation = fido_core::DeviceGeneration(2);
            }
            if scenario == 4 {
                permit.expires_at = Instant::now() + DELETE_PERSISTENCE_LIFETIME_MARGIN / 2;
            }
            assert!(
                authority
                    .consume_delete_at(
                        &mut r,
                        permit,
                        Some(current),
                        Some(worker),
                        scenario != 3,
                        Instant::now()
                    )
                    .is_err()
            );
            assert!(r.consumed && r.approved.is_none());
            assert_eq!(
                authority
                    .recovery
                    .lock()
                    .map_err(|_| "journal")?
                    .as_ref()
                    .ok_or("journal")?
                    .phase(),
                Some(crate::recovery::JournalPhase::Pending)
            );
        }
        Ok(())
    }
    #[test]
    fn intent_owns_exact_target_and_permit_is_single_mint() -> TestResult {
        let authority = test_authority();
        let mut reservation = reserve(&authority, target(vec![1, 2, 3], Some(vec![9, 8]))?)?;
        assert_eq!(reservation.intent().rp_text(), "example.com");
        assert_eq!(reservation.intent().user_name(), Some("person@example.com"));
        assert_eq!(reservation.intent().display_name(), Some("Person"));
        assert_eq!(reservation.intent().target.credential_id(), &[1, 2, 3]);
        let digest = reservation.intent().digest();

        native_teardown(&authority, reservation.intent().binding(), true);
        let permit = authority.approve_delete_credential(&mut reservation)?;
        assert_eq!(permit.digest, digest);
        assert!(
            authority
                .approve_delete_credential(&mut reservation)
                .is_err()
        );
        authority.validate_delete_permit(&reservation, &permit, Instant::now())?;
        authority.finish_delete_foundation(
            reservation,
            WorkflowCompletion::Succeeded,
            ExecutionQuiescence::Quiescent,
        )?;
        Ok(())
    }

    #[test]
    fn lifecycle_revocation_or_cancel_never_mints_a_permit() -> TestResult {
        let authority = test_authority();
        let mut revoked = reserve(&authority, target(vec![4], Some(vec![5]))?)?;
        native_teardown(&authority, revoked.intent().binding(), true);
        authority.revoke();
        assert!(authority.approve_delete_credential(&mut revoked).is_err());

        let authority = test_authority();
        let mut cancelled = reserve(&authority, target(vec![6], None)?)?;
        native_teardown(&authority, cancelled.intent().binding(), false);
        assert!(authority.approve_delete_credential(&mut cancelled).is_err());
        authority.finish_delete_foundation(
            cancelled,
            WorkflowCompletion::Cancelled,
            ExecutionQuiescence::Quiescent,
        )?;
        Ok(())
    }

    #[test]
    fn intent_digest_binds_exact_credential_and_presentation() -> TestResult {
        let a = test_authority();
        let first = reserve(&a, target(vec![1, 2, 3], Some(vec![7]))?)?;
        let first_digest = first.intent().digest();
        // Release without presentation by explicitly tearing down as cancelled.
        native_teardown(&a, first.intent().binding(), false);
        a.finish_delete_foundation(
            first,
            WorkflowCompletion::Cancelled,
            ExecutionQuiescence::Quiescent,
        )?;

        let second = reserve(&a, target(vec![1, 2, 4], Some(vec![7]))?)?;
        assert_ne!(first_digest, second.intent().digest());
        native_teardown(&a, second.intent().binding(), false);
        a.finish_delete_foundation(
            second,
            WorkflowCompletion::Cancelled,
            ExecutionQuiescence::Quiescent,
        )?;
        Ok(())
    }
}
