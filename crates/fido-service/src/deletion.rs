//! M5 credential-deletion authority foundation.
//!
//! This module intentionally stops before durable deletion journaling or worker/native dispatch.
//! An exact credential target is resolved from the trusted inspection store, moved into an
//! immutable intent, and may receive at most one short-lived native-approval permit. The permit
//! itself cannot delete anything. Final worker/device/epoch revalidation and durable
//! Pending -> DispatchCapable authority are added before any native delete symbol becomes reachable.

use crate::{
    AdmissionError, CompletionError, MonotonicClock, WorkflowCompletion, WorkflowReleaseEvidence,
    authentication::{AuthenticationAuthority, AuthenticationReservation},
    inspection::{ExactCredentialTarget, InventoryDevice},
};
use fido_core::{ExecutionQuiescence, RecoveryAdmission, SensitiveWorkflowKind};
use fido_native_ui::{PromptBinding, PromptOutcome, PromptRequest};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use thiserror::Error;

pub const DELETE_INTENT_VERSION: u8 = 1;
pub const DELETE_PERMIT_TTL: Duration = Duration::from_secs(10);

/// Backend-owned immutable description of one exact enumerated credential.
///
/// It deliberately contains no native worker handle or worker generation. Presentation continuity
/// is not operation authority; those values must be resolved freshly under the sensitive-workflow
/// gate immediately before future durable dispatch authority can be minted.
///
/// The type has no public constructor, no mutable fields, no serde, and no Clone/Copy.
pub struct DeleteCredentialIntent {
    target: ExactCredentialTarget,
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

    /// Fixed, versioned, length-delimited representation of the exact approved target and the
    /// presentation derived from that same target. No native handle, path, secret, or renderer
    /// value is accepted here.
    fn canonical(&self) -> Vec<u8> {
        fn bytes(out: &mut Vec<u8>, value: &[u8]) {
            let len = u32::try_from(value.len()).expect("bounded M5 intent field");
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
        bytes(&mut out, self.target.epoch().as_wire().as_bytes());
        bytes(&mut out, self.target.handle().as_wire().as_bytes());

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
///     let _copy = p.clone();
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

pub struct DeleteCredentialReservation {
    reservation: AuthenticationReservation,
    intent: DeleteCredentialIntent,
    approved: Option<[u8; 32]>,
}

impl DeleteCredentialReservation {
    pub fn intent(&self) -> &DeleteCredentialIntent {
        &self.intent
    }

    pub fn prompt(&self) -> &PromptRequest {
        &self.reservation.prompt
    }
}

#[derive(Debug, Error)]
pub enum DeleteCredentialError {
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Completion(#[from] CompletionError),
    #[error("deletion approval is stale, expired, replayed or revoked")]
    InvalidPermit,
    #[error("native teardown/quiescence is not established")]
    NotQuiescent,
}

impl AuthenticationAuthority {
    /// Reserve one exact current credential for a future deletion workflow.
    ///
    /// `target` can only be produced by `InspectionStore::resolve_for_mutation`; it is an owned
    /// current-epoch identity, not native operation authority. No worker/native mutation occurs.
    pub fn reserve_delete_credential(
        &self,
        target: ExactCredentialTarget,
    ) -> Result<DeleteCredentialReservation, DeleteCredentialError> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| DeleteCredentialError::InvalidPermit)?;
        let created_at = Instant::now();
        let created_ms = self.clock.now().as_millis();
        let expires_at = created_at
            .checked_add(Duration::from_secs(fido_auth::PROMPT_LIFETIME_SECS))
            .ok_or(DeleteCredentialError::InvalidPermit)?;
        let expires_ms = created_ms
            .checked_add(fido_auth::PROMPT_LIFETIME_SECS * 1000)
            .ok_or(DeleteCredentialError::InvalidPermit)?;

        let reservation = self.reserve_sensitive(SensitiveWorkflowKind::DeleteCredential)?;
        let intent = DeleteCredentialIntent {
            target,
            binding: reservation.prompt.binding(),
            nonce,
            created_ms,
            expires_ms,
            expires_at: expires_at.min(reservation.prompt.deadline()),
            lifecycle_epoch: reservation.epoch,
            authority_epoch: Arc::clone(&self.epoch),
        };
        Ok(DeleteCredentialReservation {
            reservation,
            intent,
            approved: None,
        })
    }

    /// Mint at most one short-lived exact-intent permit after trusted native approval has torn down.
    /// The permit has no dispatch API yet.
    pub fn approve_delete_credential(
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

    /// Release this foundation workflow only after native prompt teardown and independently proven
    /// worker quiescence. Future durable deletion incidents may keep RecoveryAdmission blocked.
    pub fn finish_delete_foundation(
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

    /// Future dispatch code must consume the permit by value and compare this binding while holding
    /// the gate and freshly revalidating the exact inspection epoch plus native worker/device.
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
        let now = now.max(Instant::now());
        if !gate.matches(&r.reservation.admission)
            || gate.recovery_admission() != RecoveryAdmission::Open
            || r.approved != Some(permit.digest)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        WorkerGeneration,
        inspection::InspectionStore,
        recovery::tests::MemoryStorage,
    };
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

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn authority() -> AuthenticationAuthority {
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

    fn target(id: Vec<u8>, user_id: Option<Vec<u8>>) -> Result<ExactCredentialTarget, &'static str> {
        let mut store = InspectionStore::default();
        let devices = store
            .reconcile_connected(&[device(1, 1, 1)], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        store
            .replace(
                devices[0],
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
    fn intent_owns_exact_target_and_permit_is_single_mint() -> TestResult {
        let authority = authority();
        let mut reservation =
            authority.reserve_delete_credential(target(vec![1, 2, 3], Some(vec![9, 8]))?)?;
        assert_eq!(reservation.intent().rp_text(), "example.com");
        assert_eq!(reservation.intent().user_name(), Some("person@example.com"));
        assert_eq!(reservation.intent().display_name(), Some("Person"));
        assert_eq!(
            reservation.intent().target.credential_id(),
            &[1, 2, 3]
        );
        let digest = reservation.intent().digest();

        native_teardown(&authority, reservation.intent().binding(), true);
        let permit = authority.approve_delete_credential(&mut reservation)?;
        assert_eq!(permit.digest, digest);
        assert!(authority.approve_delete_credential(&mut reservation).is_err());
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
        let authority = authority();
        let mut revoked =
            authority.reserve_delete_credential(target(vec![4], Some(vec![5]))?)?;
        native_teardown(&authority, revoked.intent().binding(), true);
        authority.revoke();
        assert!(authority.approve_delete_credential(&mut revoked).is_err());

        let authority = authority();
        let mut cancelled = authority.reserve_delete_credential(target(vec![6], None)?)?;
        native_teardown(&authority, cancelled.intent().binding(), false);
        assert!(
            authority
                .approve_delete_credential(&mut cancelled)
                .is_err()
        );
        authority.finish_delete_foundation(
            cancelled,
            WorkflowCompletion::Cancelled,
            ExecutionQuiescence::Quiescent,
        )?;
        Ok(())
    }

    #[test]
    fn intent_digest_binds_exact_credential_and_presentation() -> TestResult {
        let a = authority();
        let first = a.reserve_delete_credential(target(vec![1, 2, 3], Some(vec![7]))?)?;
        let first_digest = first.intent().digest();
        // Release without presentation by explicitly tearing down as cancelled.
        native_teardown(&a, first.intent().binding(), false);
        a.finish_delete_foundation(
            first,
            WorkflowCompletion::Cancelled,
            ExecutionQuiescence::Quiescent,
        )?;

        let second = a.reserve_delete_credential(target(vec![1, 2, 4], Some(vec![7]))?)?;
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
