//! Secret-free, authority-wide crash recovery policy. Storage acknowledges durability, not just
//! a successful write. No method in this module can send a worker request.
#[cfg(test)]
use fido_core::MutationOutcome;
use fido_core::RecoveryAdmission;
use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;

pub const MAX_JOURNAL_BYTES: usize = 1024;

/// Implementations must bound reads and atomically replace a single record. Success means file
/// contents AND its directory entry survived the platform's durable sync contract. An error may
/// have published bytes; callers must retain a barrier and must never dispatch on that error.
pub trait JournalStorage: Send {
    fn read(&mut self) -> io::Result<Option<Vec<u8>>>;
    fn replace_durable(&mut self, bytes: &[u8]) -> io::Result<()>;
}

#[cfg(unix)]
impl JournalStorage for fido_platform::recovery_file::DurableRecoveryFile {
    fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.read_bounded(MAX_JOURNAL_BYTES)
    }
    fn replace_durable(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.replace(bytes)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JournalError {
    #[error("recovery journal is unavailable or untrustworthy")]
    Unavailable,
    #[error("invalid recovery journal transition")]
    InvalidTransition,
}

pub use fido_auth::mutation::{PinOperation, pin_call_outcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoverableOperation {
    SetPin,
    ChangePin,
    DeleteCredential,
}
type JournalOperation = RecoverableOperation;
impl From<PinOperation> for RecoverableOperation {
    fn from(operation: PinOperation) -> Self {
        match operation {
            PinOperation::SetPin => Self::SetPin,
            PinOperation::ChangePin => Self::ChangePin,
        }
    }
}
impl RecoverableOperation {
    fn pin(self) -> Option<PinOperation> {
        match self {
            Self::SetPin => Some(PinOperation::SetPin),
            Self::ChangePin => Some(PinOperation::ChangePin),
            Self::DeleteCredential => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalPhase {
    Pending,
    DispatchCapable,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    NotDispatched,
    Rejected,
    ConfirmedSuccessful,
    /// Deliberate trusted-native continuation preserves the unknown historical outcome.
    AcknowledgedUnknown,
}

/// No physical identity claim, target path, intent digest, prompt/workflow ID or secret. Keep a
/// resolved tombstone so unknown historical outcome is retained after deliberate continuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u8,
    application: String,
    incident: String,
    operation: JournalOperation,
    created_unix_secs: u64,
    phase: JournalPhase,
    resolution: Option<Resolution>,
}

/// The durable dispatch receipt is not an externally constructible or importable capability.
///
/// ```compile_fail
/// let _ = fido_service::recovery::DurablePinDispatch {};
/// ```
pub struct RecoveryJournal {
    storage: Box<dyn JournalStorage>,
    record: Option<Record>,
    poisoned: bool,
}

/// Opaque proof of one successfully synced DispatchCapable incident. Only this module can
/// construct it; callers cannot manufacture authority from a phase or a successful write alone.
/// No Clone/Copy, formatting or serialization: the receipt travels inside the one-shot permit.
pub(super) struct DurablePinDispatch {
    incident: String,
    operation: PinOperation,
}

/// Opaque proof that the deletion incident reached a durably synced DispatchCapable state.
/// It is backend-private, single-owner authority and intentionally carries no credential identity.
pub(super) struct DurableCredentialDeletionDispatch {
    incident: String,
}

impl RecoveryJournal {
    pub(crate) fn load(mut storage: Box<dyn JournalStorage>) -> Self {
        let loaded = (|| {
            let Some(bytes) = storage.read().map_err(|_| ())? else {
                return Ok(None);
            };
            if bytes.len() > MAX_JOURNAL_BYTES {
                return Err(());
            }
            let record: Record = serde_json::from_slice(&bytes).map_err(|_| ())?;
            if record.schema != 1
                || record.application != "fidomanager-m4-v1"
                || record.incident.len() != 32
                || !record
                    .incident
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || (record.phase == JournalPhase::Resolved) != record.resolution.is_some()
            {
                return Err(());
            }
            Ok(Some(record))
        })();
        let (record, poisoned) = match loaded {
            Ok(record) => (record, false),
            Err(()) => (None, true),
        };
        Self {
            storage,
            record,
            poisoned,
        }
    }

    pub fn admission(&self) -> RecoveryAdmission {
        if self.poisoned || self.phase() == Some(JournalPhase::DispatchCapable) {
            RecoveryAdmission::Barrier
        } else {
            RecoveryAdmission::Open
        }
    }
    pub(crate) fn can_acknowledge(&self) -> bool {
        !self.poisoned && self.phase() == Some(JournalPhase::DispatchCapable)
    }
    pub fn phase(&self) -> Option<JournalPhase> {
        self.record.as_ref().map(|r| r.phase)
    }
    pub(crate) fn recoverable_operation(&self) -> Option<RecoverableOperation> {
        self.can_acknowledge()
            .then(|| self.record.as_ref().map(|r| r.operation))
            .flatten()
    }
    /// Operation of the current incident in any phase; callers use it to refuse acknowledging an
    /// incident that belongs to a different recovery family.
    pub(crate) fn incident_operation(&self) -> Option<RecoverableOperation> {
        self.record.as_ref().map(|r| r.operation)
    }
    pub(crate) fn incident_created_unix_secs(&self) -> Option<u64> {
        self.record.as_ref().map(|r| r.created_unix_secs)
    }
    pub fn operation(&self) -> Option<PinOperation> {
        self.record
            .as_ref()
            .and_then(|record| record.operation.pin())
    }
    pub(crate) fn has_unresolved_credential_deletion(&self) -> bool {
        !self.poisoned
            && self.record.as_ref().is_some_and(|record| {
                record.operation == JournalOperation::DeleteCredential
                    && record.phase != JournalPhase::Resolved
                    && record.resolution.is_none()
            })
    }

    pub(crate) fn pending(
        &mut self,
        operation: PinOperation,
        created_unix_secs: u64,
    ) -> Result<(), JournalError> {
        self.pending_operation(operation.into(), created_unix_secs)
    }

    pub(crate) fn pending_credential_deletion(
        &mut self,
        created_unix_secs: u64,
    ) -> Result<(), JournalError> {
        self.pending_operation(JournalOperation::DeleteCredential, created_unix_secs)
    }

    fn pending_operation(
        &mut self,
        operation: JournalOperation,
        created_unix_secs: u64,
    ) -> Result<(), JournalError> {
        // A valid Pending-only prior incident proves no dispatch-capable acknowledgement.
        // Preserve its NotDispatched tombstone durably before admitting a new incident.
        if !self.poisoned && self.phase() == Some(JournalPhase::Pending) {
            self.resolve(Resolution::NotDispatched)?;
        }
        if self.poisoned
            || self
                .record
                .as_ref()
                .is_some_and(|r| r.phase != JournalPhase::Resolved)
        {
            return Err(JournalError::InvalidTransition);
        }
        let mut incident = [0u8; 16];
        getrandom::fill(&mut incident).map_err(|_| JournalError::Unavailable)?;
        self.persist(Record {
            // Schema/application remain stable so existing M4 set/change records load unchanged.
            schema: 1,
            application: "fidomanager-m4-v1".into(),
            incident: format!("{:032x}", u128::from_be_bytes(incident)),
            operation,
            created_unix_secs,
            phase: JournalPhase::Pending,
            resolution: None,
        })
    }

    pub(super) fn dispatch_capable(
        &mut self,
        operation: PinOperation,
    ) -> Result<DurablePinDispatch, JournalError> {
        let mut record = self.record.clone().ok_or(JournalError::InvalidTransition)?;
        if record.phase != JournalPhase::Pending || record.operation != operation.into() {
            return Err(JournalError::InvalidTransition);
        }
        record.phase = JournalPhase::DispatchCapable;
        let incident = record.incident.clone();
        self.persist(record)?;
        Ok(DurablePinDispatch {
            incident,
            operation,
        })
    }

    pub(super) fn matches_dispatch(&self, receipt: &DurablePinDispatch) -> bool {
        !self.poisoned
            && self.record.as_ref().is_some_and(|record| {
                record.phase == JournalPhase::DispatchCapable
                    && record.resolution.is_none()
                    && record.incident == receipt.incident
                    && record.operation == receipt.operation.into()
            })
    }

    pub(super) fn dispatch_capable_credential_deletion(
        &mut self,
    ) -> Result<DurableCredentialDeletionDispatch, JournalError> {
        let mut record = self.record.clone().ok_or(JournalError::InvalidTransition)?;
        if record.phase != JournalPhase::Pending
            || record.operation != JournalOperation::DeleteCredential
        {
            return Err(JournalError::InvalidTransition);
        }
        record.phase = JournalPhase::DispatchCapable;
        let incident = record.incident.clone();
        self.persist(record)?;
        Ok(DurableCredentialDeletionDispatch { incident })
    }

    pub(super) fn matches_credential_deletion_dispatch(
        &self,
        receipt: &DurableCredentialDeletionDispatch,
    ) -> bool {
        !self.poisoned
            && self.record.as_ref().is_some_and(|record| {
                record.phase == JournalPhase::DispatchCapable
                    && record.resolution.is_none()
                    && record.incident == receipt.incident
                    && record.operation == JournalOperation::DeleteCredential
            })
    }

    pub(crate) fn resolve(&mut self, resolution: Resolution) -> Result<(), JournalError> {
        let mut record = self.record.clone().ok_or(JournalError::InvalidTransition)?;
        let allowed = match record.phase {
            JournalPhase::Pending => resolution == Resolution::NotDispatched,
            JournalPhase::DispatchCapable => resolution != Resolution::NotDispatched,
            JournalPhase::Resolved => false,
        };
        if !allowed {
            return Err(JournalError::InvalidTransition);
        }
        record.phase = JournalPhase::Resolved;
        record.resolution = Some(resolution);
        self.persist(record)
    }

    fn persist(&mut self, record: Record) -> Result<(), JournalError> {
        if self.poisoned {
            return Err(JournalError::Unavailable);
        }
        let bytes = serde_json::to_vec(&record).map_err(|_| JournalError::Unavailable)?;
        if self.storage.replace_durable(&bytes).is_err() {
            self.poisoned = true;
            return Err(JournalError::Unavailable);
        }
        self.record = Some(record);
        Ok(())
    }
}

pub use fido_auth::mutation::PinRecoveryPolicy;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    pub struct Disk {
        pub bytes: Option<Vec<u8>>,
        pub failure: u8,
    }
    #[derive(Clone, Default)]
    pub struct MemoryStorage(pub Arc<Mutex<Disk>>);
    impl JournalStorage for MemoryStorage {
        fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(self
                .0
                .lock()
                .unwrap_or_else(|_| panic!("disk"))
                .bytes
                .clone())
        }
        fn replace_durable(&mut self, bytes: &[u8]) -> io::Result<()> {
            let mut disk = self.0.lock().unwrap_or_else(|_| panic!("disk"));
            if disk.failure == 1 {
                return Err(io::Error::other("write failure"));
            }
            // Model failed durability acknowledgement AFTER publication too.
            disk.bytes = Some(bytes.to_vec());
            if disk.failure == 2 {
                return Err(io::Error::other("sync failure"));
            }
            Ok(())
        }
    }

    #[test]
    fn pending_restart_can_begin_fresh_only_after_durable_abort() -> Result<(), JournalError> {
        let disk = MemoryStorage::default();
        let mut j = RecoveryJournal::load(Box::new(disk.clone()));
        j.pending(PinOperation::SetPin, 1)?;
        let mut restarted = RecoveryJournal::load(Box::new(disk.clone()));
        restarted.pending(PinOperation::ChangePin, 2)?;
        assert_eq!(restarted.operation(), Some(PinOperation::ChangePin));
        assert_eq!(restarted.phase(), Some(JournalPhase::Pending));
        disk.0.lock().unwrap_or_else(|_| panic!("disk")).failure = 2;
        assert!(restarted.pending(PinOperation::SetPin, 3).is_err());
        assert_eq!(restarted.admission(), RecoveryAdmission::Barrier);
        Ok(())
    }
    #[test]
    fn pending_dispatch_resolved_restart_contract() -> Result<(), JournalError> {
        let disk = MemoryStorage::default();
        let mut j = RecoveryJournal::load(Box::new(disk.clone()));
        assert_eq!(j.phase(), None);
        j.pending(PinOperation::ChangePin, 1)?;
        assert_eq!(
            RecoveryJournal::load(Box::new(disk.clone())).admission(),
            RecoveryAdmission::Open
        );
        j.dispatch_capable(PinOperation::ChangePin)?;
        assert_eq!(
            RecoveryJournal::load(Box::new(disk.clone())).admission(),
            RecoveryAdmission::Barrier
        );
        j.resolve(Resolution::AcknowledgedUnknown)?;
        assert_eq!(
            RecoveryJournal::load(Box::new(disk.clone())).admission(),
            RecoveryAdmission::Open
        );
        let bytes = disk
            .0
            .lock()
            .unwrap_or_else(|_| panic!("disk"))
            .bytes
            .clone()
            .unwrap_or_default();
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| JournalError::Unavailable)?;
        let mut keys = value
            .as_object()
            .ok_or(JournalError::Unavailable)?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "application",
                "created_unix_secs",
                "incident",
                "operation",
                "phase",
                "resolution",
                "schema"
            ]
        );
        assert_eq!(value["resolution"], "acknowledged_unknown");
        Ok(())
    }
    #[test]
    fn credential_deletion_uses_the_same_durable_barrier_contract() -> Result<(), JournalError> {
        let disk = MemoryStorage::default();
        let mut journal = RecoveryJournal::load(Box::new(disk.clone()));
        journal.pending_credential_deletion(11)?;
        assert!(journal.has_unresolved_credential_deletion());
        assert_eq!(journal.phase(), Some(JournalPhase::Pending));
        assert_eq!(journal.operation(), None);
        assert_eq!(journal.admission(), RecoveryAdmission::Open);

        let receipt = journal.dispatch_capable_credential_deletion()?;
        assert!(journal.matches_credential_deletion_dispatch(&receipt));
        assert!(journal.has_unresolved_credential_deletion());
        assert_eq!(journal.admission(), RecoveryAdmission::Barrier);
        assert!(journal.resolve(Resolution::NotDispatched).is_err());

        journal.resolve(Resolution::AcknowledgedUnknown)?;
        assert!(!journal.has_unresolved_credential_deletion());
        assert!(!journal.matches_credential_deletion_dispatch(&receipt));
        assert_eq!(journal.admission(), RecoveryAdmission::Open);

        let restarted = RecoveryJournal::load(Box::new(disk));
        assert_eq!(restarted.phase(), Some(JournalPhase::Resolved));
        assert_eq!(restarted.operation(), None);
        assert!(!restarted.has_unresolved_credential_deletion());
        assert_eq!(restarted.admission(), RecoveryAdmission::Open);
        Ok(())
    }

    #[test]
    fn existing_m4_records_remain_schema_compatible() -> Result<(), JournalError> {
        for operation in ["set_pin", "change_pin"] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "schema": 1,
                "application": "fidomanager-m4-v1",
                "incident": "0123456789abcdef0123456789abcdef",
                "operation": operation,
                "created_unix_secs": 7,
                "phase": "dispatch_capable",
                "resolution": null
            }))
            .map_err(|_| JournalError::Unavailable)?;
            let disk = MemoryStorage::default();
            disk.0.lock().unwrap_or_else(|_| panic!("disk")).bytes = Some(bytes);
            let journal = RecoveryJournal::load(Box::new(disk));
            assert_eq!(journal.admission(), RecoveryAdmission::Barrier);
            assert_eq!(journal.phase(), Some(JournalPhase::DispatchCapable));
            assert_eq!(
                journal.operation(),
                Some(if operation == "set_pin" {
                    PinOperation::SetPin
                } else {
                    PinOperation::ChangePin
                })
            );
        }
        Ok(())
    }

    #[test]
    fn corrupt_unsupported_and_secret_extended_records_fail_closed() -> Result<(), JournalError> {
        let disk = MemoryStorage::default();
        let mut j = RecoveryJournal::load(Box::new(disk.clone()));
        j.pending(PinOperation::SetPin, 1)?;
        let valid = disk
            .0
            .lock()
            .unwrap_or_else(|_| panic!("disk"))
            .bytes
            .clone()
            .unwrap_or_default();
        for invalid in [
            b"".to_vec(),
            b"{}".to_vec(),
            b"null".to_vec(),
            vec![0xff],
            vec![b'x'; MAX_JOURNAL_BYTES + 1],
        ] {
            disk.0.lock().unwrap_or_else(|_| panic!("disk")).bytes = Some(invalid);
            assert_eq!(
                RecoveryJournal::load(Box::new(disk.clone())).admission(),
                RecoveryAdmission::Barrier
            );
        }
        for (field, value) in [
            ("schema", serde_json::json!(2)),
            ("phase", serde_json::json!("future")),
            ("pin", serde_json::json!("secret")),
            ("resolution", serde_json::json!("rejected")),
            ("incident", serde_json::json!("bad")),
        ] {
            let mut record: serde_json::Value =
                serde_json::from_slice(&valid).map_err(|_| JournalError::Unavailable)?;
            record[field] = value;
            disk.0.lock().unwrap_or_else(|_| panic!("disk")).bytes =
                Some(serde_json::to_vec(&record).map_err(|_| JournalError::Unavailable)?);
            assert_eq!(
                RecoveryJournal::load(Box::new(disk.clone())).admission(),
                RecoveryAdmission::Barrier
            );
        }
        Ok(())
    }
    #[test]
    fn write_and_sync_failure_never_acknowledge_dispatch_capable() -> Result<(), JournalError> {
        for failure in [1, 2] {
            let disk = MemoryStorage::default();
            let mut j = RecoveryJournal::load(Box::new(disk.clone()));
            j.pending(PinOperation::SetPin, 1)?;
            disk.0.lock().unwrap_or_else(|_| panic!("disk")).failure = failure;
            assert!(matches!(
                j.dispatch_capable(PinOperation::SetPin),
                Err(JournalError::Unavailable)
            ));
            assert_eq!(j.phase(), Some(JournalPhase::Pending));
            assert_eq!(j.admission(), RecoveryAdmission::Barrier);
            assert!(j.resolve(Resolution::NotDispatched).is_err());
        }
        Ok(())
    }
    #[test]
    fn durable_receipt_fails_closed_after_poisoned_resolution() -> Result<(), JournalError> {
        for failure in [1, 2] {
            let disk = MemoryStorage::default();
            let mut j = RecoveryJournal::load(Box::new(disk.clone()));
            j.pending(PinOperation::ChangePin, 1)?;
            let receipt = j.dispatch_capable(PinOperation::ChangePin)?;
            assert!(j.matches_dispatch(&receipt));
            disk.0.lock().unwrap_or_else(|_| panic!("disk")).failure = failure;
            assert!(j.resolve(Resolution::Rejected).is_err());
            assert!(!j.matches_dispatch(&receipt));
            assert_eq!(j.admission(), RecoveryAdmission::Barrier);
        }
        Ok(())
    }
    #[test]
    fn journal_read_failure_is_a_barrier_not_no_record() {
        struct FailedRead;
        impl JournalStorage for FailedRead {
            fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
                Err(io::Error::other("read failed"))
            }
            fn replace_durable(&mut self, _: &[u8]) -> io::Result<()> {
                panic!("failed read must never write")
            }
        }
        let mut journal = RecoveryJournal::load(Box::new(FailedRead));
        assert_eq!(journal.admission(), RecoveryAdmission::Barrier);
        assert!(journal.pending(PinOperation::SetPin, 1).is_err());
    }

    #[test]
    fn journal_forbids_phase_skips_and_false_not_dispatched() -> Result<(), JournalError> {
        let mut j = RecoveryJournal::load(Box::new(MemoryStorage::default()));
        assert!(j.dispatch_capable(PinOperation::SetPin).is_err());
        j.pending(PinOperation::SetPin, 1)?;
        assert!(j.dispatch_capable(PinOperation::ChangePin).is_err());
        assert!(j.resolve(Resolution::ConfirmedSuccessful).is_err());
        j.dispatch_capable(PinOperation::SetPin)?;
        assert!(j.resolve(Resolution::NotDispatched).is_err());
        j.resolve(Resolution::Rejected)?;
        assert!(j.dispatch_capable(PinOperation::SetPin).is_err());
        Ok(())
    }
    #[test]
    fn change_pin_policy_and_source_evidence_are_conservative() {
        let p = PinOperation::ChangePin.recovery_policy();
        assert!(!p.automatic_old_new_probing && !p.ordinary_retry_consuming_authentication);
        assert!(!p.passive_client_pin_after_quiescence && !p.configured_state_proves_exact_pin);
        assert!(p.verification_requires_recovery_and_visible_retries);
        assert!(
            PinOperation::SetPin
                .recovery_policy()
                .passive_client_pin_after_quiescence
        );
        for (operation, rejections) in [
            (PinOperation::SetPin, &[0x02, 0x14, 0x33, 0x37][..]),
            (
                PinOperation::ChangePin,
                &[0x02, 0x14, 0x31, 0x32, 0x33, 0x34, 0x37][..],
            ),
        ] {
            assert_eq!(
                pin_call_outcome(operation, true, 0),
                MutationOutcome::ConfirmedSuccessful
            );
            for code in -11..=255 {
                assert_eq!(
                    pin_call_outcome(operation, false, code),
                    MutationOutcome::NotDispatched
                );
                if rejections.contains(&code) {
                    assert_eq!(
                        pin_call_outcome(operation, true, code),
                        MutationOutcome::Rejected
                    );
                } else if code != 0 {
                    assert_eq!(
                        pin_call_outcome(operation, true, code),
                        MutationOutcome::OutcomeUnknown
                    );
                }
            }
        }
    }
}
