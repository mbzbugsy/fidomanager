//! Secret-free, authority-wide crash recovery policy. Storage acknowledges durability, not just
//! a successful write. No method in this module can send a worker request.
use fido_core::{MutationOutcome, RecoveryAdmission};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinOperation {
    SetPin,
    ChangePin,
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
    operation: PinOperation,
    created_unix_secs: u64,
    phase: JournalPhase,
    resolution: Option<Resolution>,
}

pub struct RecoveryJournal {
    storage: Box<dyn JournalStorage>,
    record: Option<Record>,
    poisoned: bool,
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
    pub fn phase(&self) -> Option<JournalPhase> {
        self.record.as_ref().map(|r| r.phase)
    }
    pub fn operation(&self) -> Option<PinOperation> {
        self.record.as_ref().map(|r| r.operation)
    }

    pub(crate) fn pending(
        &mut self,
        operation: PinOperation,
        created_unix_secs: u64,
    ) -> Result<(), JournalError> {
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
            schema: 1,
            application: "fidomanager-m4-v1".into(),
            incident: format!("{:032x}", u128::from_be_bytes(incident)),
            operation,
            created_unix_secs,
            phase: JournalPhase::Pending,
            resolution: None,
        })
    }

    pub(crate) fn dispatch_capable(&mut self, operation: PinOperation) -> Result<(), JournalError> {
        let mut record = self.record.clone().ok_or(JournalError::InvalidTransition)?;
        if record.phase != JournalPhase::Pending || record.operation != operation {
            return Err(JournalError::InvalidTransition);
        }
        record.phase = JournalPhase::DispatchCapable;
        self.persist(record)
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

/// Contract for a future Recovery workflow, not an implementation of read-back or probing.
#[derive(Debug, PartialEq, Eq)]
pub struct PinRecoveryPolicy {
    pub passive_client_pin_after_quiescence: bool,
    pub configured_state_proves_exact_pin: bool,
    pub automatic_old_new_probing: bool,
    pub ordinary_retry_consuming_authentication: bool,
    pub verification_requires_recovery_and_visible_retries: bool,
}
impl PinOperation {
    pub const fn recovery_policy(self) -> PinRecoveryPolicy {
        PinRecoveryPolicy {
            passive_client_pin_after_quiescence: matches!(self, Self::SetPin),
            configured_state_proves_exact_pin: false,
            automatic_old_new_probing: false,
            ordinary_retry_consuming_authentication: false,
            verification_requires_recovery_and_visible_retries: true,
        }
    }
}

/// ADR-010 conservative classifier for the exact pinned high-level API. No native call here.
/// Internal negatives lose phase evidence; even INTERNAL can occur after successful transmit.
pub fn pin_call_outcome(
    operation: PinOperation,
    entered_high_level_call: bool,
    code: i32,
) -> MutationOutcome {
    if !entered_high_level_call {
        return MutationOutcome::NotDispatched;
    }
    match code {
        0 => MutationOutcome::ConfirmedSuccessful,
        // Definitive PIN rejection statuses under CTAP 2.0/2.1 clientPIN algorithms.
        0x02 | 0x14 | 0x33 | 0x37 => MutationOutcome::Rejected,
        0x31 | 0x32 | 0x34 if operation == PinOperation::ChangePin => MutationOutcome::Rejected,
        _ => MutationOutcome::OutcomeUnknown,
    }
}

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
            assert_eq!(
                j.dispatch_capable(PinOperation::SetPin),
                Err(JournalError::Unavailable)
            );
            assert_eq!(j.phase(), Some(JournalPhase::Pending));
            assert_eq!(j.admission(), RecoveryAdmission::Barrier);
            assert!(j.resolve(Resolution::NotDispatched).is_err());
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
