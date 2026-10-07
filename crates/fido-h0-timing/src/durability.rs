//! T5: the production journal durability primitive, aimed at a private scratch namespace.
//!
//! `fido_platform::recovery_file::DurableRecoveryFile::replace` is the exact code the recovery
//! journal uses: write a fresh temporary file, F_FULLFSYNC it (fsync elsewhere), rename over the
//! record, fsync the directory and, on macOS, F_FULLFSYNC again. H0 calls that same function, so
//! T5 measures the real mechanism, not an imitation.
//!
//! The record is shaped like a production record (same keys and similar length) but names a
//! different application and operation, so even a misplaced scratch file could never be loaded as
//! a real recovery incident. It is only ever written under the session's own `journal-scratch`
//! directory, which `crate::session` creates.

use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use fido_platform::recovery_file::DurableRecoveryFile;

use crate::measurement::ScratchDurability;

pub const SCRATCH_APPLICATION: &str = "fidomanager-h0-timing-scratch-v1";

pub struct ScratchJournal {
    file: DurableRecoveryFile,
    incident: String,
    created_unix_secs: u64,
}

fn pseudo_incident() -> String {
    // Not security relevant: a scratch label of production length (32 hex digits).
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:032x}", nanos ^ (u128::from(std::process::id()) << 64))
}

impl ScratchJournal {
    pub fn open(scratch_root: &Path) -> std::io::Result<Self> {
        Ok(Self {
            file: DurableRecoveryFile::open(scratch_root)?,
            incident: pseudo_incident(),
            created_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })
    }

    pub fn record(&self, phase: &str, resolution: Option<&str>) -> Vec<u8> {
        serde_json::json!({
            "schema": 1,
            "application": SCRATCH_APPLICATION,
            "incident": self.incident,
            "operation": "h0_timing_probe",
            "created_unix_secs": self.created_unix_secs,
            "phase": phase,
            "resolution": resolution,
        })
        .to_string()
        .into_bytes()
    }

    /// Times one replace of a DispatchCapable-shaped record (durability-only mode, no device).
    pub fn timed_dispatch_capable(&mut self) -> std::io::Result<i64> {
        let bytes = self.dispatch_capable_bytes();
        let start = Instant::now();
        self.replace(&bytes)?;
        Ok(i64::try_from(start.elapsed().as_micros()).unwrap_or(i64::MAX))
    }
}

impl ScratchDurability for ScratchJournal {
    fn write_pending(&mut self) -> std::io::Result<()> {
        self.incident = pseudo_incident();
        let bytes = self.record("pending", None);
        self.file.replace(&bytes)
    }

    fn dispatch_capable_bytes(&self) -> Vec<u8> {
        self.record("dispatch_capable", None)
    }

    fn replace(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.file.replace(bytes)
    }

    fn write_resolved(&mut self) -> std::io::Result<()> {
        let bytes = self.record("resolved", Some("not_dispatched"));
        self.file.replace(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_records_use_production_shape_but_a_foreign_application() -> std::io::Result<()> {
        let root = std::env::temp_dir().join(format!("fido-h0-durability-{}", pseudo_incident()));
        let mut journal = ScratchJournal::open(&root)?;
        journal.write_pending()?;
        let micros = journal.timed_dispatch_capable()?;
        assert!(micros >= 0);
        let stored = std::fs::read(root.join("fido-authority-recovery-v1/incident.json"))?;
        let value: serde_json::Value =
            serde_json::from_slice(&stored).map_err(std::io::Error::other)?;
        assert_eq!(value["phase"], "dispatch_capable");
        assert_eq!(value["application"], SCRATCH_APPLICATION);
        assert_ne!(value["application"], "fidomanager-m4-v1");
        // Production records are bounded to 1024 bytes; stay comparable in size.
        assert!(stored.len() > 120 && stored.len() < 1024);
        journal.write_resolved()?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
