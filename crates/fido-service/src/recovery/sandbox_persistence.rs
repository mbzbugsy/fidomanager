//! MAS.1: run only by scripts/test-macos-sandbox-recovery.py, signed as a disposable sandbox app.
//! Calls the real storage, journal and authority APIs; no worker, prompt, secret or FIDO call.

use super::*;
use crate::authentication::AuthenticationAuthority;
use fido_core::SensitiveWorkflowKind;
use fido_platform::instance_lock::{InstanceLock, InstanceLockError};
use fido_platform::recovery_file::DurableRecoveryFile;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const ID: &str = "eu.fidomanager.desktop.mas1recoverytest";

unsafe extern "C" {
    fn sandbox_check(pid: i32, operation: *const std::ffi::c_char, kind: i32, ...) -> i32;
    fn csops(pid: i32, operation: u32, address: *mut std::ffi::c_void, size: usize) -> i32;
    fn geteuid() -> u32;
}

fn emit(value: serde_json::Value) -> io::Result<()> {
    println!("MAS1_EVIDENCE {value}");
    io::stdout().flush()
}

fn context() -> Result<(PathBuf, String), Box<dyn std::error::Error>> {
    let pid = std::process::id() as i32;
    let mut flags: u32 = 0;
    // SAFETY: no operation string is requested; csops receives one writable u32 for STATUS.
    let sandboxed = unsafe { sandbox_check(pid, std::ptr::null(), 0) };
    let status = unsafe { csops(pid, 0, std::ptr::from_mut(&mut flags).cast(), 4) };
    emit(
        serde_json::json!({"event": "kernel", "pid": pid, "sandboxed": sandboxed,
        "cs_status": status, "cs_flags": flags}),
    )?;
    // Every guard precedes even a stat of application data. Unsandboxed invocation must fail.
    assert_eq!(
        sandboxed, 1,
        "MAS.1 refuses to touch storage without a kernel sandbox"
    );
    assert_eq!(status, 0);
    assert_eq!(flags & (0x1 | 0x10000), 0x1 | 0x10000);
    let home = PathBuf::from(std::env::var("HOME")?);
    assert!(home.is_absolute());
    assert!(
        home.ends_with(Path::new("Library/Containers").join(ID).join("Data")),
        "HOME must be the dedicated MAS.1 sandbox container"
    );
    assert!(!home.symlink_metadata()?.file_type().is_symlink());
    let run = std::env::var("FIDOMANAGER_MAS1_RUN")?;
    assert_eq!(run.len(), 32);
    assert!(
        run.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let step = std::env::var("FIDOMANAGER_MAS1_STEP")?;
    let root = home
        .join("Library/Application Support")
        .join(ID)
        .join("runs")
        .join(run);
    Ok((root, step))
}

fn lock(root: &Path) -> Result<InstanceLock, io::Error> {
    InstanceLock::acquire(root).map_err(|error| io::Error::other(format!("{error:?}")))
}

fn journal(root: &Path) -> io::Result<RecoveryJournal> {
    Ok(RecoveryJournal::load(Box::new(DurableRecoveryFile::open(
        root,
    )?)))
}

#[derive(Clone, Copy, Debug)]
enum ExpectedInitialization {
    Loaded {
        admission: RecoveryAdmission,
        phase: Option<JournalPhase>,
        poisoned: bool,
    },
    StorageUnavailable,
}

fn expected_loaded(
    admission: RecoveryAdmission,
    phase: Option<JournalPhase>,
) -> ExpectedInitialization {
    ExpectedInitialization::Loaded {
        admission,
        phase,
        poisoned: false,
    }
}

const POISONED: ExpectedInitialization = ExpectedInitialization::Loaded {
    admission: RecoveryAdmission::Barrier,
    phase: None,
    poisoned: true,
};

fn assert_authority(
    root: &Path,
    expected: ExpectedInitialization,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = AuthenticationAuthority::awaiting_recovery_startup();
    assert_eq!(
        authority
            .gate
            .lock()
            .map_err(|_| "gate")?
            .recovery_admission(),
        RecoveryAdmission::Barrier
    );
    let initialized = authority.initialize_recovery_at(root);
    let (admission, initialization) = match expected {
        ExpectedInitialization::Loaded {
            admission,
            phase,
            poisoned,
        } => {
            assert_eq!(
                initialized,
                Ok(()),
                "must initialize storage and load a journal"
            );
            {
                let slot = authority.recovery.lock().map_err(|_| "recovery")?;
                let journal = slot.as_ref().ok_or("expected loaded journal")?;
                assert_eq!(journal.phase(), phase);
                assert_eq!(journal.poisoned, poisoned);
                assert_eq!(journal.admission(), admission);
                if poisoned {
                    assert!(!journal.can_acknowledge());
                }
            }
            let empty_reload = root.join("unused-reload");
            assert_eq!(
                authority.initialize_recovery_at(&empty_reload),
                Err(JournalError::InvalidTransition)
            );
            assert!(
                !empty_reload.exists(),
                "one-shot initialization refuses before opening fresh storage"
            );
            (admission, "loaded")
        }
        ExpectedInitialization::StorageUnavailable => {
            assert_eq!(initialized, Err(JournalError::Unavailable));
            assert!(authority.recovery.lock().map_err(|_| "recovery")?.is_none());
            (RecoveryAdmission::Barrier, "unavailable")
        }
    };
    assert_eq!(
        authority
            .gate
            .lock()
            .map_err(|_| "gate")?
            .recovery_admission(),
        admission
    );
    if admission == RecoveryAdmission::Barrier {
        for kind in [
            SensitiveWorkflowKind::CredentialInspection,
            SensitiveWorkflowKind::SetPin,
            SensitiveWorkflowKind::ChangePin,
            SensitiveWorkflowKind::DeleteCredential,
            SensitiveWorkflowKind::Reset,
            SensitiveWorkflowKind::SensitiveExport,
        ] {
            assert!(matches!(
                authority.reserve_sensitive(kind),
                Err(crate::AdmissionError::RecoveryBarrier)
            ));
        }
    }
    let slot = authority.recovery.lock().map_err(|_| "recovery")?;
    emit(
        serde_json::json!({"event": "authority", "case": root.file_name().and_then(|name| name.to_str()).ok_or("case")?,
        "initialization": initialization, "admission": format!("{admission:?}"),
        "journal_present": slot.is_some(), "phase": slot.as_ref().and_then(|j| j.phase()),
        "poisoned": slot.as_ref().map(|j| j.poisoned)}),
    )?;
    Ok(())
}

fn inspect(root: &Path, step: &str, phase: JournalPhase) -> Result<(), Box<dyn std::error::Error>> {
    let namespace = root.join("fido-authority-recovery-v1");
    let path = namespace.join("incident.json");
    // SAFETY: geteuid takes no arguments or pointers.
    let uid = unsafe { geteuid() };
    for (path, mode) in [
        (root, 0o700),
        (namespace.as_path(), 0o700),
        (path.as_path(), 0o600),
        (root.join("single-instance.lock").as_path(), 0o600),
    ] {
        let meta = path.symlink_metadata()?;
        assert!(!meta.file_type().is_symlink());
        assert_eq!(meta.uid(), uid);
        assert_eq!(meta.mode() & 0o777, mode);
    }
    let meta = path.symlink_metadata()?;
    assert!(meta.is_file());
    assert_eq!(meta.nlink(), 1);
    let bytes = DurableRecoveryFile::open(root)?
        .read_bounded(MAX_JOURNAL_BYTES)?
        .ok_or("missing record")?;
    let record: Record = serde_json::from_slice(&bytes)?;
    assert_eq!(record.phase, phase);
    let expected_resolution = match step.split_once(':').ok_or("step")?.1 {
        "dispatch" | "pending" => None,
        "not-dispatched" => Some(Resolution::NotDispatched),
        "rejected" => Some(Resolution::Rejected),
        "confirmed-successful" => Some(Resolution::ConfirmedSuccessful),
        "acknowledged-unknown" => Some(Resolution::AcknowledgedUnknown),
        _ => return Err("unexpected record case".into()),
    };
    assert_eq!(record.resolution, expected_resolution);
    assert_eq!(record.operation, RecoverableOperation::DeleteCredential);
    assert_eq!(record.application, "fidomanager-m4-v1");
    assert_eq!(record.schema, 1);
    assert_eq!(record.created_unix_secs, 1_700_000_000);
    assert_eq!(record.incident.len(), 32);
    let entries = fs::read_dir(&namespace)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        entries.len(),
        1,
        "successful replacement leaves only the tombstone/incident"
    );
    emit(
        serde_json::json!({"event": "record", "step": step, "root": root,
        "record": record, "sha256": format!("{:x}", Sha256::digest(&bytes)),
        "bytes": bytes.len(), "uid": uid, "record_mode": "0600", "directory_mode": "0700",
        "admission": format!("{:?}", journal(root)?.admission())}),
    )?;
    Ok(())
}

fn hold() -> ! {
    // The runner must terminate this process after its flushed evidence. Bound a lost runner.
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("runner did not terminate the holding fixture");
}

struct FailAfterPublication {
    disk: DurableRecoveryFile,
    calls: usize,
}
impl JournalStorage for FailAfterPublication {
    fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.disk.read_bounded(MAX_JOURNAL_BYTES)
    }
    fn replace_durable(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.disk.replace(bytes)?;
        self.calls += 1;
        if self.calls == 2 {
            Err(io::Error::other(
                "MAS.1 injected durability acknowledgement failure after publication",
            ))
        } else {
            Ok(())
        }
    }
}

fn negatives(base: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let valid = serde_json::json!({"schema": 1, "application": "fidomanager-m4-v1",
        "incident": "0123456789abcdef0123456789abcdef", "operation": "delete_credential",
        "created_unix_secs": 1_700_000_000u64, "phase": "dispatch_capable", "resolution": null});
    let mut unknown = valid.clone();
    unknown["extra"] = serde_json::json!(true);
    let mut schema = valid.clone();
    schema["schema"] = serde_json::json!(2);
    let mut resolution = valid.clone();
    resolution["resolution"] = serde_json::json!("confirmed_successful");
    let mut identity = valid.clone();
    identity["incident"] = serde_json::json!("bad");
    let mut operation = valid.clone();
    operation["operation"] = serde_json::json!("unknown");
    let mut application = valid.clone();
    application["application"] = serde_json::json!("another-format");
    let mut unresolved_tombstone = valid.clone();
    unresolved_tombstone["phase"] = serde_json::json!("resolved");
    for (name, bytes) in [
        ("malformed", b"{broken".to_vec()),
        ("corrupted-utf8", vec![0xff, 0xfe, 0x00]),
        ("empty", Vec::new()),
        ("oversized", vec![b' '; MAX_JOURNAL_BYTES + 1]),
        ("unknown-field", serde_json::to_vec(&unknown)?),
        ("unsupported-schema", serde_json::to_vec(&schema)?),
        ("inconsistent-resolution", serde_json::to_vec(&resolution)?),
        ("invalid-incident", serde_json::to_vec(&identity)?),
        ("unknown-operation", serde_json::to_vec(&operation)?),
        ("wrong-application", serde_json::to_vec(&application)?),
        (
            "unresolved-tombstone",
            serde_json::to_vec(&unresolved_tombstone)?,
        ),
    ] {
        let root = base.join(name);
        let _held = lock(&root)?;
        DurableRecoveryFile::open(&root)?.replace(&bytes)?;
        let before = fs::read(root.join("fido-authority-recovery-v1/incident.json"))?;
        assert_authority(&root, POISONED)?;
        assert_eq!(
            fs::read(root.join("fido-authority-recovery-v1/incident.json"))?,
            before
        );
        emit(
            serde_json::json!({"event": "negative", "case": name, "barrier": true,
            "ordinary_workflows_refused": 6, "record_unchanged": true}),
        )?;
    }
    for name in [
        "unreadable",
        "permissive-record",
        "record-symlink",
        "record-hardlink",
        "record-directory",
        "permissive-namespace",
        "namespace-symlink",
        "permissive-root",
    ] {
        let root = base.join(name);
        let _held = lock(&root)?;
        DurableRecoveryFile::open(&root)?.replace(&serde_json::to_vec(&valid)?)?;
        let namespace = root.join("fido-authority-recovery-v1");
        let record = namespace.join("incident.json");
        match name {
            "unreadable" => fs::set_permissions(&record, fs::Permissions::from_mode(0o000))?,
            "permissive-record" => fs::set_permissions(&record, fs::Permissions::from_mode(0o644))?,
            "record-symlink" => {
                let target = root.join("synthetic-target");
                fs::rename(&record, &target)?;
                symlink(&target, &record)?;
            }
            "record-hardlink" => fs::hard_link(&record, root.join("synthetic-hardlink"))?,
            "record-directory" => {
                fs::remove_file(&record)?;
                fs::create_dir(&record)?;
            }
            "permissive-namespace" => {
                fs::set_permissions(&namespace, fs::Permissions::from_mode(0o750))?
            }
            "namespace-symlink" => {
                let target = root.join("synthetic-namespace");
                fs::rename(&namespace, &target)?;
                symlink(&target, &namespace)?;
            }
            "permissive-root" => fs::set_permissions(&root, fs::Permissions::from_mode(0o770))?,
            _ => unreachable!(),
        }
        let initialization = match name {
            "permissive-namespace" | "namespace-symlink" | "permissive-root" => {
                ExpectedInitialization::StorageUnavailable
            }
            _ => POISONED,
        };
        assert_authority(&root, initialization)?;
        if name == "permissive-root" {
            assert!(matches!(
                InstanceLock::acquire(&root),
                Err(InstanceLockError::Unavailable(_))
            ));
        }
        emit(
            serde_json::json!({"event": "negative", "case": name, "barrier": true,
            "ordinary_workflows_refused": 6}),
        )?;
    }
    let root = base.join("failed-acknowledgement");
    let _held = lock(&root)?;
    let storage = FailAfterPublication {
        disk: DurableRecoveryFile::open(&root)?,
        calls: 0,
    };
    let mut loaded = RecoveryJournal::load(Box::new(storage));
    loaded.pending_credential_deletion(1_700_000_000)?;
    assert!(matches!(
        loaded.dispatch_capable_credential_deletion(),
        Err(JournalError::Unavailable)
    ));
    assert_eq!(loaded.admission(), RecoveryAdmission::Barrier);
    assert!(!loaded.can_acknowledge());
    // The failed write leaves the in-memory phase Pending and poisoned, even though disk now
    // contains DispatchCapable. Neither resolution path may clear that runtime barrier.
    assert!(loaded.resolve(Resolution::AcknowledgedUnknown).is_err());
    assert_eq!(
        loaded.resolve(Resolution::NotDispatched),
        Err(JournalError::Unavailable)
    );
    assert_eq!(loaded.admission(), RecoveryAdmission::Barrier);
    assert_eq!(journal(&root)?.phase(), Some(JournalPhase::DispatchCapable));
    assert_authority(
        &root,
        expected_loaded(
            RecoveryAdmission::Barrier,
            Some(JournalPhase::DispatchCapable),
        ),
    )?;
    emit(
        serde_json::json!({"event": "negative", "case": "failed-acknowledgement",
        "injection": "after successful production replace, not a real kernel sync failure",
        "no_dispatch_receipt": true, "runtime_barrier": true, "restart_barrier": true}),
    )?;
    let root = base.join("write-denied-after-pending");
    let _held = lock(&root)?;
    let mut loaded = journal(&root)?;
    loaded.pending_credential_deletion(1_700_000_000)?;
    let namespace = root.join("fido-authority-recovery-v1");
    let record = namespace.join("incident.json");
    let before = fs::read(&record)?;
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o500))?;
    assert!(matches!(
        loaded.dispatch_capable_credential_deletion(),
        Err(JournalError::Unavailable)
    ));
    assert_eq!(loaded.admission(), RecoveryAdmission::Barrier);
    assert!(!loaded.can_acknowledge());
    assert_eq!(fs::read(&record)?, before);
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700))?;
    // No dispatch receipt was minted. The unchanged, Pending-only restart may correctly reopen.
    assert_eq!(journal(&root)?.phase(), Some(JournalPhase::Pending));
    assert_authority(
        &root,
        expected_loaded(RecoveryAdmission::Open, Some(JournalPhase::Pending)),
    )?;
    emit(
        serde_json::json!({"event": "negative", "case": "write-denied-after-pending",
        "fault": "real owner-write permission denial at production temporary-file creation",
        "no_dispatch_receipt": true, "runtime_barrier": true, "record_unchanged": true,
        "restart_phase": "pending", "restart_admission": "Open"}),
    )?;
    Ok(())
}

#[test]
#[ignore = "requires the MAS.1 ad-hoc sandbox bundle and runner; never ordinary cargo test"]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (base, step) = context()?;
    let (action, case) = step.split_once(':').ok_or("expected action:case")?;
    // Validate the complete selector before creating directories.
    assert!(
        matches!(
            (action, case),
            ("negative", "matrix")
                | ("g5", "continuity")
                | ("hold" | "contend" | "child" | "reload", "lock")
                | (
                    "seed" | "reload",
                    "dispatch"
                        | "pending"
                        | "not-dispatched"
                        | "rejected"
                        | "confirmed-successful"
                        | "acknowledged-unknown",
                )
        ),
        "MAS.1 invalid step"
    );
    if action == "negative" {
        assert_eq!(case, "matrix");
        return negatives(&base.join("negative"));
    }
    if action == "g5" {
        // Only a runner-created synthetic marker in its fresh /private/tmp namespace is probed.
        // This NEVER names either distribution channel's real application data or incident.
        let outside = PathBuf::from(std::env::var("FIDOMANAGER_MAS1_SYNTHETIC_CHANNEL")?);
        let run = std::env::var("FIDOMANAGER_MAS1_RUN")?;
        assert_eq!(
            outside.file_name(),
            Some("synthetic-channel-marker.json".as_ref())
        );
        let parent = outside.parent().ok_or("external synthetic namespace")?;
        assert_eq!(parent.parent(), Some(Path::new("/private/tmp")));
        assert!(
            parent
                .file_name()
                .ok_or("namespace")?
                .to_str()
                .ok_or("utf8")?
                .starts_with(&format!("mas1-g5-{run}-"))
        );
        let denied = fs::read(&outside)
            .err()
            .ok_or("sandbox unexpectedly read external synthetic marker")?;
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        let root = base.join("g5-continuity");
        let _held = lock(&root)?;
        assert!(
            DurableRecoveryFile::open(&root)?
                .read_bounded(MAX_JOURNAL_BYTES)?
                .is_none()
        );
        assert_authority(&root, expected_loaded(RecoveryAdmission::Open, None))?;
        emit(
            serde_json::json!({"event": "g5", "external_synthetic_marker_denied": true,
            "denial_errno": denied.raw_os_error(), "container_record_missing": true,
            "container_admission": "Open", "actual_channel_migration_tested": false}),
        )?;
        return Ok(());
    }
    let root = base.join(case);
    if action == "contend" {
        assert_eq!(case, "lock");
        assert!(matches!(
            InstanceLock::acquire(&root),
            Err(InstanceLockError::AlreadyHeld)
        ));
        emit(serde_json::json!({"event": "lock-refused", "before_journal_open": true}))?;
        return Ok(());
    }
    if action == "child" {
        assert_eq!(case, "lock");
        emit(serde_json::json!({"event": "child-ready", "pid": std::process::id()}))?;
        hold();
    }
    let held = lock(&root)?;
    if action == "hold" {
        assert_eq!(case, "lock");
        // A signed inherit-only exec remains alive after the parent dies. If it inherited the
        // lock descriptor, the runner's next launch could not acquire the lock while it lives.
        let child = std::env::current_exe()?
            .parent()
            .ok_or("bundle")?
            .join("mas1-inherit-probe");
        let mut child = std::process::Command::new(child)
            .args([
                "--exact",
                "recovery::sandbox_persistence::run",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("FIDOMANAGER_MAS1_STEP", "child:lock")
            .spawn()?;
        assert_authority(&root, expected_loaded(RecoveryAdmission::Open, None))?;
        emit(
            serde_json::json!({"event": "lock-held", "child_pid": child.id(),
            "journal_initialized": true}),
        )?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            assert!(
                child.try_wait()?.is_none(),
                "inherit child exited before the lock test"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        drop(held);
        panic!("runner did not terminate the lock holder");
    }
    if case == "lock" {
        assert_eq!(action, "reload");
        assert_authority(&root, expected_loaded(RecoveryAdmission::Open, None))?;
        emit(serde_json::json!({"event": "lock-reacquired", "journal_initialized": true}))?;
        return Ok(());
    }
    let phase = match case {
        "dispatch" => JournalPhase::DispatchCapable,
        "pending" => JournalPhase::Pending,
        _ => JournalPhase::Resolved,
    };
    if action == "seed" {
        let mut loaded = journal(&root)?;
        assert!(
            loaded.phase().is_none(),
            "fresh run must not replace an existing incident"
        );
        loaded.pending_credential_deletion(1_700_000_000)?;
        if phase != JournalPhase::Pending && case != "not-dispatched" {
            let receipt = loaded.dispatch_capable_credential_deletion()?;
            assert!(loaded.matches_credential_deletion_dispatch(&receipt));
        }
        if phase == JournalPhase::Resolved {
            let resolution = match case {
                "not-dispatched" => Resolution::NotDispatched,
                "rejected" => Resolution::Rejected,
                "confirmed-successful" => Resolution::ConfirmedSuccessful,
                "acknowledged-unknown" => Resolution::AcknowledgedUnknown,
                _ => unreachable!(),
            };
            loaded.resolve(resolution)?;
        }
    } else {
        assert_eq!(action, "reload");
        assert_eq!(journal(&root)?.phase(), Some(phase));
    }
    let admission = if phase == JournalPhase::DispatchCapable {
        RecoveryAdmission::Barrier
    } else {
        RecoveryAdmission::Open
    };
    assert_authority(&root, expected_loaded(admission, Some(phase)))?;
    inspect(&root, &step, phase)?;
    if action == "seed" && phase != JournalPhase::Resolved {
        hold();
    }
    Ok(())
}
