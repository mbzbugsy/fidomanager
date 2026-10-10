//! Production authority acquisition, before any UI/IPC/worker initialization.
use crate::authentication::AuthenticationAuthority;
use crate::recovery::JournalStorage;
use fido_platform::authority_root::AuthorityRoot;
pub use fido_platform::instance_lock::InstanceLockError as SharedAuthorityError;
use fido_platform::instance_lock::{InstanceLock, InstanceLockError};
use fido_platform::recovery_file::DurableRecoveryFile;
#[cfg(all(target_os = "macos", feature = "macos-shared-authority"))]
use std::io;

pub struct SharedAuthority {
    _root: AuthorityRoot,
    _lock: InstanceLock,
    storage: Option<Box<dyn JournalStorage>>,
}

impl SharedAuthority {
    fn acquire(root: AuthorityRoot) -> Result<Self, InstanceLockError> {
        let lock = InstanceLock::acquire_in_directory(root.directory())?;
        // Only the holder may initialize/read the journal namespace.
        let storage = DurableRecoveryFile::open_in_directory(root.directory())?;
        Ok(Self {
            _root: root,
            _lock: lock,
            storage: Some(Box::new(storage)),
        })
    }

    pub fn initialize(
        &mut self,
        authority: &AuthenticationAuthority,
    ) -> Result<(), crate::recovery::JournalError> {
        let storage = self
            .storage
            .take()
            .ok_or(crate::recovery::JournalError::InvalidTransition)?;
        authority.initialize_recovery(storage)
    }

    /// Cannot be selected by renderer, environment, bundle-ID inference or runtime arguments.
    #[cfg(all(target_os = "macos", feature = "macos-shared-authority"))]
    pub fn production(sandbox: bool) -> Result<Self, InstanceLockError> {
        use fido_platform::macos_code_signing::{
            Requirement, RunningCode, SIGNATURE_FLAG_RUNTIME, STATUS_KILL, STATUS_VALID,
        };
        let failure = || {
            io::Error::other(
                "FIDOMANAGER-SHARED-AUTHORITY/1: production App Group identity unavailable",
            )
        };
        let team = crate::worker_authenticity::MACOS_RELEASE_TEAM_ID.ok_or_else(failure)?;
        let identifier = if sandbox {
            crate::shared_authority_policy::STORE_IDENTIFIER
        } else {
            crate::worker_authenticity::APP_IDENTIFIER
        };
        let requirement = Requirement::compile(&format!("anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team}\""))
            .map_err(|_| failure())?;
        let me = RunningCode::current_process().map_err(|_| failure())?;
        let network = fido_platform::os_version::current()
            .and_then(fido_platform::os_version::DynamicNetworkPolicy::for_version)
            .map_err(|_| failure())?;
        me.check_validity(network, &requirement)
            .map_err(|_| failure())?;
        let info = me.signing_information().map_err(|_| failure())?;
        if info
            .signature_flags
            .is_none_or(|flags| flags & SIGNATURE_FLAG_RUNTIME == 0)
            || info.dynamic_status.is_none_or(|flags| {
                flags & (STATUS_VALID | STATUS_KILL) != STATUS_VALID | STATUS_KILL
            })
            || !me
                .has_exact_authority_entitlements(
                    crate::shared_authority_policy::GROUP_IDENTIFIER,
                    sandbox,
                )
                .map_err(|_| failure())?
        {
            return Err(failure().into());
        }
        if sandbox {
            require_kernel_sandbox().map_err(|_| failure())?;
        }
        // Ad-hoc/unsigned code is rejected ABOVE, before even querying the real group.
        let root =
            crate::macos_app_group::resolve(crate::shared_authority_policy::GROUP_IDENTIFIER)?;
        Self::acquire(root)
    }
}

#[cfg(all(target_os = "macos", feature = "macos-shared-authority"))]
fn require_kernel_sandbox() -> io::Result<()> {
    unsafe extern "C" {
        fn sandbox_check(pid: i32, operation: *const std::ffi::c_char, kind: i32, ...) -> i32;
    }
    // SAFETY: own process PID, no operation string/filter/varargs. This queries kernel state,
    // using the same query as the SIP-enabled fixture; unknown/error/unsandboxed all refuse.
    if unsafe { sandbox_check(std::process::id() as i32, std::ptr::null(), 0) } == 1 {
        Ok(())
    } else {
        Err(io::Error::other("kernel App Sandbox unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{JournalError, JournalPhase};
    use fido_core::RecoveryAdmission;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    struct Disposable(PathBuf);
    impl Disposable {
        fn new() -> Self {
            let path = fs::canonicalize(std::env::temp_dir())
                .unwrap_or_else(|_| panic!("synthetic fixture"))
                .join(format!(
                    "fidomanager-g5-synthetic-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_else(|_| panic!("synthetic fixture"))
                        .as_nanos()
                ));
            fs::create_dir(&path).unwrap_or_else(|_| panic!("synthetic fixture"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|_| panic!("synthetic fixture"));
            Self(path)
        }
        fn acquire(&self) -> Result<SharedAuthority, InstanceLockError> {
            SharedAuthority::acquire(AuthorityRoot::open_resolved(&self.0)?)
        }
    }
    impl Drop for Disposable {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap_or_else(|_| panic!("synthetic fixture"));
        }
    }
    fn record(phase: &str, resolution: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(
            &serde_json::json!({"schema":1,"application":"fidomanager-m4-v1",
            "incident":"0123456789abcdef0123456789abcdef","operation":"delete_credential",
            "created_unix_secs":1,"phase":phase,"resolution":resolution}),
        )
        .unwrap_or_else(|_| panic!("synthetic fixture"))
    }
    fn seed(holder: &mut SharedAuthority, bytes: &[u8]) {
        holder
            .storage
            .as_mut()
            .unwrap_or_else(|| panic!("synthetic fixture"))
            .replace_durable(bytes)
            .unwrap_or_else(|_| panic!("synthetic fixture"));
    }
    #[test]
    fn both_channels_reload_the_same_schema1_record_and_barrier_after_restart() {
        let root = Disposable::new();
        for (phase, resolution, expected) in [
            (
                "dispatch_capable",
                serde_json::Value::Null,
                RecoveryAdmission::Barrier,
            ),
            (
                "resolved",
                serde_json::json!("acknowledged_unknown"),
                RecoveryAdmission::Open,
            ),
        ] {
            let mut developer = root
                .acquire()
                .unwrap_or_else(|_| panic!("synthetic fixture"));
            seed(&mut developer, &record(phase, resolution));
            assert!(matches!(
                root.acquire(),
                Err(InstanceLockError::AlreadyHeld)
            ));
            drop(developer);
            // Channel-independent acquisition uses the SAME root and storage entrypoints.
            let mut store = root
                .acquire()
                .unwrap_or_else(|_| panic!("synthetic fixture"));
            let authority = AuthenticationAuthority::awaiting_recovery_startup();
            assert_eq!(store.initialize(&authority), Ok(()));
            assert_eq!(
                authority
                    .gate
                    .lock()
                    .unwrap_or_else(|_| panic!("synthetic fixture"))
                    .recovery_admission(),
                expected
            );
            assert_eq!(
                authority
                    .recovery
                    .lock()
                    .unwrap_or_else(|_| panic!("synthetic fixture"))
                    .as_ref()
                    .unwrap_or_else(|| panic!("synthetic fixture"))
                    .phase(),
                Some(if phase == "resolved" {
                    JournalPhase::Resolved
                } else {
                    JournalPhase::DispatchCapable
                })
            );
            assert_eq!(
                store.initialize(&authority),
                Err(JournalError::InvalidTransition)
            );
        }
    }
    #[test]
    fn malformed_records_load_poisoned_but_inaccessible_namespace_refuses_startup() {
        let root = Disposable::new();
        let mut holder = root
            .acquire()
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        seed(&mut holder, b"corrupted synthetic bytes");
        let authority = AuthenticationAuthority::awaiting_recovery_startup();
        assert_eq!(holder.initialize(&authority), Ok(()));
        assert_eq!(
            authority
                .gate
                .lock()
                .unwrap_or_else(|_| panic!("synthetic fixture"))
                .recovery_admission(),
            RecoveryAdmission::Barrier
        );
        assert_eq!(
            authority
                .recovery
                .lock()
                .unwrap_or_else(|_| panic!("synthetic fixture"))
                .as_ref()
                .unwrap_or_else(|| panic!("synthetic fixture"))
                .phase(),
            None
        );
        drop(holder);
        let namespace = root.0.join("fido-authority-recovery-v1");
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        assert!(matches!(
            root.acquire(),
            Err(InstanceLockError::Unavailable(_))
        ));
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        fs::remove_dir_all(&namespace).unwrap_or_else(|_| panic!("synthetic fixture"));
        let untouched = root.0.join("untouched");
        fs::write(&untouched, b"untouched").unwrap_or_else(|_| panic!("synthetic fixture"));
        assert!(symlink(&untouched, root.0.join("single-instance.lock")).is_err());
        fs::remove_file(root.0.join("single-instance.lock"))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        symlink(&untouched, root.0.join("single-instance.lock"))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        assert!(matches!(
            root.acquire(),
            Err(InstanceLockError::Unavailable(_))
        ));
        assert_eq!(
            fs::read(untouched).unwrap_or_else(|_| panic!("synthetic fixture")),
            b"untouched"
        );
        assert!(
            !namespace.exists(),
            "lock failure must precede journal creation"
        );
    }
    #[test]
    #[cfg(all(target_os = "macos", feature = "macos-shared-authority"))]
    fn unsigned_test_process_is_rejected_before_real_group_resolution() {
        assert!(matches!(
            SharedAuthority::production(false),
            Err(InstanceLockError::Unavailable(_))
        ));
        assert!(matches!(
            SharedAuthority::production(true),
            Err(InstanceLockError::Unavailable(_))
        ));
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;
    use fido_core::RecoveryAdmission;
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Component, PathBuf};
    use std::process::{Command, Stdio};

    #[test]
    #[ignore = "synthetic subprocess entrypoint; invoked by shared process test only"]
    fn synthetic_holder() {
        let parent =
            fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| panic!("synthetic fixture"));
        let path = PathBuf::from(
            std::env::var("FIDOMANAGER_G5_SYNTHETIC_ROOT")
                .unwrap_or_else(|_| panic!("synthetic fixture")),
        );
        let relative = path
            .strip_prefix(&parent)
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        assert_eq!(relative.components().count(), 1);
        let Component::Normal(name) = relative
            .components()
            .next()
            .unwrap_or_else(|| panic!("synthetic fixture"))
        else {
            panic!("test root");
        };
        let suffix = name
            .to_str()
            .unwrap_or_else(|| panic!("synthetic fixture"))
            .strip_prefix("fidomanager-g5-process-")
            .unwrap_or_else(|| panic!("synthetic fixture"));
        assert!(suffix.len() >= 16 && suffix.bytes().all(|byte| byte.is_ascii_digit()));
        let mut holder = SharedAuthority::acquire(
            AuthorityRoot::open_resolved(&path).unwrap_or_else(|_| panic!("synthetic fixture")),
        )
        .unwrap_or_else(|_| panic!("synthetic fixture"));
        let authority = AuthenticationAuthority::awaiting_recovery_startup();
        assert_eq!(holder.initialize(&authority), Ok(()));
        assert_eq!(
            authority
                .gate
                .lock()
                .unwrap_or_else(|_| panic!("synthetic fixture"))
                .recovery_admission(),
            RecoveryAdmission::Barrier
        );
        assert_eq!(
            authority
                .recovery
                .lock()
                .unwrap_or_else(|_| panic!("synthetic recovery"))
                .as_ref()
                .unwrap_or_else(|| panic!("loaded synthetic journal"))
                .phase(),
            Some(crate::recovery::JournalPhase::DispatchCapable)
        );
        println!("G5_SYNTHETIC_READY Barrier loaded");
        use std::io::Write;
        std::io::stdout()
            .flush()
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .unwrap_or_else(|_| panic!("synthetic fixture"));
    }

    #[test]
    fn concurrent_process_and_abrupt_termination_preserve_shared_barrier() {
        let parent =
            fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| panic!("synthetic fixture"));
        let path = parent.join(format!(
            "fidomanager-g5-process-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| panic!("synthetic fixture"))
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap_or_else(|_| panic!("synthetic fixture"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("synthetic fixture"));
        let mut first = SharedAuthority::acquire(
            AuthorityRoot::open_resolved(&path).unwrap_or_else(|_| panic!("synthetic fixture")),
        )
        .unwrap_or_else(|_| panic!("synthetic fixture"));
        first.storage.as_mut().unwrap_or_else(|| panic!("synthetic fixture")).replace_durable(br#"{"schema":1,"application":"fidomanager-m4-v1","incident":"0123456789abcdef0123456789abcdef","operation":"delete_credential","created_unix_secs":1,"phase":"dispatch_capable","resolution":null}"#).unwrap_or_else(|_| panic!("synthetic fixture"));
        drop(first);
        let mut child =
            Command::new(std::env::current_exe().unwrap_or_else(|_| panic!("synthetic fixture")))
                .args([
                    "--exact",
                    "shared_authority::process_tests::synthetic_holder",
                    "--ignored",
                    "--nocapture",
                ])
                .env("FIDOMANAGER_G5_SYNTHETIC_ROOT", &path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap_or_else(|_| panic!("synthetic fixture"));
        let output = BufReader::new(
            child
                .stdout
                .take()
                .unwrap_or_else(|| panic!("synthetic fixture")),
        );
        let mut ready = false;
        for line in output.lines() {
            if line.unwrap_or_else(|_| panic!("synthetic fixture"))
                == "G5_SYNTHETIC_READY Barrier loaded"
            {
                ready = true;
                break;
            }
        }
        assert!(
            ready,
            "holder must prove exact loaded admission before contention"
        );
        assert!(matches!(
            SharedAuthority::acquire(
                AuthorityRoot::open_resolved(&path).unwrap_or_else(|_| panic!("synthetic fixture"))
            ),
            Err(InstanceLockError::AlreadyHeld)
        ));
        child.kill().unwrap_or_else(|_| panic!("synthetic fixture"));
        assert!(
            !child
                .wait()
                .unwrap_or_else(|_| panic!("synthetic fixture"))
                .success()
        );
        let mut restarted = SharedAuthority::acquire(
            AuthorityRoot::open_resolved(&path).unwrap_or_else(|_| panic!("synthetic fixture")),
        )
        .unwrap_or_else(|_| panic!("synthetic fixture"));
        let authority = AuthenticationAuthority::awaiting_recovery_startup();
        assert_eq!(restarted.initialize(&authority), Ok(()));
        assert_eq!(
            authority
                .gate
                .lock()
                .unwrap_or_else(|_| panic!("synthetic fixture"))
                .recovery_admission(),
            RecoveryAdmission::Barrier
        );
        assert_eq!(
            authority
                .recovery
                .lock()
                .unwrap_or_else(|_| panic!("synthetic recovery"))
                .as_ref()
                .unwrap_or_else(|| panic!("loaded synthetic journal"))
                .phase(),
            Some(crate::recovery::JournalPhase::DispatchCapable)
        );
        fs::remove_dir_all(path).unwrap_or_else(|_| panic!("synthetic fixture"));
    }
}
