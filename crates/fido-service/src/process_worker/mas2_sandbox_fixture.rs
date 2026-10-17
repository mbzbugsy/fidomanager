//! Ignored libtest fixture only. No production app entrypoint, journal, native FIDO or PIN APIs.
use super::*;
use crate::mas_worker_authenticity::MasWorkerVerifier;
use crate::worker_authenticity::{IdentityRejection, VerifiedSpawn};
use fido_platform::macos_code_signing::RunningCode;
use fido_platform::os_version::DynamicNetworkPolicy;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

const ID: &str = "eu.fidomanager.desktop.mas2authtest";
unsafe extern "C" {
    fn sandbox_check(pid: i32, operation: *const std::ffi::c_char, kind: i32, ...) -> i32;
    fn csops(pid: i32, operation: u32, address: *mut std::ffi::c_void, size: usize) -> i32;
}
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct ReapChild(Child);
impl std::ops::Deref for ReapChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for ReapChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for ReapChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn emit(value: serde_json::Value) {
    println!("MAS2_EVIDENCE {value}");
}

fn context() -> Result<(PathBuf, String)> {
    let pid = std::process::id();
    let mut flags = 0u32;
    // SAFETY: null-operation kernel query and a writable four-byte STATUS buffer.
    let (sandboxed, status) = unsafe {
        (
            sandbox_check(pid as i32, std::ptr::null(), 0),
            csops(pid as i32, 0, std::ptr::from_mut(&mut flags).cast(), 4),
        )
    };
    emit(
        serde_json::json!({"event":"kernel", "pid":pid, "sandboxed":sandboxed,
        "cs_status":status,"cs_flags":flags}),
    );
    assert_eq!(
        sandboxed, 1,
        "MAS.2 fixture refuses storage without a kernel sandbox"
    );
    assert_eq!(status, 0);
    assert_eq!(flags & 0x10001, 0x10001);
    let me = RunningCode::current_process()?.signing_information()?;
    assert_eq!(me.identifier.as_deref(), Some(ID));
    assert!(me.team_id.is_none());
    let home = PathBuf::from(std::env::var("HOME")?);
    assert!(
        home.is_absolute() && home.ends_with(Path::new("Library/Containers").join(ID).join("Data"))
    );
    let run = std::env::var("FIDOMANAGER_MAS2_RUN")?;
    assert!(fido_platform::build_identity::is_lower_hex(&run, 32));
    let action = std::env::var("FIDOMANAGER_MAS2_ACTION")?;
    Ok((home.join("mas2-runs").join(run), action))
}

fn network() -> Result<DynamicNetworkPolicy> {
    Ok(DynamicNetworkPolicy::for_version(
        fido_platform::os_version::current()?,
    )?)
}
fn wait_kernel(child: &mut Child) -> Result<()> {
    use std::io::BufRead;
    let stderr = child.stderr.take().ok_or("fixture child stderr")?;
    let mut line = String::new();
    io::BufReader::new(stderr).read_line(&mut line)?;
    let json = line
        .strip_prefix("MAS2_CHILD_EVIDENCE ")
        .ok_or("fixture child kernel report")?;
    let row: serde_json::Value = serde_json::from_str(json)?;
    assert_eq!(row["pid"], child.id());
    assert_eq!(row["sandboxed"], 1);
    assert_eq!(row["cs_status"], 0);
    eprintln!("MAS2_CHILD_EVIDENCE {row}");
    Ok(())
}
fn identifier() -> Result<String> {
    use fido_platform::build_identity as build;
    Ok(crate::mas_worker_policy::release_identifier(
        build::RELEASE_VERSION,
        build::RELEASE_SOURCE_COMMIT.ok_or("fixture needs its synthetic compiled commit")?,
    )
    .ok_or("fixture release identifier")?)
}
fn mode() -> Result<WorkerAuthenticity> {
    Ok(WorkerAuthenticity::MasEnforced(Arc::new(
        MasWorkerVerifier::ad_hoc_for_test(identifier()?, network()?).map_err(|_| "test policy")?,
    )))
}
fn prepare(action: &str, case: &str) -> Result<()> {
    // Test-only orchestration: the external runner prepares signed fixture files. Sandboxed
    // executable creation is quarantined by macOS; no quarantine removal or new exception.
    emit(serde_json::json!({"event":"fixture-prep", "action":action, "case":case}));
    io::stdout().flush()?;
    let mut acknowledgement = String::new();
    io::stdin().read_line(&mut acknowledgement)?;
    assert_eq!(acknowledgement, "READY\n");
    Ok(())
}
fn install(_cases: &Path, _macos: &Path, name: &str) -> Result<()> {
    prepare("install", name)
}
fn launcher(authenticity: WorkerAuthenticity) -> Result<ProcessWorkerLauncher> {
    Ok(ProcessWorkerLauncher::with_authenticity(
        Some(ResolvedWorkerExecutable::beside_current_exe("fido-worker")?),
        ProcessWorkerConfig::default(),
        authenticity,
    ))
}
fn rejected(launcher: &mut ProcessWorkerLauncher) {
    assert!(matches!(
        launcher.launch(WorkerGeneration(1)),
        Err(LaunchError::WorkerIdentityRejected {
            quiescence: ExecutionQuiescence::Quiescent
        })
    ));
    assert!(launcher.identity_latch.is_set());
}
fn prove_latched(launcher: &mut ProcessWorkerLauncher, cases: &Path, macos: &Path) -> Result<()> {
    install(cases, macos, "correct-a")?;
    rejected(launcher);
    assert!(!macos.join("hello-receipt").try_exists()?);
    Ok(())
}

struct SwappingPolicy {
    inner: WorkerAuthenticity,
    replacement: PathBuf,
    remove: bool,
}
impl WorkerIdentityCheck for SwappingPolicy {
    fn enforces_release_layout(&self) -> bool {
        true
    }
    fn latches_path_failure(&self) -> bool {
        true
    }
    fn expected_build_id(&self) -> &str {
        self.inner.expected_build_id()
    }
    fn verify_before_spawn(
        &self,
        path: &Path,
    ) -> std::result::Result<VerifiedSpawn, IdentityRejection> {
        let token = self.inner.verify_before_spawn(path)?;
        // Deliberate, test-only substitution AFTER C_s is authenticated, before Command::spawn.
        assert_eq!(
            self.replacement.file_name().and_then(|name| name.to_str()),
            Some("correct-b")
        );
        if self.remove {
            prepare("unsafe-path", "missing-worker")
        } else {
            prepare("swap", "correct-b")
        }
        .map_err(|_| IdentityRejection::StaticValidation)?;
        Ok(token)
    }
    fn verify_running_child(
        &self,
        pid: u32,
        token: &VerifiedSpawn,
    ) -> std::result::Result<ChildVerification, IdentityRejection> {
        self.inner.verify_running_child(pid, token)
    }
}

#[test]
#[ignore = "requires the disposable ad-hoc sandbox runner, never a production identity"]
fn run() -> Result<()> {
    let (root, action) = context()?;
    if action == "stage" {
        fs::create_dir_all(root.parent().ok_or("test root")?)?;
        fs::create_dir(&root)?; // UUID must be new; never reuse existing storage.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        emit(serde_json::json!({"event":"staged", "root":root}));
        return Ok(());
    }
    assert_eq!(action, "matrix");
    let executable = std::env::current_exe()?.canonicalize()?;
    let macos = executable.parent().ok_or("test app layout")?;
    assert_eq!(macos, root.join("MAS.2 Auth Test.app/Contents/MacOS"));
    let cases = root.join("MAS.2 Auth Test.app/Contents/Resources/cases");

    install(&cases, macos, "correct-a")?;
    let mut accepted = launcher(mode()?)?;
    let mut endpoint = accepted.launch(WorkerGeneration(1))?;
    let pid = endpoint.pid;
    assert!(fs::read_to_string(macos.join("hello-receipt"))?.ends_with("VARIANT-A\n"));
    assert_eq!(endpoint.contain(), ExecutionQuiescence::Quiescent);
    assert!(!accepted.identity_latch.is_set());
    emit(
        serde_json::json!({"event":"case", "case":"correct-release", "accepted":true,
        "child_pid":pid, "hello":true, "contained":true, "latched":false}),
    );

    for name in [
        "older-release",
        "wrong-flavor",
        "wrong-commit",
        "extra-grant",
        "missing-inherit",
        "false-inherit",
        "integer-inherit",
        "no-runtime",
        "unexpected-flags",
        "fat-worker",
    ] {
        install(&cases, macos, name)?;
        let mut rejected_launcher = launcher(mode()?)?;
        rejected(&mut rejected_launcher);
        assert!(!macos.join("hello-receipt").try_exists()?);
        prove_latched(&mut rejected_launcher, &cases, macos)?;
        emit(
            serde_json::json!({"event":"case", "case":name, "accepted":false,
            "hello":false, "contained":true, "latched":true}),
        );
    }

    install(&cases, macos, "correct-a")?;
    let production = MasWorkerVerifier::production().map_err(|_| "fixture metadata missing")?;
    let mut publisher = launcher(WorkerAuthenticity::MasEnforced(Arc::new(production)))?;
    rejected(&mut publisher);
    assert!(!macos.join("hello-receipt").try_exists()?);
    prove_latched(&mut publisher, &cases, macos)?;
    emit(
        serde_json::json!({"event":"case", "case":"production-publisher-refuses-adhoc",
        "accepted":false,"hello":false,"contained":true,"latched":true}),
    );

    for name in [
        "world-writable",
        "group-writable",
        "symlink",
        "directory",
        "missing-worker",
    ] {
        install(&cases, macos, "correct-a")?;
        let mut path_launcher = launcher(mode()?)?;
        prepare("unsafe-path", name)?;
        rejected(&mut path_launcher);
        assert!(!macos.join("hello-receipt").try_exists()?);
        prove_latched(&mut path_launcher, &cases, macos)?;
        emit(
            serde_json::json!({"event":"case", "case":name,"accepted":false,
            "hello":false,"contained":true,"latched":true}),
        );
    }

    install(&cases, macos, "correct-a")?;
    let swapping = SwappingPolicy {
        inner: mode()?,
        replacement: cases.join("correct-b"),
        remove: false,
    };
    let latch = IdentityLatch::default();
    let executable = ResolvedWorkerExecutable::beside_current_exe("fido-worker")?;
    let result = ProcessWorkerEndpoint::launch(
        &executable,
        &swapping,
        &latch,
        &[],
        WorkerGeneration(1),
        ProcessWorkerConfig::default(),
        None,
    );
    assert!(matches!(
        result,
        Err(LaunchError::WorkerIdentityRejected {
            quiescence: ExecutionQuiescence::Quiescent
        })
    ));
    assert!(latch.is_set());
    assert!(!macos.join("hello-receipt").try_exists()?);
    emit(
        serde_json::json!({"event":"case", "case":"static-to-spawn-swap", "accepted":false,
        "hello":false,"contained":true,"latched":true}),
    );
    install(&cases, macos, "correct-a")?;
    let missing_after_static = SwappingPolicy {
        inner: mode()?,
        replacement: cases.join("correct-b"),
        remove: true,
    };
    let failed_exec_latch = IdentityLatch::default();
    let executable = ResolvedWorkerExecutable::beside_current_exe("fido-worker")?;
    assert!(matches!(
        ProcessWorkerEndpoint::launch(
            &executable,
            &missing_after_static,
            &failed_exec_latch,
            &[],
            WorkerGeneration(1),
            ProcessWorkerConfig::default(),
            None
        ),
        Err(LaunchError::WorkerIdentityRejected {
            quiescence: ExecutionQuiescence::Quiescent
        })
    ));
    assert!(failed_exec_latch.is_set());
    assert!(!macos.join("hello-receipt").try_exists()?);
    emit(
        serde_json::json!({"event":"case", "case":"post-static-exec-refusal", "accepted":false,
        "hello":false,"contained":true,"latched":true}),
    );

    install(&cases, macos, "correct-b")?;
    let mut wrong_build = launcher(mode()?)?;
    wrong_build.fixed_args = &["--wrong-build-id"];
    rejected(&mut wrong_build);
    assert!(macos.join("hello-receipt").try_exists()?); // consistency failure is AFTER verified hello
    prove_latched(&mut wrong_build, &cases, macos)?;
    emit(
        serde_json::json!({"event":"case", "case":"build-id-consistency", "accepted":false,
        "hello":true,"contained":true,"latched":true}),
    );

    assert_eq!(
        mode()?.verify_running_child(0, &VerifiedSpawn::Development),
        Err(IdentityRejection::StartupRejected)
    );
    emit(
        serde_json::json!({"event":"case", "case":"no-unsigned-fallback", "accepted":false,
        "hello":false,"contained":true,"latched":false}),
    );

    // Two tokens coexist, including interleaved verification. There is no "last verified" hash.
    let verifier =
        MasWorkerVerifier::ad_hoc_for_test(identifier()?, network()?).map_err(|_| "test policy")?;
    let a = verifier
        .check_static(&cases.join("correct-a"))
        .map_err(|_| "static A")?;
    let b = verifier
        .check_static(&cases.join("correct-b"))
        .map_err(|_| "static B")?;
    let mut child_a = ReapChild(
        Command::new(cases.join("correct-a"))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut child_b = ReapChild(
        Command::new(cases.join("correct-b"))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    wait_kernel(&mut child_a)?;
    wait_kernel(&mut child_b)?;
    // Own and retain BOTH Child handles, unreaped throughout the thread scope and cross-checks.
    let checks = thread::scope(|scope| {
        let first = scope.spawn(|| verifier.check_running(child_a.id(), &a));
        let second = scope.spawn(|| verifier.check_running(child_b.id(), &b));
        (first.join(), second.join())
    });
    let cross_a = verifier.check_running(child_a.id(), &b);
    let cross_b = verifier.check_running(child_b.id(), &a);
    let other =
        MasWorkerVerifier::ad_hoc_for_test(identifier()?, network()?).map_err(|_| "test policy")?;
    let foreign = other.check_running(child_a.id(), &a);
    let child_pids = [child_a.id(), child_b.id()];
    let _ = child_a.kill();
    let _ = child_b.kill();
    child_a.wait()?;
    child_b.wait()?;
    assert!(matches!(checks, (Ok(Ok(())), Ok(Ok(())))));
    assert_eq!(cross_a, Err(IdentityRejection::DynamicValidation));
    assert_eq!(cross_b, Err(IdentityRejection::DynamicValidation));
    assert_eq!(foreign, Err(IdentityRejection::DynamicValidation));
    assert_ne!(a.authenticated_cdhash(), b.authenticated_cdhash());
    emit(
        serde_json::json!({"event":"case", "case":"independent-per-spawn-tokens", "accepted":true,
        "child_pids":child_pids, "cross_hash_rejected":true, "foreign_token_rejected":true,
        "static_a":crate::release_identity::lower_hex(a.authenticated_cdhash()),
        "static_b":crate::release_identity::lower_hex(b.authenticated_cdhash()),
        "hello":false,"contained":true,"latched":false}),
    );
    emit(
        serde_json::json!({"event":"complete", "real_recovery_accessed":false, "physical_fido_operations":false}),
    );
    Ok(())
}
