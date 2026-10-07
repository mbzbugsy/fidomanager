//! Opt-in check of a *packaged* worker: run only by the macOS packaging job, against the worker
//! inside an assembled `Fido Manager.app`. Uses the production launcher and resolution checks with
//! only the handshake and health check, so no authenticator is touched.
//!
//! ```text
//! FIDOMANAGER_PACKAGED_WORKER="$PWD/target/macos-package/Fido Manager.app/Contents/MacOS/fido-worker" \
//!   cargo test -p fido-worker --test packaged_worker --locked -- --ignored
//! ```

use std::path::PathBuf;

use fido_core::ExecutionQuiescence;
use fido_service::{
    ProcessWorkerConfig, ProcessWorkerLauncher, ResolvedWorkerExecutable, WorkerEndpoint,
    WorkerGeneration, WorkerLauncher,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
#[ignore = "requires an assembled macOS bundle; run by the packaging job"]
fn packaged_worker_completes_the_handshake_and_health_check() -> TestResult {
    let path = PathBuf::from(
        std::env::var_os("FIDOMANAGER_PACKAGED_WORKER")
            .ok_or("FIDOMANAGER_PACKAGED_WORKER is not set")?,
    );
    assert!(
        path.ends_with("Fido Manager.app/Contents/MacOS/fido-worker"),
        "not a bundled worker path"
    );

    let mut launcher = ProcessWorkerLauncher::new(
        ResolvedWorkerExecutable::from_absolute_path(path)?,
        ProcessWorkerConfig::default(),
    )?;
    let mut endpoint = launcher.launch(WorkerGeneration(1))?;
    assert_eq!(endpoint.generation(), WorkerGeneration(1));
    assert_eq!(endpoint.contain(), ExecutionQuiescence::Quiescent);
    Ok(())
}
