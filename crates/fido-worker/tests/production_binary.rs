//! Exercises the real `fido-worker` executable (its `main`, argument policy, startup hygiene and
//! runtime) without touching any authenticator: only the handshake and health check are used, so
//! no HID access is attempted and no hardware is needed.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fido_core::ExecutionQuiescence;
use fido_service::{
    ProcessWorkerConfig, ProcessWorkerLauncher, ResolvedWorkerExecutable, WorkerEndpoint,
    WorkerGeneration, WorkerLauncher,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fido-worker"))
}

#[test]
fn production_worker_completes_the_handshake_and_health_check() -> TestResult {
    let mut launcher = ProcessWorkerLauncher::new(
        ResolvedWorkerExecutable::from_absolute_path(worker_path())?,
        ProcessWorkerConfig::default(),
    )?;

    // `launch` performs spawn, hello handshake and a health-check exchange.
    let mut endpoint = launcher.launch(WorkerGeneration(7))?;
    assert_eq!(endpoint.generation(), WorkerGeneration(7));
    assert_eq!(endpoint.contain(), ExecutionQuiescence::Quiescent);
    Ok(())
}

#[test]
fn production_worker_accepts_no_arguments() -> TestResult {
    let status = Command::new(worker_path())
        .arg("--anything")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert_eq!(status.code(), Some(fido_worker::exit::USAGE));
    Ok(())
}

#[test]
fn debug_environment_is_refused_before_native_initialization() -> TestResult {
    let status = Command::new(worker_path())
        .env_clear()
        .env("FIDO_DEBUG", "")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert_eq!(status.code(), Some(fido_worker::exit::CONFIG));
    Ok(())
}

#[test]
fn production_worker_leaves_when_its_stdin_closes_before_the_handshake() -> TestResult {
    let mut child = Command::new(worker_path())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    drop(child.stdin.take());

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            assert_eq!(status.code(), Some(fido_worker::exit::ORDERLY));
            return Ok(());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("worker did not leave after stdin closed".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
