//! M1.5 child-process prototype: the unchanged `DiscoveryCoordinator` driving a
//! `ProcessWorkerEndpoint` over the unchanged worker protocol.

use std::error::Error;
use std::io::Cursor;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fido_core::DeviceReadStatus;
use fido_service::{DiscoveryCoordinator, DiscoveryError, DiscoveryPolicy, WorkerEndpointError};
use fido_spike_worker::{
    FrameError, HARD_DEADLINE_SLACK_MS, ProcessWorkerEndpoint, process_exists, read_frame,
};
use fido_worker_protocol::{MAX_WORKER_FRAME_BYTES, WorkerGeneration};

type TestResult = Result<(), Box<dyn Error>>;

fn worker_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fido-spike-worker"))
}

fn policy(budget_ms: u64) -> DiscoveryPolicy {
    DiscoveryPolicy {
        list_devices_budget_ms: budget_ms,
        get_device_info_budget_ms: budget_ms,
    }
}

fn spawn(generation: u64, script: &str) -> Result<ProcessWorkerEndpoint, WorkerEndpointError> {
    ProcessWorkerEndpoint::spawn(&worker_exe(), WorkerGeneration(generation), script)
}

#[test]
fn protocol_round_trips_through_a_real_child_process() -> TestResult {
    let endpoint = spawn(1, "ok")?;
    let mut coordinator = DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), policy(500))?;
    let snapshot = coordinator.refresh()?;
    assert_eq!(snapshot.devices.len(), 1);
    let device = &snapshot.devices[0];
    assert_eq!(device.read_status, DeviceReadStatus::Ready);
    assert_eq!(device.vendor_id, 0x1234);
    assert_eq!(device.versions, vec!["FIDO_2_1".to_owned()]);
    assert!(coordinator.resolve_handle(device.handle).is_some());
    Ok(())
}

#[test]
fn hung_child_is_killed_and_replaced_with_new_generation() -> TestResult {
    let endpoint = spawn(1, "hang")?;
    let hung_pid = endpoint.pid();
    let mut coordinator = DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), policy(50))?;
    assert!(process_exists(hung_pid));

    let started = Instant::now();
    let result = coordinator.refresh();
    let elapsed = started.elapsed();
    println!("hung child: refresh -> {result:?} after {elapsed:?}");
    assert!(matches!(
        result,
        Err(DiscoveryError::Endpoint(
            WorkerEndpointError::TransportFailure
        ))
    ));
    assert!(elapsed >= Duration::from_millis(50 + HARD_DEADLINE_SLACK_MS));
    assert!(elapsed < Duration::from_secs(2));

    // Quiescence is now *provable*: the process has been SIGKILLed and reaped.
    assert!(
        !process_exists(hung_pid),
        "hung worker must be gone, not merely abandoned"
    );
    assert!(matches!(
        coordinator.refresh(),
        Err(DiscoveryError::WorkerQuarantined)
    ));

    // Replacement under the unchanged coordinator API, with a strictly increasing generation.
    let replacement = spawn(2, "ok")?;
    let new_pid = replacement.pid();
    assert_ne!(new_pid, hung_pid);
    coordinator.replace_worker(replacement, WorkerGeneration(2))?;
    let snapshot = coordinator.refresh()?;
    assert_eq!(snapshot.devices.len(), 1);
    assert_eq!(snapshot.devices[0].read_status, DeviceReadStatus::Ready);
    Ok(())
}

#[test]
fn child_crash_during_request_is_detected_before_the_deadline() -> TestResult {
    let endpoint = spawn(1, "crash")?;
    let pid = endpoint.pid();
    // Large budget: detection must come from EOF/exit, not from the timeout.
    let mut coordinator = DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), policy(5_000))?;

    let started = Instant::now();
    let result = coordinator.refresh();
    let elapsed = started.elapsed();
    println!("crashing child: refresh -> {result:?} after {elapsed:?}");
    assert!(matches!(
        result,
        Err(DiscoveryError::Endpoint(WorkerEndpointError::Unavailable))
    ));
    assert!(
        elapsed < Duration::from_millis(1_000),
        "crash must not wait out the budget"
    );
    assert!(!process_exists(pid));

    coordinator.replace_worker(spawn(2, "ok")?, WorkerGeneration(2))?;
    assert_eq!(coordinator.refresh()?.devices.len(), 1);
    Ok(())
}

#[test]
fn child_death_while_idle_invalidates_handles_and_recovers() -> TestResult {
    let endpoint = spawn(1, "ok")?;
    let pid = endpoint.pid();
    let mut coordinator = DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), policy(500))?;
    let handle = coordinator.refresh()?.devices[0].handle;
    assert!(coordinator.resolve_handle(handle).is_some());

    // Kill the worker externally while the service holds a live handle (crash after the response
    // was dispatched; nothing is pending).
    Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()?;
    std::thread::sleep(Duration::from_millis(100));

    let result = coordinator.refresh();
    println!("idle-death: refresh -> {result:?}");
    assert!(matches!(
        result,
        Err(DiscoveryError::Endpoint(WorkerEndpointError::Unavailable))
    ));
    assert!(
        coordinator.resolve_handle(handle).is_none(),
        "registry must not keep resolving handles from a dead worker"
    );

    coordinator.replace_worker(spawn(2, "ok")?, WorkerGeneration(2))?;
    let after = coordinator.refresh()?;
    assert_eq!(after.devices.len(), 1);
    assert!(
        coordinator.resolve_handle(handle).is_none(),
        "handles from the old worker generation stay dead after replacement"
    );
    Ok(())
}

#[test]
fn oversized_frame_is_rejected_before_allocation() {
    let mut header = Vec::new();
    header.extend_from_slice(
        &u32::try_from(MAX_WORKER_FRAME_BYTES + 1)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    assert!(matches!(
        read_frame(&mut Cursor::new(header)),
        Err(FrameError::TooLarge)
    ));
}

#[test]
fn orphaned_child_exits_when_parent_pipe_closes() -> TestResult {
    let mut child = Command::new(worker_exe())
        .args(["--generation", "1", "--script", "ok"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    drop(child.stdin.take()); // what the OS does if the parent dies without cleanup
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait()? {
            assert!(status.success());
            return Ok(());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("orphaned worker did not exit on stdin EOF".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
