//! Containment lifecycle against real child processes: the production endpoint, handshake,
//! framing, runtime and engine, with a fixture standing in for libfido2.

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use common::{TestResult, launch, list_request, pid_exists, policy, wait_until};
use fido_core::{DeviceReadStatus, ExecutionQuiescence};
use fido_service::{
    DiscoveryCoordinator, DiscoveryError, WorkerEndpoint, WorkerEndpointError, WorkerGeneration,
};

#[test]
fn discovery_round_trips_through_a_real_child_process() -> TestResult {
    let endpoint = launch(&["--script=ok", "--tag=lifecycle-round-trip"], 1)?;
    let mut coordinator = DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), policy(500))?;

    let snapshot = coordinator.refresh()?;
    assert_eq!(snapshot.devices.len(), 1);
    let device = &snapshot.devices[0];
    assert_eq!(device.read_status, DeviceReadStatus::Ready);
    assert_eq!(device.vendor_id, 0x1234);
    assert_eq!(device.versions, vec!["FIDO_2_1".to_owned()]);
    assert!(coordinator.resolve_handle(device.handle).is_some());

    // Native device keys are worker-private and must not appear anywhere in the published view.
    assert!(!format!("{snapshot:?}").contains("fake-0"));
    Ok(())
}

#[test]
fn hung_native_call_is_killed_and_reaped_before_the_failure_is_reported() -> TestResult {
    let endpoint = launch(&["--script=hang", "--tag=lifecycle-hang"], 1)?;
    let hung_pid = endpoint.worker_pid();
    let mut coordinator = DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), policy(50))?;
    assert!(pid_exists(hung_pid));

    let started = Instant::now();
    let result = coordinator.refresh();
    let elapsed = started.elapsed();

    assert_eq!(
        result.err(),
        Some(DiscoveryError::Endpoint(
            WorkerEndpointError::ExchangeDeadlineExceeded
        ))
    );
    // Deadline is native budget (50 ms) plus the 100 ms transport margin, not a hidden 250 ms.
    assert!(elapsed >= Duration::from_millis(150), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");

    // The ordering that matters: by the time the error is visible the process is *reaped*.
    assert!(
        !pid_exists(hung_pid),
        "the hung worker must be dead and reaped, not abandoned"
    );
    assert_eq!(coordinator.contain_worker(), ExecutionQuiescence::Quiescent);
    assert_eq!(
        coordinator.refresh().err(),
        Some(DiscoveryError::WorkerQuarantined)
    );

    // Replacement under a strictly higher generation, after proof of quiescence.
    let replacement = launch(&["--script=ok", "--tag=lifecycle-hang"], 2)?;
    let replacement_pid = replacement.worker_pid();
    assert_ne!(replacement_pid, hung_pid);
    coordinator.replace_worker(replacement, WorkerGeneration(2))?;
    assert_eq!(coordinator.refresh()?.devices.len(), 1);
    Ok(())
}

#[test]
fn native_call_that_ignores_its_budget_is_killed_at_budget_plus_margin() -> TestResult {
    let mut endpoint = launch(&["--script=slow30000", "--tag=lifecycle-slow"], 1)?;
    let pid = endpoint.worker_pid();

    let started = Instant::now();
    let result = endpoint.exchange(list_request(1, 1, 100));
    let elapsed = started.elapsed();

    assert_eq!(
        result.err(),
        Some(WorkerEndpointError::ExchangeDeadlineExceeded)
    );
    assert!(elapsed >= Duration::from_millis(190), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    assert!(!pid_exists(pid));
    Ok(())
}

#[test]
fn stopped_worker_is_killed_at_the_deadline() -> TestResult {
    // SIGSTOP freezes the worker mid-flight exactly like a native call wedged in the kernel.
    let mut endpoint = launch(&["--script=ok", "--tag=lifecycle-stop"], 1)?;
    let pid = endpoint.worker_pid();
    assert!(
        Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .status()?
            .success()
    );

    let result = endpoint.exchange(list_request(1, 1, 50));
    assert_eq!(
        result.err(),
        Some(WorkerEndpointError::ExchangeDeadlineExceeded)
    );
    assert!(
        !pid_exists(pid),
        "SIGKILL must terminate a stopped process and the endpoint must reap it"
    );
    Ok(())
}

#[test]
fn crash_is_detected_from_the_closed_pipe_long_before_the_deadline() -> TestResult {
    let endpoint = launch(&["--script=crash", "--tag=lifecycle-crash"], 1)?;
    let pid = endpoint.worker_pid();
    // A large budget: detection must come from EOF, not from the timeout.
    let mut coordinator = DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), policy(5_000))?;

    let started = Instant::now();
    let result = coordinator.refresh();
    let elapsed = started.elapsed();

    assert_eq!(
        result.err(),
        Some(DiscoveryError::Endpoint(WorkerEndpointError::Unavailable))
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "crash waited out the budget: {elapsed:?}"
    );
    assert!(!pid_exists(pid));

    coordinator.replace_worker(
        launch(&["--script=ok", "--tag=lifecycle-crash"], 2)?,
        WorkerGeneration(2),
    )?;
    assert_eq!(coordinator.refresh()?.devices.len(), 1);
    Ok(())
}

#[test]
fn idle_worker_death_invalidates_handles_and_recovers() -> TestResult {
    let endpoint = launch(&["--script=ok", "--tag=lifecycle-idle-death"], 1)?;
    let pid = endpoint.worker_pid();
    let mut coordinator = DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), policy(500))?;
    let handle = coordinator.refresh()?.devices[0].handle;
    assert!(coordinator.resolve_handle(handle).is_some());

    // Crash after the response was delivered: nothing is pending when it dies.
    assert!(
        Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()?
            .success()
    );
    assert!(wait_until(Duration::from_secs(2), || !common::pid_running(
        pid
    )));

    assert_eq!(
        coordinator.refresh().err(),
        Some(DiscoveryError::Endpoint(WorkerEndpointError::Unavailable))
    );
    assert!(
        coordinator.resolve_handle(handle).is_none(),
        "a dead worker's handles must stop resolving"
    );

    coordinator.replace_worker(
        launch(&["--script=ok", "--tag=lifecycle-idle-death"], 2)?,
        WorkerGeneration(2),
    )?;
    assert_eq!(coordinator.refresh()?.devices.len(), 1);
    assert!(
        coordinator.resolve_handle(handle).is_none(),
        "old handles stay dead"
    );
    Ok(())
}

#[test]
fn contain_is_idempotent_and_refuses_further_exchanges() -> TestResult {
    let mut endpoint = launch(&["--script=ok", "--tag=lifecycle-contain"], 1)?;
    let pid = endpoint.worker_pid();

    assert_eq!(endpoint.contain(), ExecutionQuiescence::Quiescent);
    assert!(!pid_exists(pid));
    assert_eq!(endpoint.contain(), ExecutionQuiescence::Quiescent);
    assert_eq!(
        endpoint.exchange(list_request(1, 1, 100)).err(),
        Some(WorkerEndpointError::Unavailable)
    );
    Ok(())
}

#[test]
fn dropping_the_endpoint_kills_and_reaps_the_worker() -> TestResult {
    let endpoint = launch(&["--script=hang", "--tag=lifecycle-drop"], 1)?;
    let pid = endpoint.worker_pid();
    assert!(pid_exists(pid));
    drop(endpoint);
    assert!(
        !pid_exists(pid),
        "drop is deterministic cleanup, not best effort"
    );
    Ok(())
}

#[test]
fn replacing_a_live_worker_stops_it_first_so_native_execution_never_overlaps() -> TestResult {
    let old = launch(&["--script=ok", "--tag=lifecycle-overlap"], 1)?;
    let old_pid = old.worker_pid();
    let mut coordinator = DiscoveryCoordinator::new(old, WorkerGeneration(1), policy(500))?;
    coordinator.refresh()?;

    // In the thread design this overlapped two native executions. Here the old process is gone
    // by the time `replace_worker` returns.
    let new = launch(&["--script=ok", "--tag=lifecycle-overlap"], 2)?;
    coordinator.replace_worker(new, WorkerGeneration(2))?;
    assert!(!pid_exists(old_pid));
    assert_eq!(coordinator.refresh()?.devices.len(), 1);
    Ok(())
}
