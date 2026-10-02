//! Deterministic recovery for read-only discovery: the production supervisor driving real worker
//! processes through hangs, crashes and crash loops, without restarting anything else.
//!
//! Restart *policy* time comes from a manual clock so backoff and cooldown are exact; the child
//! processes themselves run in real time.

mod common;

use std::time::Duration;

use common::{
    ManualClock, TestResult, count_processes, launcher, launcher_with, policy, wait_until,
};
use fido_core::{DeviceReadStatus, ExecutionQuiescence};
use fido_service::{
    DiscoverySupervisor, LaunchError, ProcessWorkerConfig, ProcessWorkerEndpoint,
    ProcessWorkerLauncher, RestartPolicy, SupervisorError, SupervisorState, WorkerGeneration,
    WorkerLauncher,
};

/// Launches workers from a fixed sequence of scenarios (the last one repeats) and counts launches.
struct SequencedLauncher {
    scenarios: Vec<ProcessWorkerLauncher>,
    next: usize,
}

impl SequencedLauncher {
    fn new(scenarios: Vec<ProcessWorkerLauncher>) -> Self {
        Self { scenarios, next: 0 }
    }
}

impl WorkerLauncher for SequencedLauncher {
    type Endpoint = ProcessWorkerEndpoint;

    fn launch(&mut self, generation: WorkerGeneration) -> Result<Self::Endpoint, LaunchError> {
        let index = self.next.min(self.scenarios.len() - 1);
        self.next += 1;
        self.scenarios[index].launch(generation)
    }
}

fn restart_policy(threshold: u32) -> RestartPolicy {
    RestartPolicy {
        initial_backoff_ms: 250,
        max_backoff_ms: 1_000,
        crash_loop_threshold: threshold,
        crash_loop_window_ms: 60_000,
        crash_loop_cooldown_ms: 30_000,
    }
}

#[test]
fn hung_worker_is_recovered_without_restarting_the_app() -> TestResult {
    let launcher = SequencedLauncher::new(vec![
        launcher(&["--script=hang", "--tag=sup-hang"])?,
        launcher(&["--script=ok", "--tag=sup-hang"])?,
    ]);
    let clock = ManualClock::default();
    let mut supervisor =
        DiscoverySupervisor::with_clock(launcher, policy(80), restart_policy(5), clock.clone())?;

    // 1. The first worker hangs in native code: the deadline kills it and the failure is reported.
    assert!(matches!(
        supervisor.refresh(),
        Err(SupervisorError::Discovery(_))
    ));
    assert_eq!(
        count_processes("sup-hang"),
        0,
        "the hung worker must be dead before the failure is visible"
    );
    assert!(matches!(
        supervisor.status().state,
        SupervisorState::Restarting { .. }
    ));

    // 2. Inside the backoff nothing is relaunched.
    assert!(matches!(
        supervisor.refresh(),
        Err(SupervisorError::RestartBackoff { .. })
    ));
    assert_eq!(count_processes("sup-hang"), 0);

    // 3. After the backoff the next refresh replaces the worker and discovery works again.
    clock.advance(250);
    let snapshot = supervisor.refresh()?;
    assert_eq!(snapshot.devices.len(), 1);
    assert_eq!(snapshot.devices[0].read_status, DeviceReadStatus::Ready);
    assert_eq!(
        supervisor.status().worker_generation,
        Some(WorkerGeneration(2))
    );
    assert_eq!(
        count_processes("sup-hang"),
        1,
        "exactly the replacement is running"
    );
    Ok(())
}

#[test]
fn crashing_worker_is_replaced_and_old_handles_stay_dead() -> TestResult {
    let launcher = SequencedLauncher::new(vec![
        launcher(&["--script=ok,crash", "--tag=sup-crash"])?,
        launcher(&["--script=ok", "--tag=sup-crash"])?,
    ]);
    let clock = ManualClock::default();
    let mut supervisor =
        DiscoverySupervisor::with_clock(launcher, policy(500), restart_policy(5), clock.clone())?;

    let first = supervisor.refresh()?;
    let stale_handle = first.devices[0].handle;
    assert!(supervisor.resolve_handle(stale_handle).is_some());

    // The second ListDevices crashes the worker mid-call.
    assert!(supervisor.refresh().is_err());
    assert!(supervisor.resolve_handle(stale_handle).is_none());

    clock.advance(250);
    let second = supervisor.refresh()?;
    assert_eq!(
        supervisor.status().worker_generation,
        Some(WorkerGeneration(2))
    );
    assert_ne!(second.devices[0].handle, stale_handle);
    assert!(supervisor.resolve_handle(stale_handle).is_none());
    assert_eq!(count_processes("sup-crash"), 1);
    Ok(())
}

#[test]
fn crash_looping_worker_stops_being_respawned() -> TestResult {
    let launcher = SequencedLauncher::new(vec![launcher(&["--script=crash", "--tag=sup-loop"])?]);
    let clock = ManualClock::default();
    let mut supervisor =
        DiscoverySupervisor::with_clock(launcher, policy(500), restart_policy(3), clock.clone())?;

    // Three crashes inside the window open the circuit.
    for _ in 0..3 {
        assert!(supervisor.refresh().is_err());
        clock.advance(1_000);
    }
    assert_eq!(supervisor.status().launches, 3);
    assert!(matches!(
        supervisor.status().state,
        SupervisorState::CrashLoop { .. }
    ));

    // A flood of refreshes while open launches nothing.
    for _ in 0..200 {
        assert!(matches!(
            supervisor.refresh(),
            Err(SupervisorError::CrashLoop { .. })
        ));
        clock.advance(50);
    }
    assert_eq!(
        supervisor.status().launches,
        3,
        "an open circuit never spawns"
    );
    assert_eq!(count_processes("sup-loop"), 0);

    // After the cooldown exactly one probe is attempted, and its failure re-opens the circuit.
    clock.advance(30_000);
    assert!(supervisor.refresh().is_err());
    assert_eq!(supervisor.status().launches, 4);
    assert!(matches!(
        supervisor.refresh(),
        Err(SupervisorError::CrashLoop { .. })
    ));
    assert_eq!(supervisor.status().launches, 4);
    Ok(())
}

#[test]
fn worker_that_cannot_start_is_reported_and_retried_with_backoff() -> TestResult {
    // A worker that never completes the handshake: each attempt is killed after the timeout.
    let config = ProcessWorkerConfig {
        handshake_timeout: Duration::from_millis(300),
        ..ProcessWorkerConfig::default()
    };
    let launcher = SequencedLauncher::new(vec![
        launcher_with(&["--raw=silent", "--tag=sup-silent"], config)?,
        launcher(&["--script=ok", "--tag=sup-silent"])?,
    ]);
    let clock = ManualClock::default();
    let mut supervisor =
        DiscoverySupervisor::with_clock(launcher, policy(500), restart_policy(5), clock.clone())?;

    assert!(matches!(
        supervisor.refresh(),
        Err(SupervisorError::Launch(LaunchError::HandshakeTimeout))
    ));
    assert_eq!(
        count_processes("sup-silent"),
        0,
        "a failed launch leaves nothing running"
    );

    clock.advance(250);
    assert_eq!(supervisor.refresh()?.devices.len(), 1);
    assert_eq!(
        supervisor.status().worker_generation,
        Some(WorkerGeneration(2))
    );
    Ok(())
}

#[test]
fn shutdown_leaves_no_worker_behind() -> TestResult {
    let launcher = SequencedLauncher::new(vec![launcher(&["--script=ok", "--tag=sup-shutdown"])?]);
    let mut supervisor = DiscoverySupervisor::with_clock(
        launcher,
        policy(500),
        restart_policy(5),
        ManualClock::default(),
    )?;
    supervisor.refresh()?;
    assert_eq!(count_processes("sup-shutdown"), 1);

    assert_eq!(supervisor.shutdown(), ExecutionQuiescence::Quiescent);
    assert!(wait_until(Duration::from_secs(2), || count_processes(
        "sup-shutdown"
    ) == 0));
    assert!(matches!(
        supervisor.refresh(),
        Err(SupervisorError::Stopped)
    ));
    Ok(())
}

#[test]
fn every_replacement_gets_a_strictly_higher_generation() -> TestResult {
    let launcher = SequencedLauncher::new(vec![
        launcher(&["--script=crash", "--tag=sup-gen"])?,
        launcher(&["--script=crash", "--tag=sup-gen"])?,
        launcher(&["--script=ok", "--tag=sup-gen"])?,
    ]);
    let clock = ManualClock::default();
    let mut supervisor =
        DiscoverySupervisor::with_clock(launcher, policy(500), restart_policy(10), clock.clone())?;

    let mut generations = Vec::new();
    for _ in 0..3 {
        let _ = supervisor.refresh();
        if let Some(generation) = supervisor.status().worker_generation {
            generations.push(generation.0);
        }
        clock.advance(2_000);
    }
    assert_eq!(generations, vec![1, 2, 3]);
    assert!(supervisor.refresh().is_ok());
    Ok(())
}
