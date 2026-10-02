//! Handshake and framing hardening against peers that misbehave on purpose.

mod common;

use std::time::Duration;

use common::{
    TestResult, count_processes, describe_processes, launch, launch_error, list_request,
    pid_exists, policy, wait_until,
};
use fido_core::ExecutionQuiescence;
use fido_service::{
    DiscoveryCoordinator, DiscoveryError, LaunchError, ProcessWorkerConfig, WorkerEndpoint,
    WorkerEndpointError, WorkerGeneration,
};

/// Generous on purpose: the first launch of a freshly linked binary can be slow on macOS
/// (Gatekeeper/XProtect), and a short timeout would turn that into a spurious failure. Only the
/// test that *wants* a handshake timeout shortens it.
fn config(handshake_timeout: Duration) -> ProcessWorkerConfig {
    ProcessWorkerConfig {
        handshake_timeout,
        ..ProcessWorkerConfig::default()
    }
}

macro_rules! launch_failure_case {
    ($name:ident, $raw:literal, $tag:literal, $expected:expr) => {
        launch_failure_case!($name, $raw, $tag, $expected, Duration::from_secs(3));
    };
    ($name:ident, $raw:literal, $tag:literal, $expected:expr, $timeout:expr) => {
        #[test]
        fn $name() -> TestResult {
            let error = launch_error(
                &[concat!("--raw=", $raw), concat!("--tag=", $tag)],
                config($timeout),
            )?;
            assert_eq!(error, $expected);
            // A failed launch must never leave a process behind.
            assert!(
                wait_until(Duration::from_secs(3), || count_processes($tag) == 0),
                "a worker from the failed launch is still alive: {}",
                describe_processes($tag)
            );
            Ok(())
        }
    };
}

launch_failure_case!(
    silent_worker_times_out_the_handshake_and_is_killed,
    "silent",
    "hs-silent",
    LaunchError::HandshakeTimeout,
    Duration::from_millis(600)
);
launch_failure_case!(
    worker_that_dies_before_the_handshake_is_a_startup_failure,
    "exit-at-start",
    "hs-start",
    LaunchError::SpawnFailed
);
launch_failure_case!(
    handshake_with_another_protocol_version_is_rejected,
    "bad-version",
    "hs-version",
    LaunchError::HandshakeMismatch
);
launch_failure_case!(
    handshake_with_another_worker_generation_is_rejected,
    "bad-generation",
    "hs-generation",
    LaunchError::HandshakeMismatch
);
launch_failure_case!(
    handshake_from_a_different_process_than_the_spawned_one_is_rejected,
    "bad-pid",
    "hs-pid",
    LaunchError::HandshakeMismatch
);
launch_failure_case!(
    garbage_handshake_frame_is_rejected,
    "garbage-hello",
    "hs-garbage",
    LaunchError::HandshakeMalformed
);
launch_failure_case!(
    handshake_frame_over_its_bound_is_rejected_even_when_it_is_valid_json,
    "oversize-hello",
    "hs-oversize",
    LaunchError::HandshakeMalformed
);
launch_failure_case!(
    worker_that_exits_after_the_handshake_fails_the_health_check,
    "exit-after-hello",
    "hs-exit",
    LaunchError::HealthCheckFailed
);
launch_failure_case!(
    unsolicited_frame_before_the_first_request_fails_the_health_check,
    "unsolicited-after-hello",
    "hs-unsolicited",
    LaunchError::HealthCheckFailed
);

fn assert_contained(pid: u32, endpoint: &mut impl WorkerEndpoint) {
    assert!(
        !pid_exists(pid),
        "the worker must already be dead and reaped when the error is reported"
    );
    assert_eq!(endpoint.contain(), ExecutionQuiescence::Quiescent);
}

#[test]
fn garbage_response_frame_is_a_protocol_violation_that_kills_the_worker() -> TestResult {
    let mut endpoint = launch(&["--raw=garbage-response", "--tag=fr-garbage"], 1)?;
    let pid = endpoint.worker_pid();
    assert_eq!(
        endpoint.exchange(list_request(1, 1, 500)).err(),
        Some(WorkerEndpointError::MalformedFrame)
    );
    assert_contained(pid, &mut endpoint);
    Ok(())
}

#[test]
fn response_frame_over_the_bound_is_rejected_before_allocation_and_kills_the_worker() -> TestResult
{
    let mut endpoint = launch(&["--raw=oversize-response", "--tag=fr-oversize"], 1)?;
    let pid = endpoint.worker_pid();
    assert_eq!(
        endpoint.exchange(list_request(1, 1, 500)).err(),
        Some(WorkerEndpointError::FrameTooLarge)
    );
    assert_contained(pid, &mut endpoint);
    Ok(())
}

#[test]
fn response_truncated_inside_the_length_header_is_a_protocol_violation() -> TestResult {
    let mut endpoint = launch(&["--raw=truncated-header", "--tag=fr-header"], 1)?;
    let pid = endpoint.worker_pid();
    assert_eq!(
        endpoint.exchange(list_request(1, 1, 500)).err(),
        Some(WorkerEndpointError::MalformedFrame)
    );
    assert_contained(pid, &mut endpoint);
    Ok(())
}

macro_rules! correlation_violation_case {
    ($name:ident, $raw:literal, $tag:literal) => {
        #[test]
        fn $name() -> TestResult {
            let mut endpoint = launch(&[concat!("--raw=", $raw), concat!("--tag=", $tag)], 1)?;
            let pid = endpoint.worker_pid();
            assert_eq!(
                endpoint.exchange(list_request(1, 1, 500)).err(),
                Some(WorkerEndpointError::MalformedFrame)
            );
            assert_contained(pid, &mut endpoint);
            Ok(())
        }
    };
}

correlation_violation_case!(
    response_with_the_wrong_request_id_is_a_protocol_violation,
    "wrong-request-id",
    "fr-reqid"
);
correlation_violation_case!(
    response_with_the_wrong_worker_generation_is_a_protocol_violation,
    "wrong-generation-response",
    "fr-gen"
);
correlation_violation_case!(
    response_with_another_protocol_version_is_a_protocol_violation,
    "bad-protocol-response",
    "fr-proto"
);

#[test]
fn well_correlated_response_of_the_wrong_kind_quarantines_and_kills_the_worker() -> TestResult {
    let endpoint = launch(&["--raw=wrong-variant", "--tag=fr-variant"], 1)?;
    let pid = endpoint.worker_pid();
    let mut coordinator = DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), policy(500))?;

    // The endpoint cannot tell a Healthy answer to ListDevices is wrong; the coordinator can.
    assert_eq!(
        coordinator.refresh().err(),
        Some(DiscoveryError::UnexpectedResponse)
    );
    assert!(coordinator.is_quarantined());
    assert!(
        !pid_exists(pid),
        "quarantine must stop the worker, not just stop listening to it"
    );
    Ok(())
}

#[test]
fn response_truncated_by_worker_exit_is_a_protocol_violation() -> TestResult {
    let mut endpoint = launch(&["--raw=truncated-response", "--tag=fr-truncated"], 1)?;
    let pid = endpoint.worker_pid();
    assert_eq!(
        endpoint.exchange(list_request(1, 1, 500)).err(),
        Some(WorkerEndpointError::MalformedFrame)
    );
    assert_contained(pid, &mut endpoint);
    Ok(())
}

#[test]
fn unsolicited_second_frame_poisons_the_next_exchange() -> TestResult {
    let mut endpoint = launch(&["--raw=double-response", "--tag=fr-double"], 1)?;
    let pid = endpoint.worker_pid();

    // The first answer is honest and is delivered.
    assert!(endpoint.exchange(list_request(1, 1, 500)).is_ok());
    // The extra frame must never be mistaken for the answer to the next request.
    assert_eq!(
        endpoint.exchange(list_request(1, 2, 500)).err(),
        Some(WorkerEndpointError::MalformedFrame)
    );
    assert_contained(pid, &mut endpoint);
    Ok(())
}

#[test]
fn worker_that_exits_between_exchanges_is_reported_unavailable() -> TestResult {
    let mut endpoint = launch(&["--raw=exit-after-response", "--tag=fr-exit"], 1)?;
    let pid = endpoint.worker_pid();

    assert!(endpoint.exchange(list_request(1, 1, 500)).is_ok());
    assert!(wait_until(Duration::from_secs(2), || !common::pid_running(
        pid
    )));
    assert_eq!(
        endpoint.exchange(list_request(1, 2, 500)).err(),
        Some(WorkerEndpointError::Unavailable)
    );
    assert_contained(pid, &mut endpoint);
    Ok(())
}

#[test]
fn process_counter_is_not_vacuous() -> TestResult {
    // Positive control for `count_processes`, which the launch-failure cases rely on to prove
    // "nothing was left behind": it must actually see a live worker.
    let endpoint = launch(&["--script=ok", "--tag=counter-control"], 1)?;
    assert_eq!(count_processes("counter-control"), 1);
    drop(endpoint);
    assert_eq!(count_processes("counter-control"), 0);
    Ok(())
}
