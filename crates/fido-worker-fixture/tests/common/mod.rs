//! Shared helpers for the process-containment tests.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fido_service::MonotonicMillis;
use fido_service::{
    DiscoveryPolicy, LaunchError, MonotonicClock, ProcessWorkerConfig, ProcessWorkerEndpoint,
    ProcessWorkerLauncher, ResolvedWorkerExecutable, WorkerGeneration, WorkerLauncher,
};
use fido_worker_protocol::{
    CancellationId, RequestBudgetMs, WORKER_PROTOCOL_VERSION, WorkerOperationClass, WorkerRequest,
    WorkerRequestEnvelope, WorkerRequestId,
};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

pub fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fido-worker-fixture"))
}

pub fn launcher(
    args: &'static [&'static str],
) -> Result<ProcessWorkerLauncher, Box<dyn std::error::Error>> {
    launcher_with(args, ProcessWorkerConfig::default())
}

pub fn launcher_with(
    args: &'static [&'static str],
    config: ProcessWorkerConfig,
) -> Result<ProcessWorkerLauncher, Box<dyn std::error::Error>> {
    let executable = ResolvedWorkerExecutable::from_absolute_path(fixture_path())?;
    Ok(ProcessWorkerLauncher::new(executable, config)?.with_fixed_args(args))
}

pub fn launch(
    args: &'static [&'static str],
    generation: u64,
) -> Result<ProcessWorkerEndpoint, Box<dyn std::error::Error>> {
    Ok(launcher(args)?.launch(WorkerGeneration(generation))?)
}

pub fn launch_error(
    args: &'static [&'static str],
    config: ProcessWorkerConfig,
) -> Result<LaunchError, Box<dyn std::error::Error>> {
    match launcher_with(args, config)?.launch(WorkerGeneration(1)) {
        Ok(_) => Err("launch unexpectedly succeeded".into()),
        Err(error) => Ok(error),
    }
}

/// Policy with every budget equal to `budget_ms` and room for several exchanges.
pub fn policy(budget_ms: u64) -> DiscoveryPolicy {
    DiscoveryPolicy {
        list_devices_budget_ms: budget_ms,
        get_device_info_budget_ms: budget_ms,
        transaction_budget_ms: budget_ms * 4,
    }
}

pub fn list_request(generation: u64, request_id: u64, budget_ms: u64) -> WorkerRequestEnvelope {
    WorkerRequestEnvelope {
        protocol_version: WORKER_PROTOCOL_VERSION,
        request_id: WorkerRequestId(request_id),
        cancellation_id: CancellationId(request_id),
        operation_class: WorkerOperationClass::ReadOnly,
        worker_generation: WorkerGeneration(generation),
        device_generation: None,
        budget_ms: RequestBudgetMs(budget_ms),
        request: WorkerRequest::ListDevices,
    }
}

/// Does the OS still know this pid at all? A killed-but-unreaped process (zombie) still answers
/// `kill -0`, so `false` proves the process was *reaped*, not merely stopped.
pub fn pid_exists(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Is the process still *executing* (not gone, not a zombie)? Used for orphans, which are reaped
/// by init rather than by the test.
pub fn pid_running(pid: u32) -> bool {
    let output = Command::new("ps")
        .args(["-o", "stat=", "-p"])
        .arg(pid.to_string())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let state = String::from_utf8_lossy(&output.stdout);
            let state = state.trim();
            !state.is_empty() && !state.starts_with('Z')
        }
        _ => false,
    }
}

/// Command lines of live fixture-worker processes that contain `needle`.
///
/// Matching on the fixture's own executable path (not just the needle) keeps this from matching
/// an unrelated process, such as a shell whose command line merely mentions the tag.
pub fn fixture_processes(needle: &str) -> Vec<String> {
    let fixture = fixture_path().to_string_lossy().into_owned();
    let output = Command::new("ps")
        .args(["-axwwo", "pid=,command="])
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let (_pid, command) = line.trim_start().split_once(char::is_whitespace)?;
            let command = command.trim_start();
            (command.starts_with(&fixture) && command.contains(needle)).then(|| command.to_owned())
        })
        .collect()
}

pub fn count_processes(needle: &str) -> usize {
    fixture_processes(needle).len()
}

pub fn describe_processes(needle: &str) -> String {
    fixture_processes(needle).join("\n")
}

pub fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Manually advanced clock for supervisor policy; real child processes still run in real time.
#[derive(Debug, Clone, Default)]
pub struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    pub fn advance(&self, millis: u64) {
        self.0.fetch_add(millis, Ordering::SeqCst);
    }
}

impl MonotonicClock for ManualClock {
    fn now(&self) -> MonotonicMillis {
        MonotonicMillis::from_millis(self.0.load(Ordering::SeqCst))
    }
}
