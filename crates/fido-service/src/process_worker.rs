//! Production child-process worker endpoint.
//!
//! The worker runs in its own process so a hung or crashing native call can be stopped without
//! taking the trusted authority down. This module owns the whole containment lifecycle:
//!
//! ```text
//!   spawn -> hello handshake -> health check -> bounded exchanges
//!        -> (deadline | crash | protocol violation) -> SIGKILL -> bounded wait/reap
//!        -> proven quiescence -> quarantine -> replacement with a higher generation
//! ```
//!
//! # Kill/reap ordering
//!
//! Every path that abandons a worker goes through [`ProcessWorkerEndpoint::contain`]: the process
//! is killed, then polled with `try_wait` until it is reaped or `reap_timeout` passes. Only a
//! successful reap proves quiescence. If the OS does not hand back the exit status in time (for
//! example a process stuck in an uninterruptible kernel wait) the endpoint reports `Active`, keeps
//! the child handle, and will retry; the coordinator then refuses to replace the worker. A process
//! is never killed after it has been reaped, so a recycled pid can never be signalled.
//!
//! # Executable and argument policy
//!
//! The executable path comes from [`ResolvedWorkerExecutable`], which can only be built from the
//! directory of the running executable (`beside_current_exe`, the shape a Tauri sidecar takes) or
//! from an explicit absolute path for developer tools and tests. It is never read from `PATH`, the
//! environment, or any value the renderer can influence. The worker's argument list is a
//! `&'static [&'static str]`, so no runtime-derived value can reach it, and its environment is
//! cleared.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use fido_core::ExecutionQuiescence;
use fido_worker_protocol::{
    CancellationId, ChildHello, ENDPOINT_CONTROL_REQUEST_ID, FrameError, MAX_WORKER_FRAME_BYTES,
    MAX_WORKER_HANDSHAKE_FRAME_BYTES, MAX_WORKER_REQUEST_FRAME_BYTES, ParentHello, RequestBudgetMs,
    WORKER_PROTOCOL_VERSION, WorkerGeneration, WorkerOperationClass, WorkerRequest,
    WorkerRequestEnvelope, WorkerResponse, WorkerResponseEnvelope, decode_message, encode_message,
    read_frame, write_frame,
};
use thiserror::Error;

use crate::{WorkerEndpoint, WorkerEndpointError, WorkerLauncher};

const REAP_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Frames the worker may have queued toward the service before the reader thread stops reading and
/// lets pipe back-pressure throttle a misbehaving worker.
const READER_QUEUE_FRAMES: usize = 2;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum LaunchError {
    #[error("worker executable was not found or failed the safety checks")]
    ExecutableRejected,
    #[error("worker process could not be started")]
    SpawnFailed,
    #[error("worker did not complete the handshake in time")]
    HandshakeTimeout,
    #[error("worker handshake was malformed")]
    HandshakeMalformed,
    #[error("worker handshake did not match the expected protocol, generation, or process")]
    HandshakeMismatch,
    #[error("worker failed its post-handshake health check")]
    HealthCheckFailed,
    #[error("worker could not be proven stopped after a failed launch")]
    NotContained,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProcessWorkerConfigError {
    #[error("process worker durations must be greater than zero")]
    ZeroDuration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessWorkerConfig {
    /// Time allowed from spawn to a valid `ChildHello` (process start, dynamic loading,
    /// native-library initialisation).
    pub handshake_timeout: Duration,
    /// Native budget of the post-handshake health check.
    pub health_check_budget: Duration,
    /// Time added to a request's native budget before the exchange is declared dead. Transport
    /// time only (framing, scheduling); never available to native code.
    pub transport_margin: Duration,
    /// How long to wait for the OS to report a killed worker as reaped before reporting `Active`.
    pub reap_timeout: Duration,
}

impl ProcessWorkerConfig {
    pub fn validate(self) -> Result<Self, ProcessWorkerConfigError> {
        if self.handshake_timeout.is_zero()
            || self.health_check_budget.is_zero()
            || self.transport_margin.is_zero()
            || self.reap_timeout.is_zero()
        {
            return Err(ProcessWorkerConfigError::ZeroDuration);
        }
        Ok(self)
    }
}

impl Default for ProcessWorkerConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(3),
            health_check_budget: Duration::from_secs(1),
            transport_margin: Duration::from_millis(100),
            reap_timeout: Duration::from_secs(2),
        }
    }
}

/// A worker executable that passed resolution and safety checks.
#[derive(Debug, Clone)]
pub struct ResolvedWorkerExecutable {
    path: PathBuf,
}

impl ResolvedWorkerExecutable {
    /// Resolves `file_name` in the directory of the running executable. This is where a Tauri
    /// sidecar is placed (`Contents/MacOS` on macOS) and where Cargo puts a sibling binary in a
    /// development build. `file_name` is `'static` so it cannot be a runtime value.
    pub fn beside_current_exe(file_name: &'static str) -> Result<Self, LaunchError> {
        if file_name.is_empty()
            || file_name == "."
            || file_name == ".."
            || file_name.contains(['/', '\\'])
        {
            return Err(LaunchError::ExecutableRejected);
        }
        let current = std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .map_err(|_| LaunchError::ExecutableRejected)?;
        let directory = current.parent().ok_or(LaunchError::ExecutableRejected)?;
        Self::checked(directory.join(file_name))
    }

    /// Explicit absolute path, for developer tools and tests. Application code uses
    /// [`Self::beside_current_exe`].
    pub fn from_absolute_path(path: PathBuf) -> Result<Self, LaunchError> {
        if !path.is_absolute() {
            return Err(LaunchError::ExecutableRejected);
        }
        Self::checked(path)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn checked(path: PathBuf) -> Result<Self, LaunchError> {
        let path = path
            .canonicalize()
            .map_err(|_| LaunchError::ExecutableRejected)?;
        let metadata = fs::metadata(&path).map_err(|_| LaunchError::ExecutableRejected)?;
        if !metadata.is_file() {
            return Err(LaunchError::ExecutableRejected);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            // Must be executable and must not be world-writable. This is basic tamper hygiene, not
            // a substitute for code signing. (Group-writable is tolerated: a user-private group is
            // the default on many Linux setups, so build outputs are routinely 0775.)
            if mode & 0o111 == 0 || mode & 0o002 != 0 {
                return Err(LaunchError::ExecutableRejected);
            }
        }

        Ok(Self { path })
    }
}

/// Spawns [`ProcessWorkerEndpoint`]s for the supervisor.
#[derive(Debug, Clone)]
pub struct ProcessWorkerLauncher {
    executable: ResolvedWorkerExecutable,
    fixed_args: &'static [&'static str],
    config: ProcessWorkerConfig,
}

impl ProcessWorkerLauncher {
    pub const DEFAULT_WORKER_FILE_NAME: &'static str = if cfg!(windows) {
        "fido-worker.exe"
    } else {
        "fido-worker"
    };

    /// The production launcher: the worker binary next to the running application.
    pub fn beside_current_exe() -> Result<Self, LaunchError> {
        let executable =
            ResolvedWorkerExecutable::beside_current_exe(Self::DEFAULT_WORKER_FILE_NAME)?;
        Ok(Self {
            executable,
            fixed_args: &[],
            config: ProcessWorkerConfig::default(),
        })
    }

    pub fn new(
        executable: ResolvedWorkerExecutable,
        config: ProcessWorkerConfig,
    ) -> Result<Self, ProcessWorkerConfigError> {
        Ok(Self {
            executable,
            fixed_args: &[],
            config: config.validate()?,
        })
    }

    /// Arguments are compile-time constants by construction (`'static`), so nothing a renderer or
    /// user supplies at runtime can reach the worker's command line. The production worker takes
    /// none; this exists for the test fixture's scenario selector.
    pub fn with_fixed_args(mut self, args: &'static [&'static str]) -> Self {
        self.fixed_args = args;
        self
    }

    pub fn config(&self) -> ProcessWorkerConfig {
        self.config
    }
}

impl WorkerLauncher for ProcessWorkerLauncher {
    type Endpoint = ProcessWorkerEndpoint;

    fn launch(&mut self, generation: WorkerGeneration) -> Result<Self::Endpoint, LaunchError> {
        ProcessWorkerEndpoint::launch(&self.executable, self.fixed_args, generation, self.config)
    }
}

#[derive(Debug, Clone, Copy)]
enum StreamFailure {
    Closed,
    Truncated,
    TooLarge,
    Io,
}

impl StreamFailure {
    fn from_frame_error(error: &FrameError) -> Self {
        match error {
            FrameError::Eof => Self::Closed,
            FrameError::Truncated | FrameError::Empty | FrameError::Malformed => Self::Truncated,
            FrameError::TooLarge => Self::TooLarge,
            FrameError::Io(_) => Self::Io,
        }
    }

    fn endpoint_error(self) -> WorkerEndpointError {
        match self {
            Self::Closed | Self::Io => WorkerEndpointError::Unavailable,
            Self::Truncated => WorkerEndpointError::MalformedFrame,
            Self::TooLarge => WorkerEndpointError::FrameTooLarge,
        }
    }
}

enum ReaderEvent {
    Frame(Vec<u8>),
    Failed(StreamFailure),
}

enum ProcessState {
    Running(Child),
    /// Exit status collected: the process no longer exists, so no native call can be running.
    Reaped,
}

/// One child worker process behind the unchanged [`WorkerEndpoint`] contract.
pub struct ProcessWorkerEndpoint {
    process: ProcessState,
    stdin: Option<ChildStdin>,
    events: mpsc::Receiver<ReaderEvent>,
    generation: WorkerGeneration,
    pid: u32,
    config: ProcessWorkerConfig,
}

impl ProcessWorkerEndpoint {
    fn launch(
        executable: &ResolvedWorkerExecutable,
        fixed_args: &'static [&'static str],
        generation: WorkerGeneration,
        config: ProcessWorkerConfig,
    ) -> Result<Self, LaunchError> {
        let mut command = Command::new(executable.path());
        command
            .args(fixed_args)
            // Nothing from the service's environment reaches native code.
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(if cfg!(debug_assertions) {
                Stdio::inherit()
            } else {
                Stdio::null()
            });

        let mut child = command.spawn().map_err(|_| LaunchError::SpawnFailed)?;
        let pid = child.id();
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            // Unreachable with piped stdio, but never leave a spawned process behind.
            let _ = child.kill();
            let _ = child.wait();
            return Err(LaunchError::SpawnFailed);
        };

        let (events_tx, events) = mpsc::sync_channel(READER_QUEUE_FRAMES);
        let mut endpoint = Self {
            process: ProcessState::Running(child),
            stdin: Some(stdin),
            events,
            generation,
            pid,
            config,
        };
        // From here on every early return drops or explicitly fails `endpoint`, which kills and
        // reaps the child: a failed launch never leaves a process behind.
        if spawn_reader(stdout, events_tx).is_err() {
            return Err(endpoint.fail_launch(LaunchError::SpawnFailed));
        }

        match endpoint.handshake() {
            Ok(()) => Ok(endpoint),
            Err(error) => Err(endpoint.fail_launch(error)),
        }
    }

    fn fail_launch(&mut self, error: LaunchError) -> LaunchError {
        if self.contain() == ExecutionQuiescence::Quiescent {
            error
        } else {
            LaunchError::NotContained
        }
    }

    fn handshake(&mut self) -> Result<(), LaunchError> {
        let hello = ParentHello::new(self.generation, std::process::id());
        let encoded = encode_message(&hello).map_err(|_| LaunchError::HandshakeMalformed)?;
        let stdin = self.stdin.as_mut().ok_or(LaunchError::SpawnFailed)?;
        // A worker that already died (for example a dynamic-loader failure) breaks the pipe here.
        write_frame(stdin, &encoded, MAX_WORKER_HANDSHAKE_FRAME_BYTES)
            .map_err(|_| LaunchError::SpawnFailed)?;

        let reply: ChildHello = match self.events.recv_timeout(self.config.handshake_timeout) {
            Ok(ReaderEvent::Frame(bytes)) => {
                if bytes.len() > MAX_WORKER_HANDSHAKE_FRAME_BYTES {
                    return Err(LaunchError::HandshakeMalformed);
                }
                decode_message(&bytes).map_err(|_| LaunchError::HandshakeMalformed)?
            }
            Ok(ReaderEvent::Failed(StreamFailure::Closed | StreamFailure::Io))
            | Err(mpsc::RecvTimeoutError::Disconnected) => return Err(LaunchError::SpawnFailed),
            Ok(ReaderEvent::Failed(_)) => return Err(LaunchError::HandshakeMalformed),
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(LaunchError::HandshakeTimeout),
        };
        hello
            .validate_reply(&reply, self.pid)
            .map_err(|_| LaunchError::HandshakeMismatch)?;

        self.health_check()
    }

    /// Proves the request loop (not just process start) works before the worker is handed out.
    fn health_check(&mut self) -> Result<(), LaunchError> {
        let budget_ms = u64::try_from(self.config.health_check_budget.as_millis())
            .map_err(|_| LaunchError::HealthCheckFailed)?;
        let request = WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: ENDPOINT_CONTROL_REQUEST_ID,
            cancellation_id: CancellationId(0),
            operation_class: WorkerOperationClass::Control,
            worker_generation: self.generation,
            device_generation: None,
            budget_ms: RequestBudgetMs(budget_ms),
            request: WorkerRequest::HealthCheck,
        };
        let response = self
            .exchange(request)
            .map_err(|_| LaunchError::HealthCheckFailed)?;
        let healthy = response.request_id == ENDPOINT_CONTROL_REQUEST_ID
            && response.worker_generation == self.generation
            && matches!(response.response, WorkerResponse::Healthy);
        if healthy {
            Ok(())
        } else {
            Err(LaunchError::HealthCheckFailed)
        }
    }

    /// Operating-system process id of the worker, for diagnostics and tests only. The endpoint
    /// never signals a pid it did not obtain from the spawn itself.
    pub fn worker_pid(&self) -> u32 {
        self.pid
    }

    pub fn generation(&self) -> WorkerGeneration {
        self.generation
    }

    /// Kills the worker, then waits (bounded) for the OS to reap it.
    ///
    /// `Quiescent` is returned only once the exit status has been collected.
    fn terminate(&mut self) -> ExecutionQuiescence {
        let ProcessState::Running(mut child) =
            std::mem::replace(&mut self.process, ProcessState::Reaped)
        else {
            return ExecutionQuiescence::Quiescent;
        };

        // Closing stdin lets an idle worker leave on its own, but the kill below never depends on
        // the worker cooperating.
        self.stdin = None;
        // "Already exited" is not an error here: the wait below is authoritative.
        let _ = child.kill();

        let give_up_at = Instant::now() + self.config.reap_timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_exit_status)) => return ExecutionQuiescence::Quiescent,
                Ok(None) if Instant::now() < give_up_at => thread::sleep(REAP_POLL_INTERVAL),
                Ok(None) | Err(_) => {
                    // Not proven stopped. Keep the handle so containment can be retried.
                    self.process = ProcessState::Running(child);
                    return ExecutionQuiescence::Active;
                }
            }
        }
    }

    /// Whether the worker has already exited on its own. Reaps it if so.
    fn has_exited(&mut self) -> bool {
        let ProcessState::Running(child) = &mut self.process else {
            return true;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                self.process = ProcessState::Reaped;
                self.stdin = None;
                true
            }
            Ok(None) | Err(_) => false,
        }
    }

    fn abandon(&mut self, error: WorkerEndpointError) -> WorkerEndpointError {
        // Terminate before reporting: by the time the caller sees the failure the worker is
        // already stopped (or the endpoint holds an honest `Active`).
        let _ = self.terminate();
        error
    }
}

impl Drop for ProcessWorkerEndpoint {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

impl WorkerEndpoint for ProcessWorkerEndpoint {
    fn exchange(
        &mut self,
        request: WorkerRequestEnvelope,
    ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
        if matches!(self.process, ProcessState::Reaped) {
            return Err(WorkerEndpointError::Unavailable);
        }

        // Anything already queued is a death notice or an unsolicited frame; neither may be
        // carried into a new exchange.
        match self.events.try_recv() {
            Ok(ReaderEvent::Frame(_)) => {
                return Err(self.abandon(WorkerEndpointError::MalformedFrame));
            }
            Ok(ReaderEvent::Failed(failure)) => {
                return Err(self.abandon(failure.endpoint_error()));
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(self.abandon(WorkerEndpointError::Unavailable));
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if self.has_exited() {
            return Err(WorkerEndpointError::Unavailable);
        }

        let native_budget = Duration::from_millis(request.budget_ms.0);
        let wait = native_budget
            .checked_add(self.config.transport_margin)
            .ok_or(WorkerEndpointError::TransportFailure)?;
        let deadline = Instant::now()
            .checked_add(wait)
            .ok_or(WorkerEndpointError::TransportFailure)?;

        let encoded =
            encode_message(&request).map_err(|_| WorkerEndpointError::TransportFailure)?;
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(self.abandon(WorkerEndpointError::Unavailable));
        };
        match write_frame(stdin, &encoded, MAX_WORKER_REQUEST_FRAME_BYTES) {
            Ok(()) => {}
            // The service built a request the worker is required to reject: a service bug, not a
            // worker fault. Nothing was sent.
            Err(FrameError::TooLarge | FrameError::Empty) => {
                return Err(WorkerEndpointError::FrameTooLarge);
            }
            Err(_) => return Err(self.abandon(WorkerEndpointError::Unavailable)),
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.events.recv_timeout(remaining) {
            Ok(ReaderEvent::Frame(bytes)) => {
                let response = decode_message::<WorkerResponseEnvelope>(&bytes)
                    .map_err(|_| self.abandon(WorkerEndpointError::MalformedFrame))?;
                // Strictly one request is in flight, so the only acceptable frame is the answer
                // to *this* request from *this* worker generation. Anything else is a stale or
                // unsolicited frame that raced past the pre-flight check above: a protocol
                // violation, never an answer. (The coordinator validates the remaining fields.)
                if response.request_id != request.request_id
                    || response.worker_generation != request.worker_generation
                {
                    return Err(self.abandon(WorkerEndpointError::MalformedFrame));
                }
                Ok(response)
            }
            Ok(ReaderEvent::Failed(failure)) => Err(self.abandon(failure.endpoint_error())),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(self.abandon(WorkerEndpointError::Unavailable))
            }
            // The decisive difference from a thread worker: the service can act on a timeout.
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(self.abandon(WorkerEndpointError::ExchangeDeadlineExceeded))
            }
        }
    }

    fn transport_margin_ms(&self) -> u64 {
        u64::try_from(self.config.transport_margin.as_millis()).unwrap_or(u64::MAX)
    }

    fn contain(&mut self) -> ExecutionQuiescence {
        self.terminate()
    }
}

fn spawn_reader(mut stdout: ChildStdout, events: mpsc::SyncSender<ReaderEvent>) -> io::Result<()> {
    thread::Builder::new()
        .name("fido-worker-reader".to_owned())
        .spawn(move || {
            loop {
                let event = match read_frame(&mut stdout, MAX_WORKER_FRAME_BYTES) {
                    Ok(bytes) => ReaderEvent::Frame(bytes),
                    Err(error) => ReaderEvent::Failed(StreamFailure::from_frame_error(&error)),
                };
                let terminal = matches!(event, ReaderEvent::Failed(_));
                // `send` blocks when the queue is full, which stops this thread reading and lets
                // pipe back-pressure throttle a worker that floods frames. It errors, ending the
                // thread, once the endpoint (the receiver) is gone.
                if events.send(event).is_err() || terminal {
                    break;
                }
            }
        })
        .map(|_| ())
}
