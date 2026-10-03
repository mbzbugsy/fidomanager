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
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
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
    verification_display_scope: Option<[u8; 32]>,
}

impl ProcessWorkerLauncher {
    fn display_scope() -> Option<[u8; 32]> {
        let mut scope = [0; 32];
        getrandom::fill(&mut scope).ok()?;
        Some(scope)
    }
    /// Fixed backend-only mode. Unsupported platforms retain discovery and refuse authentication.
    pub fn enable_authentication(mut self) -> Self {
        if cfg!(target_os = "macos") {
            self.fixed_args = &["--authentication"];
        }
        self
    }

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
            verification_display_scope: Self::display_scope(),
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
            verification_display_scope: Self::display_scope(),
        })
    }

    /// Arguments are compile-time constants by construction (`'static`), so nothing a renderer or
    /// user supplies at runtime can reach the worker's command line. The production worker accepts
    /// only its fixed authentication mode; this also supports the test fixture scenario selector.
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
        ProcessWorkerEndpoint::launch(
            &self.executable,
            self.fixed_args,
            generation,
            self.config,
            self.verification_display_scope,
        )
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

/// The part of an OS process the endpoint needs. A trait so the kill/reap contract can be tested
/// against a process that refuses to die, which no real child can be made to do portably.
trait WorkerProcess: Send {
    /// Sends SIGKILL (or the platform equivalent). Failure is not authoritative: reaping is.
    fn kill(&mut self) -> io::Result<()>;

    /// `Ok(true)` only once the exit status has been *collected* (the process is reaped). A
    /// process that was signalled but has not been reaped yet answers `Ok(false)`.
    fn try_reap(&mut self) -> io::Result<bool>;
}

impl WorkerProcess for Child {
    fn kill(&mut self) -> io::Result<()> {
        Child::kill(self)
    }

    fn try_reap(&mut self) -> io::Result<bool> {
        self.try_wait().map(|status| status.is_some())
    }
}

enum ProcessState {
    Running(Box<dyn WorkerProcess>),
    /// Exit status collected: the process no longer exists, so no native call can be running.
    Reaped,
}

/// One child worker process behind the unchanged [`WorkerEndpoint`] contract.
pub struct ProcessWorkerEndpoint {
    process: ProcessState,
    stdin: Option<Box<dyn Write + Send>>,
    events: mpsc::Receiver<ReaderEvent>,
    generation: WorkerGeneration,
    pid: u32,
    config: ProcessWorkerConfig,
    #[cfg(unix)]
    secret: Option<std::os::unix::net::UnixStream>,
    revocation: Option<(std::sync::Arc<std::sync::atomic::AtomicU64>, u64)>,
    verification_display_scope: Option<[u8; 32]>,
}

impl ProcessWorkerEndpoint {
    fn launch(
        executable: &ResolvedWorkerExecutable,
        fixed_args: &'static [&'static str],
        generation: WorkerGeneration,
        config: ProcessWorkerConfig,
        verification_display_scope: Option<[u8; 32]>,
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

        #[cfg(unix)]
        let secret = if fixed_args.first() == Some(&"--authentication") {
            Some(
                fido_platform::process::secret_channel::attach(&mut command)
                    .map_err(|_| LaunchError::SpawnFailed)?,
            )
        } else {
            None
        };

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
            process: ProcessState::Running(Box::new(child)),
            stdin: Some(Box::new(stdin)),
            events,
            generation,
            pid,
            config,
            #[cfg(unix)]
            secret,
            revocation: None,
            verification_display_scope,
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
        let mut hello = ParentHello::new(self.generation, std::process::id());
        hello.verification_display_scope = self.verification_display_scope;
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
        #[cfg(unix)]
        {
            self.secret = None;
        }
        // "Already exited" is not an error here: the wait below is authoritative.
        let _ = child.kill();

        let give_up_at = Instant::now() + self.config.reap_timeout;
        loop {
            match child.try_reap() {
                Ok(true) => return ExecutionQuiescence::Quiescent,
                Ok(false) if Instant::now() < give_up_at => thread::sleep(REAP_POLL_INTERVAL),
                Ok(false) | Err(_) => {
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
        match child.try_reap() {
            Ok(true) => {
                self.process = ProcessState::Reaped;
                self.stdin = None;
                true
            }
            Ok(false) | Err(_) => false,
        }
    }

    #[cfg(test)]
    fn from_parts(
        process: Box<dyn WorkerProcess>,
        stdin: Box<dyn Write + Send>,
        events: mpsc::Receiver<ReaderEvent>,
        generation: WorkerGeneration,
        config: ProcessWorkerConfig,
    ) -> Self {
        Self {
            process: ProcessState::Running(process),
            stdin: Some(stdin),
            events,
            generation,
            pid: 0,
            config,
            #[cfg(unix)]
            secret: None,
            revocation: None,
            verification_display_scope: None,
        }
    }

    pub(crate) fn set_revocation(
        &mut self,
        epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
        expected: u64,
    ) {
        self.revocation = Some((epoch, expected));
    }

    fn revoked(&self) -> bool {
        self.revocation.as_ref().is_some_and(|(epoch, expected)| {
            epoch.load(std::sync::atomic::Ordering::SeqCst) != *expected
        })
    }

    #[cfg(unix)]
    pub(crate) fn submit_secret(
        &mut self,
        binding: fido_auth::AcquisitionBinding,
        request_id: u64,
        pin: fido_auth::PinSecret,
    ) -> Result<(), WorkerEndpointError> {
        if self.revoked() {
            return Err(self.abandon(WorkerEndpointError::Unavailable));
        }
        let secret = self.secret.take().ok_or(WorkerEndpointError::Unavailable)?;
        let result = fido_auth::send_secret(&secret, binding, request_id, pin);
        // Close immediately: EOF seals the one-use frame. No reusable channel or PIN queue.
        drop(secret);
        result.map_err(|_| self.abandon(WorkerEndpointError::TransportFailure))
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
        if self.revoked() {
            return Err(self.abandon(WorkerEndpointError::Unavailable));
        }
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

        let event = loop {
            if self.revoked() {
                return Err(self.abandon(WorkerEndpointError::Unavailable));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self
                .events
                .recv_timeout(remaining.min(Duration::from_millis(25)))
            {
                Err(mpsc::RecvTimeoutError::Timeout) if !remaining.is_zero() => continue,
                event => break event,
            }
        };
        match event {
            Ok(ReaderEvent::Frame(bytes)) => {
                let response = decode_message::<WorkerResponseEnvelope>(&bytes)
                    .map_err(|_| self.abandon(WorkerEndpointError::MalformedFrame))?;
                // Strictly one request is in flight, so the only acceptable frame is the answer
                // to *this* request, speaking *this* protocol, from *this* worker generation. Anything else is a stale or
                // unsolicited frame that raced past the pre-flight check above: a protocol
                // violation, never an answer. (The coordinator validates the remaining fields.)
                if response.protocol_version != WORKER_PROTOCOL_VERSION
                    || response.request_id != request.request_id
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use fido_worker_protocol::{
        WorkerRequestId, WorkerResponse, WorkerResponseEnvelope, WorkerResponseEvidence,
    };

    use super::*;
    use crate::{DiscoveryCoordinator, DiscoveryError, DiscoveryPolicy};

    /// Shared handle on a fake OS process: counts kills and lets a test decide when (and
    /// whether) the OS reports it as reaped.
    #[derive(Clone, Default)]
    struct ProcessControl {
        kills: Arc<AtomicU32>,
        reaped: Arc<AtomicBool>,
    }

    struct FakeProcess(ProcessControl);

    impl WorkerProcess for FakeProcess {
        fn kill(&mut self) -> io::Result<()> {
            self.0.kills.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn try_reap(&mut self) -> io::Result<bool> {
            Ok(self.0.reaped.load(Ordering::SeqCst))
        }
    }

    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedSink {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if let Ok(mut sink) = self.0.lock() {
                sink.extend_from_slice(buffer);
            }
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn quick_config() -> ProcessWorkerConfig {
        ProcessWorkerConfig {
            handshake_timeout: Duration::from_millis(200),
            health_check_budget: Duration::from_millis(200),
            transport_margin: Duration::from_millis(20),
            reap_timeout: Duration::from_millis(30),
        }
    }

    struct Fixture {
        endpoint: ProcessWorkerEndpoint,
        control: ProcessControl,
        worker_events: mpsc::SyncSender<ReaderEvent>,
    }

    fn fixture(generation: u64) -> Fixture {
        let control = ProcessControl::default();
        let (worker_events, events) = mpsc::sync_channel(READER_QUEUE_FRAMES);
        let endpoint = ProcessWorkerEndpoint::from_parts(
            Box::new(FakeProcess(control.clone())),
            Box::new(SharedSink::default()),
            events,
            WorkerGeneration(generation),
            quick_config(),
        );
        Fixture {
            endpoint,
            control,
            worker_events,
        }
    }

    fn list_request(generation: u64, request_id: u64) -> WorkerRequestEnvelope {
        WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: WorkerRequestId(request_id),
            cancellation_id: CancellationId(request_id),
            operation_class: WorkerOperationClass::ReadOnly,
            worker_generation: WorkerGeneration(generation),
            device_generation: None,
            budget_ms: RequestBudgetMs(10),
            request: WorkerRequest::ListDevices,
        }
    }

    fn empty_list_response(generation: u64, request_id: u64) -> WorkerResponseEnvelope {
        WorkerResponseEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: WorkerRequestId(request_id),
            worker_generation: WorkerGeneration(generation),
            device_generation: None,
            evidence: WorkerResponseEvidence {
                execution_quiescence: ExecutionQuiescence::Quiescent,
                mutation_outcome: None,
            },
            response: WorkerResponse::DevicesListed {
                devices: Vec::new(),
            },
        }
    }

    fn frame_of(response: &WorkerResponseEnvelope) -> Result<ReaderEvent, FrameError> {
        Ok(ReaderEvent::Frame(encode_message(response)?))
    }

    /// Runs one exchange while a "worker" thread delivers `reply` shortly *after* the request was
    /// written, which is the only moment a frame counts as an answer (a frame queued earlier is
    /// unsolicited by definition).
    fn exchange_answered_with(
        fixture: &mut Fixture,
        mut request: WorkerRequestEnvelope,
        reply: ReaderEvent,
    ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
        request.budget_ms = RequestBudgetMs(500);
        let sender = fixture.worker_events.clone();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            let _ = sender.send(reply);
        });
        let result = fixture.endpoint.exchange(request);
        let _ = worker.join();
        result
    }

    fn coordinator_policy() -> DiscoveryPolicy {
        DiscoveryPolicy {
            list_devices_budget_ms: 10,
            get_device_info_budget_ms: 10,
            transaction_budget_ms: 100,
        }
    }

    #[test]
    fn timeout_alone_is_not_quiescence() {
        let mut fixture = fixture(1);

        // The worker never answers: the exchange deadline fires and the endpoint kills it, but
        // the (fake) OS never reports the process reaped.
        assert_eq!(
            fixture.endpoint.exchange(list_request(1, 1)).err(),
            Some(WorkerEndpointError::ExchangeDeadlineExceeded)
        );
        assert!(fixture.control.kills.load(Ordering::SeqCst) >= 1);
        assert_eq!(fixture.endpoint.contain(), ExecutionQuiescence::Active);
    }

    #[test]
    fn kill_without_reap_never_proves_quiescence_and_every_retry_kills_again() {
        let mut fixture = fixture(1);

        for attempt in 1..=3u32 {
            assert_eq!(fixture.endpoint.contain(), ExecutionQuiescence::Active);
            assert_eq!(fixture.control.kills.load(Ordering::SeqCst), attempt);
        }

        // A worker that is only signalled, never reaped, must not be usable either.
        assert_eq!(
            fixture.endpoint.exchange(list_request(1, 1)).err(),
            Some(WorkerEndpointError::Unavailable)
        );
    }

    #[test]
    fn kill_plus_reap_proves_quiescence_and_a_reaped_process_is_never_signalled_again() {
        let mut fixture = fixture(1);
        assert_eq!(fixture.endpoint.contain(), ExecutionQuiescence::Active);

        fixture.control.reaped.store(true, Ordering::SeqCst);
        assert_eq!(fixture.endpoint.contain(), ExecutionQuiescence::Quiescent);
        let kills_when_reaped = fixture.control.kills.load(Ordering::SeqCst);

        // Once reaped the pid may be recycled by the OS: no further signal may ever be sent.
        assert_eq!(fixture.endpoint.contain(), ExecutionQuiescence::Quiescent);
        drop(fixture.endpoint);
        assert_eq!(
            fixture.control.kills.load(Ordering::SeqCst),
            kills_when_reaped
        );
    }

    #[test]
    fn replacement_requires_the_old_process_to_be_reaped() -> Result<(), Box<dyn std::error::Error>>
    {
        let old = fixture(1);
        let old_control = old.control.clone();
        let mut coordinator =
            DiscoveryCoordinator::new(old.endpoint, WorkerGeneration(1), coordinator_policy())?;

        // 1. Timeout alone: the worker was killed but the OS never reports it reaped.
        assert_eq!(
            coordinator.refresh().err(),
            Some(DiscoveryError::Endpoint(
                WorkerEndpointError::ExchangeDeadlineExceeded
            ))
        );
        assert!(old_control.kills.load(Ordering::SeqCst) >= 1);

        // 2. Kill without reap does not permit replacement, and nothing about the coordinator
        //    changes: same generation, still quarantined.
        let refused = fixture(2);
        refused.control.reaped.store(true, Ordering::SeqCst);
        assert_eq!(
            coordinator
                .replace_worker(refused.endpoint, WorkerGeneration(2))
                .err(),
            Some(DiscoveryError::PreviousWorkerNotContained)
        );
        assert_eq!(coordinator.worker_generation(), WorkerGeneration(1));
        assert!(coordinator.is_quarantined());

        // 3. Kill plus reap permits replacement.
        old_control.reaped.store(true, Ordering::SeqCst);
        let accepted = fixture(2);
        accepted.control.reaped.store(true, Ordering::SeqCst);
        coordinator.replace_worker(accepted.endpoint, WorkerGeneration(2))?;
        assert_eq!(coordinator.worker_generation(), WorkerGeneration(2));
        assert!(!coordinator.is_quarantined());
        Ok(())
    }

    #[test]
    fn late_response_after_a_timeout_cannot_regain_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture(1);

        assert_eq!(
            fixture.endpoint.exchange(list_request(1, 1)).err(),
            Some(WorkerEndpointError::ExchangeDeadlineExceeded)
        );

        // The (not yet reaped) worker finally answers request 1. That frame is a late response to
        // an abandoned exchange: it must be treated as a violation, never delivered as an answer
        // to a later request, even a request with the same id.
        fixture
            .worker_events
            .try_send(frame_of(&empty_list_response(1, 1))?)
            .map_err(|_| "event queue full")?;
        assert_eq!(
            fixture.endpoint.exchange(list_request(1, 1)).err(),
            Some(WorkerEndpointError::MalformedFrame)
        );
        Ok(())
    }

    #[test]
    fn late_response_cannot_reactivate_a_quarantined_coordinator()
    -> Result<(), Box<dyn std::error::Error>> {
        let Fixture {
            endpoint,
            control,
            worker_events,
        } = fixture(1);
        let mut coordinator =
            DiscoveryCoordinator::new(endpoint, WorkerGeneration(1), coordinator_policy())?;
        assert!(coordinator.refresh().is_err());

        worker_events
            .try_send(frame_of(&empty_list_response(1, 1))?)
            .map_err(|_| "event queue full")?;
        assert_eq!(
            coordinator.refresh().err(),
            Some(DiscoveryError::WorkerQuarantined),
            "a quarantined worker is not consulted again, whatever it sends"
        );

        // Replacement drops the old endpoint and the late frame with it.
        control.reaped.store(true, Ordering::SeqCst);
        let replacement = fixture(2);
        replacement.control.reaped.store(true, Ordering::SeqCst);
        replacement
            .worker_events
            .try_send(frame_of(&empty_list_response(2, 1))?)
            .map_err(|_| "event queue full")?;
        coordinator.replace_worker(replacement.endpoint, WorkerGeneration(2))?;
        assert_eq!(coordinator.worker_generation(), WorkerGeneration(2));
        Ok(())
    }

    type Tamper = fn(&mut WorkerResponseEnvelope);

    #[test]
    fn response_with_another_request_id_generation_or_protocol_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let tampers: [(&str, Tamper); 3] = [
            ("request id", |response| {
                response.request_id = WorkerRequestId(99);
            }),
            ("worker generation", |response| {
                response.worker_generation = WorkerGeneration(2);
            }),
            ("protocol version", |response| {
                response.protocol_version += 1
            }),
        ];

        for (what, tamper) in tampers {
            let mut fixture = fixture(1);
            let mut response = empty_list_response(1, 1);
            tamper(&mut response);

            assert_eq!(
                exchange_answered_with(&mut fixture, list_request(1, 1), frame_of(&response)?)
                    .err(),
                Some(WorkerEndpointError::MalformedFrame),
                "a response with the wrong {what} must be a protocol violation"
            );
            assert!(
                fixture.control.kills.load(Ordering::SeqCst) >= 1,
                "the violating worker must be killed ({what})"
            );
        }
        Ok(())
    }

    #[test]
    fn late_response_to_an_earlier_request_is_not_the_answer_to_the_next_one()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture(1);
        // Request 2 is in flight; the worker answers the *abandoned* request 1 instead.
        assert_eq!(
            exchange_answered_with(
                &mut fixture,
                list_request(1, 2),
                frame_of(&empty_list_response(1, 1))?
            )
            .err(),
            Some(WorkerEndpointError::MalformedFrame)
        );
        Ok(())
    }

    #[test]
    fn frame_queued_before_the_request_is_unsolicited_even_if_it_looks_valid()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture(1);
        fixture
            .worker_events
            .try_send(frame_of(&empty_list_response(1, 5))?)
            .map_err(|_| "event queue full")?;
        assert_eq!(
            fixture.endpoint.exchange(list_request(1, 5)).err(),
            Some(WorkerEndpointError::MalformedFrame)
        );
        Ok(())
    }

    #[test]
    fn exact_correlation_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture(1);
        let response = exchange_answered_with(
            &mut fixture,
            list_request(1, 7),
            frame_of(&empty_list_response(1, 7))?,
        )?;
        assert_eq!(response.request_id, WorkerRequestId(7));
        assert_eq!(fixture.control.kills.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[cfg(unix)]
    mod executable_resolution {
        use std::os::unix::fs::PermissionsExt;

        use super::*;

        struct TempFile {
            directory: PathBuf,
            file: PathBuf,
        }

        impl TempFile {
            fn new(name: &str, mode: u32) -> Result<Self, Box<dyn std::error::Error>> {
                let directory = std::env::temp_dir()
                    .join(format!("fido-service-exe-{}-{name}", std::process::id()));
                fs::create_dir_all(&directory)?;
                let file = directory.join("worker");
                fs::write(&file, b"not a real worker")?;
                fs::set_permissions(&file, fs::Permissions::from_mode(mode))?;
                Ok(Self { directory, file })
            }
        }

        impl Drop for TempFile {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.directory);
            }
        }

        #[test]
        fn regular_executable_that_is_not_world_writable_is_accepted()
        -> Result<(), Box<dyn std::error::Error>> {
            let temp = TempFile::new("ok", 0o755)?;
            let resolved = ResolvedWorkerExecutable::from_absolute_path(temp.file.clone())?;
            assert!(resolved.path().ends_with("worker"));
            // Group-writable is tolerated (user-private groups make 0775 common).
            let group = TempFile::new("group", 0o775)?;
            assert!(ResolvedWorkerExecutable::from_absolute_path(group.file.clone()).is_ok());
            Ok(())
        }

        #[test]
        fn relative_missing_directory_non_executable_and_world_writable_are_rejected()
        -> Result<(), Box<dyn std::error::Error>> {
            assert_eq!(
                ResolvedWorkerExecutable::from_absolute_path(PathBuf::from("fido-worker")).err(),
                Some(LaunchError::ExecutableRejected),
                "a bare name would be resolved through PATH"
            );
            assert_eq!(
                ResolvedWorkerExecutable::from_absolute_path(PathBuf::from(
                    "/definitely/not/here/fido-worker"
                ))
                .err(),
                Some(LaunchError::ExecutableRejected)
            );

            let temp = TempFile::new("dir", 0o755)?;
            assert_eq!(
                ResolvedWorkerExecutable::from_absolute_path(temp.directory.clone()).err(),
                Some(LaunchError::ExecutableRejected)
            );

            let not_executable = TempFile::new("noexec", 0o644)?;
            assert_eq!(
                ResolvedWorkerExecutable::from_absolute_path(not_executable.file.clone()).err(),
                Some(LaunchError::ExecutableRejected)
            );

            let world_writable = TempFile::new("worldw", 0o757)?;
            assert_eq!(
                ResolvedWorkerExecutable::from_absolute_path(world_writable.file.clone()).err(),
                Some(LaunchError::ExecutableRejected)
            );
            Ok(())
        }
    }

    #[test]
    fn file_names_that_could_escape_the_executable_directory_are_rejected() {
        for name in ["", ".", "..", "../fido-worker", "sub/fido-worker", "a\\b"] {
            assert_eq!(
                ResolvedWorkerExecutable::beside_current_exe(name).err(),
                Some(LaunchError::ExecutableRejected),
                "{name:?}"
            );
        }
    }
}
