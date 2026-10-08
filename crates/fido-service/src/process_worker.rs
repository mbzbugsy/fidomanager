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
//!
//! # Per-spawn worker authenticity (ADR-017 §5.3)
//!
//! Every `launch()` (first start, replacement after a crash or timeout, breaker probe) runs, in
//! this order, with nothing cached between spawns:
//!
//! ```text
//!   1-2  re-resolve the canonical packaged worker; regular file, executable, not world-writable
//!        (release: expected .app/Contents/MacOS layout, no symlink, not group-writable)
//!   3    static validation against the exact requirement + EXPECTED (release builds)
//!   4    spawn exactly that path; the endpoint takes exclusive ownership of the Child
//!   5    dynamic validation of THAT child by pid while it is unreaped (release builds)
//!   6    only then: ParentHello, handshake timeout, ChildHello (incl. build_id), health check
//! ```
//!
//! Any identity failure latches the terminal authenticity state *before* containment, never
//! sends anything to the child, and never falls back to another executable or a weaker mode.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use fido_core::ExecutionQuiescence;
use fido_worker_protocol::{
    CancellationId, ChildHello, ENDPOINT_CONTROL_REQUEST_ID, FrameError, HandshakeError,
    MAX_WORKER_FRAME_BYTES, MAX_WORKER_HANDSHAKE_FRAME_BYTES, MAX_WORKER_REQUEST_FRAME_BYTES,
    ParentHello, RequestBudgetMs, WORKER_PROTOCOL_VERSION, WorkerGeneration, WorkerOperationClass,
    WorkerRequest, WorkerRequestEnvelope, WorkerResponse, WorkerResponseEnvelope, decode_message,
    encode_message, read_frame, write_frame,
};
use thiserror::Error;

use crate::worker_authenticity::{
    ChildVerification, IdentityLatch, WorkerAuthenticity, WorkerIdentityCheck,
};
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
    /// ADR-017 §5.7: the worker failed its code identity, release identity or build identity
    /// checks. Terminal for the app session. `quiescence` records whether the rejected child (if
    /// one was spawned) was proven stopped; the rejection itself stays latched either way.
    #[error("worker identity could not be verified")]
    WorkerIdentityRejected { quiescence: ExecutionQuiescence },
}

impl LaunchError {
    /// Integrity failures that must never be retried in this app session (ADR-017 §5.7).
    pub const fn is_terminal_integrity_failure(self) -> bool {
        matches!(
            self,
            Self::WorkerIdentityRejected { .. } | Self::ExecutableRejected
        )
    }
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

/// A worker executable that passed resolution and safety checks. The checks are repeated on every
/// launch ([`Self::revalidate`]); construction-time success alone never authorizes a spawn.
#[derive(Debug, Clone)]
pub struct ResolvedWorkerExecutable {
    path: PathBuf,
    origin: ExecutableOrigin,
}

#[derive(Debug, Clone)]
enum ExecutableOrigin {
    BesideCurrentExe(&'static str),
    Absolute(PathBuf),
}

fn current_exe_directory() -> Result<PathBuf, LaunchError> {
    let current = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|_| LaunchError::ExecutableRejected)?;
    current
        .parent()
        .map(Path::to_path_buf)
        .ok_or(LaunchError::ExecutableRejected)
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
        let directory = current_exe_directory()?;
        Ok(Self {
            path: Self::checked(&directory.join(file_name), false)?,
            origin: ExecutableOrigin::BesideCurrentExe(file_name),
        })
    }

    /// Explicit absolute path, for developer tools and tests. Application code uses
    /// [`Self::beside_current_exe`].
    pub fn from_absolute_path(path: PathBuf) -> Result<Self, LaunchError> {
        if !path.is_absolute() {
            return Err(LaunchError::ExecutableRejected);
        }
        Ok(Self {
            path: Self::checked(&path, false)?,
            origin: ExecutableOrigin::Absolute(path),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-resolves and re-checks the executable for one spawn (ADR-017 §5.3 steps 1–2) and returns
    /// the exact canonical path to execute. The resolved location must not have moved since
    /// construction. With `release_layout` the worker must be the packaged
    /// `<App>.app/Contents/MacOS/<name>` beside the canonical main executable, must not be a
    /// symlink and must not be group-writable.
    pub(crate) fn revalidate(&self, release_layout: bool) -> Result<PathBuf, LaunchError> {
        let requested = match &self.origin {
            ExecutableOrigin::BesideCurrentExe(file_name) => {
                let directory = current_exe_directory()?;
                if release_layout {
                    let in_bundle = directory.file_name() == Some("MacOS".as_ref())
                        && directory.parent().is_some_and(|contents| {
                            contents.file_name() == Some("Contents".as_ref())
                        });
                    if !in_bundle {
                        return Err(LaunchError::ExecutableRejected);
                    }
                }
                directory.join(file_name)
            }
            // Release enforcement accepts only the packaged worker beside the application.
            ExecutableOrigin::Absolute(_) if release_layout => {
                return Err(LaunchError::ExecutableRejected);
            }
            ExecutableOrigin::Absolute(path) => path.clone(),
        };
        if release_layout {
            let link =
                fs::symlink_metadata(&requested).map_err(|_| LaunchError::ExecutableRejected)?;
            if !link.file_type().is_file() {
                return Err(LaunchError::ExecutableRejected);
            }
        }
        let canonical = Self::checked(&requested, release_layout)?;
        if canonical != self.path || (release_layout && canonical.parent() != requested.parent()) {
            return Err(LaunchError::ExecutableRejected);
        }
        Ok(canonical)
    }

    fn checked(path: &Path, strict: bool) -> Result<PathBuf, LaunchError> {
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
            // a substitute for code signing. (Group-writable is tolerated in development: a
            // user-private group is the default on many Linux setups, so build outputs are
            // routinely 0775. Release enforcement refuses it.)
            let forbidden = if strict { 0o022 } else { 0o002 };
            if mode & 0o111 == 0 || mode & forbidden != 0 {
                return Err(LaunchError::ExecutableRejected);
            }
        }
        #[cfg(not(unix))]
        let _ = strict;

        Ok(path)
    }
}

/// Spawns [`ProcessWorkerEndpoint`]s for the supervisor.
#[derive(Debug, Clone)]
pub struct ProcessWorkerLauncher {
    /// `None` only when release startup authentication failed before a worker path existed; such
    /// a launcher can never spawn.
    executable: Option<ResolvedWorkerExecutable>,
    fixed_args: &'static [&'static str],
    config: ProcessWorkerConfig,
    verification_display_scope: Option<[u8; 32]>,
    authenticity: WorkerAuthenticity,
    identity_latch: IdentityLatch,
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

    /// The production launcher: the worker binary next to the running application. This is the
    /// single construction site of the release worker-authenticity mode (ADR-017 §5.6).
    ///
    /// Development and ad-hoc builds fail with `ExecutableRejected` if the worker is missing, as
    /// before. The `macos-release-signing` flavor always returns a launcher: when release startup
    /// authentication (S1–S8) fails, the launcher is permanently unable to spawn and every launch
    /// reports the terminal `WorkerIdentityRejected`, so the application runs without FIDO
    /// functionality and shows the integrity error. It never downgrades to development behavior.
    pub fn beside_current_exe() -> Result<Self, LaunchError> {
        #[cfg(feature = "macos-release-signing")]
        {
            let authenticity = crate::worker_authenticity::release_startup();
            let executable =
                ResolvedWorkerExecutable::beside_current_exe(Self::DEFAULT_WORKER_FILE_NAME).ok();
            let authenticity = match (&executable, authenticity) {
                (Some(_), authenticity) => authenticity,
                (None, _) => WorkerAuthenticity::StartupRejected,
            };
            Ok(Self::with_authenticity(
                executable,
                ProcessWorkerConfig::default(),
                authenticity,
            ))
        }
        #[cfg(not(feature = "macos-release-signing"))]
        {
            let executable =
                ResolvedWorkerExecutable::beside_current_exe(Self::DEFAULT_WORKER_FILE_NAME)?;
            Ok(Self::with_authenticity(
                Some(executable),
                ProcessWorkerConfig::default(),
                WorkerAuthenticity::UnsignedDevelopment,
            ))
        }
    }

    /// Developer tools and tests: an explicit executable in development (non-enforcing) mode.
    /// The application itself may use only [`Self::beside_current_exe`] (renderer-boundary check).
    pub fn new(
        executable: ResolvedWorkerExecutable,
        config: ProcessWorkerConfig,
    ) -> Result<Self, ProcessWorkerConfigError> {
        Ok(Self::with_authenticity(
            Some(executable),
            config.validate()?,
            WorkerAuthenticity::UnsignedDevelopment,
        ))
    }

    fn with_authenticity(
        executable: Option<ResolvedWorkerExecutable>,
        config: ProcessWorkerConfig,
        authenticity: WorkerAuthenticity,
    ) -> Self {
        Self {
            executable,
            fixed_args: &[],
            config,
            verification_display_scope: Self::display_scope(),
            authenticity,
            identity_latch: IdentityLatch::default(),
        }
    }

    /// TEST-ONLY: a launcher whose release startup authentication failed.
    #[cfg(test)]
    pub(crate) fn startup_rejected_for_test() -> Self {
        Self::with_authenticity(
            None,
            ProcessWorkerConfig::default(),
            WorkerAuthenticity::StartupRejected,
        )
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
        // A latched rejection is terminal: nothing is resolved, validated or spawned again.
        if self.identity_latch.is_set() {
            return Err(LaunchError::WorkerIdentityRejected {
                quiescence: ExecutionQuiescence::Quiescent,
            });
        }
        let Some(executable) = self.executable.as_ref() else {
            self.identity_latch.set();
            return Err(LaunchError::WorkerIdentityRejected {
                quiescence: ExecutionQuiescence::Quiescent,
            });
        };
        ProcessWorkerEndpoint::launch(
            executable,
            &self.authenticity,
            &self.identity_latch,
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

    /// Whether the process has exited, **without** collecting its exit status, so its pid stays
    /// reserved for it. Used only while its identity is being validated by pid.
    fn exited_without_reaping(&mut self) -> io::Result<bool>;
}

impl WorkerProcess for Child {
    fn kill(&mut self) -> io::Result<()> {
        Child::kill(self)
    }

    fn try_reap(&mut self) -> io::Result<bool> {
        self.try_wait().map(|status| status.is_some())
    }

    fn exited_without_reaping(&mut self) -> io::Result<bool> {
        #[cfg(unix)]
        {
            fido_platform::process::child_exited_unreaped(self.id())
        }
        #[cfg(not(unix))]
        {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }
}

/// Why a handshake failed: an ordinary launch failure, or a build-identity integrity failure.
enum HandshakeFailure {
    Launch(LaunchError),
    Identity,
}

impl From<LaunchError> for HandshakeFailure {
    fn from(error: LaunchError) -> Self {
        Self::Launch(error)
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
    #[allow(clippy::too_many_arguments)]
    fn launch(
        executable: &ResolvedWorkerExecutable,
        authenticity: &dyn WorkerIdentityCheck,
        latch: &IdentityLatch,
        fixed_args: &'static [&'static str],
        generation: WorkerGeneration,
        config: ProcessWorkerConfig,
        verification_display_scope: Option<[u8; 32]>,
    ) -> Result<Self, LaunchError> {
        // Steps 1-2, repeated on every spawn.
        let path = executable.revalidate(authenticity.enforces_release_layout())?;
        // Step 3: static validation of exactly this file, before exec. Nothing was spawned, so
        // the rejection is latched and trivially contained.
        if authenticity.verify_before_spawn(&path).is_err() {
            latch.set();
            return Err(LaunchError::WorkerIdentityRejected {
                quiescence: ExecutionQuiescence::Quiescent,
            });
        }

        let mut command = Command::new(&path);
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
        let endpoint = Self {
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
        endpoint.establish(authenticity, latch, move || spawn_reader(stdout, events_tx))
    }

    /// Everything after the spawn, in the ADR-017 §5.3 order: dynamic identity of the running
    /// child (step 5) strictly before the stdout reader starts and before the first byte —
    /// `ParentHello` — is written; then the handshake (whose timeout starts at that write), the
    /// build-identity check (step 7) and the health check.
    ///
    /// # PID ownership invariant
    ///
    /// Dynamic validation names the child by pid. That is sound only because this endpoint holds
    /// the one `Child` handle and has not reaped it: until its exit status is collected the kernel
    /// keeps the process (at worst as a zombie) and cannot hand the pid to another process.
    /// Nothing else waits on this child — there is no global reaper and no concurrent
    /// `try_wait`/`wait` task — and the only paths that reap are `terminate`/`has_exited` on this
    /// endpoint, none of which runs before step 5 completes. The exit check during validation uses
    /// `waitid(WNOWAIT)`, which does not reap. A child that exited before or during validation is
    /// rejected.
    fn establish(
        mut self,
        authenticity: &dyn WorkerIdentityCheck,
        latch: &IdentityLatch,
        start_reader: impl FnOnce() -> io::Result<()>,
    ) -> Result<Self, LaunchError> {
        self.authenticate_running_child(authenticity, latch)?;
        if start_reader().is_err() {
            return Err(self.fail_launch(LaunchError::SpawnFailed));
        }
        match self.handshake(authenticity.expected_build_id()) {
            Ok(()) => Ok(self),
            Err(HandshakeFailure::Identity) => Err(self.reject_identity(latch)),
            Err(HandshakeFailure::Launch(error)) => Err(self.fail_launch(error)),
        }
    }

    /// ADR-017 §5.3 step 5. Nothing has been written to the child yet.
    fn authenticate_running_child(
        &mut self,
        authenticity: &dyn WorkerIdentityCheck,
        latch: &IdentityLatch,
    ) -> Result<(), LaunchError> {
        let verified = match authenticity.verify_running_child(self.pid) {
            Ok(ChildVerification::NotRequired) => return Ok(()),
            Ok(ChildVerification::Verified) => true,
            Err(_) => false,
        };
        let still_running = match &mut self.process {
            ProcessState::Running(process) => process.exited_without_reaping().ok() == Some(false),
            ProcessState::Reaped => false,
        };
        if verified && still_running {
            Ok(())
        } else {
            Err(self.reject_identity(latch))
        }
    }

    /// ADR-017 §5.7: latch first, then contain. The latch survives whatever containment reports;
    /// `NotContained` is carried alongside as `quiescence: Active`, never instead of the rejection.
    fn reject_identity(&mut self, latch: &IdentityLatch) -> LaunchError {
        latch.set();
        let quiescence = self.contain();
        LaunchError::WorkerIdentityRejected { quiescence }
    }

    fn fail_launch(&mut self, error: LaunchError) -> LaunchError {
        if self.contain() == ExecutionQuiescence::Quiescent {
            error
        } else {
            LaunchError::NotContained
        }
    }

    fn handshake(&mut self, expected_build_id: &str) -> Result<(), HandshakeFailure> {
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
                    return Err(LaunchError::HandshakeMalformed.into());
                }
                decode_message(&bytes).map_err(|_| LaunchError::HandshakeMalformed)?
            }
            Ok(ReaderEvent::Failed(StreamFailure::Closed | StreamFailure::Io))
            | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(LaunchError::SpawnFailed.into());
            }
            Ok(ReaderEvent::Failed(_)) => return Err(LaunchError::HandshakeMalformed.into()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(LaunchError::HandshakeTimeout.into());
            }
        };
        match hello.validate_reply(&reply, self.pid, expected_build_id) {
            Ok(()) => {}
            Err(HandshakeError::BuildIdMismatch) => return Err(HandshakeFailure::Identity),
            Err(_) => return Err(LaunchError::HandshakeMismatch.into()),
        }

        Ok(self.health_check()?)
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

    #[cfg(unix)]
    pub(crate) fn submit_mutation_secret(
        &mut self,
        binding: fido_auth::mutation::PinMutationBinding,
        request: u64,
        secrets: fido_auth::mutation::PinMutationSecrets,
    ) -> Result<(), WorkerEndpointError> {
        if self.revoked() {
            return Err(self.abandon(WorkerEndpointError::Unavailable));
        }
        let secret = self.secret.take().ok_or(WorkerEndpointError::Unavailable)?;
        let result = fido_auth::mutation::send_mutation_secret(&secret, binding, request, secrets);
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
        exited: Arc<AtomicBool>,
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

        fn exited_without_reaping(&mut self) -> io::Result<bool> {
            Ok(self.0.exited.load(Ordering::SeqCst))
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

    /// ADR-017 §5.3/§5.7 ordering and latch tests against a fake process and a fake policy.
    mod worker_identity {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        use super::*;
        use crate::worker_authenticity::IdentityRejection;

        const BUILD: &str = "0.1.0+0123456789abcdef0123456789abcdef01234567";

        /// Records what had happened at the moment the running child was verified.
        struct FakeIdentity {
            verdict: Result<ChildVerification, IdentityRejection>,
            sink: SharedSink,
            bytes_written_at_verification: Arc<Mutex<Option<usize>>>,
            reader_started: Arc<AtomicBool>,
            reader_started_at_verification: Arc<Mutex<Option<bool>>>,
        }

        impl WorkerIdentityCheck for FakeIdentity {
            fn enforces_release_layout(&self) -> bool {
                false
            }
            fn verify_before_spawn(&self, _path: &Path) -> Result<(), IdentityRejection> {
                Ok(())
            }
            fn verify_running_child(
                &self,
                _pid: u32,
            ) -> Result<ChildVerification, IdentityRejection> {
                let written = self.sink.0.lock().map(|bytes| bytes.len()).ok();
                if let Ok(mut slot) = self.bytes_written_at_verification.lock() {
                    *slot = written;
                }
                if let Ok(mut slot) = self.reader_started_at_verification.lock() {
                    *slot = Some(self.reader_started.load(Ordering::SeqCst));
                }
                self.verdict
            }
            fn expected_build_id(&self) -> &str {
                BUILD
            }
        }

        struct Harness {
            endpoint: ProcessWorkerEndpoint,
            control: ProcessControl,
            worker_events: mpsc::SyncSender<ReaderEvent>,
            identity: FakeIdentity,
            latch: IdentityLatch,
            kills_with_latch_set: Arc<AtomicUsize>,
        }

        /// A process whose `kill` records whether the latch was already set at that moment.
        struct LatchObservingProcess {
            control: ProcessControl,
            latch: IdentityLatch,
            kills_with_latch_set: Arc<AtomicUsize>,
        }

        impl WorkerProcess for LatchObservingProcess {
            fn kill(&mut self) -> io::Result<()> {
                if self.latch.is_set() {
                    self.kills_with_latch_set.fetch_add(1, Ordering::SeqCst);
                }
                FakeProcess(self.control.clone()).kill()
            }
            fn try_reap(&mut self) -> io::Result<bool> {
                FakeProcess(self.control.clone()).try_reap()
            }
            fn exited_without_reaping(&mut self) -> io::Result<bool> {
                FakeProcess(self.control.clone()).exited_without_reaping()
            }
        }

        fn harness(verdict: Result<ChildVerification, IdentityRejection>) -> Harness {
            let control = ProcessControl::default();
            let latch = IdentityLatch::default();
            let kills_with_latch_set = Arc::new(AtomicUsize::new(0));
            let sink = SharedSink::default();
            let (worker_events, events) = mpsc::sync_channel(READER_QUEUE_FRAMES);
            let endpoint = ProcessWorkerEndpoint::from_parts(
                Box::new(LatchObservingProcess {
                    control: control.clone(),
                    latch: latch.clone(),
                    kills_with_latch_set: Arc::clone(&kills_with_latch_set),
                }),
                Box::new(sink.clone()),
                events,
                WorkerGeneration(1),
                quick_config(),
            );
            Harness {
                endpoint,
                control,
                worker_events,
                identity: FakeIdentity {
                    verdict,
                    sink,
                    bytes_written_at_verification: Arc::new(Mutex::new(None)),
                    reader_started: Arc::new(AtomicBool::new(false)),
                    reader_started_at_verification: Arc::new(Mutex::new(None)),
                },
                latch,
                kills_with_latch_set,
            }
        }

        fn establish(h: Harness) -> (Result<ProcessWorkerEndpoint, LaunchError>, Harness2) {
            let Harness {
                endpoint,
                control,
                worker_events,
                identity,
                latch,
                kills_with_latch_set,
            } = h;
            let started = Arc::clone(&identity.reader_started);
            let result = endpoint.establish(&identity, &latch, move || {
                started.store(true, Ordering::SeqCst);
                Ok(())
            });
            (
                result,
                Harness2 {
                    control,
                    _worker_events: worker_events,
                    identity,
                    latch,
                    kills_with_latch_set,
                },
            )
        }

        struct Harness2 {
            control: ProcessControl,
            _worker_events: mpsc::SyncSender<ReaderEvent>,
            identity: FakeIdentity,
            latch: IdentityLatch,
            kills_with_latch_set: Arc<AtomicUsize>,
        }

        impl Harness2 {
            fn written(&self) -> usize {
                self.identity
                    .sink
                    .0
                    .lock()
                    .map(|b| b.len())
                    .unwrap_or(usize::MAX)
            }
        }

        fn hello(build_id: &str) -> Result<ReaderEvent, FrameError> {
            Ok(ReaderEvent::Frame(encode_message(&ChildHello::new(
                WorkerGeneration(1),
                0,
                build_id,
            ))?))
        }

        #[test]
        fn nothing_is_written_before_dynamic_verification_succeeds() {
            let h = harness(Ok(ChildVerification::Verified));
            h.control.reaped.store(true, Ordering::SeqCst);
            let (result, h) = establish(h);
            // No ChildHello arrives, so the handshake times out after ParentHello was written.
            assert!(matches!(result, Err(LaunchError::HandshakeTimeout)));
            assert_eq!(
                *h.identity
                    .bytes_written_at_verification
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
                Some(0),
                "ParentHello must not precede dynamic verification"
            );
            assert_eq!(
                *h.identity
                    .reader_started_at_verification
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
                Some(false)
            );
            assert!(
                h.written() > 0,
                "ParentHello is written only after verification"
            );
            assert!(!h.latch.is_set());
        }

        #[test]
        fn failed_dynamic_verification_sends_nothing_latches_then_contains() {
            for rejection in [
                IdentityRejection::DynamicValidation,
                IdentityRejection::Cdhash,
                IdentityRejection::TeamId,
                IdentityRejection::DynamicStatus,
            ] {
                let h = harness(Err(rejection));
                h.control.reaped.store(true, Ordering::SeqCst);
                let (result, h) = establish(h);
                assert_eq!(
                    result.err(),
                    Some(LaunchError::WorkerIdentityRejected {
                        quiescence: ExecutionQuiescence::Quiescent
                    })
                );
                assert_eq!(
                    h.written(),
                    0,
                    "no ParentHello, PIN, PUAT or request ({rejection:?})"
                );
                assert!(!h.identity.reader_started.load(Ordering::SeqCst));
                assert!(h.latch.is_set());
                assert!(h.control.kills.load(Ordering::SeqCst) >= 1);
                assert_eq!(
                    h.kills_with_latch_set.load(Ordering::SeqCst),
                    h.control.kills.load(Ordering::SeqCst) as usize,
                    "the latch is set before the first containment signal"
                );
            }
        }

        #[test]
        fn not_contained_keeps_the_identity_rejection_latched() {
            let h = harness(Err(IdentityRejection::DynamicValidation));
            // The OS never reports the rejected child reaped.
            let (result, h) = establish(h);
            assert_eq!(
                result.err(),
                Some(LaunchError::WorkerIdentityRejected {
                    quiescence: ExecutionQuiescence::Active
                }),
                "NotContained is carried alongside, never instead of, the rejection"
            );
            assert!(h.latch.is_set());
            assert!(h.kills_with_latch_set.load(Ordering::SeqCst) >= 1);
            assert_eq!(h.written(), 0);
        }

        #[test]
        fn child_exiting_during_validation_is_rejected() {
            let h = harness(Ok(ChildVerification::Verified));
            h.control.exited.store(true, Ordering::SeqCst);
            h.control.reaped.store(true, Ordering::SeqCst);
            let (result, h) = establish(h);
            assert_eq!(
                result.err(),
                Some(LaunchError::WorkerIdentityRejected {
                    quiescence: ExecutionQuiescence::Quiescent
                })
            );
            assert_eq!(h.written(), 0);
            assert!(h.latch.is_set());
        }

        #[test]
        fn development_mode_does_not_peek_or_reject_an_early_exit() {
            let h = harness(Ok(ChildVerification::NotRequired));
            h.control.exited.store(true, Ordering::SeqCst);
            h.control.reaped.store(true, Ordering::SeqCst);
            let (result, h) = establish(h);
            // An early death stays an ordinary, restartable launch failure in development.
            assert!(matches!(result, Err(LaunchError::HandshakeTimeout)));
            assert!(!h.latch.is_set());
        }

        #[test]
        fn wrong_child_hello_build_id_is_a_terminal_identity_failure() -> Result<(), FrameError> {
            for build in [
                "0.1.0+development",
                "",
                "0.1.0+0123456789abcdef0123456789abcdef01234568",
            ] {
                let h = harness(Ok(ChildVerification::NotRequired));
                h.control.reaped.store(true, Ordering::SeqCst);
                h.worker_events
                    .try_send(hello(build)?)
                    .map_err(|_| FrameError::Malformed)?;
                let (result, h) = establish(h);
                assert_eq!(
                    result.err(),
                    Some(LaunchError::WorkerIdentityRejected {
                        quiescence: ExecutionQuiescence::Quiescent
                    }),
                    "{build:?}"
                );
                assert!(h.latch.is_set());
                assert!(h.control.kills.load(Ordering::SeqCst) >= 1);
            }
            Ok(())
        }

        #[test]
        fn matching_build_id_passes_the_identity_step() -> Result<(), FrameError> {
            let h = harness(Ok(ChildVerification::NotRequired));
            h.control.reaped.store(true, Ordering::SeqCst);
            h.worker_events
                .try_send(hello(BUILD)?)
                .map_err(|_| FrameError::Malformed)?;
            let (result, h) = establish(h);
            // Only the (unanswered) health check fails; identity is not involved.
            assert!(matches!(result, Err(LaunchError::HealthCheckFailed)));
            assert!(!h.latch.is_set());
            Ok(())
        }

        #[test]
        fn a_latched_or_startup_rejected_launcher_never_spawns() {
            let mut launcher = ProcessWorkerLauncher::startup_rejected_for_test();
            for _ in 0..3 {
                assert_eq!(
                    launcher.launch(WorkerGeneration(1)).err(),
                    Some(LaunchError::WorkerIdentityRejected {
                        quiescence: ExecutionQuiescence::Quiescent
                    })
                );
            }
            assert!(launcher.identity_latch.is_set());
        }

        #[cfg(unix)]
        #[test]
        fn path_checks_run_again_on_every_launch() -> Result<(), Box<dyn std::error::Error>> {
            use std::os::unix::fs::PermissionsExt;
            let directory =
                std::env::temp_dir().join(format!("fido-service-relaunch-{}", std::process::id()));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir_all(&directory)?;
            let file = directory.join("worker");
            fs::write(&file, b"#!/bin/sh\nexit 0\n")?;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o755))?;
            let mut launcher = ProcessWorkerLauncher::new(
                ResolvedWorkerExecutable::from_absolute_path(file.clone())?,
                quick_config(),
            )?;
            // Passes the path checks and is spawned; it exits without a handshake.
            assert_eq!(
                launcher.launch(WorkerGeneration(1)).err(),
                Some(LaunchError::SpawnFailed)
            );
            fs::set_permissions(&file, fs::Permissions::from_mode(0o757))?;
            assert_eq!(
                launcher.launch(WorkerGeneration(2)).err(),
                Some(LaunchError::ExecutableRejected),
                "a world-writable replacement is refused at the next spawn"
            );
            fs::remove_file(&file)?;
            let other = directory.join("other");
            fs::write(&other, b"other")?;
            fs::set_permissions(&other, fs::Permissions::from_mode(0o755))?;
            std::os::unix::fs::symlink(&other, &file)?;
            assert_eq!(
                launcher.launch(WorkerGeneration(3)).err(),
                Some(LaunchError::ExecutableRejected),
                "a path that now resolves elsewhere is refused"
            );
            fs::remove_file(&file)?;
            assert_eq!(
                launcher.launch(WorkerGeneration(4)).err(),
                Some(LaunchError::ExecutableRejected)
            );
            let _ = fs::remove_dir_all(&directory);
            Ok(())
        }

        #[cfg(unix)]
        #[test]
        fn release_layout_refuses_absolute_paths_and_group_writable_files()
        -> Result<(), Box<dyn std::error::Error>> {
            use std::os::unix::fs::PermissionsExt;
            let directory =
                std::env::temp_dir().join(format!("fido-service-layout-{}", std::process::id()));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir_all(&directory)?;
            let file = directory.join("fido-worker");
            fs::write(&file, b"worker")?;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o775))?;
            let resolved = ResolvedWorkerExecutable::from_absolute_path(file.clone())?;
            assert!(resolved.revalidate(false).is_ok());
            assert_eq!(
                resolved.revalidate(true).err(),
                Some(LaunchError::ExecutableRejected),
                "release enforcement accepts only the packaged worker beside the app"
            );
            assert_eq!(
                ResolvedWorkerExecutable::checked(&file, true).err(),
                Some(LaunchError::ExecutableRejected),
                "group-writable is refused in release enforcement"
            );
            fs::set_permissions(&file, fs::Permissions::from_mode(0o755))?;
            assert!(ResolvedWorkerExecutable::checked(&file, true).is_ok());
            // The test binary does not live in an .app bundle: the release layout is refused.
            let beside = ResolvedWorkerExecutable {
                path: file.clone(),
                origin: ExecutableOrigin::BesideCurrentExe("fido-worker"),
            };
            assert_eq!(
                beside.revalidate(true).err(),
                Some(LaunchError::ExecutableRejected)
            );
            let _ = fs::remove_dir_all(&directory);
            Ok(())
        }
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
