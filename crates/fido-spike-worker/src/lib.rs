//! M1.5 spike: a minimal child-process `WorkerEndpoint`.
//!
//! Nothing here is production infrastructure. It exists to answer one question empirically: can the
//! existing, unmodified `WorkerEndpoint` trait and worker protocol be carried across a process
//! boundary, and does that boundary give the service a kill/quiescence guarantee the in-process
//! thread cannot?
//!
//! Transport: length-prefixed (u32 big-endian) JSON frames over the child's stdin/stdout. The
//! child's stderr is discarded and no other file descriptors are inherited.

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use fido_service::{WorkerEndpoint, WorkerEndpointError};
use fido_worker_protocol::{
    MAX_WORKER_FRAME_BYTES, WorkerGeneration, WorkerRequestEnvelope, WorkerResponseEnvelope,
};

/// Deliberately the same slack as `InProcessWorkerEndpoint` so the two placements are comparable.
pub const HARD_DEADLINE_SLACK_MS: u64 = 250;

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    TooLarge,
    Eof,
}

pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > MAX_WORKER_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge)?;
    writer
        .write_all(&len.to_be_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(FrameError::Io)
}

/// Reads one frame, enforcing the protocol's frame bound *before* allocating or deserializing.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Err(FrameError::Eof),
        Err(error) => return Err(FrameError::Io(error)),
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_WORKER_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(FrameError::Io)?;
    Ok(payload)
}

enum ReaderEvent {
    Response(WorkerResponseEnvelope),
    /// Child closed stdout / died / sent garbage.
    Gone,
    TooLarge,
}

/// Child-process worker endpoint. Implements the *unchanged* `fido_service::WorkerEndpoint`.
pub struct ProcessWorkerEndpoint {
    child: Child,
    stdin: ChildStdin,
    events: mpsc::Receiver<ReaderEvent>,
    reaped: bool,
}

impl ProcessWorkerEndpoint {
    /// `script` configures the fake backend inside the child (see the `fido-spike-worker` bin).
    pub fn spawn(
        executable: &Path,
        generation: WorkerGeneration,
        script: &str,
    ) -> Result<Self, WorkerEndpointError> {
        let mut child = Command::new(executable)
            .arg("--generation")
            .arg(generation.0.to_string())
            .arg("--script")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| WorkerEndpointError::Unavailable)?;
        let stdin = child.stdin.take().ok_or(WorkerEndpointError::Unavailable)?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(WorkerEndpointError::Unavailable)?;

        let (tx, events) = mpsc::channel();
        thread::Builder::new()
            .name("spike-worker-reader".to_owned())
            .spawn(move || {
                loop {
                    let event = match read_frame(&mut stdout) {
                        Ok(bytes) => {
                            match serde_json::from_slice::<WorkerResponseEnvelope>(&bytes) {
                                Ok(response) => ReaderEvent::Response(response),
                                Err(_) => ReaderEvent::Gone,
                            }
                        }
                        Err(FrameError::TooLarge) => ReaderEvent::TooLarge,
                        Err(_) => ReaderEvent::Gone,
                    };
                    let terminal = !matches!(event, ReaderEvent::Response(_));
                    if tx.send(event).is_err() || terminal {
                        break;
                    }
                }
            })
            .map_err(|_| WorkerEndpointError::Unavailable)?;

        Ok(Self {
            child,
            stdin,
            events,
            reaped: false,
        })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// SIGKILL and reap. After this returns `Ok`, the worker process no longer exists, so no native
    /// call can still be executing: this is the only place in either placement where
    /// `ExecutionQuiescence::Quiescent` can be proven rather than assumed.
    pub fn terminate(&mut self) -> io::Result<ExitStatus> {
        if !self.reaped {
            // Ignore "already exited"; wait() below is authoritative.
            let _ = self.child.kill();
        }
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
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
        if self.reaped {
            return Err(WorkerEndpointError::Unavailable);
        }
        let wait_ms = request
            .budget_ms
            .0
            .checked_add(HARD_DEADLINE_SLACK_MS)
            .ok_or(WorkerEndpointError::TransportFailure)?;

        // Anything already queued is either a death notice or an unsolicited frame; neither is
        // acceptable to carry into a new exchange.
        if self.events.try_recv().is_ok() {
            let _ = self.terminate();
            return Err(WorkerEndpointError::Unavailable);
        }

        let encoded =
            serde_json::to_vec(&request).map_err(|_| WorkerEndpointError::TransportFailure)?;
        if let Err(error) = write_frame(&mut self.stdin, &encoded) {
            let _ = self.terminate();
            return Err(match error {
                FrameError::TooLarge => WorkerEndpointError::FrameTooLarge,
                _ => WorkerEndpointError::Unavailable,
            });
        }

        match self.events.recv_timeout(Duration::from_millis(wait_ms)) {
            Ok(ReaderEvent::Response(response)) => Ok(response),
            Ok(ReaderEvent::TooLarge) => {
                let _ = self.terminate();
                Err(WorkerEndpointError::FrameTooLarge)
            }
            Ok(ReaderEvent::Gone) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = self.terminate();
                Err(WorkerEndpointError::Unavailable)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The decisive difference from the thread placement: we can act on the timeout.
                let _ = self.terminate();
                Err(WorkerEndpointError::TransportFailure)
            }
        }
    }
}

/// Test helper: is a pid still known to the OS? (`kill -0`; works on macOS and Linux.)
pub fn process_exists(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
