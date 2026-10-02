//! Child-process runtime: handshake, request loop, and parent-death watchdog.
//!
//! Thread layout (this is what makes cleanup work while a native call is blocked):
//!
//! ```text
//!   stdin-reader thread   reads frames; ends the process on EOF / protocol violation
//!   watchdog thread       polls the parent pid; ends the process if the parent changed
//!   main thread           the only thread that calls native code; writes responses
//! ```
//!
//! The reader and the watchdog never touch native code, so they keep running while the main thread
//! is wedged inside libfido2. They terminate the process with `_exit`, which skips exit handlers
//! that are not safe to run concurrently with a blocked native thread.
//!
//! The service is strictly request/response, so the runtime treats a second request that arrives
//! before the first response as a protocol violation. Cancellation is termination: the service
//! kills the process at its deadline.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use fido_libfido2::NativeDiscoveryBackend;
use fido_platform::process::{exit_immediately, parent_process_id};
use fido_worker_protocol::{
    ChildHello, FrameError, MAX_WORKER_FRAME_BYTES, MAX_WORKER_HANDSHAKE_FRAME_BYTES,
    MAX_WORKER_REQUEST_FRAME_BYTES, ParentHello, WorkerRequestEnvelope, read_message,
    write_message,
};

use crate::engine::WorkerEngine;
use crate::exit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// How long to wait for the service's hello after start. The service sends it immediately.
    pub handshake_timeout: Duration,
    /// How often the watchdog compares the current parent pid with the one the service declared.
    pub parent_poll_interval: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            parent_poll_interval: Duration::from_millis(100),
        }
    }
}

enum Inbound {
    Hello(ParentHello),
    Request(WorkerRequestEnvelope),
}

/// Runs the worker until the process ends. Never returns: every exit path is an explicit
/// `exit_immediately` so no thread can be left behind blocked in native code.
pub fn run<B, R, W>(input: R, mut output: W, backend: B, config: RuntimeConfig) -> !
where
    B: NativeDiscoveryBackend,
    R: Read + Send + 'static,
    W: Write,
{
    // A panic on any thread (a bug, never a peer-controlled condition) must not leave a
    // half-alive worker: kill the whole process so the service sees a plain worker death.
    std::panic::set_hook(Box::new(|_| exit_immediately(exit::INTERNAL)));

    let busy = Arc::new(AtomicBool::new(false));
    let (inbound_tx, inbound_rx) = mpsc::sync_channel::<Inbound>(1);
    if spawn_reader(input, inbound_tx, Arc::clone(&busy)).is_err() {
        exit_immediately(exit::OS);
    }

    let hello = match inbound_rx.recv_timeout(config.handshake_timeout) {
        Ok(Inbound::Hello(hello)) => hello,
        Ok(Inbound::Request(_)) | Err(_) => exit_immediately(exit::HANDSHAKE),
    };
    if hello.validate_for_worker(parent_process_id()).is_err() {
        exit_immediately(exit::HANDSHAKE);
    }

    let reply = ChildHello::new(hello.worker_generation, std::process::id());
    if write_message(&mut output, &reply, MAX_WORKER_HANDSHAKE_FRAME_BYTES).is_err() {
        exit_immediately(exit::PARENT_GONE);
    }

    // Started only after the parent identity has been verified, so the pid it compares against is
    // known to be this process's real parent.
    if spawn_parent_watchdog(hello.parent_pid, config.parent_poll_interval).is_err() {
        exit_immediately(exit::OS);
    }

    let mut engine = WorkerEngine::new(backend, hello.worker_generation);
    loop {
        let request = match inbound_rx.recv() {
            Ok(Inbound::Request(request)) => request,
            Ok(Inbound::Hello(_)) => exit_immediately(exit::PROTOCOL),
            Err(_) => exit_immediately(exit::INTERNAL),
        };

        let response = engine.handle(request);

        // Cleared before the response is written: the service cannot send its next request until
        // it has read this response, so the reader can never observe a stale `busy` flag.
        busy.store(false, Ordering::Release);
        if write_message(&mut output, &response, MAX_WORKER_FRAME_BYTES).is_err() {
            exit_immediately(exit::PARENT_GONE);
        }
    }
}

fn spawn_reader<R>(
    mut input: R,
    inbound_tx: mpsc::SyncSender<Inbound>,
    busy: Arc<AtomicBool>,
) -> std::io::Result<()>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name("fido-worker-stdin".to_owned())
        .spawn(move || {
            let hello: ParentHello =
                match read_message(&mut input, MAX_WORKER_HANDSHAKE_FRAME_BYTES) {
                    Ok(hello) => hello,
                    Err(error) => exit_immediately(frame_error_exit_code(&error)),
                };
            if inbound_tx.send(Inbound::Hello(hello)).is_err() {
                exit_immediately(exit::INTERNAL);
            }

            loop {
                match read_message::<_, WorkerRequestEnvelope>(
                    &mut input,
                    MAX_WORKER_REQUEST_FRAME_BYTES,
                ) {
                    Ok(request) => {
                        // A request while another is still being served means the service
                        // pipelined: the contract is strictly one request in flight.
                        if busy.swap(true, Ordering::AcqRel) {
                            exit_immediately(exit::PROTOCOL);
                        }
                        if inbound_tx.send(Inbound::Request(request)).is_err() {
                            exit_immediately(exit::INTERNAL);
                        }
                    }
                    Err(error) => exit_immediately(frame_error_exit_code(&error)),
                }
            }
        })
        .map(|_| ())
}

fn frame_error_exit_code(error: &FrameError) -> i32 {
    match error {
        // Parent closed its end between frames: it asked us to stop, or it died.
        FrameError::Eof => exit::ORDERLY,
        FrameError::Io(_) => exit::PARENT_GONE,
        FrameError::Truncated
        | FrameError::TooLarge
        | FrameError::Empty
        | FrameError::Malformed => exit::PROTOCOL,
    }
}

fn spawn_parent_watchdog(expected_parent_pid: u32, interval: Duration) -> std::io::Result<()> {
    thread::Builder::new()
        .name("fido-worker-watchdog".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(interval);
                // If the parent died, the OS reparents this process and the pid changes. This
                // catches the case where stdin never reaches EOF, for example because another
                // process inherited a copy of the pipe's write end.
                if parent_process_id() != expected_parent_pid {
                    exit_immediately(exit::PARENT_GONE);
                }
            }
        })
        .map(|_| ())
}
