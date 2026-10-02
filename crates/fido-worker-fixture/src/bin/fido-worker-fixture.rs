//! Test fixture worker. Never shipped; it exists so the process-containment tests can drive the
//! *production* endpoint, handshake, framing, runtime and engine against misbehaving natives and
//! misbehaving peers.
//!
//! Exactly one scenario flag selects the behaviour:
//!
//! * `--script=STEPS[;--info=STEPS]`-style scripted native backend, run through the production
//!   runtime. `--script=` drives `manifest()` and `--info=` drives `get_info()`; each is a comma
//!   list consumed one entry per call (then `ok` forever): `ok`, `hang` (block forever, ignoring
//!   the deadline), `crash` (abort), `slow<ms>` (sleep ignoring the deadline, then succeed).
//! * `--raw=MODE` speaks the wire protocol by hand to misbehave on purpose; see `raw`.
//!
//! `--tag=NAME` is ignored by the fixture. Tests put a unique tag on the command line so they can
//! find *their* worker processes with `pgrep -f` even when other tests run in parallel.
//!
//! The scenario arrives as a command-line flag because the service's launcher only accepts
//! compile-time-constant arguments.

use std::collections::VecDeque;
use std::io::{Write, stdin, stdout};
use std::thread;
use std::time::Duration;

use fido_libfido2::{
    NativeDeadline, NativeDeviceInfo, NativeDeviceKey, NativeDiscoveredDevice,
    NativeDiscoveryBackend, NativeError,
};
use fido_platform::process::{close_inherited_descriptors, exit_immediately};
use fido_worker::engine::WorkerEngine;
use fido_worker::runtime::{RuntimeConfig, run};
use fido_worker::{exit, harden_process};
use fido_worker_protocol::{
    ChildHello, MAX_WORKER_FRAME_BYTES, MAX_WORKER_HANDSHAKE_FRAME_BYTES,
    MAX_WORKER_REQUEST_FRAME_BYTES, ParentHello, WorkerRequestEnvelope, read_message, write_frame,
    write_message,
};

#[derive(Debug, Clone, Copy)]
enum Step {
    Ok,
    Hang,
    Crash,
    Slow(u64),
}

fn parse_steps(raw: &str) -> VecDeque<Step> {
    raw.split(',')
        .filter_map(|word| {
            let word = word.trim();
            match word {
                "ok" => Some(Step::Ok),
                "hang" => Some(Step::Hang),
                "crash" => Some(Step::Crash),
                other => other
                    .strip_prefix("slow")
                    .and_then(|millis| millis.parse::<u64>().ok())
                    .map(Step::Slow),
            }
        })
        .collect()
}

#[derive(Default)]
struct ScriptedBackend {
    manifest: VecDeque<Step>,
    info: VecDeque<Step>,
}

fn apply(step: Step) {
    match step {
        Step::Ok => {}
        Step::Hang => loop {
            thread::park();
        },
        Step::Crash => std::process::abort(),
        Step::Slow(millis) => thread::sleep(Duration::from_millis(millis)),
    }
}

impl NativeDiscoveryBackend for ScriptedBackend {
    fn manifest(
        &mut self,
        _deadline: NativeDeadline,
    ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
        apply(self.manifest.pop_front().unwrap_or(Step::Ok));
        Ok(vec![NativeDiscoveredDevice {
            key: NativeDeviceKey::from_bytes(b"fake-0".to_vec())?,
            vendor_id: 0x1234,
            product_id: 0x5678,
            manufacturer: Some("Fixture".to_owned()),
            product: Some("Fake Authenticator".to_owned()),
        }])
    }

    fn get_info(
        &mut self,
        _key: &NativeDeviceKey,
        _deadline: NativeDeadline,
    ) -> Result<NativeDeviceInfo, NativeError> {
        apply(self.info.pop_front().unwrap_or(Step::Ok));
        Ok(NativeDeviceInfo {
            aaguid: Some([0x42; 16]),
            versions: vec!["FIDO_2_1".to_owned()],
            extensions: Vec::new(),
            transports: vec!["usb".to_owned()],
            options: Vec::new(),
            max_message_size: Some(1_200),
            firmware_version: Some(1),
        })
    }
}

fn main() {
    let mut script = None;
    let mut info = None;
    let mut raw_mode = None;
    for argument in std::env::args().skip(1) {
        if let Some(value) = argument.strip_prefix("--script=") {
            script = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix("--info=") {
            info = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix("--raw=") {
            raw_mode = Some(value.to_owned());
        } else if argument.starts_with("--tag=") {
            // Only there to make the command line unique.
        } else {
            exit_immediately(exit::USAGE);
        }
    }

    // `--raw=fds` must observe descriptors *before* the production sweep, so it hardens itself.
    if raw_mode.as_deref() == Some("fds") {
        report_descriptor_sweep();
    }

    if let Err(code) = harden_process() {
        exit_immediately(code);
    }

    match raw_mode {
        Some(mode) => raw(&mode),
        None => run(
            stdin(),
            stdout(),
            ScriptedBackend {
                manifest: parse_steps(script.as_deref().unwrap_or("")),
                info: parse_steps(info.as_deref().unwrap_or("")),
            },
            RuntimeConfig::default(),
        ),
    }
}

/// Prints how many inherited descriptors the production sweep closed, then how many a second sweep
/// found (it must be zero), and exits.
fn report_descriptor_sweep() -> ! {
    let first = close_inherited_descriptors().unwrap_or(usize::MAX);
    let second = close_inherited_descriptors().unwrap_or(usize::MAX);
    let _ = writeln!(stdout(), "first={first} second={second}");
    let _ = stdout().flush();
    exit_immediately(exit::ORDERLY)
}

fn park_forever() -> ! {
    loop {
        thread::park();
    }
}

/// Hand-rolled protocol peers. Modes that misbehave during the handshake fail the *launch*; modes
/// that misbehave on the second request (after a normal handshake and health check) fail an
/// *exchange*.
fn raw(mode: &str) -> ! {
    let mut input = stdin().lock();
    let mut output = stdout().lock();

    let hello: ParentHello = match read_message(&mut input, MAX_WORKER_HANDSHAKE_FRAME_BYTES) {
        Ok(hello) => hello,
        Err(_) => exit_immediately(exit::HANDSHAKE),
    };
    let pid = std::process::id();
    let good_reply = ChildHello::new(hello.worker_generation, pid);

    match mode {
        "silent" => park_forever(),
        "bad-version" => {
            let mut reply = good_reply;
            reply.protocol_version = reply.protocol_version.wrapping_add(1);
            let _ = write_message(&mut output, &reply, MAX_WORKER_HANDSHAKE_FRAME_BYTES);
            park_forever()
        }
        "bad-generation" => {
            let mut reply = good_reply;
            reply.worker_generation.0 = reply.worker_generation.0.wrapping_add(1);
            let _ = write_message(&mut output, &reply, MAX_WORKER_HANDSHAKE_FRAME_BYTES);
            park_forever()
        }
        "bad-pid" => {
            let mut reply = good_reply;
            reply.worker_pid = pid.wrapping_add(1);
            let _ = write_message(&mut output, &reply, MAX_WORKER_HANDSHAKE_FRAME_BYTES);
            park_forever()
        }
        "garbage-hello" => {
            let _ = write_frame(&mut output, b"definitely not json", MAX_WORKER_FRAME_BYTES);
            park_forever()
        }
        "oversize-hello" => {
            // A perfectly valid hello, padded past the handshake bound.
            let mut payload = serde_json_bytes(&good_reply);
            payload.resize(MAX_WORKER_HANDSHAKE_FRAME_BYTES + 1_024, b' ');
            let _ = write_frame(&mut output, &payload, MAX_WORKER_FRAME_BYTES);
            park_forever()
        }
        "exit-after-hello" => {
            let _ = write_message(&mut output, &good_reply, MAX_WORKER_HANDSHAKE_FRAME_BYTES);
            exit_immediately(exit::ORDERLY)
        }
        "unsolicited-after-hello" => {
            let _ = write_message(&mut output, &good_reply, MAX_WORKER_HANDSHAKE_FRAME_BYTES);
            let _ = write_frame(&mut output, b"{}", MAX_WORKER_FRAME_BYTES);
            park_forever()
        }
        _ => {}
    }

    // Normal handshake, then serve the first request (the endpoint's health check) honestly and
    // misbehave on the second.
    if write_message(&mut output, &good_reply, MAX_WORKER_HANDSHAKE_FRAME_BYTES).is_err() {
        exit_immediately(exit::PARENT_GONE);
    }
    let mut engine = WorkerEngine::new(ScriptedBackend::default(), hello.worker_generation);
    let mut served = 0u32;
    loop {
        let request: WorkerRequestEnvelope =
            match read_message(&mut input, MAX_WORKER_REQUEST_FRAME_BYTES) {
                Ok(request) => request,
                Err(_) => exit_immediately(exit::ORDERLY),
            };
        served += 1;
        let response = engine.handle(request);

        if served == 1 {
            let _ = write_message(&mut output, &response, MAX_WORKER_FRAME_BYTES);
            continue;
        }

        match mode {
            "garbage-response" => {
                let _ = write_frame(&mut output, b"{\"nope\":", MAX_WORKER_FRAME_BYTES);
                park_forever()
            }
            "oversize-response" => {
                // Header only: declares one byte more than the bound and sends nothing else.
                let declared = u32::try_from(MAX_WORKER_FRAME_BYTES + 1).unwrap_or(u32::MAX);
                let _ = output.write_all(&declared.to_be_bytes());
                let _ = output.flush();
                park_forever()
            }
            "truncated-response" => {
                let _ = output.write_all(&100u32.to_be_bytes());
                let _ = output.write_all(&[b'{'; 10]);
                let _ = output.flush();
                exit_immediately(exit::ORDERLY)
            }
            "double-response" => {
                // One honest response plus an unsolicited second frame.
                let _ = write_message(&mut output, &response, MAX_WORKER_FRAME_BYTES);
                let _ = write_message(&mut output, &response, MAX_WORKER_FRAME_BYTES);
                park_forever()
            }
            "exit-after-response" => {
                let _ = write_message(&mut output, &response, MAX_WORKER_FRAME_BYTES);
                exit_immediately(exit::ORDERLY)
            }
            _ => exit_immediately(exit::USAGE),
        }
    }
}

fn serde_json_bytes(reply: &ChildHello) -> Vec<u8> {
    fido_worker_protocol::encode_message(reply).unwrap_or_default()
}
