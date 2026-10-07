//! Test fixture worker. Never shipped; it exists so the process-containment tests can drive the
//! *production* endpoint, handshake, framing, runtime and engine against misbehaving natives and
//! misbehaving peers.
//!
//! Exactly one scenario flag selects the behaviour:
//!
//! * `--script=STEPS[;--info=STEPS]`-style scripted native backend, run through the production
//!   runtime. `--script=` drives `manifest()` and `--info=` drives `get_info()`; each is a comma
//!   list consumed one entry per call (then `ok` forever): `ok`, `hang` (block forever, ignoring
//!   the deadline), `crash` (die abruptly mid-call), `slow<ms>` (sleep ignoring the deadline, then succeed).
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
    MAX_WORKER_REQUEST_FRAME_BYTES, ParentHello, WorkerRequestEnvelope, WorkerResponse,
    read_message, write_frame, write_message,
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
    cleanup_failed: bool,
    wrong_pin: bool,
    two_devices: bool,
    mutation_mode: Option<String>,
    deletion_mode: Option<String>,
    deletion_log: Option<std::path::PathBuf>,
}

fn apply(step: Step) {
    match step {
        Step::Ok => {}
        Step::Hang => loop {
            thread::park();
        },
        // Dies abruptly in the middle of a native call, exactly like a crash from the service's
        // point of view (the pipe closes with a request in flight). It deliberately avoids
        // `abort()` and real signals: those make macOS write a crash report, or Linux a core dump,
        // on every test run. Signal deaths are covered by the `kill -9` tests instead.
        Step::Crash => exit_immediately(134),
        Step::Slow(millis) => thread::sleep(Duration::from_millis(millis)),
    }
}

struct AuthFixture {
    deletion_inventory: bool,
    cleanup_failed: bool,
    wrong_pin: bool,
    kind: fido_auth::GrantKind,
}
impl fido_libfido2::NativeAuthenticationSession for AuthFixture {
    fn kind(&self) -> fido_auth::GrantKind {
        self.kind
    }
    fn pin_retries(&self) -> Option<u8> {
        Some(8)
    }
    fn inspect(
        self: Box<Self>,
        binding: fido_auth::AcquisitionBinding,
        pin: fido_auth::PinSecret,
        deadline: NativeDeadline,
    ) -> fido_libfido2::inspection::NativeInspection {
        let deletion_inventory = self.deletion_inventory;
        let evidence = self.validate(binding, pin, deadline);
        fido_libfido2::inspection::NativeInspection {
            evidence,
            inventory: Some(if deletion_inventory {
                fido_worker_fixture::inventory()
            } else {
                fido_core::inventory::OwnedInventory {
                    metadata_existing: 0,
                    rps: Vec::new(),
                }
            }),
            error: None,
        }
    }
    fn validate(
        self: Box<Self>,
        binding: fido_auth::AcquisitionBinding,
        pin: fido_auth::PinSecret,
        _deadline: NativeDeadline,
    ) -> fido_auth::AuthenticationEvidence {
        drop(pin);
        fido_auth::AuthenticationEvidence {
            binding,
            kind: self.kind(),
            status: if self.cleanup_failed {
                fido_auth::AuthenticationStatus::CleanupFailed
            } else if self.wrong_pin {
                fido_auth::AuthenticationStatus::WrongPin
            } else {
                fido_auth::AuthenticationStatus::Validated
            },
            attached_puat_cleared: !self.cleanup_failed,
        }
    }
}
struct MutationFixture {
    operation: fido_auth::mutation::PinOperation,
    mode: String,
}
impl fido_libfido2::NativePinMutationSession for MutationFixture {
    fn operation(&self) -> fido_auth::mutation::PinOperation {
        self.operation
    }
    fn pin_retries(&self) -> Option<u8> {
        (self.operation == fido_auth::mutation::PinOperation::ChangePin).then_some(1)
    }
    fn execute(
        self: Box<Self>,
        secrets: fido_auth::mutation::PinMutationSecrets,
        _: NativeDeadline,
    ) -> fido_auth::mutation::PinMutationResult {
        assert_eq!(secrets.operation(), self.operation);
        drop(secrets);
        match self.mode.as_str() {
            "crash" => exit_immediately(134),
            "hang" => apply(Step::Hang),
            _ => {}
        }
        fido_auth::mutation::PinMutationResult::from_code(
            self.operation,
            self.mode != "pre-entry",
            match self.mode.as_str() {
                "reject" => 0x37,
                "unknown" => -2,
                _ => 0,
            },
            self.mode != "cleanup",
        )
    }
}
struct DeletionFixture {
    mode: String,
    log: Option<std::path::PathBuf>,
    selected_key: NativeDeviceKey,
}
impl DeletionFixture {
    fn record(&self, event: &str) {
        if let Some(path) = &self.log {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap_or_else(|_| exit_immediately(exit::OS));
            writeln!(file, "{event}").unwrap_or_else(|_| exit_immediately(exit::OS));
            file.sync_all()
                .unwrap_or_else(|_| exit_immediately(exit::OS));
        }
    }
}
impl fido_libfido2::NativeCredentialDeletionSession for DeletionFixture {
    fn kind(&self) -> fido_auth::GrantKind {
        fido_auth::GrantKind::CredMan
    }
    fn pin_retries(&self) -> u8 {
        8
    }
    fn execute(
        self: Box<Self>,
        target: fido_core::inventory::DeletionIdentity,
        pin: fido_auth::PinSecret,
        _: NativeDeadline,
    ) -> fido_auth::deletion::DeleteCredentialResult {
        drop(pin);
        self.record("proof");
        let mut credentials = fido_worker_fixture::inventory().rps.remove(0).credentials;
        match self.mode.as_str() {
            "absent" => credentials.clear(),
            "ambiguous" => credentials.push(credentials[0].clone()),
            "wrong-user" => credentials[0].user_id = Some(vec![255]),
            "malformed" => credentials[0].user_name = Some("bad\n".into()),
            "wrong-id" => credentials[0].id = vec![255],
            _ => {}
        }
        if self.selected_key
            != NativeDeviceKey::from_bytes(b"ioreg://100".to_vec())
                .unwrap_or_else(|_| panic!("fixture key"))
            || !fido_libfido2::deletion::matches_current_credentials(&target, &credentials)
        {
            self.record("proof-rejected");
            return fido_auth::deletion::DeleteCredentialResult::from_code(false, -1, true);
        }
        self.record("entered");
        match self.mode.as_str() {
            "crash" => exit_immediately(134),
            "lost-response" => exit_immediately(0),
            "hang" => apply(Step::Hang),
            _ => {}
        }
        fido_auth::deletion::DeleteCredentialResult::from_code(
            true,
            match self.mode.as_str() {
                "reject" => 0x2e,
                "unknown" => -2,
                _ => 0,
            },
            self.mode != "cleanup",
        )
    }
}
impl NativeDiscoveryBackend for ScriptedBackend {
    fn prepare_credential_deletion(
        &mut self,
        key: &NativeDeviceKey,
        _: NativeDeadline,
    ) -> Result<Box<dyn fido_libfido2::NativeCredentialDeletionSession>, NativeError> {
        let mode = self.deletion_mode.clone().ok_or(NativeError::new(
            fido_libfido2::NativeErrorKind::Unsupported,
            None,
        ))?;
        if mode == "prepare-failure" {
            return Err(NativeError::new(
                fido_libfido2::NativeErrorKind::Unsupported,
                None,
            ));
        }
        let session = DeletionFixture {
            mode: mode.clone(),
            log: self.deletion_log.clone(),
            selected_key: if mode == "wrong-device" {
                NativeDeviceKey::from_bytes(b"ioreg://101".to_vec())?
            } else {
                key.clone()
            },
        };
        session.record("prepared");
        Ok(Box::new(session))
    }
    fn prepare_pin_mutation(
        &mut self,
        _: &NativeDeviceKey,
        operation: fido_auth::mutation::PinOperation,
        _: NativeDeadline,
    ) -> Result<Box<dyn fido_libfido2::NativePinMutationSession>, NativeError> {
        let mode = self.mutation_mode.clone().ok_or(NativeError::new(
            fido_libfido2::NativeErrorKind::Unsupported,
            None,
        ))?;
        if mode == "prepare-failure" {
            return Err(NativeError::new(
                fido_libfido2::NativeErrorKind::Unsupported,
                None,
            ));
        }
        Ok(Box::new(MutationFixture { operation, mode }))
    }
    fn prepare_authentication(
        &mut self,
        key: &NativeDeviceKey,
        _: NativeDeadline,
    ) -> Result<Box<dyn fido_libfido2::NativeAuthenticationSession>, NativeError> {
        Ok(Box::new(AuthFixture {
            deletion_inventory: self.deletion_mode.is_some(),
            cleanup_failed: self.cleanup_failed,
            wrong_pin: self.wrong_pin,
            kind: if key == &NativeDeviceKey::from_bytes(b"ioreg://101".to_vec())? {
                fido_auth::GrantKind::CredManReadOnly
            } else {
                fido_auth::GrantKind::CredMan
            },
        }))
    }
    fn manifest(
        &mut self,
        _deadline: NativeDeadline,
    ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
        apply(self.manifest.pop_front().unwrap_or(Step::Ok));
        (0..if self.two_devices { 2 } else { 1 })
            .map(|i| {
                Ok(NativeDiscoveredDevice {
                    key: NativeDeviceKey::from_bytes(format!("ioreg://{}", 100 + i).into_bytes())?,
                    vendor_id: 0x1234,
                    product_id: 0x5678,
                    manufacturer: Some("Fixture".to_owned()),
                    product: Some("Fake Authenticator".to_owned()),
                })
            })
            .collect()
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
            options: if self.mutation_mode.is_some() {
                vec![fido_libfido2::NativeDeviceOption {
                    name: "clientPin".into(),
                    enabled: true,
                }]
            } else {
                Vec::new()
            },
            max_message_size: Some(1_200),
            firmware_version: Some(1),
        })
    }
}

fn main() {
    let mut authentication = false;
    let mut mutation_mode = None;
    let mut deletion_mode = None;
    let mut deletion_log = None;
    let mut cleanup_failed = false;
    let mut wrong_pin = false;
    let mut two_devices = false;
    let mut script = None;
    let mut info = None;
    let mut raw_mode = None;
    for argument in std::env::args().skip(1) {
        if argument == "--authentication" {
            authentication = true;
        } else if let Some(mode) = argument.strip_prefix("--mutation=") {
            mutation_mode = Some(mode.to_owned());
        } else if let Some(mode) = argument.strip_prefix("--deletion=") {
            deletion_mode = Some(mode.to_owned());
        } else if let Some(path) = argument.strip_prefix("--deletion-log=") {
            deletion_log = Some(std::path::PathBuf::from(path));
        } else if argument == "--cleanup-failed" {
            cleanup_failed = true;
        } else if argument == "--wrong-pin" {
            wrong_pin = true;
        } else if argument == "--two-devices" {
            two_devices = true;
        } else if let Some(value) = argument.strip_prefix("--script=") {
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

    #[cfg(unix)]
    if authentication {
        if fido_platform::process::close_inherited_descriptors_except(Some(3)).is_err() {
            exit_immediately(exit::OS);
        }
        if fido_platform::process::close_inherited_descriptors_except(Some(3)).unwrap_or(usize::MAX)
            != 0
        {
            exit_immediately(exit::OS);
        }
        let channel = fido_platform::process::secret_channel::receive()
            .unwrap_or_else(|_| exit_immediately(exit::CONFIG));
        fido_worker::runtime::run_with_secret(
            stdin(),
            stdout(),
            ScriptedBackend {
                manifest: VecDeque::new(),
                info: VecDeque::new(),
                cleanup_failed,
                wrong_pin,
                two_devices,
                mutation_mode,
                deletion_mode,
                deletion_log,
            },
            RuntimeConfig::default(),
            Some(Box::new(channel)),
        );
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
                cleanup_failed,
                wrong_pin,
                two_devices,
                mutation_mode,
                deletion_mode,
                deletion_log,
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
    if mode == "exit-at-start" {
        // A worker that dies before it ever reads the handshake (for example a loader failure).
        exit_immediately(exit::ORDERLY);
    }

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
            "truncated-header" => {
                // Two bytes of a four-byte length header, then death.
                let _ = output.write_all(&[0, 0]);
                let _ = output.flush();
                exit_immediately(exit::ORDERLY)
            }
            "wrong-request-id" => {
                let mut response = response;
                response.request_id.0 = response.request_id.0.wrapping_add(1_000);
                let _ = write_message(&mut output, &response, MAX_WORKER_FRAME_BYTES);
                park_forever()
            }
            "wrong-generation-response" => {
                let mut response = response;
                response.worker_generation.0 = response.worker_generation.0.wrapping_add(1);
                let _ = write_message(&mut output, &response, MAX_WORKER_FRAME_BYTES);
                park_forever()
            }
            "bad-protocol-response" => {
                let mut response = response;
                response.protocol_version = response.protocol_version.wrapping_add(1);
                let _ = write_message(&mut output, &response, MAX_WORKER_FRAME_BYTES);
                park_forever()
            }
            "wrong-variant" => {
                // Correctly correlated, but not the kind of answer the request asked for.
                let mut response = response;
                response.response = WorkerResponse::Healthy;
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
