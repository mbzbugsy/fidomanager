//! M1.5 spike child worker. Speaks the unchanged worker protocol over stdin/stdout frames, running
//! the *real* `WorkerEngine` (via `InProcessWorkerEndpoint`) over a scripted fake native backend.
//!
//! `--script` is a comma list consumed one entry per native `manifest()` call:
//!   ok     -> one fake device
//!   hang   -> block forever inside the "native" call (never returns, ignores the budget)
//!   crash  -> abort the whole process mid-call
//! After the script is exhausted, `ok` is assumed.

use std::collections::VecDeque;
use std::io::{stdin, stdout};
use std::process::exit;
use std::thread;
use std::time::Duration;

use fido_libfido2::{
    NativeDeviceInfo, NativeDeviceKey, NativeDiscoveredDevice, NativeDiscoveryBackend, NativeError,
};
use fido_service::{InProcessWorkerEndpoint, WorkerEndpoint, WorkerEndpointError};
use fido_spike_worker::{FrameError, read_frame, write_frame};
use fido_worker_protocol::{WorkerGeneration, WorkerRequestEnvelope};

enum Step {
    Ok,
    Hang,
    Crash,
}

struct ScriptedBackend {
    script: VecDeque<Step>,
}

impl NativeDiscoveryBackend for ScriptedBackend {
    fn manifest(&mut self, _budget_ms: u64) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
        match self.script.pop_front().unwrap_or(Step::Ok) {
            Step::Ok => Ok(vec![NativeDiscoveredDevice {
                key: NativeDeviceKey::from_bytes(b"fake-0".to_vec())?,
                vendor_id: 0x1234,
                product_id: 0x5678,
                manufacturer: Some("Spike".to_owned()),
                product: Some("Fake Authenticator".to_owned()),
            }]),
            Step::Hang => loop {
                thread::park();
            },
            Step::Crash => std::process::abort(),
        }
    }

    fn get_info(
        &mut self,
        _key: &NativeDeviceKey,
        _budget_ms: u64,
    ) -> Result<NativeDeviceInfo, NativeError> {
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

fn parse_script(raw: &str) -> VecDeque<Step> {
    raw.split(',')
        .filter_map(|word| match word.trim() {
            "ok" => Some(Step::Ok),
            "hang" => Some(Step::Hang),
            "crash" => Some(Step::Crash),
            _ => None,
        })
        .collect()
}

fn main() {
    let mut generation = None;
    let mut script = String::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match (flag.as_str(), args.next()) {
            ("--generation", Some(value)) => generation = value.parse::<u64>().ok(),
            ("--script", Some(value)) => script = value,
            _ => exit(64),
        }
    }
    let Some(generation) = generation else {
        exit(64)
    };
    let generation = WorkerGeneration(generation);

    let Ok(mut inner) = InProcessWorkerEndpoint::spawn(
        ScriptedBackend {
            script: parse_script(&script),
        },
        generation,
    ) else {
        exit(70)
    };

    let mut input = stdin().lock();
    let mut output = stdout().lock();
    loop {
        let bytes = match read_frame(&mut input) {
            Ok(bytes) => bytes,
            // Parent closed our stdin (or died): the orphan cleans itself up.
            Err(FrameError::Eof) => exit(0),
            Err(_) => exit(65),
        };
        let Ok(request) = serde_json::from_slice::<WorkerRequestEnvelope>(&bytes) else {
            exit(65)
        };
        match inner.exchange(request) {
            Ok(response) => {
                let Ok(encoded) = serde_json::to_vec(&response) else {
                    exit(70)
                };
                if write_frame(&mut output, &encoded).is_err() {
                    exit(0);
                }
            }
            // The native call outlived even this process's own wait: stay wedged and silent so the
            // parent's kill is the only way out. (An `exit` here would look like a crash.)
            Err(WorkerEndpointError::TransportFailure) => loop {
                thread::sleep(Duration::from_secs(3600));
            },
            Err(_) => exit(70),
        }
    }
}
