//! Production worker executable.
//!
//! Takes no arguments and reads no environment: everything it needs arrives in the handshake over
//! stdin. The service resolves and spawns it from a fixed location (never from `PATH` and never
//! from a renderer-influenced value).

use fido_platform::process::exit_immediately;
use fido_worker::{exit, harden_process};

fn main() {
    if std::env::args_os().len() > 1 {
        exit_immediately(exit::USAGE);
    }
    if let Err(code) = harden_process() {
        exit_immediately(code);
    }
    start()
}

#[cfg(feature = "native-libfido2")]
fn start() -> ! {
    use fido_libfido2::LibFido2Adapter;
    use fido_worker::runtime::{RuntimeConfig, run};

    run(
        std::io::stdin(),
        std::io::stdout(),
        LibFido2Adapter::new(),
        RuntimeConfig::default(),
    )
}

#[cfg(not(feature = "native-libfido2"))]
fn start() -> ! {
    exit_immediately(exit::CONFIG)
}
