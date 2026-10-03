//! Production worker executable.
//!
//! Accepts only the fixed backend authentication mode (no runtime paths or secret arguments).
//! Refuses FIDO_DEBUG; correlation arrives through stdin and PIN through the dedicated socket. The service resolves and spawns it from a fixed location (never from `PATH` and never
//! from a renderer-influenced value).

use fido_platform::process::exit_immediately;
use fido_worker::{exit, harden_process};

fn main() {
    // fido_init honors FIDO_DEBUG even with flags=0. Refuse before any native initialization.
    if std::env::var_os("FIDO_DEBUG").is_some() {
        exit_immediately(exit::CONFIG);
    }
    let authentication = std::env::args_os().skip(1).collect::<Vec<_>>() == ["--authentication"];
    if std::env::args_os().len() > 1 && !authentication {
        exit_immediately(exit::USAGE);
    }
    #[cfg(all(target_os = "macos", feature = "native-libfido2"))]
    if authentication {
        if fido_platform::process::close_inherited_descriptors_except(Some(3)).is_err() {
            exit_immediately(exit::OS);
        }
        let channel = fido_platform::process::secret_channel::receive()
            .unwrap_or_else(|_| exit_immediately(exit::CONFIG));
        fido_worker::runtime::run_with_secret(
            std::io::stdin(),
            std::io::stdout(),
            fido_libfido2::LibFido2Adapter::new(),
            fido_worker::runtime::RuntimeConfig::default(),
            Some(Box::new(channel)),
        );
    }
    if authentication {
        exit_immediately(exit::CONFIG);
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
