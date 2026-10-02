//! Developer tool: drive discovery through the production supervisor and child worker.
//!
//! ```text
//! cargo build -p fido-worker
//! cargo run -p fido-service --example discover -- --watch
//! ```
//!
//! `--watch` keeps refreshing once a second and survives worker failures, which makes it the
//! easiest way to observe containment on real hardware: kill or stop the `fido-worker` process
//! and watch the supervisor report the failure, back off, and launch a replacement generation.
//!
//! `--worker PATH` overrides the worker executable (default: `fido-worker` in the same Cargo
//! target directory as this example). This is a developer tool; the application never accepts a
//! worker path from anywhere.

use std::path::PathBuf;
use std::{env, thread, time::Duration};

use fido_core::{Aaguid, DeviceListSnapshot};
use fido_service::{
    DiscoveryPolicy, DiscoverySupervisor, ProcessWorkerConfig, ProcessWorkerLauncher,
    ResolvedWorkerExecutable, RestartPolicy,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut watch = false;
    let mut worker_override: Option<PathBuf> = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--watch" => watch = true,
            "--worker" => {
                worker_override = Some(PathBuf::from(
                    arguments.next().ok_or("--worker requires a path")?,
                ));
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let worker_path = match worker_override {
        Some(path) => path,
        None => {
            // target/<profile>/examples/discover -> target/<profile>/fido-worker
            let example = env::current_exe()?;
            let profile_dir = example
                .parent()
                .and_then(|examples| examples.parent())
                .ok_or("cannot locate the Cargo target directory")?;
            profile_dir.join(ProcessWorkerLauncher::DEFAULT_WORKER_FILE_NAME)
        }
    };
    println!("worker executable: {}", worker_path.display());

    let launcher = ProcessWorkerLauncher::new(
        ResolvedWorkerExecutable::from_absolute_path(worker_path)?,
        ProcessWorkerConfig::default(),
    )?;
    let mut supervisor = DiscoverySupervisor::new(
        launcher,
        DiscoveryPolicy::default(),
        RestartPolicy::default(),
    )?;

    if watch {
        println!("FidoManager discovery watch started; press Ctrl+C to stop.");
        loop {
            report(&mut supervisor);
            thread::sleep(Duration::from_secs(1));
        }
    }

    match supervisor.refresh() {
        Ok(snapshot) => {
            print_snapshot(&snapshot);
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn report(supervisor: &mut DiscoverySupervisor<ProcessWorkerLauncher>) {
    let outcome = supervisor.refresh();
    let status = supervisor.status();
    println!(
        "[supervisor] state={:?} generation={:?} launches={} consecutive_failures={}",
        status.state,
        status.worker_generation.map(|generation| generation.0),
        status.launches,
        status.consecutive_failures,
    );
    match outcome {
        Ok(snapshot) => print_snapshot(&snapshot),
        Err(error) => println!("refresh failed: {error}"),
    }
}

fn print_snapshot(snapshot: &DeviceListSnapshot) {
    println!(
        "FidoManager native discovery: epoch={} {} device(s)",
        snapshot.enumeration_epoch.0,
        snapshot.devices.len()
    );

    for device in &snapshot.devices {
        println!(
            "- handle={:032x} generation={} {:04x}:{:04x} {} {} status={:?} aaguid={} versions={:?} transports={:?}",
            device.handle.as_raw(),
            device.generation.0,
            device.vendor_id,
            device.product_id,
            device.manufacturer.as_deref().unwrap_or("<unknown>"),
            device.product.as_deref().unwrap_or("<unknown>"),
            device.read_status,
            format_aaguid(device.aaguid.as_ref()),
            device.versions,
            device.transports,
        );
    }
}

fn format_aaguid(aaguid: Option<&Aaguid>) -> String {
    aaguid
        .map(|value| format!("{:032x}", u128::from_be_bytes(*value.as_bytes())))
        .unwrap_or_else(|| "<none>".to_owned())
}
