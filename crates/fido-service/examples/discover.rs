use std::{env, thread, time::Duration};

use fido_core::{Aaguid, DeviceListSnapshot};
use fido_service::{DiscoveryCoordinator, DiscoveryPolicy, spawn_libfido2_worker};
use fido_worker_protocol::WorkerGeneration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let watch = env::args().skip(1).any(|argument| argument == "--watch");
    let generation = WorkerGeneration(1);
    let endpoint = spawn_libfido2_worker(generation)?;
    let mut coordinator =
        DiscoveryCoordinator::new(endpoint, generation, DiscoveryPolicy::default())?;

    if watch {
        println!("FidoManager discovery watch started; press Ctrl+C to stop.");
        loop {
            let snapshot = coordinator.refresh()?;
            print_snapshot(&snapshot);
            thread::sleep(Duration::from_secs(1));
        }
    }

    let snapshot = coordinator.refresh()?;
    print_snapshot(&snapshot);
    Ok(())
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
