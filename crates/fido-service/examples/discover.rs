use fido_service::{DiscoveryCoordinator, DiscoveryPolicy, spawn_libfido2_worker};
use fido_worker_protocol::WorkerGeneration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generation = WorkerGeneration(1);
    let endpoint = spawn_libfido2_worker(generation)?;
    let mut coordinator =
        DiscoveryCoordinator::new(endpoint, generation, DiscoveryPolicy::default())?;
    let snapshot = coordinator.refresh()?;

    println!(
        "FidoManager native discovery: {} device(s)",
        snapshot.devices.len()
    );
    for device in snapshot.devices {
        println!(
            "- {:04x}:{:04x} {} {} status={:?} aaguid={:?} versions={:?} transports={:?}",
            device.vendor_id,
            device.product_id,
            device.manufacturer.as_deref().unwrap_or("<unknown>"),
            device.product.as_deref().unwrap_or("<unknown>"),
            device.read_status,
            device.aaguid,
            device.versions,
            device.transports,
        );
    }

    Ok(())
}
