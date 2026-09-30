use std::sync::Arc;

use serde::Serialize;

use crate::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoundationStatus {
    phase: &'static str,
    worker_protocol_version: u16,
    reviewed_libfido2_baseline: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorList {
    enumeration_epoch: String,
    devices: Vec<AuthenticatorSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSummary {
    handle: String,
    generation: String,
    vendor_id: u16,
    product_id: u16,
    manufacturer: Option<String>,
    product: Option<String>,
    aaguid: Option<String>,
    versions: Vec<String>,
    extensions: Vec<String>,
    transports: Vec<String>,
    options: Vec<AuthenticatorOption>,
    max_message_size: Option<String>,
    firmware_version: Option<String>,
    read_status: String,
    freshness: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorOption {
    name: String,
    enabled: bool,
}

#[tauri::command]
pub fn foundation_status() -> FoundationStatus {
    let info = fido_service::foundation_info();
    FoundationStatus {
        phase: info.phase,
        worker_protocol_version: info.worker_protocol_version,
        reviewed_libfido2_baseline: info.reviewed_libfido2_baseline,
    }
}

#[tauri::command]
pub async fn list_authenticators(
    state: tauri::State<'_, AppState>,
) -> Result<AuthenticatorList, String> {
    let discovery = Arc::clone(&state.discovery);

    tauri::async_runtime::spawn_blocking(move || {
        let mut coordinator = discovery
            .lock()
            .map_err(|_| "native discovery authority lock is poisoned".to_owned())?;
        let snapshot = coordinator.refresh().map_err(|error| error.to_string())?;

        let devices = snapshot
            .devices
            .into_iter()
            .map(|device| AuthenticatorSummary {
                handle: format!("{:032x}", device.handle.as_raw()),
                generation: device.generation.0.to_string(),
                vendor_id: device.vendor_id,
                product_id: device.product_id,
                manufacturer: device.manufacturer,
                product: device.product,
                aaguid: device
                    .aaguid
                    .map(|value| format!("{:032x}", u128::from_be_bytes(*value.as_bytes()))),
                versions: device.versions,
                extensions: device.extensions,
                transports: device.transports,
                options: device
                    .options
                    .into_iter()
                    .map(|option| AuthenticatorOption {
                        name: option.name,
                        enabled: option.enabled,
                    })
                    .collect(),
                max_message_size: device.max_message_size.map(|value| value.to_string()),
                firmware_version: device.firmware_version.map(|value| value.to_string()),
                read_status: format!("{:?}", device.read_status),
                freshness: format!("{:?}", device.freshness),
            })
            .collect();

        Ok(AuthenticatorList {
            enumeration_epoch: snapshot.enumeration_epoch.0.to_string(),
            devices,
        })
    })
    .await
    .map_err(|error| format!("native discovery task failed: {error}"))?
}
