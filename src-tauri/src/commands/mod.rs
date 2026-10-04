use std::sync::Arc;

use serde::Serialize;

use crate::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoundationStatus {
    phase: &'static str,
    worker_protocol_version: u16,
    reviewed_libfido2_baseline: &'static str,
    inspection_activity: fido_service::activity::ActivityView,
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
    inspection: fido_service::inspection::InspectionDisplay,
    display_name: String,
    display_detail: String,
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
    pin_check_passed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorOption {
    name: String,
    enabled: bool,
}

#[tauri::command]
pub fn foundation_status(state: tauri::State<'_, AppState>) -> FoundationStatus {
    let info = fido_service::foundation_info();
    FoundationStatus {
        phase: info.phase,
        worker_protocol_version: info.worker_protocol_version,
        reviewed_libfido2_baseline: info.reviewed_libfido2_baseline,
        inspection_activity: state.activity.view(),
    }
}

#[tauri::command]
pub async fn list_authenticators(
    state: tauri::State<'_, AppState>,
) -> Result<AuthenticatorList, String> {
    let discovery = Arc::clone(&state.discovery);
    let inspection = Arc::clone(&state.inspection);
    let verification_history = Arc::clone(&state.verification_history);
    let activity = Arc::clone(&state.activity);
    #[cfg(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    ))]
    let native_menu = state
        .authentication_menu
        .lock()
        .ok()
        .and_then(|m| m.clone());

    tauri::async_runtime::spawn_blocking(move || {
        let mut coordinator = discovery
            .lock()
            .map_err(|_| "native discovery authority lock is poisoned".to_owned())?;
        // Lock order everywhere is discovery -> inspection. No renderer command takes a store
        // lock and then asks for discovery. Publish one coherent connected-device/inventory DTO.
        let snapshot = match coordinator.refresh() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                if let Ok(mut store) = inspection.lock() {
                    let settle = store.awaiting_retired_worker()
                        && matches!(error, fido_service::SupervisorError::RestartBackoff { .. });
                    if !settle {
                        store.clear();
                    }
                }
                return Err(error.to_string());
            }
        };
        let worker = coordinator
            .status()
            .worker_generation
            .ok_or("worker unavailable")?;
        let mut store = inspection
            .lock()
            .map_err(|_| "inspection store unavailable")?;
        let inventory_devices = store
            .reconcile_connected(&snapshot.devices, worker)
            .map_err(|_| "connected inventory unavailable")?;
        // A remembered problem belongs to a connected key's card; drop it when that key is gone.
        activity.retain_connected(
            &inventory_devices
                .iter()
                .map(|device| device.handle)
                .collect::<Vec<_>>(),
        );
        let presentations =
            fido_service::presentation::authenticator_presentations(&snapshot.devices);
        // Keep history only for uniquely identified currently connected macOS IORegistry entries.
        // Markers remain backend-only: the renderer receives a historical boolean, never a path,
        // connection hash, acquisition or reusable approval.
        let mut present = std::collections::BTreeMap::new();
        for id in snapshot
            .devices
            .iter()
            .filter_map(|d| d.verification_history_id)
        {
            *present.entry(id).or_insert(0usize) += 1;
        }
        let passed = verification_history
            .lock()
            .map(|mut history| {
                history.retain(|id| present.get(id) == Some(&1));
                history.clone()
            })
            .unwrap_or_default();

        #[cfg(all(
            feature = "native-pin",
            not(feature = "native-ui-spike"),
            target_os = "macos"
        ))]
        if let Some(menu) = native_menu {
            menu.update(
                snapshot
                    .devices
                    .iter()
                    .zip(&presentations)
                    .map(|(device, presentation)| {
                        crate::authentication::NativeTarget::new(device.handle, presentation)
                    })
                    .collect(),
            );
        }

        let devices = snapshot
            .devices
            .into_iter()
            .zip(presentations)
            .zip(inventory_devices)
            .map(
                |((device, presentation), inventory_device)| AuthenticatorSummary {
                    inspection: store.display_for(inventory_device),
                    display_name: presentation.name,
                    display_detail: presentation.detail,
                    pin_check_passed: device
                        .verification_history_id
                        .is_some_and(|id| passed.contains(&id)),
                    handle: inventory_device.handle.as_wire(),
                    generation: inventory_device.generation.0.to_string(),
                    vendor_id: device.vendor_id,
                    product_id: device.product_id,
                    manufacturer: device.manufacturer,
                    product: device.product,
                    aaguid: device
                        .aaguid
                        .map(|value| format!("{:032x}", u128::from_be_bytes(*value.as_bytes()))),
                    versions: device.versions,
                    extensions: device.extensions,
                    transports: presentation.transports,
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
                    read_status: device.read_status.as_wire_name().to_owned(),
                    freshness: device.freshness.as_wire_name().to_owned(),
                },
            )
            .collect();

        Ok(AuthenticatorList {
            enumeration_epoch: snapshot.enumeration_epoch.0.to_string(),
            devices,
        })
    })
    .await
    .map_err(|error| format!("native discovery task failed: {error}"))?
}

/// BooGooCypher readiness status only. Takes no renderer input, reads no FIDO state and returns
/// a bare typed status. The backend serves a cached result and bounds any network request.
#[tauri::command]
pub async fn boogoocypher_status(
    state: tauri::State<'_, AppState>,
) -> Result<boogoocypher_status::ReadinessStatus, String> {
    let readiness = Arc::clone(&state.boogoocypher);
    Ok(readiness.status().await)
}
