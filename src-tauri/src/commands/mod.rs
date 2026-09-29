use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoundationStatus {
    phase: &'static str,
    worker_protocol_version: u16,
    reviewed_libfido2_baseline: &'static str,
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
