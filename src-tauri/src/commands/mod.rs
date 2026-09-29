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
    FoundationStatus {
        phase: "milestone-0-foundation",
        worker_protocol_version: fido_worker_protocol::WORKER_PROTOCOL_VERSION,
        reviewed_libfido2_baseline: fido_libfido2::REVIEWED_LIBFIDO2_BASELINE,
    }
}
