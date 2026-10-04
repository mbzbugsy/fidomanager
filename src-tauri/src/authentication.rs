//! Backend-only native menu entry. The WebView cannot invoke it or provide any parameters.
use crate::AppState;
use fido_service::authentication;
use std::sync::{Arc, Mutex};
use tauri::Manager;

#[derive(Clone, PartialEq, Eq)]
pub struct NativeTarget {
    id: String,
    handle: authentication::DeviceHandle,
    label: String,
}
impl NativeTarget {
    pub fn new(
        handle: authentication::DeviceHandle,
        presentation: &fido_service::presentation::AuthenticatorPresentation,
    ) -> Self {
        Self {
            // Backend-owned event identity only; never displayed or accepted from the renderer.
            id: format!("inspect-credentials-{:032x}", handle.as_raw()),
            handle,
            label: presentation.label(),
        }
    }
}

fn select_target(targets: &[NativeTarget], id: &str) -> Option<NativeTarget> {
    targets.iter().find(|target| target.id == id).cloned()
}

#[derive(Clone)]
pub struct AuthenticationMenu {
    submenu: tauri::menu::Submenu<tauri::Wry>,
    targets: Arc<Mutex<Vec<NativeTarget>>>,
}
impl AuthenticationMenu {
    pub fn new(submenu: tauri::menu::Submenu<tauri::Wry>) -> Self {
        Self {
            submenu,
            targets: Arc::new(Mutex::new(Vec::new())),
        }
    }
    pub fn update(&self, targets: Vec<NativeTarget>) {
        let owned = self.clone();
        let app = self.submenu.app_handle().clone();
        let callback_app = app.clone();
        let _ = app.run_on_main_thread(move || {
            if owned.targets.lock().is_ok_and(|old| *old == targets) {
                return;
            }
            let update = (|| -> tauri::Result<()> {
                while owned.submenu.remove_at(0)?.is_some() {}
                if targets.is_empty() {
                    let item = tauri::menu::MenuItem::new(
                        &callback_app,
                        "No security key available",
                        false,
                        None::<&str>,
                    )?;
                    owned.submenu.append(&item)?;
                } else {
                    for target in &targets {
                        let item = tauri::menu::MenuItem::with_id(
                            &callback_app,
                            &target.id,
                            format!("Inspect credentials on {}…", target.label),
                            true,
                            None::<&str>,
                        )?;
                        owned.submenu.append(&item)?;
                    }
                }
                Ok(())
            })();
            if let Ok(mut current) = owned.targets.lock() {
                // A failed/partial native menu update cannot authorize any target.
                *current = if update.is_ok() { targets } else { Vec::new() };
            }
        });
    }
    fn select(&self, id: &str) -> Option<NativeTarget> {
        select_target(&self.targets.lock().ok()?, id)
    }
}

fn notice(app: &tauri::AppHandle, message: &'static str) {
    if let Ok(mut value) = app.state::<AppState>().authentication_notice.lock() {
        // Presentation revision only: it cannot identify or authorize an acquisition.
        value.0 = value.0.saturating_add(1);
        value.1 = Some(message);
    }
}

pub fn start(app: &tauri::AppHandle, id: &str) {
    let state = app.state::<AppState>();
    let target = state
        .authentication_menu
        .lock()
        .ok()
        .and_then(|menu| menu.as_ref()?.select(id));
    let Some(target) = target else {
        return;
    };
    let authority = Arc::clone(&state.authentication);
    let reservation = match authority.reserve() {
        Ok(reservation) => reservation,
        Err(error) => {
            eprintln!("[authentication] admission={error}");
            notice(
                app,
                "Authentication cannot start while another workflow, cooldown or recovery barrier is active.",
            );
            return;
        }
    };
    let discovery = Arc::clone(&state.discovery);
    let app = app.clone();
    std::thread::spawn(move || {
        let mut supervisor = match discovery.lock() {
            Ok(supervisor) => supervisor,
            // Retain gate on poisoned owner; never imply cleanup.
            Err(_) => {
                eprintln!("[authentication] authority unavailable");
                notice(&app, "Authentication unavailable. Recovery is required.");
                return;
            }
        };
        // Refresh before using the native-menu selection. Stale handles are rejected, never
        // rebound to another key. Other connected keys cannot change the selected target.
        let snapshot = match supervisor.refresh() {
            Ok(snapshot) if snapshot.devices.iter().any(|d| d.handle == target.handle) => snapshot,
            _ => {
                authority.cancel_unpresented(&mut supervisor, reservation);
                eprintln!("[authentication] selected key is unavailable");
                notice(
                    &app,
                    "The selected security key is no longer available. Select it again from the native menu after discovery recovers.",
                );
                return;
            }
        };
        let Some(index) = snapshot
            .devices
            .iter()
            .position(|d| d.handle == target.handle)
        else {
            return;
        };
        let device = &snapshot.devices[index];
        let handle = device.handle;
        let history_id = device.verification_history_id;
        let target_label =
            fido_service::presentation::authenticator_presentations(&snapshot.devices)[index]
                .label();
        let snapshot_label = target_label.clone();
        let presenter_app = app.clone();
        let mut result = authority.inspect(
            &mut supervisor,
            handle,
            reservation,
            move |request, controller, reply, retries, epoch, expected| {
                presenter_app
                    .clone()
                    .run_on_main_thread(move || {
                        let binding = request.binding();
                        if let Some(window) = presenter_app.get_webview_window("main") {
                            if let Ok(parent) = window.ns_window() {
                                // SAFETY: live main NSWindow from trusted Tauri registry on main thread.
                                if unsafe {
                                    authentication::present(
                                        parent,
                                        request,
                                        Arc::clone(&controller),
                                        reply.clone(),
                                        retries,
                                        (epoch, expected),
                                        &target_label,
                                    )
                                }
                                .is_ok()
                                {
                                    return;
                                }
                            }
                        }
                        authentication::presentation_failed(binding, controller, reply);
                    })
                    .map_err(|_| "main thread unavailable")
            },
        );
        if let Ok(mut store) = app.state::<AppState>().inspection.lock() {
            store.clear();
            if let Some(inventory) = result.inventory.take() {
                let assessment = inventory.assess();
                if store.replace(handle, snapshot_label, inventory).is_ok() {
                    eprintln!(
                        "[inspection] snapshot={:?} total_kind={} mutation_issued=false",
                        assessment.completeness,
                        match assessment.total {
                            fido_service::inspection::CredentialTotal::Exact(_) => "exact",
                            fido_service::inspection::CredentialTotal::AtLeast(_) => "at_least",
                            _ => "unknown",
                        }
                    );
                } else {
                    result.status = authentication::Status::Uncertain;
                }
            }
        } else {
            result.status = authentication::Status::Uncertain;
        }
        // Only typed categories and booleans. No native paths, PIN, tokens, account metadata.
        eprintln!(
            "[authentication] status={:?} grant={:?} attached_puat_cleared={} worker_quiescent={} prompt_torn_down={}",
            result.status,
            result.grant_kind,
            result.attached_puat_cleared,
            result.worker_quiescent,
            result.prompt_torn_down
        );
        if let Some(id) = history_id {
            if let Ok(mut history) = app.state::<AppState>().verification_history.lock() {
                history.remove(&id);
                if result.status == authentication::Status::Validated
                    && result.attached_puat_cleared
                    && result.worker_quiescent
                    && result.prompt_torn_down
                {
                    history.insert(id);
                }
            }
        }
        // This message is display history, never durable authenticated/approved state. Only
        // fixed backend text crosses the existing read-only foundation-status DTO.
        let message = if result.inspection_error.is_some() {
            match result.inspection_error {
                Some(fido_service::inspection::InspectionError::BoundExceeded) => {
                    "Credential inventory exceeds supported application bounds. No snapshot was stored."
                }
                Some(fido_service::inspection::InspectionError::Malformed) => {
                    "The authenticator returned malformed inventory. No snapshot was stored."
                }
                Some(fido_service::inspection::InspectionError::CleanupFailed) => {
                    "Cleanup could not be proven. The worker was discarded; no snapshot was stored."
                }
                Some(fido_service::inspection::InspectionError::Unsupported) => {
                    "Credential inspection is unsupported for this authenticator."
                }
                Some(fido_service::inspection::InspectionError::DeviceAbsent) => {
                    "The authenticator disconnected during inspection."
                }
                Some(
                    fido_service::inspection::InspectionError::Busy
                    | fido_service::inspection::InspectionError::AccessDenied,
                ) => "The authenticator is busy or access was denied.",
                Some(fido_service::inspection::InspectionError::TimedOut) => {
                    "Credential inspection timed out; the worker was discarded."
                }
                _ => "Credential inspection failed. No successful empty inventory was substituted.",
            }
        } else if !result.worker_quiescent || !result.prompt_torn_down {
            "Authentication outcome uncertain. Recovery is required before another attempt."
        } else {
            use authentication::Status;
            match result.status {
                Status::Validated if result.attached_puat_cleared => {
                    "Credential inspection finished. Temporary authorization cleared; the read-only inventory is available below."
                }
                Status::WrongPin => {
                    "Incorrect PIN. The attempt ended; no automatic retry was made."
                }
                Status::PinBlocked => "PIN blocked. The attempt ended.",
                Status::PinAuthBlocked => "PIN authentication blocked. The attempt ended.",
                Status::Cancelled => "Authentication cancelled.",
                Status::Revoked => "Authentication ended because local authority was lost.",
                Status::TimedOut => "Authentication timed out. No automatic retry was made.",
                Status::Unsupported => {
                    "Authentication is unavailable for this key or native session."
                }
                Status::CleanupFailed => {
                    "Temporary authorization cleanup could not be proven. The worker was discarded."
                }
                _ => "Authentication outcome uncertain. No automatic retry was made.",
            }
        };
        notice(&app, message);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_service::presentation::AuthenticatorPresentation;

    #[test]
    fn native_labels_do_not_route_targets_and_stale_ids_fail_closed() {
        let presentation = AuthenticatorPresentation {
            name: "Security Key(F829)".to_owned(),
            detail: "Thetis · USB".to_owned(),
            transports: vec!["USB".to_owned()],
        };
        let first = NativeTarget::new(authentication::DeviceHandle::from_raw(9), &presentation);
        let second = NativeTarget::new(authentication::DeviceHandle::from_raw(10), &presentation);
        let targets = [first.clone(), second.clone()];
        assert_eq!(first.label, "Security Key(F829) · Thetis · USB");
        assert_eq!(first.label, second.label);
        assert!(!format!("Inspect credentials on {}…", first.label).contains("00000009"));
        assert!(!format!("Inspect credentials on {}…", second.label).contains("0000000a"));
        assert_eq!(
            select_target(&targets, &first.id).map(|t| t.handle),
            Some(first.handle)
        );
        assert_eq!(
            select_target(&targets, &second.id).map(|t| t.handle),
            Some(second.handle)
        );
        assert!(select_target(&targets, &first.label).is_none());
        let replacement = [NativeTarget::new(
            authentication::DeviceHandle::from_raw(11),
            &presentation,
        )];
        assert!(select_target(&replacement, &first.id).is_none());
        assert!(select_target(&replacement, &second.id).is_none());
    }
}
