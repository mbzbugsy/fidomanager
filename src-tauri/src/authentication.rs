//! Backend-only native menu entry. The WebView cannot invoke it or provide any parameters.
use crate::AppState;
use fido_service::activity::{self, ActivityOutcome};
use fido_service::authentication;
use std::sync::atomic::{AtomicBool, Ordering};
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
    // Presentation only: the inspect items are greyed while an inspection runs. The backend gate
    // stays the authority, and a selection that still arrives is suppressed or refused there.
    enabled: Arc<AtomicBool>,
}
impl AuthenticationMenu {
    pub fn new(submenu: tauri::menu::Submenu<tauri::Wry>) -> Self {
        Self {
            submenu,
            targets: Arc::new(Mutex::new(Vec::new())),
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
        let owned = self.clone();
        let _ = self.submenu.app_handle().run_on_main_thread(move || {
            let has_targets = owned.targets.lock().is_ok_and(|t| !t.is_empty());
            if let Ok(items) = owned.submenu.items() {
                for item in items {
                    if let Some(item) = item.as_menuitem() {
                        let _ = item.set_enabled(enabled && has_targets);
                    }
                }
            }
        });
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
                            owned.enabled.load(Ordering::SeqCst),
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

/// Greys the native inspect items for exactly the lifetime of one start attempt.
struct MenuBusy(Option<AuthenticationMenu>);
impl MenuBusy {
    fn new(menu: Option<AuthenticationMenu>) -> Self {
        if let Some(menu) = &menu {
            menu.set_enabled(false);
        }
        Self(menu)
    }
}
impl Drop for MenuBusy {
    fn drop(&mut self) {
        if let Some(menu) = &self.0 {
            menu.set_enabled(true);
        }
    }
}

pub fn start(app: &tauri::AppHandle, id: &str) {
    let state = app.state::<AppState>();
    let menu = state
        .authentication_menu
        .lock()
        .ok()
        .and_then(|menu| menu.clone());
    let Some(target) = menu.as_ref().and_then(|menu| menu.select(id)) else {
        return;
    };
    // Presentation-level reentrancy guard. A duplicate or reentrant menu event while one start is
    // running is dropped silently; it would only be refused by the gate below anyway. This guard
    // authorizes nothing: every start that is not dropped here still needs gate admission.
    let Some(claim) = state.activity.try_claim() else {
        eprintln!("[authentication] duplicate start suppressed");
        return;
    };
    let menu_busy = MenuBusy::new(menu);
    let authority = Arc::clone(&state.authentication);
    let reservation = match authority.reserve() {
        Ok(reservation) => reservation,
        Err(error) => {
            eprintln!("[authentication] admission={error}");
            claim.finish(ActivityOutcome::Issue(activity::admission_message(error)));
            return;
        }
    };
    let discovery = Arc::clone(&state.discovery);
    let app = app.clone();
    std::thread::spawn(move || {
        let _menu_busy = menu_busy;
        let mut supervisor = match discovery.lock() {
            Ok(supervisor) => supervisor,
            // Retain gate on poisoned owner; never imply cleanup.
            Err(_) => {
                eprintln!("[authentication] authority unavailable");
                claim.finish(ActivityOutcome::Issue(activity::RESTART_NEEDED));
                return;
            }
        };
        // Refresh before using the native-menu selection. Stale handles are rejected, never
        // rebound to another key. Other connected keys cannot change the selected target.
        let snapshot = match supervisor.refresh() {
            Ok(snapshot) => snapshot,
            _ => {
                if let Ok(mut store) = app.state::<AppState>().inspection.lock() {
                    store.clear();
                }
                authority.cancel_unpresented(&mut supervisor, reservation);
                eprintln!("[authentication] selected key is unavailable");
                claim.finish(ActivityOutcome::Issue(activity::KEY_UNAVAILABLE));
                return;
            }
        };
        let Some(worker_generation) = supervisor.status().worker_generation else {
            authority.cancel_unpresented(&mut supervisor, reservation);
            claim.finish(ActivityOutcome::Issue(activity::KEY_UNAVAILABLE));
            return;
        };
        let inventory_devices = {
            let state = app.state::<AppState>();
            let prepared = state.inspection.lock().ok().and_then(|mut store| {
                store
                    .reconcile_connected(&snapshot.devices, worker_generation)
                    .ok()
            });
            let Some(devices) = prepared else {
                authority.cancel_unpresented(&mut supervisor, reservation);
                claim.finish(ActivityOutcome::Issue(activity::INVENTORY_UNAVAILABLE));
                return;
            };
            devices
        };
        let Some(index) = snapshot
            .devices
            .iter()
            .position(|d| d.handle == target.handle)
        else {
            let quiescent = authority.cancel_unpresented(&mut supervisor, reservation);
            if let Ok(mut store) = app.state::<AppState>().inspection.lock() {
                if quiescent == fido_service::inspection::ExecutionQuiescence::Quiescent {
                    store.proven_retirement(worker_generation);
                } else {
                    store.clear();
                }
            }
            claim.finish(ActivityOutcome::Issue(activity::KEY_DISCONNECTED));
            return;
        };
        let inventory_device = inventory_devices[index];
        if let Ok(mut store) = app.state::<AppState>().inspection.lock() {
            // Retire ONLY this key's prior view, before PIN/acquisition.
            store.invalidate(inventory_device);
        } else {
            authority.cancel_unpresented(&mut supervisor, reservation);
            claim.finish(ActivityOutcome::Issue(activity::INVENTORY_UNAVAILABLE));
            return;
        }
        // Presentation only: attribute the running attempt to this key's card.
        claim.target(inventory_device.handle);
        let device = &snapshot.devices[index];
        let handle = device.handle;
        let history_id = device.verification_history_id;
        let target_label =
            fido_service::presentation::authenticator_presentations(&snapshot.devices)[index]
                .label();
        let snapshot_label = target_label.clone();
        let presenter_app = app.clone();
        let mut result = authority.inspect_with_progress(
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
            |progress| claim.progress(progress),
        );
        if let Ok(mut store) = app.state::<AppState>().inspection.lock() {
            if result.worker_quiescent {
                store.proven_retirement(worker_generation);
            } else {
                store.clear();
            }
            if let Some(inventory) = result.inventory.take() {
                let assessment = inventory.assess();
                if store
                    .replace(inventory_device, snapshot_label, inventory)
                    .is_ok()
                {
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
        // Presentation only; never durable approved state. Only typed categories reach the UI.
        claim.finish(activity::outcome_for(&result));
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
