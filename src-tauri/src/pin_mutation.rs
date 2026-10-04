//! Only trusted native menu routing enters this module. No Tauri command or renderer parameters.
use crate::{
    AppState,
    authentication::{AuthenticationMenu, MenuBusy, NativeAction, NativeTarget},
};
use fido_service::{
    activity::{self, ActivityOutcome},
    mutation,
};
use std::sync::Arc;
use tauri::Manager;

pub(super) fn start(
    app: &tauri::AppHandle,
    target: NativeTarget,
    menu: Option<AuthenticationMenu>,
) {
    let state = app.state::<AppState>();
    let Some(claim) = state.activity.try_claim() else {
        return;
    };
    let menu_busy = MenuBusy::new(menu.clone());
    let authority = Arc::clone(&state.authentication);
    let discovery = Arc::clone(&state.discovery);
    let app = app.clone();
    std::thread::spawn(move || {
        let _menu_busy = menu_busy;
        let Ok(mut supervisor) = discovery.lock() else {
            claim.finish(ActivityOutcome::Issue(activity::RESTART_NEEDED));
            return;
        };
        if target.action == NativeAction::Recovery {
            let presenter_app = app.clone();
            let result = authority.acknowledge_pin_recovery(
                &mut supervisor,
                move |request, controller, reply, operation, epoch, expected| {
                    let callback_app = presenter_app.clone();
                    presenter_app.run_on_main_thread(move || {
                        let binding = request.binding();
                        if let Some(window) = callback_app.get_webview_window("main") {
                            if let Ok(parent) = window.ns_window() {
                                // SAFETY: trusted live main NSWindow on its AppKit main thread.
                                if unsafe {
                                    mutation::present_recovery(
                                        parent,
                                        request,
                                        Arc::clone(&controller),
                                        reply.clone(),
                                        operation,
                                        (epoch, expected),
                                        "The incident record does not identify a reconnected physical key. PIN configuration of the previous key cannot be established.",
                                    )
                                }.is_ok() {
                                    return;
                                }
                            }
                        }
                        mutation::presentation_failed(binding, controller, reply);
                    }).map_err(|_| "main thread unavailable")
                },
            );
            if let Some(menu) = &menu {
                menu.update(Vec::new(), &authority);
            }
            claim.finish(if result.is_ok() {
                ActivityOutcome::Success(
                    "Uncertainty acknowledged. The previous PIN result remains unconfirmed.",
                )
            } else {
                ActivityOutcome::Issue(
                    "The PIN result remains unconfirmed. Review it from the Security key menu.",
                )
            });
            return;
        }
        let NativeAction::Pin(operation) = target.action else {
            return;
        };
        let Ok(snapshot) = supervisor.refresh() else {
            claim.finish(ActivityOutcome::Issue(activity::KEY_UNAVAILABLE));
            return;
        };
        let Some(index) = snapshot
            .devices
            .iter()
            .position(|d| d.handle == target.handle)
        else {
            claim.finish(ActivityOutcome::Issue(activity::KEY_DISCONNECTED));
            return;
        };
        if mutation::native_pin_operation(&snapshot.devices[index]) != Some(operation) {
            claim.finish(ActivityOutcome::Issue(
                "PIN operation is no longer available on this security key.",
            ));
            return;
        }
        let Some(worker) = supervisor.status().worker_generation else {
            claim.finish(ActivityOutcome::Issue(activity::KEY_UNAVAILABLE));
            return;
        };
        let state = app.state::<AppState>();
        let devices = state
            .inspection
            .lock()
            .ok()
            .and_then(|mut store| store.reconcile_connected(&snapshot.devices, worker).ok());
        let Some(devices) = devices else {
            claim.finish(ActivityOutcome::Issue(activity::INVENTORY_UNAVAILABLE));
            return;
        };
        state.activity.retain_connected(&devices);
        claim.target(devices[index]);
        // Preserve unrelated cards; invalidate only the selected key's historical authentication.
        if let Some(id) = snapshot.devices[index].verification_history_id {
            if let Ok(mut history) = state.verification_history.lock() {
                history.remove(&id);
            }
        }
        let reservation =
            match authority.reserve_pin_intent(&mut supervisor, target.handle, operation) {
                Ok(r) => r,
                Err(_) => {
                    claim.finish(ActivityOutcome::Issue(
                        "Security key operation cannot start. Review the Security key menu.",
                    ));
                    return;
                }
            };
        let label = fido_service::presentation::authenticator_presentations(&snapshot.devices)
            [index]
            .label();
        let presenter_app = app.clone();
        let sheet_label = label.clone();
        let result = authority.mutate_pin(
            &mut supervisor,
            reservation,
            move |request, controller, reply, operation, retries, epoch, expected| {
                let callback_app = presenter_app.clone();
                presenter_app
                    .run_on_main_thread(move || {
                        let binding = request.binding();
                        if let Some(window) = callback_app.get_webview_window("main") {
                            if let Ok(parent) = window.ns_window() {
                                // SAFETY: exact trusted target/operation and live main NSWindow, on main thread.
                                if unsafe {
                                    mutation::present_mutation(
                                        parent,
                                        request,
                                        Arc::clone(&controller),
                                        reply.clone(),
                                        (operation, retries),
                                        (epoch, expected),
                                        &sheet_label,
                                    )
                                }
                                .is_ok()
                                {
                                    return;
                                }
                            }
                        }
                        mutation::presentation_failed(binding, controller, reply);
                    })
                    .map_err(|_| "main thread unavailable")
            },
        );
        if let Ok(mut store) = state.inspection.lock() {
            if result.worker_quiescent {
                store.proven_retirement(worker);
            } else {
                store.clear();
            }
        }
        if let Some(menu) = &menu {
            menu.update(Vec::new(), &authority);
        }
        // Categories only: no secret length, native path, request identity or PIN.
        eprintln!(
            "[pin-mutation] operation={operation:?} outcome={:?} worker_quiescent={} prompt_torn_down={} recovery_required={}",
            result.outcome,
            result.worker_quiescent,
            result.prompt_torn_down,
            result.recovery_required
        );
        claim.finish_pin(&label, mutation::activity_outcome(operation, &result));
    });
}
