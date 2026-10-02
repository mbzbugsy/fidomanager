//! Explicit local CLI opt-in, compiled only with the debug-only native-ui-spike feature.
//! No invoke handler, capability, event, or frontend schema is added.

use fido_service::native_ui_spike::{self as authority, SpikeResult};
use tauri::Manager;

pub fn start(app: &tauri::AppHandle) {
    let scenario =
        std::env::args().find_map(|arg| arg.strip_prefix("--native-ui-spike=").map(str::to_owned));
    let Some(scenario) = scenario else {
        return;
    };
    let expected = match scenario.as_str() {
        "manual" => None,
        "native-cancel" | "cancel" => Some(SpikeResult::Cancelled),
        "native-continue" => Some(SpikeResult::Approved),
        "timeout" => Some(SpikeResult::TimedOut),
        "teardown" => Some(SpikeResult::TornDown),
        "parent-close" | "replace-parent" => Some(SpikeResult::ParentLost),
        "shutdown" => Some(SpikeResult::Shutdown),
        _ => {
            eprintln!("[native-ui-spike] unknown scenario");
            return;
        }
    };
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let _ = window.show();
    let _ = window.set_focus();
    let app = app.clone();
    // Give the real Tauri window one normal event-loop turn to map and become foreground.
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let action_window = window.clone();
        let action_scenario = scenario.clone();
        let _ = app.run_on_main_thread(move || {
            eprintln!("[native-ui-spike] scenario={action_scenario}");
            if let Ok(parent) = action_window.ns_window() {
                // SAFETY: obtained on main thread from the trusted Tauri window registry.
                if let Err(e) = unsafe { authority::start(parent, action_scenario == "timeout") } {
                    eprintln!("[native-ui-spike] presentation rejected: {e}");
                }
            }
        });
        let Some(expected) = expected else {
            return;
        };
        std::thread::sleep(std::time::Duration::from_secs(1));
        let action_app = app.clone();
        let _ = app.run_on_main_thread(move || match scenario.as_str() {
            "native-cancel" => authority::exercise_native_button(false),
            "native-continue" => authority::exercise_native_button(true),
            "cancel" => authority::cancel(),
            "teardown" => authority::teardown(),
            "parent-close" | "replace-parent" => {
                // Keep an independent window alive to observe parent loss before application
                // shutdown. A replacement has a different native identity and no transferred
                // sheet, result, or renderer capability. Close the original real main window.
                let title = if scenario == "replace-parent" {
                    "Fido Manager — replacement window spike"
                } else {
                    "Fido Manager — parent-loss observer"
                };
                let _ = tauri::WebviewWindowBuilder::new(
                    &action_app,
                    "spike-observer",
                    tauri::WebviewUrl::default(),
                )
                .title(title)
                .build();
                let _ = window.destroy();
            }
            "shutdown" => action_app.exit(0),
            _ => {}
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Some(observed) = authority::result() {
                let passed = observed == expected;
                eprintln!(
                    "[native-ui-spike] scenario passed={passed} expected={expected:?} observed={observed:?}"
                );
                app.exit(if passed { 0 } else { 1 });
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        eprintln!("[native-ui-spike] no terminal result after native teardown; FAIL");
        app.exit(1);
    });
}
