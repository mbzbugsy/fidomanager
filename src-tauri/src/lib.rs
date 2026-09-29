mod commands;

use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        // Security invariant: single-instance is registered before any future plugin.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Second-launch arguments are intentionally ignored: they are untrusted input.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .invoke_handler(tauri::generate_handler![commands::foundation_status])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| panic!("failed to run FidoManager: {error}"));
}
