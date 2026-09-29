mod commands;

use tauri::Manager;

pub fn run() {
    let result = tauri::Builder::default()
        // Security invariant: single-instance is registered before any future plugin.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Second-launch arguments are intentionally ignored: they are untrusted input.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .invoke_handler(tauri::generate_handler![commands::foundation_status])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("failed to run FidoManager: {error}");
        std::process::exit(1);
    }
}
