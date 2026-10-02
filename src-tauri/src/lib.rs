mod commands;

use std::sync::{Arc, Mutex};

use tauri::Manager;

type DiscoveryAuthority = fido_service::DiscoveryCoordinator<fido_service::InProcessWorkerEndpoint>;

pub(crate) struct AppState {
    discovery: Arc<Mutex<DiscoveryAuthority>>,
}

pub fn run() {
    let worker_generation = fido_service::WorkerGeneration(1);
    let endpoint = match fido_service::spawn_libfido2_worker(worker_generation) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            eprintln!("failed to start native FIDO worker: {error}");
            std::process::exit(1);
        }
    };
    let discovery = match fido_service::DiscoveryCoordinator::new(
        endpoint,
        worker_generation,
        fido_service::DiscoveryPolicy::default(),
    ) {
        Ok(coordinator) => Arc::new(Mutex::new(coordinator)),
        Err(error) => {
            eprintln!("failed to initialize native discovery: {error}");
            std::process::exit(1);
        }
    };

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
        .manage(AppState { discovery })
        .invoke_handler(tauri::generate_handler![
            commands::foundation_status,
            commands::list_authenticators,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("failed to run FidoManager: {error}");
        std::process::exit(1);
    }
}
