mod commands;

use std::sync::{Arc, Mutex};

use tauri::Manager;

/// Discovery authority. It supervises a killable child worker process: the application process
/// itself never links libfido2 or runs native FIDO code.
type DiscoveryAuthority = fido_service::DiscoverySupervisor<fido_service::ProcessWorkerLauncher>;

pub(crate) struct AppState {
    discovery: Arc<Mutex<DiscoveryAuthority>>,
}

pub fn run() {
    // The worker executable is resolved from the directory of this executable (the place a Tauri
    // sidecar is bundled, and where Cargo puts the sibling binary in development). It is never
    // read from PATH, the environment, or any value the renderer can influence, and it is started
    // lazily on the first discovery request so a second instance that exits immediately never
    // spawns one.
    let launcher = match fido_service::ProcessWorkerLauncher::beside_current_exe() {
        Ok(launcher) => launcher,
        Err(error) => {
            eprintln!(
                "native FIDO worker executable is unavailable: {error} \
                 (build it with `cargo build -p fido-worker`)"
            );
            std::process::exit(1);
        }
    };
    let discovery = match fido_service::DiscoverySupervisor::new(
        launcher,
        fido_service::DiscoveryPolicy::default(),
        fido_service::RestartPolicy::default(),
    ) {
        Ok(supervisor) => Arc::new(Mutex::new(supervisor)),
        Err(error) => {
            eprintln!("failed to initialize native discovery: {error}");
            std::process::exit(1);
        }
    };

    let built = tauri::Builder::default()
        // Security invariant: single-instance is registered before any future plugin.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Second-launch arguments are intentionally ignored: they are untrusted input.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(AppState {
            discovery: Arc::clone(&discovery),
        })
        .invoke_handler(tauri::generate_handler![
            commands::foundation_status,
            commands::list_authenticators,
        ])
        .build(tauri::generate_context!());

    let app = match built {
        Ok(app) => app,
        Err(error) => {
            eprintln!("failed to build Fido Manager: {error}");
            std::process::exit(1);
        }
    };

    app.run(move |_app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            // Deterministic cleanup: kill and reap the worker before the process ends. If a
            // discovery transaction currently holds the lock we do not wait for it; the worker's
            // own parent-death watchdog and stdin-EOF handling then end it.
            if let Ok(mut supervisor) = discovery.try_lock() {
                let _ = supervisor.shutdown();
            }
        }
    });
}
