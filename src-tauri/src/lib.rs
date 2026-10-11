#[cfg(all(
    feature = "native-pin",
    not(feature = "native-ui-spike"),
    target_os = "macos"
))]
mod authentication;
mod commands;
#[cfg(all(feature = "native-ui-spike", target_os = "macos"))]
mod native_ui_spike;
#[cfg(all(
    feature = "native-pin",
    not(feature = "native-ui-spike"),
    target_os = "macos"
))]
mod pin_mutation;
#[cfg(all(feature = "macos-app-sandbox", not(feature = "macos-shared-authority")))]
mod sandbox_instance;

#[cfg(all(feature = "macos-app-sandbox", not(target_os = "macos")))]
compile_error!("the macos-app-sandbox flavor is macOS-only (ADR-018)");
#[cfg(all(feature = "macos-shared-authority", not(target_os = "macos")))]
compile_error!("macos-shared-authority is macOS-only");
use std::sync::{Arc, Mutex};

#[cfg(any(
    not(feature = "macos-shared-authority"),
    all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    )
))]
use tauri::Manager;

/// Discovery authority. It supervises a killable child worker process: the application process
/// itself never links libfido2 or runs native FIDO code.
type DiscoveryAuthority = fido_service::DiscoverySupervisor<fido_service::ProcessWorkerLauncher>;

pub(crate) struct AppState {
    discovery: Arc<Mutex<DiscoveryAuthority>>,
    inspection: Arc<Mutex<fido_service::inspection::InspectionStore>>,
    // Status only. Isolated from every FIDO type; nothing here is consulted by any local
    // operation, and no value from it is ever an input to authentication.
    boogoocypher: Arc<boogoocypher_status::ReadinessService<boogoocypher_status::ReqwestTransport>>,
    // Presentation only: start-slot suppression, per-key activity and outcome text. Never
    // consulted for authorization or admission; the sensitive-workflow gate stays authoritative.
    activity: Arc<fido_service::activity::ActivityTracker>,
    // Historical display facts only; not grants and never checked by authentication admission.
    verification_history: Arc<Mutex<std::collections::BTreeSet<[u8; 32]>>>,
    #[cfg(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    ))]
    authentication: Arc<fido_service::authentication::AuthenticationAuthority>,
    #[cfg(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    ))]
    authentication_menu: Mutex<Option<authentication::AuthenticationMenu>>,
}

fn enforce_store_worker_gate() {
    #[cfg(all(feature = "macos-shared-authority", feature = "macos-app-sandbox"))]
    {
        eprintln!("production sandbox worker authenticity remains unvalidated (ADR-018 G4)");
        std::process::exit(1);
    }
}

pub fn run() {
    // Production identity validation and OS-resolved shared flock precede recovery, UI, IPC,
    // plugins, discovery and worker initialization. No legacy or empty per-channel fallback.
    #[cfg(all(target_os = "macos", feature = "macos-shared-authority"))]
    let mut shared_authority = match fido_service::shared_authority::SharedAuthority::production(
        cfg!(feature = "macos-app-sandbox"),
    ) {
        Ok(authority) => authority,
        Err(fido_service::shared_authority::SharedAuthorityError::AlreadyHeld) => {
            std::process::exit(0)
        }
        Err(_) => {
            eprintln!("shared recovery authority unavailable; startup refused");
            std::process::exit(1);
        }
    };
    let authentication_authority = Arc::new(
        fido_service::authentication::AuthenticationAuthority::awaiting_recovery_startup(),
    );
    #[cfg(all(target_os = "macos", feature = "macos-shared-authority"))]
    if shared_authority
        .initialize(&authentication_authority)
        .is_err()
    {
        eprintln!("shared recovery initialization unavailable; startup refused");
        std::process::exit(1);
    }
    // MAS.2/G4 must independently establish store worker authenticity. Never launch a
    // production sandbox worker using UnsignedDevelopment while that gate remains open.
    enforce_store_worker_gate();

    // The worker executable is resolved from the directory of this executable (the place a Tauri
    // sidecar is bundled, and where Cargo puts the sibling binary in development). It is never
    // read from PATH, the environment, or any value the renderer can influence, and it is started
    // lazily on the first discovery request so a second instance that exits immediately never
    // spawns one.
    let launcher = match fido_service::ProcessWorkerLauncher::beside_current_exe() {
        Ok(launcher) => launcher.enable_authentication(),
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

    let auth_for_events = Arc::clone(&authentication_authority);
    #[cfg(not(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    )))]
    let auth_for_startup = Arc::clone(&authentication_authority);
    let builder = tauri::Builder::default();
    // Security invariant: single-instance is registered before any future plugin.
    #[cfg(not(any(feature = "macos-app-sandbox", feature = "macos-shared-authority")))]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        // Second-launch arguments are intentionally ignored: they are untrusted input.
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }));
    // ADR-018: the plugin's /tmp socket is denied inside the App Sandbox; use the container lock.
    #[cfg(all(feature = "macos-app-sandbox", not(feature = "macos-shared-authority")))]
    let builder = builder.plugin(sandbox_instance::init());
    let builder = builder
        .manage(AppState {
            discovery: Arc::clone(&discovery),
            inspection: Arc::new(Mutex::new(
                fido_service::inspection::InspectionStore::default(),
            )),
            boogoocypher: Arc::new(boogoocypher_status::ReadinessService::new(
                boogoocypher_status::ReqwestTransport::new(),
            )),
            activity: Arc::new(fido_service::activity::ActivityTracker::default()),
            verification_history: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            #[cfg(all(
                feature = "native-pin",
                not(feature = "native-ui-spike"),
                target_os = "macos"
            ))]
            authentication: Arc::clone(&authentication_authority),
            #[cfg(all(
                feature = "native-pin",
                not(feature = "native-ui-spike"),
                target_os = "macos"
            ))]
            authentication_menu: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            commands::foundation_status,
            commands::list_authenticators,
            commands::boogoocypher_status,
            commands::delete_credential,
        ]);
    #[cfg(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    ))]
    let builder = builder
        .setup(|app| {
            #[cfg(not(feature = "macos-shared-authority"))]
            initialize_recovery(app, &app.state::<AppState>().authentication);
            fido_service::authentication::install_lifecycle(Arc::clone(
                &app.state::<AppState>().authentication.epoch,
            ))?;
            let menu = tauri::menu::Menu::default(app.handle())?;
            let item = tauri::menu::MenuItem::with_id(
                app.handle(),
                "inspect-credentials",
                "No security key available",
                false,
                None::<&str>,
            )?;
            let submenu =
                tauri::menu::Submenu::with_items(app.handle(), "Security key", true, &[&item])?;
            menu.append(&submenu)?;
            *app.state::<AppState>()
                .authentication_menu
                .lock()
                .map_err(|_| "native menu unavailable")? =
                Some(authentication::AuthenticationMenu::new(submenu));
            app.set_menu(menu)?;
            Ok(())
        })
        .on_menu_event(|app, event| {
            if event.id().as_ref().starts_with("inspect-credentials-")
                || event.id().as_ref().starts_with("pin-mutation-")
                || event.id().as_ref() == "recover-pin"
            {
                authentication::start(app, event.id().as_ref());
            }
        })
        .on_window_event(|window, event| {
            if matches!(
                event,
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
            ) {
                window.state::<AppState>().authentication.revoke();
                fido_service::authentication::shutdown_native_prompt();
            }
        });
    #[cfg(not(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    )))]
    let builder = builder.setup(move |app| {
        #[cfg(not(feature = "macos-shared-authority"))]
        initialize_recovery(app, &auth_for_startup);
        #[cfg(feature = "macos-shared-authority")]
        let _ = (app, &auth_for_startup);
        Ok(())
    });
    let built = builder.build(tauri::generate_context!());

    let app = match built {
        Ok(app) => app,
        Err(error) => {
            eprintln!("failed to build Fido Manager: {error}");
            std::process::exit(1);
        }
    };

    app.run(move |_app_handle, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            auth_for_events.revoke();
            #[cfg(all(
                feature = "native-pin",
                not(feature = "native-ui-spike"),
                target_os = "macos"
            ))]
            fido_service::authentication::shutdown_native_prompt();
        }
        #[cfg(all(feature = "native-ui-spike", target_os = "macos"))]
        match &event {
            tauri::RunEvent::Ready => native_ui_spike::start(_app_handle),
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
                fido_service::native_ui_spike::shutdown()
            }
            _ => {}
        }
        if let tauri::RunEvent::Exit = event {
            // Deterministic cleanup: kill and reap the worker before the process ends. If a
            // discovery transaction currently holds the lock we do not wait for it; the worker's
            // own parent-death watchdog and stdin-EOF handling then end it.
            if let Ok(mut supervisor) = discovery.try_lock() {
                let _ = supervisor.shutdown();
            }
        }
    });
    #[cfg(all(target_os = "macos", feature = "macos-shared-authority"))]
    std::process::exit(0); // kernel releases shared authority only at actual process termination
}

// Framework-derived application data location only. Storage errors leave ordinary sensitive
// admission blocked while passive discovery remains available. No recovery data crosses IPC.
#[cfg(not(feature = "macos-shared-authority"))]
fn initialize_recovery(
    app: &tauri::App,
    authority: &fido_service::authentication::AuthenticationAuthority,
) {
    #[cfg(unix)]
    {
        let initialized = app
            .path()
            .app_data_dir()
            .ok()
            .is_some_and(|path| authority.initialize_recovery_at(&path).is_ok());
        if !initialized {
            eprintln!("sensitive recovery storage unavailable; admission remains blocked");
        }
    }
    #[cfg(not(unix))]
    let _ = (app, authority); // Windows journal placement remains ADR-013 work; fail closed.
}
