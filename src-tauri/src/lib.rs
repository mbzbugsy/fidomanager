#[cfg(all(
    feature = "native-pin",
    not(feature = "native-ui-spike"),
    target_os = "macos"
))]
mod authentication;
mod commands;
#[cfg(all(feature = "native-ui-spike", target_os = "macos"))]
mod native_ui_spike;

use std::sync::{Arc, Mutex};

use tauri::Manager;

/// Discovery authority. It supervises a killable child worker process: the application process
/// itself never links libfido2 or runs native FIDO code.
type DiscoveryAuthority = fido_service::DiscoverySupervisor<fido_service::ProcessWorkerLauncher>;

pub(crate) struct AppState {
    discovery: Arc<Mutex<DiscoveryAuthority>>,
    // Presentation history only; never consulted for authorization or workflow admission.
    authentication_notice: Arc<Mutex<(u64, Option<&'static str>)>>,
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

pub fn run() {
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

    let authentication_authority =
        Arc::new(fido_service::authentication::AuthenticationAuthority::default());
    let auth_for_events = Arc::clone(&authentication_authority);
    let builder = tauri::Builder::default()
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
            authentication_notice: Arc::new(Mutex::new((0, None))),
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
        ]);
    #[cfg(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    ))]
    let builder = builder
        .setup(|app| {
            fido_service::authentication::install_lifecycle(Arc::clone(
                &app.state::<AppState>().authentication.epoch,
            ))?;
            let menu = tauri::menu::Menu::default(app.handle())?;
            let item = tauri::menu::MenuItem::with_id(
                app.handle(),
                "validate-authentication",
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
            if event.id().as_ref().starts_with("validate-authentication-") {
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
}
