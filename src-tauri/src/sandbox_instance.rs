//! ADR-018 single-instance authority for the macOS App Sandbox flavor.
//!
//! `tauri-plugin-single-instance` coordinates through `/tmp/<identifier>_si.sock`. Inside the App
//! Sandbox that path is outside the container, so binding it is denied
//! (`deny(1) file-write-create /private/tmp/…_si.sock`) and the plugin silently "launches
//! normally": two management authorities would run against one container. This plugin replaces it
//! in the sandbox flavor only. It takes an exclusive lock inside the framework-derived application
//! data directory, which is the same root the recovery journal uses. It runs during plugin
//! initialization, before any window, IPC command, worker spawn or recovery startup exists.
//!
//! A second process exits immediately. Launch Services already activates the running instance
//! for an ordinary second launch; only `open -n` or a direct exec reach this path. Second-launch
//! arguments are never read. If the lock cannot be established safely the process fails closed.

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager, Runtime};

struct HeldInstanceLock(#[allow(dead_code)] fido_service::instance::InstanceLock);

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("fidomanager-sandbox-instance")
        .setup(|app, _api| {
            let Ok(application_data) = app.path().app_data_dir() else {
                eprintln!("application data location unavailable; refusing to start");
                std::process::exit(1);
            };
            match fido_service::instance::InstanceLock::acquire(&application_data) {
                Ok(lock) => {
                    app.manage(HeldInstanceLock(lock));
                    Ok(())
                }
                Err(fido_service::instance::InstanceLockError::AlreadyHeld) => {
                    std::process::exit(0)
                }
                Err(fido_service::instance::InstanceLockError::Unavailable(_)) => {
                    eprintln!("single-instance lock unavailable; refusing to start");
                    std::process::exit(1);
                }
            }
        })
        .build()
}
