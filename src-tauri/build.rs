fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(&["foundation_status"]));

    if let Err(error) = tauri_build::try_build(attributes) {
        eprintln!("failed to run tauri-build: {error}");
        std::process::exit(1);
    }
}
