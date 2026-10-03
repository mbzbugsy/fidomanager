use std::{env, path::Path};

fn main() {
    println!("cargo:rerun-if-env-changed=LIBFIDO2_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    if env::var_os("CARGO_FEATURE_NATIVE_LIBFIDO2").is_none() {
        return;
    }
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        // Pin the reviewed ABI on macOS; production links PUAT APIs by default.
        // An older runtime dylib fails loading its required symbols.
        assert!(
            env::var_os("LIBFIDO2_LIB_DIR").is_none(),
            "macOS M2 resolves the reviewed library through pkg-config, not a directory override"
        );
        assert!(
            pkg_config("--modversion").trim() == "1.17.0",
            "macOS M2 requires reviewed libfido2 1.17.0"
        );
        let directory = pkg_config("--variable=libdir");
        let directory = Path::new(directory.trim());
        assert!(
            directory.is_absolute() && directory.is_dir(),
            "invalid reviewed library directory"
        );
        println!("cargo:rustc-link-search=native={}", directory.display());
    } else if let Some(directory) = env::var_os("LIBFIDO2_LIB_DIR") {
        // Linux discovery only. No native PUAT enablement against distro 1.14.
        println!(
            "cargo:rustc-link-search=native={}",
            Path::new(&directory).display()
        );
    }
}

fn pkg_config(option: &str) -> String {
    let output = std::process::Command::new("pkg-config")
        .args([option, "libfido2"])
        .output()
        .unwrap_or_else(|_| panic!("macOS M2 requires pkg-config and libfido2 1.17.0"));
    assert!(output.status.success(), "reviewed libfido2 not found");
    String::from_utf8(output.stdout).unwrap_or_else(|_| panic!("invalid pkg-config output"))
}
