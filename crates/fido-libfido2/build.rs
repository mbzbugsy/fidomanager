use std::{env, path::Path};

fn main() {
    println!("cargo:rerun-if-env-changed=LIBFIDO2_LIB_DIR");

    if env::var_os("CARGO_FEATURE_NATIVE_LIBFIDO2").is_none() {
        return;
    }

    if let Some(directory) = env::var_os("LIBFIDO2_LIB_DIR") {
        println!(
            "cargo:rustc-link-search=native={}",
            Path::new(&directory).display()
        );
        return;
    }

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        for candidate in ["/opt/homebrew/lib", "/usr/local/lib", "/opt/local/lib"] {
            if Path::new(candidate).is_dir() {
                println!("cargo:rustc-link-search=native={candidate}");
            }
        }
    }
}
