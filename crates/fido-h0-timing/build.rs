use std::{env, fs, path::PathBuf, process::Command};

// Links the same checksum-pinned private libfido2 archive as `fido-libfido2`, but on its own and
// only on macOS, so this measurement binary never shares a Rust dependency with production
// mutation code. The final link map is written next to the archive so the structural test can
// prove which libfido2 objects were (and were not) linked.

fn validated_pkg_config_libdir(output: &[u8]) -> Result<PathBuf, &'static str> {
    let output = std::str::from_utf8(output).map_err(|_| "invalid dependency directory UTF-8")?;
    let directory = output.strip_suffix('\n').unwrap_or(output);
    if directory.chars().any(char::is_control) {
        return Err("control character in dependency directory");
    }
    let directory = PathBuf::from(directory);
    if !directory.is_absolute() || !directory.is_dir() {
        return Err("dependency directory must be an existing absolute directory");
    }
    Ok(directory)
}

fn pinned_revision(root: &std::path::Path) -> String {
    let lock = fs::read_to_string(root.join("native/libfido2/source.lock.json"))
        .unwrap_or_else(|_| panic!("libfido2 source lock unavailable"));
    lock.lines()
        .find_map(|line| {
            let line = line.trim();
            let value = line.strip_prefix("\"revision\":")?.trim();
            Some(value.trim_matches(|c| c == '"' || c == ',').to_owned())
        })
        .filter(|revision| revision.len() == 40 && revision.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("libfido2 source lock has no valid revision"))
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let root = manifest
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| panic!("workspace root unavailable"));
    println!(
        "cargo:rerun-if-changed={}",
        root.join("native/libfido2/source.lock.json").display()
    );
    println!("cargo:rerun-if-env-changed=FIDOMANAGER_H0_CHECK_ONLY");
    println!(
        "cargo:rustc-env=FIDO_H0_LIBFIDO2_REVISION={}",
        pinned_revision(&root)
    );

    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "macos" {
        // No native FIDO library is linked anywhere else: hardware measurement is macOS only.
        return;
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("private-libfido2");
    let map = output.join("h0-link.map");
    println!("cargo:rustc-env=FIDO_H0_LINK_MAP={}", map.display());
    if env::var_os("FIDOMANAGER_H0_CHECK_ONLY").is_some() {
        // Type-check only (for example cross-checking from Linux). Linking then fails loudly;
        // there is no fallback to a system library.
        return;
    }
    for input in [
        "scripts/build-libfido2.py",
        "native/libfido2/credman-allocation-bound.patch",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(input).display());
    }
    let build = Command::new("python3")
        .arg(root.join("scripts/build-libfido2.py"))
        .args(["build", "--out-dir"])
        .arg(&output)
        .arg("--target")
        .arg(env::var("TARGET").unwrap_or_default())
        .output()
        .unwrap_or_else(|_| panic!("private libfido2 builder unavailable; Python 3 is required"));
    assert!(
        build.status.success(),
        "private libfido2 build failed (no system fallback):\n{}\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static:-bundle=fidomanager_fido2_bounded");
    for package in ["libcrypto", "libcbor"] {
        let directory = Command::new("pkg-config")
            .args(["--variable=libdir", package])
            .output()
            .unwrap_or_else(|_| panic!("pkg-config is required for native dependencies"));
        assert!(directory.status.success(), "native dependency unavailable");
        let directory = validated_pkg_config_libdir(&directory.stdout)
            .unwrap_or_else(|reason| panic!("{reason}"));
        println!("cargo:rustc-link-search=native={}", directory.display());
    }
    for library in ["crypto", "cbor", "z"] {
        println!("cargo:rustc-link-lib={library}");
    }
    for framework in ["CoreFoundation", "IOKit"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    println!(
        "cargo:rustc-link-arg-bin=fido-h0-timing=-Wl,-map,{}",
        map.display()
    );
}
