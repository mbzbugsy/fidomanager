use std::{env, path::PathBuf, process::Command};

fn validated_pkg_config_libdir(output: &[u8]) -> Result<PathBuf, &'static str> {
    let output = std::str::from_utf8(output).map_err(|_| "invalid dependency directory UTF-8")?;
    // pkg-config terminates its output with LF. Consume exactly that record terminator,
    // preserving path whitespace and rejecting any remaining control characters.
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

fn main() {
    println!("cargo:rerun-if-env-changed=LIBFIDO2_LIB_DIR");
    for variable in [
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_LIBDIR",
        "PKG_CONFIG_SYSROOT_DIR",
        "SDKROOT",
        "DEVELOPER_DIR",
        "PATH",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    if env::var_os("CARGO_FEATURE_NATIVE_LIBFIDO2").is_none() {
        return;
    }
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "macos" {
        // Linux discovery retains its existing system-library policy; native PUAT is macOS only.
        if let Some(directory) = env::var_os("LIBFIDO2_LIB_DIR") {
            println!(
                "cargo:rustc-link-search=native={}",
                PathBuf::from(directory).display()
            );
        }
        return;
    }
    assert!(
        env::var_os("LIBFIDO2_LIB_DIR").is_none(),
        "macOS production forbids system libfido2 directory overrides"
    );
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default())
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| panic!("workspace root unavailable"));
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("private-libfido2");
    for input in [
        "scripts/build-libfido2.py",
        "native/libfido2/source.lock.json",
        "native/libfido2/credman-allocation-bound.patch",
        "target/native-sources/b974e7cf2ee7392134cc12c08b76a068cf250dd8.tar.gz",
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
    // Keep the native archive separate from the Rust rlib so the final link map can prove the
    // exact archive/object identity instead of hiding it inside an intermediate Rust archive.
    println!("cargo:rustc-link-lib=static:-bundle=fidomanager_fido2_bounded");
    // Only transitive crypto/CBOR dependencies use pkg-config; never query libfido2 here.
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
}

#[cfg(test)]
mod tests {
    use super::validated_pkg_config_libdir;
    use std::{env, fs, path::PathBuf};

    #[test]
    fn dependency_libdir_rejects_invalid_output_before_cargo_emission() {
        let root = PathBuf::from(env::var_os("FIDOMANAGER_LIBDIR_TEST_ROOT").unwrap());
        assert!(root.is_dir());
        let directory = root.to_str().unwrap();
        for output in [directory.to_owned(), format!("{directory}\n")] {
            assert_eq!(
                validated_pkg_config_libdir(output.as_bytes()),
                Ok(root.clone())
            );
        }
        let file = root.join("regular-file");
        fs::write(&file, b"not a directory").unwrap();
        for output in [
            format!("{directory}\n\n"),
            format!("{directory}\r"),
            format!("{directory}\r\n"),
            format!("{directory}\ncargo:rustc-link-lib=fido2\n"),
            format!("{directory}\t"),
            format!("{directory}\0"),
            format!("{directory}\u{0085}"),
        ] {
            assert_eq!(
                validated_pkg_config_libdir(output.as_bytes()),
                Err("control character in dependency directory"),
                "{output:?}"
            );
        }
        for output in [
            "relative-directory".to_owned(),
            String::new(),
            root.join("missing-directory").to_str().unwrap().to_owned(),
            file.to_str().unwrap().to_owned(),
        ] {
            assert_eq!(
                validated_pkg_config_libdir(output.as_bytes()),
                Err("dependency directory must be an existing absolute directory"),
                "{output:?}"
            );
        }
        assert_eq!(
            validated_pkg_config_libdir(&[0xff]),
            Err("invalid dependency directory UTF-8")
        );
    }
}
