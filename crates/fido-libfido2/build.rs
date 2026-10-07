use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=LIBFIDO2_LIB_DIR");
    for variable in ["SDKROOT", "DEVELOPER_DIR", "PATH"] {
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
        "scripts/build-native-deps.py",
        "native/libfido2/source.lock.json",
        "native/libfido2/credman-allocation-bound.patch",
        "native/openssl/source.lock.json",
        "native/openssl/LICENSE.upstream",
        "native/libcbor/source.lock.json",
        "native/libcbor/LICENSE.upstream",
        "target/native-sources/b974e7cf2ee7392134cc12c08b76a068cf250dd8.tar.gz",
        "target/native-sources/openssl-3.5.9.tar.gz",
        "target/native-sources/libcbor-6730c20ab487c0b4dc5fb3fea918937085355bac.tar.gz",
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
    // The only native search path is the private build output. Project-unique archive names mean
    // no Homebrew/system libfido2, libcrypto or libcbor can satisfy these link requests.
    println!("cargo:rustc-link-search=native={}", output.display());
    // Keep the native archives separate from the Rust rlib so the final link map can prove the
    // exact archive/object identity instead of hiding it inside an intermediate Rust archive.
    for archive in [
        "fidomanager_fido2_bounded",
        "fidomanager_cbor",
        "fidomanager_crypto",
    ] {
        println!("cargo:rustc-link-lib=static:-bundle={archive}");
    }
    // zlib, CoreFoundation and IOKit are macOS system components.
    println!("cargo:rustc-link-lib=z");
    for framework in ["CoreFoundation", "IOKit"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
