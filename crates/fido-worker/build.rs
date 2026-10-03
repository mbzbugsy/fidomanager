use std::{env, path::PathBuf};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "macos"
        && env::var_os("CARGO_FEATURE_NATIVE_LIBFIDO2").is_some()
    {
        // Developer/CI evidence only, never bundled or emitted by the application. The link map
        // identifies the exact private archive/object that supplies the patched identity probe.
        let map = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("native-link.map");
        println!(
            "cargo:rustc-link-arg-bin=fido-worker=-Wl,-map,{}",
            map.display()
        );
    }
}
