//! Structural proof that the H0 timing tool cannot erase (or otherwise mutate) an authenticator.
//!
//! These checks fail if a later change adds any route to a destructive command:
//!
//! 1. sources and build script contain no destructive libfido2/CTAP identifier, no raw HID report
//!    I/O, no custom transport hook, no dynamic symbol lookup and no process spawning;
//! 2. every native declaration is in a closed allowlist (discovery, open, GetInfo, close, parsed
//!    GetInfo getters, IORegistry notifications), and only two files may declare natives;
//! 3. the crate's resolved dependency graph (Cargo.lock) is exactly the reviewed set, so no
//!    production mutation crate can arrive transitively;
//! 4. the built executable's symbol table contains no destructive libfido2 symbol (and, on macOS,
//!    does contain the read-only ones, so the absence check is not vacuous);
//! 5. on macOS, the linker map of the final executable shows libfido2's `reset.c` object was not
//!    linked, and the archive is the pinned private build.
//!
//! The scanned set deliberately excludes this test file, which must spell the forbidden names.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CRATE: &str = env!("CARGO_MANIFEST_DIR");
const BINARY: &str = env!("CARGO_BIN_EXE_fido-h0-timing");

/// Never allowed in H0 sources, build script or manifest.
const FORBIDDEN_EVERYWHERE: &[&str] = &[
    // The destructive command and every path that could emit an arbitrary CTAP frame.
    "fido_dev_reset",
    "CTAP_CBOR_RESET",
    "fido_tx",
    "fido_rx",
    "fido_dev_set_io_functions",
    "fido_dev_set_transport_functions",
    "fido_dev_io_handle",
    "fido_dev_cancel",
    // Other state-changing or PIN/UV commands (also invalidate some authenticators' post-power-up
    // permission, so they must never appear on an Option A path).
    "fido_dev_set_pin",
    "fido_dev_get_retry_count",
    "fido_dev_get_uv_retry_count",
    "fido_dev_get_puat",
    "fido_dev_make_cred",
    "fido_dev_get_assert",
    "fido_credman_",
    "fido_bio_",
    "fido_dev_largeblob_",
    "fido_dev_enable_entattest",
    "fido_dev_toggle_always_uv",
    "fido_dev_set_pin_minlen",
    "fido_dev_force_pin_change",
    // Raw HID access and dynamic loading.
    "IOHIDDeviceSetReport",
    "IOHIDDeviceOpen",
    "IOHIDDeviceCreate",
    "IOHIDManager",
    "hid_write",
    "dlopen",
    "dlsym",
    "libloading",
    // Production authority types that must not be implemented by M6.0.
    "ExecuteReset",
    "ResetDispatchPermit",
    "ResetCeremonyGrant",
    "ResetIntent",
];

/// Additionally forbidden in runtime sources (the build script legitimately runs the pinned
/// archive builder at build time).
const FORBIDDEN_IN_RUNTIME: &[&str] = &["process::Command", "Command::new", "fido2-token"];

const ALLOWED_LIBFIDO2: &[&str] = &[
    "fido_init",
    "fido_dev_info_new",
    "fido_dev_info_free",
    "fido_dev_info_manifest",
    "fido_dev_info_ptr",
    "fido_dev_info_path",
    "fido_dev_info_vendor",
    "fido_dev_info_product",
    "fido_dev_info_manufacturer_string",
    "fido_dev_info_product_string",
    "fido_dev_new",
    "fido_dev_free",
    "fido_dev_open",
    "fido_dev_close",
    "fido_dev_set_timeout",
    "fido_cbor_info_new",
    "fido_cbor_info_free",
    "fido_dev_get_cbor_info",
    "fido_cbor_info_aaguid_ptr",
    "fido_cbor_info_aaguid_len",
    "fido_cbor_info_versions_ptr",
    "fido_cbor_info_versions_len",
    "fido_cbor_info_extensions_ptr",
    "fido_cbor_info_extensions_len",
    "fido_cbor_info_options_name_ptr",
    "fido_cbor_info_options_value_ptr",
    "fido_cbor_info_options_len",
    "fido_cbor_info_maxmsgsiz",
    "fido_cbor_info_fwversion",
    "fido_cbor_info_reset_transports_ptr",
    "fido_cbor_info_reset_transports_len",
    "fido_cbor_info_long_touch_reset",
];

const ALLOWED_PLATFORM: &[&str] = &[
    "IONotificationPortCreate",
    "IONotificationPortDestroy",
    "IONotificationPortGetRunLoopSource",
    "IOServiceMatching",
    "IOServiceAddMatchingNotification",
    "IOIteratorNext",
    "IOObjectRelease",
    "kCFRunLoopDefaultMode",
    "CFRunLoopGetCurrent",
    "CFRunLoopAddSource",
    "CFRunLoopRunInMode",
    "CFNumberCreate",
    "CFStringCreateWithCString",
    "CFDictionarySetValue",
    "CFRelease",
];

const NATIVE_FILES: &[&str] = &["src/macos/fido.rs", "src/macos/insertion.rs"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn runtime_sources() -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let root = Path::new(CRATE);
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files)?;
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            Ok((relative, fs::read_to_string(&path)?))
        })
        .collect()
}

fn forbidden_hits(text: &str, forbidden: &[&str]) -> Vec<String> {
    forbidden
        .iter()
        .filter(|token| text.contains(*token))
        .map(|token| (*token).to_owned())
        .collect()
}

/// Names declared inside `extern "C" { … }` blocks (functions and statics).
fn extern_declarations(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("extern \"C\" {") {
        let body_start = start + "extern \"C\" {".len();
        let mut depth = 1usize;
        let mut end = body_start;
        for (offset, ch) in rest[body_start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = body_start + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &rest[body_start..end];
        for raw in body.split(';') {
            let tokens: Vec<&str> = raw
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .filter(|t| !t.is_empty())
                .collect();
            for pair in tokens.windows(2) {
                if pair[0] == "fn" || pair[0] == "static" {
                    names.push(pair[1].to_owned());
                    break;
                }
            }
        }
        rest = &rest[end..];
    }
    names
}

#[test]
fn sources_build_script_and_manifest_have_no_destructive_route() -> TestResult {
    let root = Path::new(CRATE);
    let mut violations = Vec::new();
    for (name, text) in runtime_sources()? {
        for hit in forbidden_hits(&text, FORBIDDEN_EVERYWHERE)
            .into_iter()
            .chain(forbidden_hits(&text, FORBIDDEN_IN_RUNTIME))
        {
            violations.push(format!("{name}: {hit}"));
        }
    }
    for name in ["build.rs", "Cargo.toml"] {
        let text = fs::read_to_string(root.join(name))?;
        for hit in forbidden_hits(&text, FORBIDDEN_EVERYWHERE) {
            violations.push(format!("{name}: {hit}"));
        }
    }
    assert!(
        violations.is_empty(),
        "forbidden capability: {violations:#?}"
    );
    Ok(())
}

#[test]
fn native_declarations_are_a_closed_allowlist() -> TestResult {
    let mut libfido2 = BTreeSet::new();
    for (name, text) in runtime_sources()? {
        let declared = extern_declarations(&text);
        if !NATIVE_FILES.contains(&name.as_str()) {
            assert!(
                declared.is_empty() && !text.contains("#[link("),
                "{name} must not declare natives: {declared:?}"
            );
            continue;
        }
        for symbol in declared {
            if symbol.starts_with("fido_") {
                assert!(
                    ALLOWED_LIBFIDO2.contains(&symbol.as_str()),
                    "{name}: libfido2 function outside the read-only allowlist: {symbol}"
                );
                libfido2.insert(symbol);
            } else {
                assert!(
                    ALLOWED_PLATFORM.contains(&symbol.as_str()),
                    "{name}: native outside the observation allowlist: {symbol}"
                );
            }
        }
        for link in text
            .match_indices("#[link(name = \"")
            .map(|(i, _)| &text[i..])
        {
            assert!(
                link.starts_with("#[link(name = \"IOKit\", kind = \"framework\")]")
                    || link.starts_with("#[link(name = \"CoreFoundation\", kind = \"framework\")]"),
                "{name}: unexpected link attribute"
            );
        }
    }
    // Every declared libfido2 function is reviewed; the declared set is the whole allowlist.
    let expected: BTreeSet<String> = ALLOWED_LIBFIDO2.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(libfido2, expected);
    Ok(())
}

#[test]
fn checker_detects_injected_destructive_declarations() {
    // Built with concat! so this file never spells a call-shaped destructive name itself (the
    // repository-wide renderer-boundary script rejects any Rust source that does).
    let injected = concat!(
        "unsafe extern \"C\" {\n    fn fido_init(flags: c_int);\n    fn fido_dev_",
        "reset(device: *mut c_void) -> c_int;\n}\n"
    );
    let declared = extern_declarations(injected);
    assert_eq!(declared, ["fido_init", "fido_dev_reset"]);
    assert!(!ALLOWED_LIBFIDO2.contains(&"fido_dev_reset"));
    assert_eq!(
        forbidden_hits(injected, FORBIDDEN_EVERYWHERE),
        ["fido_dev_reset"]
    );
    let raw = "unsafe extern \"C\" { static kCFRunLoopDefaultMode: *const c_void; fn IOHIDDeviceSetReport(d: *mut c_void) -> i32; }";
    assert_eq!(
        extern_declarations(raw),
        ["kCFRunLoopDefaultMode", "IOHIDDeviceSetReport"]
    );
    assert!(!ALLOWED_PLATFORM.contains(&"IOHIDDeviceSetReport"));
}

/// Dependencies of one package as recorded in the workspace Cargo.lock.
fn locked_dependencies(lock: &str, package: &str) -> Option<BTreeSet<String>> {
    let header = format!("name = \"{package}\"\n");
    let block = lock.split("[[package]]").find(|b| b.contains(&header))?;
    let mut deps = BTreeSet::new();
    if let Some(list) = block.split("dependencies = [").nth(1) {
        for line in list.split(']').next()?.lines() {
            let name = line.trim().trim_matches(|c| c == '"' || c == ',');
            if let Some(name) = name.split_whitespace().next().filter(|n| !n.is_empty()) {
                deps.insert(name.to_owned());
            }
        }
    }
    Some(deps)
}

#[test]
fn resolved_dependency_graph_contains_no_mutation_crate() -> TestResult {
    let lock = fs::read_to_string(Path::new(CRATE).join("../../Cargo.lock"))?;
    let set =
        |items: &[&str]| -> BTreeSet<String> { items.iter().map(|s| (*s).to_owned()).collect() };
    assert_eq!(
        locked_dependencies(&lock, "fido-h0-timing"),
        Some(set(&["fido-platform", "libc", "serde", "serde_json"]))
    );
    // fido-platform is the production durability primitive; it must stay free of FIDO crates.
    assert_eq!(
        locked_dependencies(&lock, "fido-platform"),
        Some(set(&["libc"]))
    );
    Ok(())
}

fn symbol_table() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("nm").arg(BINARY).output()?;
    assert!(output.status.success(), "nm failed on the H0 binary");
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
fn executable_has_no_destructive_native_symbol() -> TestResult {
    let symbols = symbol_table()?;
    for forbidden in [
        "fido_dev_reset",
        "fido_dev_set_pin",
        "fido_credman_del",
        "fido_dev_set_io_functions",
        "fido_dev_set_transport_functions",
        "fido_dev_cancel",
        "fido_dev_largeblob",
        "fido_dev_enable_entattest",
        "fido_dev_toggle_always_uv",
        "IOHIDDeviceSetReport",
    ] {
        assert!(
            !symbols.contains(forbidden),
            "H0 executable contains {forbidden}"
        );
    }
    if cfg!(target_os = "macos") {
        // Positive control: the private libfido2 is linked, so the absence above is meaningful.
        for required in [
            " T _fido_dev_get_cbor_info",
            " T _fido_dev_info_manifest",
            " T _fido_dev_open",
        ] {
            assert!(symbols.contains(required), "missing {required}");
        }
        assert!(
            !symbols.contains(" U _fido_"),
            "libfido2 must be statically linked, not resolved at run time"
        );
    } else {
        // No libfido2 is linked at all off macOS.
        assert!(
            !symbols.contains("fido_dev_"),
            "unexpected libfido2 symbols"
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn link_map_excludes_the_reset_object_and_binds_the_pinned_archive() -> TestResult {
    let map_path = PathBuf::from(env!("FIDO_H0_LINK_MAP"));
    let map = fs::read_to_string(&map_path)?;
    let linked = map
        .lines()
        .find_map(|line| line.strip_prefix("# Path: "))
        .ok_or("link map has no output path")?;
    assert_eq!(
        fs::read(linked)?,
        fs::read(BINARY)?,
        "link map does not describe the tested executable; rebuild"
    );
    let objects = map.split("# Sections:").next().unwrap_or_default();
    assert!(
        objects.contains("libfidomanager_fido2_bounded.a(info.c.o)")
            && objects.contains("libfidomanager_fido2_bounded.a(dev.c.o)"),
        "private libfido2 objects not linked"
    );
    assert!(
        !objects.contains("(reset.c.o)"),
        "libfido2 reset.c object is linked into the H0 executable"
    );
    let archive_dir = map_path.parent().ok_or("map has no directory")?;
    let identity = fs::read_to_string(archive_dir.join("build-identity.json"))?;
    assert!(
        identity.contains(fido_h0_timing::LIBFIDO2_REVISION),
        "linked archive is not the pinned revision"
    );
    Ok(())
}
