#!/usr/bin/env python3
"""Deterministic negative controls for credential/PIN symbol attribution; no hardware."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("verifier", Path(__file__).with_name("verify-libfido2-linkage.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
names = ["fido_credman_" + suffix for suffix in verifier.CREDMAN_SYMBOLS]
symbols = "\n".join("000 T _" + name for name in names)
link_map = "\n".join("000 0 [ 9] _" + name for name in names)
verifier.verify_credman_symbols(symbols, link_map, "9")
for bad_symbols, bad_map in (
    (symbols.replace("T _" + names[0], "U _" + names[0]), link_map),
    (symbols, link_map.replace("[ 9] _" + names[-1], "[ 8] _" + names[-1])),
    (symbols, "# Dead Stripped Symbols:\n" + link_map),
    (symbols, link_map.replace(names[0], "unrelated")),
):
    try:
        verifier.verify_credman_symbols(bad_symbols, bad_map, "9")
    except RuntimeError:
        pass
    else:
        raise AssertionError("invalid M3 attribution passed")
print("PASS: all M3 symbols; missing, unresolved, other-object and dead-stripped controls rejected")

pin_archive = "/cargo/private-libfido2/libfidomanager_fido2_bounded.a"
pin_symbols = "000 T _fido_dev_set_pin"
pin_map = "[ 12] " + pin_archive + "(pin.c.o)\n000 0 [ 12] _fido_dev_set_pin"
verifier.verify_pin_symbol(pin_symbols, pin_map, pin_archive)
for bad_symbols, bad_map in (
    (pin_symbols.replace("T _", "U _"), pin_map),
    (pin_symbols, pin_map.replace("[ 12] _", "[ 13] _")),
    (pin_symbols, pin_map.replace(pin_archive, "/opt/homebrew/lib/libfido2.a")),
    (pin_symbols, "[ 12] " + pin_archive + "(pin.c.o)\n# Dead Stripped Symbols:\n000 0 [ 12] _fido_dev_set_pin"),
    (pin_symbols, pin_map.replace("pin.c.o", "unrelated.c.o")),
):
    try:
        verifier.verify_pin_symbol(bad_symbols, bad_map, pin_archive)
    except RuntimeError:
        pass
    else:
        raise AssertionError("invalid PIN attribution passed")
print("PASS: PIN symbol unresolved, wrong object/archive and dead-stripped controls rejected")

delete_archive = "/cargo/private-libfido2/libfidomanager_fido2_bounded.a"
delete_symbols = "000 T _fido_credman_del_dev_rk"
delete_map = "[ 12] " + delete_archive + "(credman.c.o)\n000 0 [ 12] _fido_credman_del_dev_rk"
verifier.verify_deletion_symbol(delete_symbols, delete_map, delete_archive)
for bad_symbols, bad_map in (
    (delete_symbols.replace("T _", "U _"), delete_map),
    (delete_symbols, delete_map.replace("[ 12] _", "[ 13] _")),
    (delete_symbols, delete_map.replace(delete_archive, "/opt/homebrew/lib/libfido2.a")),
    (delete_symbols, "[ 12] " + delete_archive + "(credman.c.o)\n# Dead Stripped Symbols:\n000 0 [ 12] _fido_credman_del_dev_rk"),
    (delete_symbols, delete_map.replace("credman.c.o", "unrelated.c.o")),
):
    try:
        verifier.verify_deletion_symbol(bad_symbols, bad_map, delete_archive)
    except RuntimeError:
        pass
    else:
        raise AssertionError("invalid deletion attribution passed")
print("PASS: deletion symbol unresolved, wrong object/archive and dead-stripped controls rejected")

# M7.1: link-map input allowlist and private OpenSSL/libcbor attribution.
private_dir = "/fm-test/target/debug/build/fido-libfido2-1/out/private-libfido2/"
archives = {"openssl": private_dir + "libfidomanager_crypto.a", "libcbor": private_dir + "libfidomanager_cbor.a"}
fido2 = private_dir + "libfidomanager_fido2_bounded.a"
inputs = [
    "linker synthesized",
    "/fm-test/target/debug/deps/fido_worker-1.rcgu.o",
    "/fm-test/target/debug/deps/libfido_core-1.rlib(lib.o)",
    fido2 + "(credman.c.o)",
    archives["openssl"] + "(libcrypto-lib-sha256.o)",
    archives["libcbor"] + "(cbor.c.o)",
    "/fm-sdk/usr/lib/libSystem.tbd",
    "/fm-sdk/usr/lib/libz.tbd",
    "/fm-sdk/System/Library/Frameworks/IOKit.framework/IOKit.tbd",
    "/fm-sysroot/lib/rustlib/aarch64-apple-darwin/lib/libstd-1.rlib(std.o)",
]


def synthetic_map(paths, live, dead=()):
    lines = ["# Path: /fm-test/target/debug/fido-worker", "# Arch: arm64", "# Object files:"]
    lines += [f"[{index:3}] {path}" for index, path in enumerate(paths)]
    lines += ["# Sections:", "# Symbols:", "# Address\tSize    \tFile  Name"]
    lines += [f"0x100000000\t0x00000010\t[{paths.index(path):3}] {symbol}" for path, symbol in live]
    lines += ["# Dead Stripped Symbols:"] + [f"<<dead>>\t0x00000010\t[{paths.index(path):3}] {symbol}" for path, symbol in dead]
    return "\n".join(lines) + "\n"


defined = {"openssl": {"_EVP_sha256", "_OPENSSL_init_crypto"}, "libcbor": {"_cbor_load"}}
good_live = [(inputs[4], "_EVP_sha256"), (inputs[5], "_cbor_load"), (inputs[3], "_fido_init")]


def check_inputs(paths):
    objects, _ = verifier.parse_link_map(synthetic_map(paths, []))
    verifier.verify_link_inputs(objects, "/fm-test/target/debug", [fido2, *archives.values()], "/fm-sysroot", "/fm-sdk")


def check_attribution(paths, live, undefined=frozenset(), dead=()):
    objects, parsed = verifier.parse_link_map(synthetic_map(paths, live, dead))
    verifier.verify_dependency_attribution(objects, parsed, archives, defined, set(undefined))


check_inputs(inputs)
check_attribution(inputs, good_live)
for label, paths in (
    ("Homebrew libcrypto dylib", [*inputs, "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"]),
    ("Homebrew libcbor archive", [*inputs, "/opt/homebrew/lib/libcbor.a(cbor.c.o)"]),
    ("stray libcrypto.a in target", [*inputs, "/fm-test/target/debug/deps/libcrypto.a(sha256.o)"]),
    ("SDK libcrypto stub", [*inputs, "/fm-sdk/usr/lib/libcrypto.tbd"]),
    ("stub outside SDK", [*inputs, "/usr/local/lib/libz.tbd"]),
    ("rlib outside Cargo/Rust", [*inputs, "/tmp/evil.rlib(x.o)"]),
    ("missing private libcbor objects", [path for path in inputs if "cbor" not in path]),
):
    try:
        check_inputs(paths)
    except RuntimeError:
        pass
    else:
        raise AssertionError(f"link input control accepted: {label}")
other = [*inputs, "/fm-test/target/debug/deps/libother-1.rlib(evp.o)"]
for label, paths, live, undefined, dead in (
    ("OpenSSL symbol from another object", other, [(other[-1], "_EVP_sha256"), good_live[1]], (), ()),
    ("libcbor symbol from the libfido2 archive", inputs, [good_live[0], (inputs[3], "_cbor_load")], (), ()),
    ("libcbor resolved dynamically", inputs, good_live, {"_cbor_load"}, ()),
    ("OpenSSL resolved dynamically", inputs, good_live, {"_OPENSSL_init_crypto"}, ()),
    ("only dead-stripped OpenSSL objects", inputs, [good_live[1]], (), [good_live[0]]),
):
    try:
        check_attribution(paths, live, undefined, dead)
    except RuntimeError:
        pass
    else:
        raise AssertionError(f"attribution control accepted: {label}")
print("PASS: link inputs limited to Cargo/Rust/SDK/private archives; Homebrew, stray and dynamic OpenSSL/libcbor controls rejected")
