#!/usr/bin/env python3
"""Verify a macOS Cargo worker against its actual link map and private archive identity."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess

# Every production credman symbol declared/called by the M3 adapter; all live in credman.c.
CREDMAN_SYMBOLS = (
    "metadata_new", "metadata_free", "rp_new", "rp_free", "rk_new", "rk_free",
    "get_dev_metadata", "get_dev_rp", "get_dev_rk", "rk_existing", "rp_count",
    "rp_id", "rp_id_hash_ptr", "rp_id_hash_len", "rk_count", "rk",
)

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.util.spec_from_file_location("native_builder", ROOT / "scripts/build-libfido2.py")
builder = importlib.util.module_from_spec(loader)
loader.loader.exec_module(builder)
dependencies = builder.dependencies
# Only these macOS SDK link stubs may appear as linker inputs (the worker's reviewed system set).
SYSTEM_STUBS = re.compile(
    r"^(?:usr/lib/lib(?:z|iconv|System|c|m)\.tbd"
    r"|usr/lib/system/lib[A-Za-z0-9_]+\.tbd"
    r"|System/Library/Frameworks/(?:CoreFoundation|IOKit)\.framework/(?:CoreFoundation|IOKit)\.tbd)$"
)
OBJECT_LINE = re.compile(r"^\[\s*(\d+)\]\s+(.+)$")
SYMBOL_LINE = re.compile(r"^0x[0-9A-Fa-f]+\s+0x[0-9A-Fa-f]+\s+\[\s*(\d+)\]\s+(_\S+)$")


def parse_link_map(content):
    """Return ({object id: input path}, [(object id, live symbol)])."""
    header, _, rest = content.partition("# Sections:")
    objects = {}
    for line in header.partition("# Object files:")[2].splitlines():
        match = OBJECT_LINE.match(line)
        if match:
            objects[match.group(1)] = match.group(2)
    live_symbols = rest.partition("# Symbols:")[2].split("# Dead Stripped Symbols:", 1)[0]
    live = [match.groups() for match in map(SYMBOL_LINE.match, live_symbols.splitlines()) if match]
    return objects, live


def inside(path, root):
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path == root or path.startswith(root + os.sep)


def verify_link_inputs(objects, profile_dir, private_archives, rust_sysroot, sdk):
    """Every linker input is Cargo output, Rust's own std, a reviewed SDK stub or a private archive."""
    private = {os.path.realpath(path) for path in private_archives}
    used = set()
    for path in objects.values():
        if path == "linker synthesized":
            continue
        member = re.match(r"^(.+?)\(([^()]+)\)$", path)
        container = member.group(1) if member else path
        if os.path.realpath(container) in private:
            used.add(os.path.realpath(container))
            continue
        if container.endswith(".tbd"):
            # Resolve the SDK location but keep the stub name the linker used (libz.tbd -> libz.1.tbd).
            located = os.path.join(os.path.realpath(os.path.dirname(container)), os.path.basename(container))
            relative = os.path.relpath(located, os.path.realpath(sdk))
            if not inside(container, sdk) or not SYSTEM_STUBS.match(relative):
                raise RuntimeError(f"Unreviewed system link input: {container}")
            continue
        if container.endswith(".rlib") and (inside(container, Path(profile_dir) / "deps")
                                             or inside(container, Path(rust_sysroot) / "lib/rustlib")):
            continue
        if container.endswith(".o") and not member and inside(container, Path(profile_dir) / "deps"):
            continue
        # Anything else (a Homebrew/system libcrypto/libcbor archive or dylib, a stray .a) fails.
        raise RuntimeError(f"Unreviewed native link input: {path}")
    if used != private:
        raise RuntimeError("Not every private native archive contributed objects to the worker")


def verify_dependency_attribution(objects, live, archives, defined, worker_undefined):
    """Every live OpenSSL/libcbor definition must come from the reviewed private archive objects."""
    for name, archive in archives.items():
        ids = {object_id for object_id, path in objects.items()
               if os.path.realpath(path.rsplit("(", 1)[0]) == os.path.realpath(archive) and path.endswith(")")}
        attributed = [symbol for object_id, symbol in live if object_id in ids]
        if not ids or not attributed:
            raise RuntimeError(f"No live {name} objects from the private archive")
        for object_id, symbol in live:
            if symbol in defined[name] and object_id not in ids:
                raise RuntimeError(f"{name} symbol {symbol} is not attributed to the private archive")
        dynamic = worker_undefined & defined[name]
        if dynamic:
            raise RuntimeError(f"Worker resolves {name} symbols dynamically: {sorted(dynamic)[:5]}")
    return True


def defined_symbols(archive):
    output = subprocess.check_output(["nm", "-gUj", str(archive)], text=True)
    return {line.strip() for line in output.splitlines() if line.startswith("_")}


def verify_private_dependencies(worker, content, archive, metadata):
    directory = archive.parent
    recorded = metadata.get("dependencies", {})
    archives = {}
    for name in dependencies.DEPENDENCIES:
        spec = dependencies.lock(name)
        path = directory / spec["archive_name"]
        entry = recorded.get(name, {})
        expected = {
            "version": spec["version"], "upstream_commit": spec["upstream_commit"],
            "source_archive_sha256": spec["archive_sha256"], "static_archive": spec["archive_name"],
            "static_archive_sha256": builder.sha256(path), "deployment_target": dependencies.DEPLOYMENT_TARGET,
        }
        if any(entry.get(key) != value for key, value in expected.items()):
            raise RuntimeError(f"Linked private {name} archive identity mismatch")
        archives[name] = path
    if recorded["openssl"].get("openssldir") != dependencies.OPENSSL_PREFIX or not set(
            dependencies.OPENSSL_POLICY) <= set(recorded["openssl"].get("build_options", [])):
        raise RuntimeError("Linked private OpenSSL was not built with the reviewed policy")
    architecture = metadata.get("architecture")
    if recorded["openssl"].get("configure_target") != dependencies.OPENSSL_CONFIGURE_TARGETS.get(architecture):
        raise RuntimeError("Linked private OpenSSL was not configured for the explicit Rust target")
    if metadata.get("openssl_api_compat") != "0x10100000L":
        raise RuntimeError("Linked libfido2 was not compiled with OPENSSL_API_COMPAT=0x10100000L")
    probe = recorded["openssl"].get("runtime_independence_probe", "")
    if not (probe.startswith("implicit init ignored") or probe.startswith("not executed (cross-architecture")):
        raise RuntimeError("Linked private OpenSSL lacks its runtime-independence probe result")
    objects, live = parse_link_map(content)
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], cwd=ROOT, text=True).strip()
    sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
    verify_link_inputs(objects, worker.parent, [archive, *archives.values()], sysroot, sdk)
    undefined = {line.strip() for line in subprocess.check_output(["nm", "-guj", str(worker)], text=True).splitlines()}
    verify_dependency_attribution(objects, live, archives,
                                  {name: defined_symbols(path) for name, path in archives.items()}, undefined)


def verify_credman_symbols(symbols, content, object_id):
    live = content.split("# Dead Stripped Symbols:", 1)[0]
    for suffix in CREDMAN_SYMBOLS:
        symbol = "fido_credman_" + suffix
        if not re.search(r"\bT _" + re.escape(symbol) + r"$", symbols, re.M):
            raise RuntimeError("Production worker lacks used credman symbol: " + symbol)
        if not re.search(r"\[\s*" + object_id + r"\]\s+_" + re.escape(symbol) + r"$", live, re.M):
            raise RuntimeError("Production credman symbol is not attributed to the private archive: " + symbol)


def verify_pin_symbol(symbols, content, archive_path):
    symbol = "fido_dev_set_pin"
    live = content.split("# Dead Stripped Symbols:", 1)[0]
    match = re.search(
        r"^\[\s*(\d+)\]\s+" + re.escape(archive_path) + r"\(pin\.c\.o\)$",
        content, re.M,
    )
    if (not match
            or not re.search(r"\bT _" + symbol + r"$", symbols, re.M)
            or not re.search(r"\[\s*" + match.group(1) + r"\]\s+_" + symbol + r"$", live, re.M)):
        raise RuntimeError("PIN mutation symbol is not a live definition from the exact pinned private archive")


def verify_deletion_symbol(symbols, content, archive_path):
    symbol = "fido_credman_del_dev_rk"
    live = content.split("# Dead Stripped Symbols:", 1)[0]
    match = re.search(
        r"^\[\s*(\d+)\]\s+" + re.escape(archive_path) + r"\(credman\.c\.o\)$",
        content, re.M,
    )
    if (not match
            or not re.search(r"\bT _" + symbol + r"$", symbols, re.M)
            or not re.search(r"\[\s*" + match.group(1) + r"\]\s+_" + symbol + r"$", live, re.M)):
        raise RuntimeError("Credential deletion symbol is not a live definition from the exact pinned private archive")


def verify(worker):
    if platform.system() != "Darwin":
        raise RuntimeError("Production linkage verification currently requires macOS")
    worker = worker.resolve(strict=True)
    spec = builder.lock()
    loads = subprocess.check_output(["otool", "-L", str(worker)], text=True).splitlines()[1:]
    if any(re.search(r"lib(?:fido2|fidomanager_fido2).*\.dylib", line) for line in loads):
        raise RuntimeError("Worker dynamically loads replaceable libfido2")
    if any(re.search(r"lib(?:crypto|ssl|cbor)[.\d]*\.dylib|/opt/homebrew|/usr/local|@rpath|@loader_path", line)
           for line in loads):
        raise RuntimeError("Worker dynamically loads a replaceable libcrypto/libcbor or non-system path")
    symbols = subprocess.check_output(["nm", "-g", str(worker)], text=True)
    for symbol in (spec["identity_symbol"], "fido_init", "fido_dev_get_puat"):
        if not re.search(r"\bT _" + re.escape(symbol) + r"$", symbols, re.M):
            raise RuntimeError("Worker does not statically define the reviewed native symbols")
    if re.search(r"\bU _(?:fido_|fidomanager_libfido2_)", symbols):
        raise RuntimeError("Worker has dynamically unresolved FIDO symbols")

    # Cargo's unstripped linker output and public binary are hard links/copies. Compare bytes,
    # rather than choosing a stale map merely because it names the same executable/profile.
    worker_hash = builder.sha256(worker)
    matching = []
    for map_path in (worker.parent / "build").glob("fido-worker-*/out/native-link.map"):
        content = map_path.read_text(errors="replace")
        binary_match = re.search(r"^# Path: (.+)$", content, re.M)
        if not binary_match:
            continue
        linked_binary = Path(binary_match.group(1))
        if linked_binary.is_file() and builder.sha256(linked_binary) == worker_hash:
            matching.append(content)
    if not matching:
        raise RuntimeError("No matching Cargo link map; run cargo clean -p fido-worker then cargo build -p fido-worker --locked")
    for content in matching:
        object_match = re.search(r"^\[\s*(\d+)\]\s+(.+libfidomanager_fido2_bounded\.a)\(credman\.c\.o\)$", content, re.M)
        if not object_match:
            continue
        object_id, archive_path = object_match.groups()
        # Tie the retained probe to the actual patched credential-management object.
        if not re.search(r"\[\s*" + object_id + r"\]\s+_" + re.escape(spec["identity_symbol"]) + r"$", content, re.M):
            continue
        verify_credman_symbols(symbols, content, object_id)
        verify_pin_symbol(symbols, content, archive_path)
        verify_deletion_symbol(symbols, content, archive_path)
        archive = Path(archive_path).resolve(strict=True)
        if archive.parent.name != "private-libfido2":
            raise RuntimeError("Native object did not come from Cargo's private build")
        metadata = json.loads((archive.parent / "build-identity.json").read_text())
        expected = {
            "version": "1.17.0", "revision": spec["revision"],
            "enumeration_limit": spec["enumeration_limit"], "patch_sha256": spec["patch_sha256"],
            "source_archive_sha256": spec["archive_sha256"], "fuzz": False,
            "static_archive_sha256": builder.sha256(archive),
        }
        if any(metadata.get(key) != value for key, value in expected.items()):
            raise RuntimeError("Linked private archive identity mismatch")
        verify_private_dependencies(worker, content, archive, metadata)
        print("PASS: worker statically links pinned patched libfido2 1.17.0; limit=256; all 16 used credman symbols plus fido_dev_set_pin and fido_credman_del_dev_rk attributed; no libfido2 dylib")
        print("PASS: every live OpenSSL 3.5.9 / libcbor 0.14.0 definition is attributed to the private static archives; "
              "no libcrypto/libcbor dylib; link inputs limited to Cargo output, Rust std, reviewed SDK stubs and private archives")
        return metadata
    raise RuntimeError("Link map does not bind the worker probe to the reviewed credman object")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path)
    verify(parser.parse_args().worker)
