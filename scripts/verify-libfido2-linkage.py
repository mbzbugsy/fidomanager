#!/usr/bin/env python3
"""Verify a macOS Cargo worker against its actual link map and private archive identity."""

import argparse
import importlib.util
import json
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


def verify_credman_symbols(symbols, content, object_id):
    live = content.split("# Dead Stripped Symbols:", 1)[0]
    for suffix in CREDMAN_SYMBOLS:
        symbol = "fido_credman_" + suffix
        if not re.search(r"\bT _" + re.escape(symbol) + r"$", symbols, re.M):
            raise RuntimeError("Production worker lacks used credman symbol: " + symbol)
        if not re.search(r"\[\s*" + object_id + r"\]\s+_" + re.escape(symbol) + r"$", live, re.M):
            raise RuntimeError("Production credman symbol is not attributed to the private archive: " + symbol)


def verify(worker):
    if platform.system() != "Darwin":
        raise RuntimeError("Production linkage verification currently requires macOS")
    worker = worker.resolve(strict=True)
    spec = builder.lock()
    loads = subprocess.check_output(["otool", "-L", str(worker)], text=True).splitlines()[1:]
    if any(re.search(r"lib(?:fido2|fidomanager_fido2).*\.dylib", line) for line in loads):
        raise RuntimeError("Worker dynamically loads replaceable libfido2")
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
        raise RuntimeError("No matching Cargo link map; build the production fido-worker first")
    for content in matching:
        object_match = re.search(r"^\[\s*(\d+)\]\s+(.+libfidomanager_fido2_bounded\.a)\(credman\.c\.o\)$", content, re.M)
        if not object_match:
            continue
        object_id, archive_path = object_match.groups()
        # Tie the retained probe to the actual patched credential-management object.
        if not re.search(r"\[\s*" + object_id + r"\]\s+_" + re.escape(spec["identity_symbol"]) + r"$", content, re.M):
            continue
        verify_credman_symbols(symbols, content, object_id)
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
        print("PASS: worker statically links pinned patched libfido2 1.17.0; limit=256; all 16 used credman symbols attributed; no libfido2 dylib")
        return
    raise RuntimeError("Link map does not bind the worker probe to the reviewed credman object")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path)
    verify(parser.parse_args().worker)
