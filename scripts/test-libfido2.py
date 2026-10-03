#!/usr/bin/env python3
"""Deterministic pinned-source/native tests; no authenticator access."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.util.spec_from_file_location("native_builder", ROOT / "scripts/build-libfido2.py")
builder = importlib.util.module_from_spec(loader)
loader.loader.exec_module(builder)


def function(source, name, return_type="static int"):
    # Only the named full function bodies are extracted; no modeled parser/allocator logic.
    start = source.index(return_type + "\n" + name + "(")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


def parser_source(credman, cbor, patched):
    output = function(cbor, "cbor_decode_uint64", "int")
    if patched:
        constant = re.search(r"^#define FIDOMANAGER_CREDMAN_MAX_ENTRIES \d+$", credman, re.M)
        assert constant
        output += "\n" + constant.group() + "\n"
        output += function(credman, builder.lock()["identity_symbol"], "uint32_t")
    for name in ("credman_grow_array", "credman_parse_rp_count", "credman_parse_rk_count"):
        output += function(credman, name)
    return output


def source_tests():
    spec = builder.lock()
    with tempfile.TemporaryDirectory(prefix="fidomanager-native-tests-") as temporary:
        work = Path(temporary)
        source = work / "source"
        builder.prepare(source)
        patched = (source / "src/credman.c").read_text()
        cbor = (source / "src/cbor.c").read_text()
        with tarfile.open(builder.source_archive()) as archive:
            original = archive.extractfile("libfido2-" + spec["revision"] + "/src/credman.c").read().decode()
        flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libcbor", "libcrypto"], text=True))
        for is_patched in (True, False):
            (work / "reviewed-parser.inc").write_text(parser_source(patched if is_patched else original, cbor, is_patched))
            binary = work / ("patched" if is_patched else "unpatched")
            command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-D_DARWIN_C_SOURCE", "-D_GNU_SOURCE",
                       "-DHAVE_CLOCK_GETTIME",
                       "-DFIDOMANAGER_TEST_LIMIT=" + str(spec["enumeration_limit"]),
                       "-I" + str(source / "src"), "-I" + str(work),
                       str(ROOT / "native/libfido2/tests/credman_bounds.c"), "-o", str(binary), *flags]
            if platform.system() == "Darwin":
                command.extend(["-DHAVE_STRLCAT", "-DHAVE_STRLCPY"])
            if not is_patched:
                command.insert(1, "-DEXPECT_UNPATCHED")
            subprocess.run(command, check=True)
            subprocess.run([str(binary)], check=True)

        # Corruption must fail before extraction/build; no arbitrary source or patch fallback.
        corrupt = work / "corrupt.tar.gz"
        corrupt.write_bytes(b"unreviewed archive")
        try:
            builder.checked_inputs(corrupt)
        except RuntimeError:
            pass
        else:
            raise AssertionError("corrupt source accepted")
        missing = work / "missing.tar.gz"
        try:
            builder.checked_inputs(missing)
        except RuntimeError:
            pass
        else:
            raise AssertionError("missing source accepted")

        # Mutate an isolated patch copy, preserving the reviewed lock; never edit the checkout.
        isolated = work / "native"
        isolated.mkdir()
        (isolated / "source.lock.json").write_text(json.dumps(spec))
        (isolated / "credman-allocation-bound.patch").write_text("unreviewed patch")
        original_native = builder.NATIVE
        builder.NATIVE = isolated
        try:
            try:
                builder.checked_inputs()
            except RuntimeError:
                pass
            else:
                raise AssertionError("unreviewed patch accepted")
        finally:
            builder.NATIVE = original_native

        # Apply against an altered source file: git apply must reject the reviewed context.
        (source / "src/credman.c").write_text(original.replace("void *new_ptr;", "void *different_pointer;"))
        result = subprocess.run(["git", "apply", "--check", str(ROOT / "native/libfido2/credman-allocation-bound.patch")], cwd=source, capture_output=True)
        assert result.returncode != 0, "patch applied to a changed upstream allocation function"

        # Execute the real Cargo build script with an unpatched-library override. This must
        # fail before resolving source/build paths or starting the native builder.
        script = work / "cargo-build-script"
        subprocess.run(["rustc", str(ROOT / "crates/fido-libfido2/build.rs"), "--edition=2024", "-o", str(script)], check=True)
        environment = dict(os.environ, CARGO_FEATURE_NATIVE_LIBFIDO2="1", CARGO_CFG_TARGET_OS="macos", LIBFIDO2_LIB_DIR="/unpatched/system/library")
        rejected = subprocess.run([str(script)], env=environment, capture_output=True, text=True)
        assert rejected.returncode != 0 and "forbids system libfido2 directory overrides" in rejected.stderr
    print("PASS: corrupt/missing source, corrupt patch and changed patch context fail closed")
    print("PASS: production Cargo build script rejects a system-library override")


def archive_tests(directory):
    spec = builder.lock()
    archive = directory / spec["archive_name"]
    metadata = json.loads((directory / "build-identity.json").read_text())
    assert metadata["static_archive_sha256"] == builder.sha256(archive)
    assert metadata["version"] == "1.17.0" and metadata["revision"] == spec["revision"]
    assert metadata["enumeration_limit"] == spec["enumeration_limit"] and metadata["fuzz"] is False
    assert metadata["patch_sha256"] == spec["patch_sha256"]
    assert metadata["source_archive_sha256"] == spec["archive_sha256"]
    assert not re.search(r"/(?:Users|home|private|opt)/", json.dumps(metadata)), "local path in build metadata"
    with tempfile.TemporaryDirectory(prefix="fidomanager-link-test-") as temporary:
        work = Path(temporary)
        probe = work / "probe.c"
        symbol = spec["identity_symbol"]
        probe.write_text(f"#include <stdint.h>\nuint32_t {symbol}(void);\nint main(void) {{ return {symbol}() == {spec['enumeration_limit']} ? 0 : 1; }}\n")
        binary = work / "probe"
        dependencies = shlex.split(subprocess.check_output(["pkg-config", "--libs", "libcrypto", "libcbor", "zlib"], text=True))
        subprocess.run(["cc", str(probe), str(archive), *dependencies, "-framework", "IOKit", "-framework", "CoreFoundation", "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
        # The unpatched system ABI cannot resolve the private identity symbol.
        system_flags = shlex.split(subprocess.check_output(["pkg-config", "--libs", "libfido2"], text=True))
        rejected = subprocess.run(["cc", str(probe), *system_flags, "-o", str(work / "system")], capture_output=True, text=True)
        assert rejected.returncode != 0 and symbol in rejected.stderr, "system library satisfied private identity probe"
    print("PASS: private archive identity and baseline; system libfido2 fails linkage")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--rebuild", action="store_true", help="Build twice in separate paths and compare archive bytes (macOS)")
    args = parser.parse_args()
    source_tests()
    if args.rebuild:
        target = "aarch64-apple-darwin" if platform.machine() == "arm64" else "x86_64-apple-darwin"
        with tempfile.TemporaryDirectory(prefix="fidomanager-reproducibility-") as temporary:
            digests = []
            for name in ("first", "second"):
                directory = Path(temporary) / name
                result = subprocess.run(["python3", str(ROOT / "scripts/build-libfido2.py"), "build", "--out-dir", str(directory), "--target", target], capture_output=True, text=True)
                if result.returncode != 0:
                    raise RuntimeError(result.stdout + result.stderr)
                archive_tests(directory)
                digests.append(builder.sha256(directory / builder.lock()["archive_name"]))
            assert digests[0] == digests[1], "separate-path native builds are not reproducible"
        print("PASS: separate-path static archive rebuilds are byte-identical")
    if args.build_dir:
        archive_tests(args.build_dir.resolve())
