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
import shutil
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


def host_target():
    return "aarch64-apple-darwin" if platform.machine() == "arm64" else "x86_64-apple-darwin"


def harness_flags(work):
    if platform.system() != "Darwin":
        # Linux keeps its discovery-only system-library policy for this source-level harness.
        return shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libcbor", "libcrypto"], text=True)), None
    # macOS: the harness uses the same private pinned headers/archives as the production worker.
    private = builder.dependencies.build(work / "private-deps", work / "private-deps", host_target())
    return ["-I" + str(private["include"]),
            *(str(work / "private-deps" / builder.dependencies.lock(name)["archive_name"])
              for name in ("libcbor", "openssl"))], private


def api_compat_control(work, private):
    """Prove libfido2 needs the OpenSSL 3 version knowledge the private .pc files provide.

    Upstream CMake adds OPENSSL_API_COMPAT=0x10100000L only when CRYPTO_VERSION >= 3.0. Presenting
    the same private OpenSSL as 1.1.1 must drop the define and fail libfido2's own -Werror build.
    """
    source = work / "compat-source"
    builder.prepare(source)
    pkgconfig = work / "compat-pkgconfig"
    shutil.copytree(private["pkgconfig"], pkgconfig)
    crypto = pkgconfig / "libcrypto.pc"
    crypto.write_text(re.sub(r"^Version: .*$", "Version: 1.1.1", crypto.read_text(), flags=re.M))
    environment = dict(private["environment"], PKG_CONFIG_LIBDIR=str(pkgconfig))
    output = work / "compat-build"
    architecture = "arm64" if platform.machine() == "arm64" else "x86_64"
    subprocess.run(builder.configure_command(source, output, private["toolchain"]["cc"], architecture, work),
                   env=environment, check=True, capture_output=True)
    commands = json.loads((output / "compile_commands.json").read_text())
    assert commands and not any("OPENSSL_API_COMPAT" in entry["command"] for entry in commands)
    result = subprocess.run(["cmake", "--build", str(output), "--target", "fido2", "--", "-k", "-j4"],
                            env=environment, capture_output=True, text=True)
    assert result.returncode != 0 and "[-Werror,-Wdeprecated-declarations]" in result.stdout + result.stderr, \
        "libfido2 built without OPENSSL_API_COMPAT; the private OpenSSL 3 version knowledge is not load-bearing"


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
        flags, private = harness_flags(work)
        if private is not None:
            api_compat_control(work, private)
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
            disabled_asserts = subprocess.run([*command, "-DNDEBUG"], capture_output=True, text=True)
            assert disabled_asserts.returncode != 0 and "NDEBUG is forbidden" in disabled_asserts.stderr, "test harness accepted disabled assertions"

        removed_variables = ("CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
                             "CMAKE_TOOLCHAIN_FILE", "CMAKE_GENERATOR", "CMAKE_PREFIX_PATH",
                             "CMAKE_C_COMPILER_LAUNCHER", "CMAKE_C_LINKER_LAUNCHER",
                             "CPATH", "C_INCLUDE_PATH", "LIBRARY_PATH",
                             "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "OPENSSL_CONF", "MAKEFLAGS")
        inherited = dict.fromkeys(removed_variables, "untrusted override")
        host_variables = {"PATH": "/host/bin", "SDKROOT": "/host/sdk",
                          "DEVELOPER_DIR": "/host/Xcode", "HOME": "/host/home",
                          "TMPDIR": "/host/tmp"}
        inherited.update(host_variables, ZERO_AR_DATE="0", SOURCE_DATE_EPOCH="0")
        environment = builder.native_build_environment(inherited)
        assert all(name not in environment for name in removed_variables)
        assert all(environment[name] == value for name, value in host_variables.items())
        assert environment["ZERO_AR_DATE"] == "1" and environment["SOURCE_DATE_EPOCH"] == "1781654400"
        assert all(inherited[name] == "untrusted override" for name in removed_variables)

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
    print("PASS: explicit native build environment allowlist (no compiler/pkg-config/OpenSSL overrides)")
    print("PASS: patched and unpatched harness builds reject NDEBUG")
    if platform.system() == "Darwin":
        print("PASS: libfido2 presented OpenSSL 1.1.1 drops OPENSSL_API_COMPAT and fails -Werror; private 3.5.9 .pc is load-bearing")


# openbsd-compat implementations whose upstream notices are reproduced in THIRD_PARTY_NOTICES.md.
NOTICED_COMPAT = {"_freezero", "_recallocarray", "_explicit_bzero", "_getpagesize"}
COMPAT_SYMBOLS = NOTICED_COMPAT | {"_asprintf", "_getline", "_clock_gettime", "_strlcat", "_strlcpy",
                                   "_strsep", "_timingsafe_bcmp", "_readpassphrase", "_getopt_long"}


def archive_tests(directory):
    spec = builder.lock()
    archive = directory / spec["archive_name"]
    metadata = json.loads((directory / "build-identity.json").read_text())
    assert metadata["static_archive_sha256"] == builder.sha256(archive)
    assert metadata["version"] == "1.17.0" and metadata["revision"] == spec["revision"]
    assert metadata["enumeration_limit"] == spec["enumeration_limit"] and metadata["fuzz"] is False
    assert metadata["patch_sha256"] == spec["patch_sha256"]
    assert metadata["source_archive_sha256"] == spec["archive_sha256"]
    assert metadata["deployment_target"] == "11.0"
    assert not re.search(r"/(?:Users|home|private|opt)/", json.dumps(metadata)), "local path in build metadata"
    private = []
    for name in builder.dependencies.DEPENDENCIES:
        lock = builder.dependencies.lock(name)
        entry = metadata["dependencies"][name]
        path = directory / lock["archive_name"]
        assert entry["version"] == lock["version"] and entry["source_archive_sha256"] == lock["archive_sha256"]
        assert entry["static_archive_sha256"] == builder.sha256(path) and entry["deployment_target"] == "11.0"
        private.append(str(path))
    assert set(builder.dependencies.OPENSSL_POLICY) <= set(metadata["dependencies"]["openssl"]["build_options"])
    compat = {line.split()[-1] for line in subprocess.check_output(["nm", "-gU", str(archive)], text=True).splitlines()
              if line.split() and line.split()[-1] in COMPAT_SYMBOLS}
    assert compat <= NOTICED_COMPAT, f"compat code without a reviewed notice: {sorted(compat - NOTICED_COMPAT)}"
    with tempfile.TemporaryDirectory(prefix="fidomanager-link-test-") as temporary:
        work = Path(temporary)
        probe = work / "probe.c"
        symbol = spec["identity_symbol"]
        probe.write_text(f"#include <stdint.h>\nuint32_t {symbol}(void);\nint main(void) {{ return {symbol}() == {spec['enumeration_limit']} ? 0 : 1; }}\n")
        binary = work / "probe"
        # Only private archives and system frameworks/zlib: no pkg-config resolution at all.
        subprocess.run(["cc", "-mmacosx-version-min=11.0", str(probe), str(archive), *private, "-lz",
                        "-framework", "IOKit", "-framework", "CoreFoundation", "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
        loads = subprocess.check_output(["otool", "-L", str(binary)], text=True)
        assert not re.search(r"libcrypto|libcbor|libfido2|/opt/homebrew|/usr/local", loads), loads
        # The unpatched system ABI cannot resolve the private identity symbol.
        system_flags = shlex.split(subprocess.check_output(["pkg-config", "--libs", "libfido2"], text=True))
        rejected = subprocess.run(["cc", str(probe), *system_flags, "-o", str(work / "system")], capture_output=True, text=True)
        assert rejected.returncode != 0 and symbol in rejected.stderr, "system library satisfied private identity probe"
    print("PASS: private archive identity and baseline; probe links only private static archives; system libfido2 fails linkage")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--rebuild", action="store_true", help="Build twice in separate paths and compare archive bytes (macOS)")
    args = parser.parse_args()
    source_tests()
    if args.rebuild:
        target = host_target()
        names = [builder.lock()["archive_name"], *(builder.dependencies.lock(name)["archive_name"]
                                                    for name in builder.dependencies.DEPENDENCIES)]
        with tempfile.TemporaryDirectory(prefix="fidomanager-reproducibility-") as temporary:
            digests = []
            for name in ("first", "second"):
                directory = Path(temporary) / name
                result = subprocess.run(["python3", str(ROOT / "scripts/build-libfido2.py"), "build", "--out-dir", str(directory), "--target", target], capture_output=True, text=True)
                if result.returncode != 0:
                    raise RuntimeError(result.stdout + result.stderr)
                archive_tests(directory)
                digests.append([builder.sha256(directory / archive) for archive in names])
            assert digests[0] == digests[1], "separate-path native builds are not reproducible"
        print("PASS: separate-path libfido2, libcrypto and libcbor static archive rebuilds are byte-identical")
    if args.build_dir:
        archive_tests(args.build_dir.resolve())
