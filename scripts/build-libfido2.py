#!/usr/bin/env python3
"""Checksum-pinned source preparation and private macOS static build (no Cargo fetch)."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native/libfido2"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
_dependencies_spec = importlib.util.spec_from_file_location("native_dependencies", ROOT / "scripts/build-native-deps.py")
dependencies = importlib.util.module_from_spec(_dependencies_spec)
_dependencies_spec.loader.exec_module(dependencies)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def lock():
    return json.loads((NATIVE / "source.lock.json").read_text())


def source_archive():
    return ROOT / "target/native-sources" / (lock()["revision"] + ".tar.gz")


def checked_inputs(archive=None):
    spec = lock()
    archive = archive or source_archive()
    if not archive.is_file():
        raise RuntimeError("Pinned source missing: run python3 scripts/build-libfido2.py fetch")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES or sha256(archive) != spec["archive_sha256"]:
        raise RuntimeError("Pinned libfido2 source checksum mismatch")
    patch = NATIVE / "credman-allocation-bound.patch"
    if sha256(patch) != spec["patch_sha256"]:
        raise RuntimeError("Reviewed libfido2 patch checksum mismatch")
    return spec, archive, patch


def fetch():
    archive = source_archive()
    if archive.exists():
        checked_inputs()
        print("Pinned libfido2 source cache verified")
    else:
        archive.parent.mkdir(parents=True, exist_ok=True)
        # Download to a private temporary file; publish only after checking the pinned digest.
        with tempfile.TemporaryDirectory(dir=archive.parent) as temporary:
            download = Path(temporary) / "source.tar.gz"
            with urllib.request.urlopen(lock()["url"], timeout=60) as response, download.open("wb") as output:
                total = 0
                while chunk := response.read(65536):
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise RuntimeError("Source download exceeds bound")
                    output.write(chunk)
            checked_inputs(download)
            download.replace(archive)
        print("Pinned libfido2 source fetched and verified")
    # The private OpenSSL and libcbor sources are the rest of the worker's native input set.
    for name in dependencies.DEPENDENCIES:
        dependencies.fetch(name)


def prepare(destination, archive=None):
    spec, archive, patch = checked_inputs(archive)
    destination.mkdir(parents=True, exist_ok=False)
    prefix = "libfido2-" + spec["revision"] + "/"
    total = 0
    with tarfile.open(archive) as source:
        for member in source:
            if member.name == prefix.rstrip("/") and member.isdir():
                continue
            if not member.name.startswith(prefix):
                raise RuntimeError("Unexpected source archive root")
            relative = Path(member.name[len(prefix):])
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("Unsafe source archive path")
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                total += member.size
                if total > 32 * 1024 * 1024:
                    raise RuntimeError("Extracted source exceeds bound")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as data, target.open("xb") as output:
                    shutil.copyfileobj(data, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                raise RuntimeError("Links and special files are not permitted in pinned source")
    credman = destination / "src/credman.c"
    if sha256(credman) != spec["credman_upstream_sha256"]:
        raise RuntimeError("Unexpected upstream credential-management source")
    # git apply is exact (no patch fuzz). Patched-file digest also rejects relocated hunks.
    for options in (["--check"], []):
        subprocess.run(["git", "apply", *options, str(patch)], cwd=destination, check=True)
    if sha256(credman) != spec["credman_patched_sha256"]:
        raise RuntimeError("Patched credential-management source checksum mismatch")
    if "set(FIDO_VERSION ${FIDO_MAJOR}.${FIDO_MINOR}.${FIDO_PATCH})" not in (destination / "CMakeLists.txt").read_text():
        raise RuntimeError("Unexpected upstream build definition")
    return spec


def native_build_environment(inherited):
    # Explicit allowlist of host/Xcode selection variables (shared with the private OpenSSL and
    # libcbor builds); CC/CFLAGS/CMAKE_*/PKG_CONFIG_*/OPENSSL_* and similar overrides never pass.
    return dependencies.build_environment(inherited)


def verify_private_dependency_use(cmake_output, source, private, tools):
    """Prove libfido2 was configured and compiled against exactly the private OpenSSL/libcbor."""
    cache = (cmake_output / "CMakeCache.txt").read_text()
    include = os.path.realpath(private["include"])
    expected = {
        "CRYPTO_VERSION": dependencies.lock("openssl")["version"],
        "CBOR_VERSION": dependencies.lock("libcbor")["version"],
        "CRYPTO_INCLUDE_DIRS": str(private["include"]), "CBOR_INCLUDE_DIRS": str(private["include"]),
    }
    for key, value in expected.items():
        if not re.search(r"^" + key + r":INTERNAL=" + re.escape(value) + r"$", cache, re.M):
            raise RuntimeError(f"libfido2 did not resolve the private dependency ({key})")
    resource = subprocess.check_output([tools["cc"], "-print-resource-dir"], text=True).strip()
    allowed = [os.path.realpath(path) for path in (source, cmake_output, include, tools["sdk"], resource)]
    depfiles = sorted((cmake_output / "src/CMakeFiles/fido2.dir").rglob("*.o.d"))
    if not depfiles:
        raise RuntimeError("libfido2 compiler dependency files missing")
    resolved = {"openssl/opensslv.h": False, "cbor.h": False}
    for depfile in depfiles:
        _, _, listed = depfile.read_text().replace("\\\n", " ").partition(": ")
        for token in re.split(r"(?<!\\)\s+", listed.strip()):
            path = os.path.realpath(token.replace("\\ ", " "))
            if not any(path == root or path.startswith(root + os.sep) for root in allowed):
                raise RuntimeError(f"libfido2 compiled against an unreviewed header: {path}")
            for header in resolved:
                if path.endswith("/" + header):
                    if not path.startswith(include + os.sep):
                        raise RuntimeError(f"libfido2 resolved {header} outside the private build: {path}")
                    resolved[header] = True
    if not all(resolved.values()):
        raise RuntimeError("libfido2 objects do not include the private OpenSSL/libcbor headers")


def build(output, target):
    if platform.system() != "Darwin" or target not in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
        raise RuntimeError("Private libfido2 build is currently enabled only for macOS")
    if os.environ.get("LIBFIDO2_LIB_DIR") is not None:
        raise RuntimeError("LIBFIDO2_LIB_DIR overrides are forbidden for the private macOS build")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fido-source-", dir=output) as temporary:
        # Private static libcrypto and libcbor from pinned source, built fresh for this invocation.
        private = dependencies.build(Path(temporary) / "dependencies", output, target)
        tools = private["toolchain"]
        source = Path(temporary) / "source"
        spec = prepare(source)
        architecture = "arm64" if target.startswith("aarch64") else "x86_64"
        compiler = tools["cc"]
        environment = dict(private["environment"])
        # pkg-config (used by upstream CMake) sees only the private .pc files: no Homebrew/system copy.
        environment["PKG_CONFIG_LIBDIR"] = str(private["pkgconfig"])
        cmake_output = output / "cmake"
        # Each invocation configures from verified fresh source, never a stale CMake cache.
        if cmake_output.exists():
            shutil.rmtree(cmake_output)
        flags = f"-ffile-prefix-map={source}=/libfido2 -ffile-prefix-map={output}=/fido-build"
        configure = [
            "cmake", "-S", str(source), "-B", str(cmake_output), "-G", "Unix Makefiles",
            "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_C_COMPILER={compiler}",
            f"-DCMAKE_OSX_ARCHITECTURES={architecture}", "-DCMAKE_OSX_DEPLOYMENT_TARGET=11.0",
            f"-DCMAKE_C_FLAGS={flags}", "-DBUILD_SHARED_LIBS=OFF", "-DBUILD_STATIC_LIBS=ON",
            "-DBUILD_TESTS=OFF", "-DBUILD_EXAMPLES=OFF", "-DBUILD_TOOLS=OFF", "-DBUILD_MANPAGES=OFF",
            "-DFUZZ=OFF", "-DUSE_HIDAPI=OFF", "-DUSE_PCSC=OFF", "-DNFC_LINUX=OFF",
        ]
        subprocess.run(configure, env=environment, check=True)
        subprocess.run(["cmake", "--build", str(cmake_output), "--target", "fido2", "--parallel", "4"], env=environment, check=True)
        commands = json.loads((cmake_output / "compile_commands.json").read_text())
        credman_commands = [entry["command"] for entry in commands if entry["file"] == str(source / "src/credman.c")]
        if len(credman_commands) != 1 or "FIDO_FUZZ" in credman_commands[0]:
            raise RuntimeError("Credential-management object was not compiled once in production mode")
        verify_private_dependency_use(cmake_output, source, private, tools)
        archive = output / spec["archive_name"]
        shutil.copyfile(cmake_output / "src/libfido2.a", archive)
        dependencies.verify_archive(archive, architecture, forbidden=(temporary,))
        symbols = subprocess.check_output(["nm", "-g", str(archive)], text=True)
        if " T _" + spec["identity_symbol"] not in symbols:
            raise RuntimeError("Patched identity symbol missing from private archive")
        metadata = {
            "version": spec["version"], "revision": spec["revision"],
            "enumeration_limit": spec["enumeration_limit"], "patch_sha256": spec["patch_sha256"],
            "source_archive_sha256": spec["archive_sha256"], "static_archive_sha256": sha256(archive),
            "architecture": architecture, "deployment_target": dependencies.DEPLOYMENT_TARGET, "fuzz": False,
            "compiler": tools["compiler"],
            "dependencies": {**private["metadata"], **private["system"]},
        }
        (output / "build-identity.json").write_text(json.dumps(metadata, indent=2) + "\n")
    # Only the archives and path-free metadata are needed after building.
    shutil.rmtree(cmake_output)
    print("Private static libfido2 1.17.0 built against private static OpenSSL 3.5.9 and libcbor 0.14.0; "
          "production enumeration ceiling=256")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fetch")
    build_command = commands.add_parser("build")
    build_command.add_argument("--out-dir", type=Path, required=True)
    build_command.add_argument("--target", required=True)
    args = parser.parse_args()
    if args.command == "fetch":
        fetch()
    else:
        build(args.out_dir.resolve(), args.target)


if __name__ == "__main__":
    main()
