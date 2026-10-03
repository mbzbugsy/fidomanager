#!/usr/bin/env python3
"""Checksum-pinned source preparation and private macOS static build (no Cargo fetch)."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native/libfido2"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024


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
        return
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


def pkg_config(option, package):
    return subprocess.check_output(["pkg-config", option, package], text=True).strip()


def build(output, target):
    if platform.system() != "Darwin" or target not in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
        raise RuntimeError("Private libfido2 build is currently enabled only for macOS")
    if os.environ.get("LIBFIDO2_LIB_DIR") is not None:
        raise RuntimeError("LIBFIDO2_LIB_DIR overrides are forbidden for the private macOS build")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fido-source-", dir=output) as temporary:
        source = Path(temporary) / "source"
        spec = prepare(source)
        architecture = "arm64" if target.startswith("aarch64") else "x86_64"
        compiler = subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
        environment = dict(os.environ)
        # Do not inherit flags that could substitute a compiler, enable FUZZ or alter this build.
        for name in ("CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "CMAKE_TOOLCHAIN_FILE", "CMAKE_GENERATOR", "CMAKE_PREFIX_PATH"):
            environment.pop(name, None)
        environment.update(ZERO_AR_DATE="1", SOURCE_DATE_EPOCH="1781654400")
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
        archive = output / spec["archive_name"]
        shutil.copyfile(cmake_output / "src/libfido2.a", archive)
        symbols = subprocess.check_output(["nm", "-g", str(archive)], text=True)
        if " T _" + spec["identity_symbol"] not in symbols:
            raise RuntimeError("Patched identity symbol missing from private archive")
        metadata = {
            "version": spec["version"], "revision": spec["revision"],
            "enumeration_limit": spec["enumeration_limit"], "patch_sha256": spec["patch_sha256"],
            "source_archive_sha256": spec["archive_sha256"], "static_archive_sha256": sha256(archive),
            "architecture": architecture, "fuzz": False,
            "compiler": subprocess.check_output([compiler, "--version"], text=True).splitlines()[0],
            "dependencies": {name: pkg_config("--modversion", name) for name in ("libcrypto", "libcbor", "zlib")},
        }
        (output / "build-identity.json").write_text(json.dumps(metadata, indent=2) + "\n")
    # Only the archive and path-free metadata are needed after building.
    shutil.rmtree(cmake_output)
    print("Private static libfido2 1.17.0 built; production enumeration ceiling=256")


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
