#!/usr/bin/env python3
"""Build an UNSIGNED (ad-hoc sealed) local Fido Manager.app and optional unsigned DMG.

Pipeline (macOS host-native only, no credentials):

  release fido-worker (explicit --target dir; private static libfido2 + OpenSSL + libcbor built
  from pinned source) -> verify link map provenance and system-only linkage at macOS 11.0
  -> stage worker as Tauri externalBin -> tauri build (production frontend, app bundle only)
  -> add reviewed THIRD_PARTY_NOTICES.md -> ad-hoc inside-out signing -> structural checks
  -> optional DMG (hdiutil) + re-check

The bundle contains no third-party dylibs and no Contents/Frameworks directory. The output is a
development/CI artifact. It is not Developer ID signed, not notarized, not stapled, and must not
be published.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import time
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "target/macos-package"
OVERLAY = ROOT / "src-tauri/tauri.macos-bundle.conf.json"
# Credential-bearing variables that would make Tauri sign or notarize. This path refuses them.
SIGNING_ENVIRONMENT = (
    "APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD", "APPLE_SIGNING_IDENTITY", "APPLE_ID",
    "APPLE_PASSWORD", "APPLE_TEAM_ID", "APPLE_API_KEY", "APPLE_API_KEY_PATH", "APPLE_API_ISSUER",
    "APPLE_PROVIDER_SHORT_NAME", "TAURI_SIGNING_PRIVATE_KEY", "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
    "LIBFIDO2_LIB_DIR",
)


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load("check_macos_bundle", "check-macos-bundle.py")
signer = load("sign_macos_bundle", "sign-macos-bundle.py")
linkage = load("verify_libfido2_linkage", "verify-libfido2-linkage.py")
DEPLOYMENT_TARGET = checker.DEPLOYMENT_TARGET


def run(command, **options):
    print("+ " + " ".join(str(part) for part in command), flush=True)
    subprocess.run([str(part) for part in command], check=True, **options)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_triple():
    info = subprocess.check_output(["rustc", "-vV"], text=True)
    triple = re.search(r"^host: (\S+)$", info, re.M).group(1)
    if triple not in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
        raise RuntimeError(f"Unsupported packaging host {triple}; universal builds are not supported")
    return triple


def clean_environment():
    present = [name for name in SIGNING_ENVIRONMENT if name in os.environ]
    if present:
        raise RuntimeError("Unsigned packaging refuses signing/notarization/override variables: " + ", ".join(present))
    # The reviewed floor applies to Rust code too (rustc's x86_64 default would be older).
    return dict(os.environ, MACOSX_DEPLOYMENT_TARGET=DEPLOYMENT_TARGET)


def build_worker(triple, environment):
    # A fresh production link guarantees the link map describes exactly this binary.
    run(["cargo", "clean", "--release", "--target", triple, "-p", "fido-worker"], cwd=ROOT, env=environment)
    run(["cargo", "build", "--release", "--locked", "--target", triple, "-p", "fido-worker"], cwd=ROOT, env=environment)
    worker = ROOT / "target" / triple / "release/fido-worker"
    # Link-map provenance: libfido2, OpenSSL and libcbor objects all from the private archives.
    identity = linkage.verify(worker)
    for dep in checker.dependencies(worker):
        if not dep.startswith(checker.SYSTEM_PREFIXES) or checker.FORBIDDEN_LINKAGE.search(dep):
            raise RuntimeError(f"Release worker has a non-system dynamic dependency: {dep}")
    minimum = checker.minimum_os(worker)
    if checker.version_tuple(minimum) > checker.version_tuple(DEPLOYMENT_TARGET):
        raise RuntimeError(f"Release worker requires macOS {minimum}, above the reviewed floor {DEPLOYMENT_TARGET}")
    return worker, identity


def tauri_build(minimum, environment):
    app = ROOT / "target/release/bundle/macos/Fido Manager.app"
    if app.exists():
        shutil.rmtree(app)
    overlay = json.dumps({"bundle": {"macOS": {"minimumSystemVersion": minimum}}})
    # The Tauri CLI rewrites dependency syntax in the app manifest; keep the reviewed file intact.
    manifest = ROOT / "src-tauri/Cargo.toml"
    reviewed = manifest.read_bytes()
    try:
        run(["pnpm", "tauri", "build", "--ci", "--bundles", "app", "--config", OVERLAY, "--config", overlay],
            cwd=ROOT, env=environment)
    finally:
        manifest.write_bytes(reviewed)
    return app


def install_notices(app, worker_source):
    contents = app / "Contents"
    if sha256(contents / "MacOS/fido-worker") != sha256(worker_source):
        raise RuntimeError("Bundled worker is not the verified release worker")
    if (contents / "Frameworks").exists():
        raise RuntimeError("Tauri produced Contents/Frameworks; the reviewed bundle has no dylibs")
    notices = contents / "Resources" / checker.NOTICES
    shutil.copyfile(ROOT / checker.NOTICES, notices)
    notices.chmod(0o644)


def hdiutil(*arguments):
    for attempt in range(3):
        result = subprocess.run(["hdiutil", *arguments], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        print(f"hdiutil {arguments[0]} attempt {attempt + 1} failed: {result.stderr.strip()}", flush=True)
        time.sleep(3)
    raise RuntimeError(f"hdiutil {arguments[0]} failed")


def make_dmg(app, version, arch, frontend_dist):
    dmg = PACKAGE / f"FidoManager-{version}-{arch}-UNSIGNED.dmg"
    root = PACKAGE / "dmg-root"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir()
    run(["ditto", app, root / app.name])
    (root / "Applications").symlink_to("/Applications")
    hdiutil("create", "-volname", "Fido Manager", "-srcfolder", str(root), "-fs", "HFS+",
            "-format", "UDZO", "-ov", str(dmg))
    shutil.rmtree(root)
    hdiutil("verify", str(dmg))
    with tempfile.TemporaryDirectory(prefix="fidomanager-dmg-") as mount:
        hdiutil("attach", str(dmg), "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount)
        try:
            entries = sorted(path.name for path in Path(mount).iterdir() if not path.name.startswith("."))
            if entries != ["Applications", app.name]:
                raise RuntimeError(f"Unexpected DMG contents: {entries}")
            checker.check(Path(mount) / app.name, signature_mode="adhoc", expected_version=version,
                          frontend_dist=frontend_dist, execute_worker=True)
        finally:
            hdiutil("detach", mount, "-force")
    return dmg


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dmg", action="store_true", help="also create and verify an unsigned DMG")
    arguments = parser.parse_args()
    if platform.system() != "Darwin":
        raise RuntimeError("macOS packaging requires a macOS host")
    environment = clean_environment()
    triple = host_triple()
    version = json.loads((ROOT / "src-tauri/tauri.conf.json").read_text())["version"]

    shutil.rmtree(PACKAGE, ignore_errors=True)
    (PACKAGE / "sidecar").mkdir(parents=True)
    worker, identity = build_worker(triple, environment)
    sidecar = PACKAGE / "sidecar" / f"fido-worker-{triple}"
    shutil.copyfile(worker, sidecar)
    sidecar.chmod(0o755)

    built = tauri_build(DEPLOYMENT_TARGET, environment)
    app = PACKAGE / built.name
    shutil.move(built, app)
    install_notices(app, worker)
    signer.sign(app, "-")
    frontend = ROOT / "dist"
    summary = checker.check(app, signature_mode="adhoc", expected_version=version,
                            frontend_dist=frontend, execute_worker=True)
    summary["release_worker_sha256_before_signing"] = sha256(worker)
    summary["native_dependencies"] = {
        "libfido2": {key: identity[key] for key in ("version", "revision", "source_archive_sha256",
                                                    "patch_sha256", "static_archive_sha256", "deployment_target")},
        **identity["dependencies"],
    }
    summary["third_party_notices_sha256"] = sha256(ROOT / checker.NOTICES)
    summary["bundled_sha256"] = {
        path.relative_to(app).as_posix(): sha256(path)
        for path in sorted(app.rglob("*")) if path.is_file() and checker.is_mach_o(path)
    }
    if arguments.dmg:
        summary["dmg"] = make_dmg(app, version, summary["architecture"], frontend).name
    summary["notarized"] = False
    summary["developer_id_signed"] = False
    (PACKAGE / "package-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"PASS: unsigned local package at {app.relative_to(ROOT)} (NOT for distribution)")


if __name__ == "__main__":
    main()
