#!/usr/bin/env python3
"""Build an UNSIGNED (ad-hoc sealed) local Fido Manager.app and optional unsigned DMG.

Pipeline (macOS host-native only, no credentials):

  release fido-worker (explicit --target dir) -> verify private libfido2 link map
  -> stage worker as Tauri externalBin -> tauri build (production frontend, app bundle only)
  -> copy reviewed worker dylibs into Contents/Frameworks and rewrite them to
     @executable_path/../Frameworks (no rpath, no search paths)
  -> ad-hoc inside-out signing -> structural checks -> optional DMG (hdiutil) + re-check

The output is a development/CI artifact. It is not Developer ID signed, not notarized, not
stapled, and must not be published.
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
SYSTEM_PREFIXES = ("/usr/lib/", "/System/Library/")
FRAMEWORK_PREFIX = "@executable_path/../Frameworks/"
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
    return dict(os.environ)


def build_worker(triple, environment):
    # A fresh production link guarantees the link map describes exactly this binary.
    run(["cargo", "clean", "--release", "--target", triple, "-p", "fido-worker"], cwd=ROOT, env=environment)
    run(["cargo", "build", "--release", "--locked", "--target", triple, "-p", "fido-worker"], cwd=ROOT, env=environment)
    worker = ROOT / "target" / triple / "release/fido-worker"
    run(["python3", ROOT / "scripts/verify-libfido2-linkage.py", worker], cwd=ROOT, env=environment)
    return worker


def private_dependencies(worker):
    """Return {absolute origin: bundled name} for the worker's non-system dylibs."""
    found = {}
    for dep in checker.dependencies(worker):
        if dep.startswith(SYSTEM_PREFIXES):
            continue
        name = Path(dep).name
        if not dep.startswith("/") or not any(pattern.match(name) for pattern in checker.PRIVATE_DYLIBS):
            raise RuntimeError(f"Worker has an unreviewed non-system dependency: {dep}")
        found[dep] = name
    for origin in list(found):
        for dep in checker.dependencies(Path(origin)):
            if not dep.startswith(SYSTEM_PREFIXES):
                raise RuntimeError(f"{origin} has a transitive non-system dependency: {dep}")
    return found


def provenance(origin):
    resolved = Path(origin).resolve(strict=True)
    return {
        "load_command": origin, "resolved_origin": str(resolved), "origin_sha256": sha256(resolved),
        "origin_minos": checker.minimum_os(resolved),
        "origin_signature": "adhoc" if "Signature=adhoc" in subprocess.run(
            ["codesign", "-dv", str(resolved)], capture_output=True, text=True).stderr else "other",
    }


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


def relocate(app, worker_source, dependencies):
    contents = app / "Contents"
    worker = contents / "MacOS/fido-worker"
    if sha256(worker) != sha256(worker_source):
        raise RuntimeError("Bundled worker is not the verified release worker")
    frameworks = contents / "Frameworks"
    frameworks.mkdir()
    changes = []
    for origin, name in sorted(dependencies.items()):
        target = frameworks / name
        shutil.copyfile(Path(origin).resolve(strict=True), target)
        target.chmod(0o644)
        run(["install_name_tool", "-id", FRAMEWORK_PREFIX + name, target])
        changes += ["-change", origin, FRAMEWORK_PREFIX + name]
    if changes:
        run(["install_name_tool", *changes, worker])
    worker.chmod(0o755)


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
    worker = build_worker(triple, environment)
    dependencies = private_dependencies(worker)
    sidecar = PACKAGE / "sidecar" / f"fido-worker-{triple}"
    shutil.copyfile(worker, sidecar)
    sidecar.chmod(0o755)

    minimum = max(["11.0", checker.minimum_os(worker), *(checker.minimum_os(Path(d)) for d in dependencies)],
                  key=checker.version_tuple)
    built = tauri_build(minimum, environment)
    app = PACKAGE / built.name
    shutil.move(built, app)
    relocate(app, worker, dependencies)
    signer.sign(app, "-")
    frontend = ROOT / "dist"
    summary = checker.check(app, signature_mode="adhoc", expected_version=version,
                            frontend_dist=frontend, execute_worker=True)
    summary["release_worker_sha256_before_relocation"] = sha256(worker)
    summary["native_dependencies"] = {name: provenance(origin) for origin, name in dependencies.items()}
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
