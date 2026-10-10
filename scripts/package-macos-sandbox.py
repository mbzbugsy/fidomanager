#!/usr/bin/env python3
"""Build a LOCAL-TEST App Sandbox (Mac App Store compatibility) Fido Manager.app (ADR-018).

Pipeline (macOS host-native only, no credentials, ad-hoc signing only):

  release fido-worker (identical M7.1 build: private static libfido2 + OpenSSL + libcbor, link-map
  provenance, system-only linkage at macOS 11.0) -> tauri build with the compile-time
  `macos-app-sandbox` feature and an isolated test identity -> reviewed notices -> ad-hoc
  inside-out signing WITH the reviewed App Sandbox entitlements and Hardened Runtime
  -> sandbox bundle checks

The output uses a separate bundle identifier (and therefore a separate App Sandbox container) so
local sandbox testing never shares data with any other Fido Manager build. It is not signed with
any certificate, carries no provisioning profile, is not an installer package, and must not be
distributed or submitted. Mac App Store distribution signing is a separate, credentialed step that
this script refuses to perform.

The Developer ID path (scripts/package-macos.py, scripts/sign-macos-bundle.py, ADR-017) is not
changed by this script: that path still applies zero entitlements.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "target/macos-sandbox-test"
OVERLAY = ROOT / "src-tauri/tauri.macos-bundle.conf.json"
ENTITLEMENTS = ROOT / "packaging/macos-app-sandbox"
FEATURE = "macos-app-sandbox"
# Isolated local-test identity: its own container under ~/Library/Containers.
TEST_IDENTIFIER = "eu.fidomanager.desktop.sandboxtest"
TEST_PRODUCT_NAME = "Fido Manager Sandbox Test"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packager = load("package_macos", "package-macos.py")
sandbox_checker = load("check_macos_sandbox_bundle", "check-macos-sandbox-bundle.py")
run = packager.run


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tauri_build(environment, sidecar):
    built = ROOT / "target/release/bundle/macos" / f"{TEST_PRODUCT_NAME}.app"
    if built.exists():
        shutil.rmtree(built)
    overlay = json.dumps({
        "identifier": TEST_IDENTIFIER,
        "productName": TEST_PRODUCT_NAME,
        "bundle": {
            "externalBin": [os.path.relpath(sidecar, ROOT / "src-tauri")],
            "macOS": {"minimumSystemVersion": packager.DEPLOYMENT_TARGET},
        },
    })
    manifest = ROOT / "src-tauri/Cargo.toml"
    reviewed = manifest.read_bytes()
    try:
        run(["pnpm", "tauri", "build", "--ci", "--bundles", "app", "--features", FEATURE,
             "--config", OVERLAY, "--config", overlay], cwd=ROOT, env=environment)
    finally:
        manifest.write_bytes(reviewed)
    return built


def codesign(path, entitlements, identifier=None):
    # Ad-hoc only. --force replaces Tauri's linker/ad-hoc signature and any entitlements in it.
    command = ["codesign", "--force", "--sign", "-", "--timestamp=none", "--options", "runtime",
               "--entitlements", str(entitlements)]
    if identifier:
        command += ["--identifier", identifier]
    run([*command, path])


def sign_local(app):
    contents = app / "Contents"
    worker = contents / "MacOS" / sandbox_checker.WORKER
    # Inside-out, never --deep: helper first (sandbox inheritance only), then the bundle.
    codesign(worker, ENTITLEMENTS / "worker.entitlements", identifier=f"{TEST_IDENTIFIER}.{worker.name}")
    codesign(app, ENTITLEMENTS / "app.entitlements")
    run(["codesign", "--verify", "--strict", "--deep", "--verbose=2", app])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args()
    if platform.system() != "Darwin":
        raise RuntimeError("macOS packaging requires a macOS host")
    environment = packager.clean_environment()
    triple = packager.host_triple()
    version = json.loads((ROOT / "src-tauri/tauri.conf.json").read_text())["version"]

    shutil.rmtree(OUTPUT, ignore_errors=True)
    (OUTPUT / "sidecar").mkdir(parents=True)
    worker, identity = packager.build_worker(triple, environment)
    sidecar = OUTPUT / "sidecar" / "fido-worker"
    shutil.copyfile(worker, OUTPUT / "sidecar" / f"fido-worker-{triple}")
    (OUTPUT / "sidecar" / f"fido-worker-{triple}").chmod(0o755)

    built = tauri_build(environment, sidecar)
    app = OUTPUT / built.name
    shutil.move(built, app)
    packager.install_notices(app, worker)
    sign_local(app)
    summary = sandbox_checker.check(app, expected_identifier=TEST_IDENTIFIER, expected_name=TEST_PRODUCT_NAME,
                                    expected_version=version, frontend_dist=ROOT / "dist")
    summary["release_worker_sha256_before_signing"] = sha256(worker)
    summary["libfido2_static_archive_sha256"] = identity["static_archive_sha256"]
    summary["cargo_feature"] = FEATURE
    summary["local_test_only"] = True
    summary["mac_app_store_signed"] = False
    summary["provisioning_profile"] = False
    (OUTPUT / "sandbox-package-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"PASS: local App Sandbox test package at {app.relative_to(ROOT)} (NOT for distribution)")


if __name__ == "__main__":
    main()
