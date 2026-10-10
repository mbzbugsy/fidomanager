#!/usr/bin/env python3
"""Structural and entitlement checks for a LOCAL-TEST App Sandbox Fido Manager.app (ADR-018).

Reuses the M7.0/M7.1 tree, linkage, static-symbol and frontend checks from check-macos-bundle.py
unchanged, then checks the sandbox flavor's signature shape:

- both executables carry exactly the reviewed entitlement sets in packaging/macos-app-sandbox/
  (no forbidden or extra key, no temporary exception, no file or network-server access);
- both carry Hardened Runtime and are ad-hoc signed (local test only: no Team ID, no certificate);
- the bundle seal verifies (`codesign --verify --strict --deep`).

The worker is never asked to do FIDO work here. It is executed once, directly, OUTSIDE any
sandbox: an inherit-only helper must be killed by the system before `main` (SIGTRAP), which proves
the worker cannot run unsandboxed in this flavor.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ENTITLEMENTS = ROOT / "packaging/macos-app-sandbox"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load("check_macos_bundle", "check-macos-bundle.py")
CheckError, require, run = base.CheckError, base.require, base.run
MAIN_EXECUTABLE, WORKER = base.MAIN_EXECUTABLE, base.WORKER
DEFAULT_IDENTIFIER = "eu.fidomanager.desktop.sandboxtest"
DEFAULT_NAME = "Fido Manager Sandbox Test"

# The only keys either executable may carry in this flavor. The exact set per executable is the
# reviewed file; this list is a second, independent guard against widening.
APP_KEYS = {"com.apple.security.app-sandbox", "com.apple.security.device.usb",
            "com.apple.security.network.client"}
WORKER_KEYS = {"com.apple.security.app-sandbox", "com.apple.security.inherit"}


def reviewed(name):
    granted = plistlib.loads((ENTITLEMENTS / name).read_bytes())
    require(all(value is True for value in granted.values()), f"{name}: every entitlement must be boolean true")
    return granted


def check_reviewed_files():
    app, worker = reviewed("app.entitlements"), reviewed("worker.entitlements")
    require(set(app) == APP_KEYS, f"app.entitlements is not the reviewed set: {sorted(app)}")
    require(set(worker) == WORKER_KEYS, f"worker.entitlements is not the reviewed set: {sorted(worker)}")
    for granted in (app, worker):
        for key in granted:
            require(key not in base.FORBIDDEN_ENTITLEMENTS, f"forbidden entitlement {key}")
            require(".temporary-exception." not in key, f"temporary exception entitlement {key}")
    return app, worker


def check_info(app, expected_identifier, expected_name, expected_version):
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    require(info.get("CFBundleIdentifier") == expected_identifier, "bundle identifier mismatch")
    require(info.get("CFBundleName") == expected_name, "bundle name mismatch")
    require(info.get("CFBundlePackageType") == "APPL", "bundle package type mismatch")
    require(info.get("CFBundleExecutable") == MAIN_EXECUTABLE, "main executable name mismatch")
    require(info.get("CFBundleShortVersionString") == expected_version
            and info.get("CFBundleVersion") == expected_version, "bundle version mismatch")
    require(info.get("CFBundleIconFile") == "icon.icns", "bundle icon mismatch")
    for key in base.FORBIDDEN_PLIST_KEYS:
        require(key not in info, f"forbidden Info.plist key: {key}")
    return info


def check_signatures(app, main, worker, expected_identifier, app_entitlements, worker_entitlements):
    for binary, expected, identifier in ((main, app_entitlements, expected_identifier),
                                         (worker, worker_entitlements, f"{expected_identifier}.{WORKER}")):
        fields = base.signature(binary)
        granted = base.entitlements(binary)
        require(granted == expected, f"{binary.name}: entitlements {sorted(granted)} != reviewed {sorted(expected)}")
        flags = " ".join(fields.get("CodeDirectory v", []))
        require("runtime" in flags, f"{binary.name}: Hardened Runtime missing")
        require("linker-signed" not in flags, f"{binary.name}: still only linker-signed")
        require(fields.get("Signature") == ["adhoc"], f"{binary.name}: local sandbox test must be ad-hoc signed")
        require(fields.get("TeamIdentifier") == ["not set"], f"{binary.name}: local test code has a Team ID")
        require(fields.get("Identifier") == [identifier], f"{binary.name}: signing identifier mismatch")
    bundle = run(["codesign", "-dvvv", str(app)]).stderr
    require(re.search(r"^Sealed Resources version=2 ", bundle, re.M), "bundle resources are not sealed")
    require(re.search(r"^Info\.plist entries=\d+$", bundle, re.M), "Info.plist is not bound to the signature")
    result = run(["codesign", "--verify", "--strict", "--deep", "--verbose=2", str(app)])
    require(result.returncode == 0, f"codesign verification failed: {result.stderr.strip()}")


def check_worker_requires_sandboxed_parent(worker):
    # Started from this (unsandboxed) process, an app-sandbox + inherit helper must be terminated
    # by libsystem_secinit before main(). Exit 0/64/78 would mean the worker ran unsandboxed.
    result = subprocess.run([str(worker)], stdin=subprocess.DEVNULL, capture_output=True, timeout=20, env={})
    require(result.returncode == -signal.SIGTRAP,
            f"inherit-only worker ran outside a sandbox (exit {result.returncode}); sandbox inheritance not enforced")


def check(app, *, expected_identifier=DEFAULT_IDENTIFIER, expected_name=DEFAULT_NAME, expected_version,
          frontend_dist=None, execute_worker=True):
    app = app.resolve(strict=True)
    require(app.suffix == ".app" and app.is_dir(), "not an application bundle")
    app_entitlements, worker_entitlements = check_reviewed_files()
    info = check_info(app, expected_identifier, expected_name, expected_version)
    main, worker = base.check_tree(app)
    arch, minimum = base.check_linkage(main, worker, info)
    base.check_symbols(main, worker)
    assets = base.check_frontend(main, frontend_dist) if frontend_dist else 0
    check_signatures(app, main, worker, expected_identifier, app_entitlements, worker_entitlements)
    if execute_worker:
        check_worker_requires_sandboxed_parent(worker)
    return {
        "bundle_identifier": expected_identifier, "version": expected_version, "architecture": arch,
        "minimum_system_version": info["LSMinimumSystemVersion"], "newest_code_minos": minimum,
        "worker_dynamic_dependencies": sorted(base.dependencies(worker)),
        "embedded_frontend_assets": assets, "signature": "adhoc+runtime (local App Sandbox test)",
        "app_entitlements": sorted(app_entitlements), "worker_entitlements": sorted(worker_entitlements),
        "worker_refused_outside_sandbox": execute_worker,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("app", type=Path)
    parser.add_argument("--frontend-dist", type=Path)
    parser.add_argument("--no-execute-worker", action="store_true")
    arguments = parser.parse_args()
    version = json.loads((ROOT / "src-tauri/tauri.conf.json").read_text())["version"]
    try:
        summary = check(arguments.app, expected_version=version, frontend_dist=arguments.frontend_dist,
                        execute_worker=not arguments.no_execute_worker)
    except CheckError as error:
        raise SystemExit(f"FAIL: {error}")
    print("PASS: App Sandbox bundle structure, linkage, entitlements and signature shape")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
