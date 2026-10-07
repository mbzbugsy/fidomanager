#!/usr/bin/env python3
"""Regression tests for check-macos-bundle.py against mutated copies of a real assembled bundle."""

import argparse
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load("check_macos_bundle", "check-macos-bundle.py")
signer = load("sign_macos_bundle", "sign-macos-bundle.py")
VERSION = json.loads((ROOT / "src-tauri/tauri.conf.json").read_text())["version"]
FRAMEWORKS = "@executable_path/../Frameworks/"


def quiet(*command):
    subprocess.run([str(part) for part in command], check=True, capture_output=True)


def edit_plist(key, value):
    def mutate(app):
        path = app / "Contents/Info.plist"
        info = plistlib.loads(path.read_bytes())
        info[key] = value
        path.write_bytes(plistlib.dumps(info))
    return mutate


def resign_worker(*options):
    def mutate(app):
        quiet("codesign", "--force", "--sign", "-", "--timestamp=none", *options,
              "--identifier", checker.WORKER_IDENTIFIER, app / "Contents/MacOS/fido-worker")
        quiet("codesign", "--force", "--sign", "-", "--timestamp=none", app)
    return mutate


def library(app, pattern):
    return next(path for path in (app / "Contents/Frameworks").iterdir() if pattern.match(path.name))


def homebrew_path(app):
    crypto = library(app, checker.PRIVATE_DYLIBS[0]).name
    quiet("install_name_tool", "-change", FRAMEWORKS + crypto,
          "/opt/homebrew/opt/openssl@3/lib/" + crypto, app / "Contents/MacOS/fido-worker")


def write_entitlements(directory):
    path = directory / "debug.entitlements"
    path.write_bytes(plistlib.dumps({"com.apple.security.get-task-allow": True}))
    return path


def cases(directory):
    worker = Path("Contents/MacOS/fido-worker")
    return [
        ("duplicate worker in Resources",
         lambda app: shutil.copy2(app / worker, app / "Contents/Resources/fido-worker"), True,
         "duplicate or misplaced worker"),
        ("target-triple sidecar left beside worker",
         lambda app: shutil.copy2(app / worker, app / "Contents/MacOS/fido-worker-aarch64-apple-darwin"), True,
         "duplicate or misplaced worker"),
        ("missing worker", lambda app: (app / worker).unlink(), True, "bundled worker missing"),
        ("world-writable worker", lambda app: (app / worker).chmod(0o757), False, "worker permissions unsafe"),
        ("non-executable worker", lambda app: (app / worker).chmod(0o644), False, "worker permissions unsafe"),
        ("symlinked worker", lambda app: ((app / worker).unlink(), (app / worker).symlink_to("/usr/bin/true")),
         False, "symlink in bundle"),
        ("unexpected libfido2 dylib",
         lambda app: shutil.copy2(library(app, checker.PRIVATE_DYLIBS[1]),
                                  app / "Contents/Frameworks/libfido2.1.dylib"), True, "unexpected bundled library"),
        ("missing bundled library", lambda app: library(app, checker.PRIVATE_DYLIBS[1]).unlink(), True,
         "neither system nor bundled"),
        ("Homebrew load command", homebrew_path, True, "forbidden dependency"),
        ("LC_RPATH search path",
         lambda app: quiet("install_name_tool", "-add_rpath", "/opt/homebrew/lib", app / worker), True,
         "forbidden LC_RPATH"),
        ("unexpected resource", lambda app: (app / "Contents/Resources/updater.json").write_text("{}"), True,
         "unexpected bundle entry"),
        ("wrong bundle identifier", edit_plist("CFBundleIdentifier", "com.example.other"), True,
         "bundle identifier mismatch"),
        ("wrong version", edit_plist("CFBundleShortVersionString", "9.9.9"), True, "bundle version mismatch"),
        ("LSEnvironment injection", edit_plist("LSEnvironment", {"DYLD_LIBRARY_PATH": "/tmp"}), True,
         "forbidden Info.plist key: LSEnvironment"),
        ("ATS exception", edit_plist("NSAppTransportSecurity", {"NSAllowsArbitraryLoads": True}), True,
         "forbidden Info.plist key: NSAppTransportSecurity"),
        ("understated minimum macOS", edit_plist("LSMinimumSystemVersion", "10.13"), True,
         "is below bundled code minimum"),
        ("debug entitlement",
         lambda app: resign_worker("--entitlements", write_entitlements(directory))(app), False,
         "forbidden entitlement com.apple.security.get-task-allow"),
        ("ad-hoc Hardened Runtime", resign_worker("--options", "runtime"), False,
         "ad-hoc Hardened Runtime breaks library validation"),
        ("unsigned worker", lambda app: quiet("codesign", "--remove-signature", app / worker), False, "not signed"),
        ("tampered library after sealing",
         lambda app: library(app, checker.PRIVATE_DYLIBS[1]).open("ab").write(b"\0"), False,
         "codesign verification failed"),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    app = parser.parse_args().app.resolve(strict=True)
    checker.check(app, signature_mode="adhoc", expected_version=VERSION, execute_worker=False)
    with tempfile.TemporaryDirectory(prefix="fidomanager-bundle-check-") as temporary:
        directory = Path(temporary)
        executed = 0
        for label, mutate, resign, expected in cases(directory):
            copy = directory / "case" / app.name
            shutil.rmtree(copy.parent, ignore_errors=True)
            copy.parent.mkdir()
            subprocess.run(["ditto", str(app), str(copy)], check=True)
            mutate(copy)
            if resign:
                # Re-seal so the targeted structural check, not signature verification, must fail.
                quiet("codesign", "--force", "--sign", "-", "--timestamp=none", copy)
            try:
                checker.check(copy, signature_mode="adhoc", expected_version=VERSION, execute_worker=False)
            except checker.CheckError as error:
                if expected not in str(error):
                    raise SystemExit(f"FAIL: {label}: wrong rejection: {error}")
            else:
                raise SystemExit(f"FAIL: {label}: mutated bundle was accepted")
            executed += 1
        try:
            checker.check(app, signature_mode="developer-id", expected_version=VERSION, execute_worker=False)
        except checker.CheckError as error:
            if "not signed with Developer ID" not in str(error):
                raise SystemExit(f"FAIL: ad-hoc bundle wrong Developer ID rejection: {error}")
        else:
            raise SystemExit("FAIL: ad-hoc bundle accepted as Developer ID signed")
    print(f"PASS: bundle checker rejected {executed} mutated bundles and refused to treat ad-hoc as Developer ID")


if __name__ == "__main__":
    main()
