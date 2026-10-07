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
WORKER = Path("Contents/MacOS/fido-worker")
# Exactly the reviewed worker system linkage, so a synthetic worker fails only where intended.
SYSTEM_LINKAGE = ("-mmacosx-version-min=11.0", "-lz", "-liconv", "-framework", "CoreFoundation", "-framework", "IOKit")
REQUIRED = "".join(f"int {symbol}(void) {{ return 0; }}\n" for symbol in checker.WORKER_STATIC_SYMBOLS)


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
              "--identifier", checker.WORKER_IDENTIFIER, app / WORKER)
        quiet("codesign", "--force", "--sign", "-", "--timestamp=none", app)
    return mutate


def change_load(system, replacement):
    """Rewrite one existing system load command of the worker to an attacker-chosen path."""
    def mutate(app):
        original = next(dep for dep in checker.dependencies(app / WORKER) if system in dep)
        quiet("install_name_tool", "-change", original, replacement, app / WORKER)
    return mutate


def synthetic_worker(directory, source, *flags):
    """Replace the worker with a tiny program that differs from a valid worker in one respect."""
    def mutate(app):
        path = directory / "synthetic.c"
        path.write_text(source + "int main(int argc, char **argv) { (void)argv; return argc > 99; }\n")
        quiet("cc", path, "-o", app / WORKER, *SYSTEM_LINKAGE, *flags)
        (app / WORKER).chmod(0o755)
    return mutate


def raise_minos(app):
    raised = app.parent / "raised-worker"
    quiet("vtool", "-set-build-version", "macos", "12.0", "26.0", "-replace", "-output", raised, app / WORKER)
    shutil.move(raised, app / WORKER)
    (app / WORKER).chmod(0o755)


def reintroduce_frameworks(with_library):
    def mutate(app):
        (app / "Contents/Frameworks").mkdir()
        if with_library:
            shutil.copy2(app / "Contents/MacOS/fidomanager-app", app / "Contents/Frameworks/libcrypto.3.dylib")
    return mutate


def write_entitlements(directory):
    path = directory / "debug.entitlements"
    path.write_bytes(plistlib.dumps({"com.apple.security.get-task-allow": True}))
    return path


def cases(directory):
    notices = Path("Contents/Resources") / checker.NOTICES
    return [
        ("duplicate worker in Resources",
         lambda app: shutil.copy2(app / WORKER, app / "Contents/Resources/fido-worker"), True,
         "duplicate or misplaced worker"),
        ("target-triple sidecar left beside worker",
         lambda app: shutil.copy2(app / WORKER, app / "Contents/MacOS/fido-worker-aarch64-apple-darwin"), True,
         "duplicate or misplaced worker"),
        ("missing worker", lambda app: (app / WORKER).unlink(), True, "bundled worker missing"),
        ("world-writable worker", lambda app: (app / WORKER).chmod(0o757), False, "worker permissions unsafe"),
        ("non-executable worker", lambda app: (app / WORKER).chmod(0o644), False, "worker permissions unsafe"),
        ("symlinked worker", lambda app: ((app / WORKER).unlink(), (app / WORKER).symlink_to("/usr/bin/true")),
         False, "symlink in bundle"),
        ("empty Contents/Frameworks reintroduced", reintroduce_frameworks(False), True,
         "Contents/Frameworks must not exist"),
        ("third-party dylib in Contents/Frameworks", reintroduce_frameworks(True), True,
         "Contents/Frameworks must not exist"),
        ("Homebrew libcrypto load command",
         change_load("libz", "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"), True, "forbidden dependency"),
        ("/usr/local libcbor load command", change_load("libz", "/usr/local/lib/libcbor.0.14.dylib"), True,
         "forbidden dependency"),
        ("@rpath libcbor load command", change_load("libiconv", "@rpath/libcbor.0.14.dylib"), True,
         "forbidden dependency"),
        ("@loader_path libfido2 load command", change_load("libiconv", "@loader_path/libfido2.1.dylib"), True,
         "forbidden dependency"),
        ("M7.0-style relocated libcrypto",
         change_load("libz", "@executable_path/../Frameworks/libcrypto.3.dylib"), True, "forbidden dependency"),
        ("non-system absolute dependency", change_load("libiconv", "/Library/Frameworks/Evil.framework/Evil"), True,
         "non-system dependency"),
        ("LC_RPATH search path",
         lambda app: quiet("install_name_tool", "-add_rpath", "/opt/homebrew/lib", app / WORKER), True,
         "forbidden LC_RPATH"),
        ("LC_DYLD_ENVIRONMENT injection",
         synthetic_worker(directory, REQUIRED, "-Wl,-dyld_env,DYLD_INSERT_LIBRARIES=/tmp/inject.dylib"), True,
         "forbidden LC_DYLD_ENVIRONMENT"),
        ("libcbor resolved dynamically",
         synthetic_worker(directory, REQUIRED + "int cbor_new_definite_map(void);\n"
                          "int use(void) { return cbor_new_definite_map(); }\n", "-Wl,-U,_cbor_new_definite_map"),
         True, "unresolved FIDO/OpenSSL/libcbor symbols"),
        ("worker without static OpenSSL",
         synthetic_worker(directory, REQUIRED.replace("EVP_sha256", "not_openssl")), True,
         "does not statically define EVP_sha256"),
        ("Homebrew OPENSSLDIR compiled in",
         synthetic_worker(directory, REQUIRED + '__attribute__((used)) static const char dir[] = '
                          '"OPENSSLDIR: \\"/opt/homebrew/etc/openssl@3\\"";\n'), True,
         "external OpenSSL directory"),
        ("raised Mach-O minimum macOS", raise_minos, True, "is below bundled code minimum 12.0"),
        ("understated minimum macOS", edit_plist("LSMinimumSystemVersion", "10.13"), True,
         "is below bundled code minimum"),
        ("silently raised LSMinimumSystemVersion", edit_plist("LSMinimumSystemVersion", "12.0"), True,
         "is not the declared deployment target 11.0"),
        ("missing third-party notices", lambda app: (app / notices).unlink(), True, "third-party notices missing"),
        ("altered third-party notices", lambda app: (app / notices).open("a").write("\nparaphrase\n"), True,
         "do not match the reviewed repository copy"),
        ("unexpected resource", lambda app: (app / "Contents/Resources/updater.json").write_text("{}"), True,
         "unexpected bundle entry"),
        ("wrong bundle identifier", edit_plist("CFBundleIdentifier", "com.example.other"), True,
         "bundle identifier mismatch"),
        ("wrong version", edit_plist("CFBundleShortVersionString", "9.9.9"), True, "bundle version mismatch"),
        ("LSEnvironment injection", edit_plist("LSEnvironment", {"DYLD_LIBRARY_PATH": "/tmp"}), True,
         "forbidden Info.plist key: LSEnvironment"),
        ("ATS exception", edit_plist("NSAppTransportSecurity", {"NSAllowsArbitraryLoads": True}), True,
         "forbidden Info.plist key: NSAppTransportSecurity"),
        ("debug entitlement",
         lambda app: resign_worker("--entitlements", write_entitlements(directory))(app), False,
         "forbidden entitlement com.apple.security.get-task-allow"),
        ("ad-hoc Hardened Runtime", resign_worker("--options", "runtime"), False,
         "ad-hoc Hardened Runtime breaks library validation"),
        ("unsigned worker", lambda app: quiet("codesign", "--remove-signature", app / WORKER), False, "not signed"),
        ("tampered worker after sealing", lambda app: (app / WORKER).open("ab").write(b"\0"), False,
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
        # The signer itself refuses to seal a bundle that carries a Frameworks directory again.
        copy = directory / "case" / app.name
        shutil.rmtree(copy.parent, ignore_errors=True)
        copy.parent.mkdir()
        subprocess.run(["ditto", str(app), str(copy)], check=True)
        reintroduce_frameworks(True)(copy)
        try:
            signer.sign(copy, "-")
        except RuntimeError as error:
            if "Contents/Frameworks" not in str(error):
                raise SystemExit(f"FAIL: signer wrong Frameworks rejection: {error}")
        else:
            raise SystemExit("FAIL: signer sealed a bundle with Contents/Frameworks")
    print(f"PASS: bundle checker rejected {executed} mutated bundles, refused to treat ad-hoc as Developer ID, "
          "and the signer refused a reintroduced Frameworks directory")


if __name__ == "__main__":
    main()
