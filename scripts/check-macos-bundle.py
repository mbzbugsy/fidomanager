#!/usr/bin/env python3
"""Deterministic structural checks for an assembled macOS Fido Manager.app.

Uses only non-secret tools (plistlib, otool, nm, lipo, codesign). Proves layout, worker
placement, native linkage and signature *shape*; it never proves notarization or authenticity.
"""

import argparse
import json
from pathlib import Path
import plistlib
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ID = "eu.fidomanager.desktop"
PRODUCT_NAME = "Fido Manager"
MAIN_EXECUTABLE = "fidomanager-app"
WORKER = "fido-worker"
WORKER_IDENTIFIER = BUNDLE_ID + "." + WORKER
IDENTITY_SYMBOL = "fidomanager_libfido2_1_17_0_credman_limit"
# Exact reviewed set of relocated worker dependencies (see M7.0 validation document).
PRIVATE_DYLIBS = (re.compile(r"^libcrypto\.3\.dylib$"), re.compile(r"^libcbor\.0\.\d+\.dylib$"))
FRAMEWORK_PREFIX = "@executable_path/../Frameworks/"
SYSTEM_PREFIXES = ("/usr/lib/", "/System/Library/")
FORBIDDEN_LINKAGE = re.compile(r"/opt/homebrew|/usr/local|libfido2|@rpath|@loader_path")
# Never acceptable in this product, regardless of signing identity.
FORBIDDEN_ENTITLEMENTS = (
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.cs.allow-jit",
)
FORBIDDEN_PLIST_KEYS = ("LSEnvironment", "NSAppTransportSecurity", "SUFeedURL", "SUPublicEDKey")
MACH_O_MAGIC = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")
WORKER_EXIT_USAGE, WORKER_EXIT_ORDERLY, WORKER_EXIT_CONFIG = 64, 0, 78


class CheckError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CheckError(message)


def run(command, **options):
    return subprocess.run(command, capture_output=True, text=True, **options)


def output(command):
    result = run(command)
    require(result.returncode == 0, f"{command[0]} failed: {result.stderr.strip()}")
    return result.stdout


def is_mach_o(path):
    with path.open("rb") as source:
        return source.read(4) in MACH_O_MAGIC


def version_tuple(text):
    return tuple(int(part) for part in text.split("."))


def minimum_os(binary):
    commands = output(["otool", "-l", str(binary)])
    versions = re.findall(r"^\s*minos (\S+)$", commands, re.M)
    versions += re.findall(r"cmd LC_VERSION_MIN_MACOSX\n.*\n\s*version (\S+)", commands)
    require(versions, f"{binary.name}: no minimum macOS version load command")
    return max(versions, key=version_tuple)


def load_commands(binary):
    return re.findall(r"^\s*cmd (\S+)$", output(["otool", "-l", str(binary)]), re.M)


def dependencies(binary):
    lines = output(["otool", "-L", str(binary)]).splitlines()[1:]
    deps = [line.strip().split(" (compatibility")[0] for line in lines if line.strip()]
    install_id = output(["otool", "-D", str(binary)]).splitlines()[1:]
    return [dep for dep in deps if dep not in install_id]


def entitlements(binary):
    result = run(["codesign", "-d", "--entitlements", "-", "--xml", str(binary)])
    require(result.returncode == 0, f"{binary.name}: cannot read entitlements")
    data = result.stdout.strip().encode()
    return plistlib.loads(data) if data else {}


def signature(binary):
    result = run(["codesign", "-dvvv", str(binary)])
    require(result.returncode == 0, f"{binary.name}: not signed ({result.stderr.strip()})")
    fields = {}
    for line in result.stderr.splitlines():
        key, _, value = line.partition("=")
        fields.setdefault(key, []).append(value)
    return fields


# The worker's exact expected system linkage: HID via IOKit/CoreFoundation, nothing network-capable.
WORKER_SYSTEM_DEPENDENCIES = {
    "/usr/lib/libz.1.dylib",
    "/usr/lib/libiconv.2.dylib",
    "/usr/lib/libSystem.B.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
}


def check_info(app, expected_version):
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    require(info.get("CFBundleIdentifier") == BUNDLE_ID, "bundle identifier mismatch")
    require(info.get("CFBundleName") == PRODUCT_NAME, "bundle name mismatch")
    require(info.get("CFBundleDisplayName") == PRODUCT_NAME, "bundle display name mismatch")
    require(info.get("CFBundlePackageType") == "APPL", "bundle package type mismatch")
    require(info.get("CFBundleExecutable") == MAIN_EXECUTABLE, "main executable name mismatch")
    require(info.get("CFBundleShortVersionString") == expected_version
            and info.get("CFBundleVersion") == expected_version, "bundle version mismatch")
    require(info.get("CFBundleIconFile") == "icon.icns", "bundle icon mismatch")
    for key in FORBIDDEN_PLIST_KEYS:
        require(key not in info, f"forbidden Info.plist key: {key}")
    return info


def check_tree(app):
    contents = app / "Contents"
    allowed = {"Contents/Info.plist", "Contents/PkgInfo", f"Contents/MacOS/{MAIN_EXECUTABLE}",
               f"Contents/MacOS/{WORKER}", "Contents/Resources/icon.icns",
               "Contents/_CodeSignature/CodeResources"}
    directories = {"Contents", "Contents/MacOS", "Contents/Resources", "Contents/Frameworks",
                   "Contents/_CodeSignature"}
    frameworks = []
    for path in sorted(app.rglob("*")):
        relative = path.relative_to(app).as_posix()
        require(not path.is_symlink(), f"symlink in bundle: {relative}")
        if WORKER in path.name and relative != f"Contents/MacOS/{WORKER}":
            raise CheckError(f"duplicate or misplaced worker: {relative}")
        if path.is_dir():
            require(relative in directories, f"unexpected directory: {relative}")
        elif path.parent == contents / "Frameworks":
            require(any(pattern.match(path.name) for pattern in PRIVATE_DYLIBS),
                    f"unexpected bundled library: {relative}")
            frameworks.append(path)
        else:
            require(relative in allowed, f"unexpected bundle entry: {relative}")
    worker = contents / "MacOS" / WORKER
    require(worker.is_file(), "bundled worker missing at Contents/MacOS/fido-worker")
    mode = stat.S_IMODE(worker.lstat().st_mode)
    require(mode & 0o100 and not mode & 0o022, f"worker permissions unsafe: {oct(mode)}")
    # The app resolves the worker beside its own canonical executable; they must share a directory.
    require((contents / "MacOS" / MAIN_EXECUTABLE).is_file(), "main executable missing")
    require((contents / "Resources/icon.icns").read_bytes()
            == (ROOT / "src-tauri/icons/icon.icns").read_bytes(), "bundle icon is not the project icon")
    code = sorted(path for path in app.rglob("*") if path.is_file() and is_mach_o(path))
    require(code == sorted([contents / "MacOS" / MAIN_EXECUTABLE, worker, *frameworks]),
            "unexpected Mach-O set in bundle")
    return contents / "MacOS" / MAIN_EXECUTABLE, worker, frameworks


def check_linkage(main, worker, frameworks, info):
    bundled = {path.name for path in frameworks}
    used = set()
    archs = set()
    newest = "0"
    for binary in (main, worker, *frameworks):
        archs.add(output(["lipo", "-archs", str(binary)]).strip())
        newest = max(newest, minimum_os(binary), key=version_tuple)
        commands = load_commands(binary)
        for forbidden in ("LC_RPATH", "LC_DYLD_ENVIRONMENT"):
            require(forbidden not in commands, f"{binary.name}: forbidden {forbidden}")
        for dep in dependencies(binary):
            require(not FORBIDDEN_LINKAGE.search(dep), f"{binary.name}: forbidden dependency {dep}")
            if dep.startswith(SYSTEM_PREFIXES):
                continue
            require(binary != main, f"main application must not load bundled native code: {dep}")
            require(dep.startswith(FRAMEWORK_PREFIX) and dep[len(FRAMEWORK_PREFIX):] in bundled,
                    f"{binary.name}: dependency is neither system nor bundled: {dep}")
            used.add(dep[len(FRAMEWORK_PREFIX):])
        for line in output(["otool", "-D", str(binary)]).splitlines()[1:]:
            require(not FORBIDDEN_LINKAGE.search(line), f"{binary.name}: forbidden install name {line}")
    require(len(archs) == 1, f"mixed architectures in bundle: {sorted(archs)}")
    require(used == bundled, "bundled libraries do not match the worker's dependencies")
    system = {dep for dep in dependencies(worker) if dep.startswith(SYSTEM_PREFIXES)}
    require(system == WORKER_SYSTEM_DEPENDENCIES, f"worker system linkage changed: {sorted(system)}")
    minimum = info.get("LSMinimumSystemVersion", "0")
    require(version_tuple(minimum) >= version_tuple(newest),
            f"LSMinimumSystemVersion {minimum} is below bundled code minimum {newest}")
    return archs.pop(), newest


def check_symbols(main, worker, frameworks):
    worker_symbols = output(["nm", "-g", str(worker)])
    for symbol in (IDENTITY_SYMBOL, "fido_init", "fido_dev_get_puat"):
        require(re.search(r"\bT _" + symbol + r"$", worker_symbols, re.M),
                f"worker does not statically define {symbol}")
    require(not re.search(r"\bU _(?:fido_|fidomanager_libfido2_)", worker_symbols),
            "worker has unresolved FIDO symbols")
    for binary in (main, *frameworks):
        require(not re.search(r"\b[TU] _(?:fido_|fidomanager_libfido2_)", output(["nm", "-g", str(binary)])),
                f"{binary.name} must not define or import native FIDO symbols")


def check_frontend(main, dist):
    binary = main.read_bytes()
    assets = sorted(path.relative_to(dist).as_posix() for path in dist.rglob("*") if path.is_file())
    require("index.html" in assets, "frontend dist has no index.html")
    for asset in assets:
        require(("/" + asset).encode() in binary, f"production frontend asset not embedded: {asset}")
    return len(assets)


def check_signatures(app, main, worker, frameworks, mode):
    for binary in (main, worker, *frameworks):
        fields = signature(binary)
        granted = entitlements(binary)
        for key in FORBIDDEN_ENTITLEMENTS:
            require(key not in granted, f"{binary.name}: forbidden entitlement {key}")
        require(not granted, f"{binary.name}: unexpected entitlements {sorted(granted)}")
        flags = " ".join(fields.get("CodeDirectory v", []))
        if mode == "adhoc":
            require(fields.get("Signature") == ["adhoc"], f"{binary.name}: expected ad-hoc signature")
            require(fields.get("TeamIdentifier") == ["not set"], f"{binary.name}: ad-hoc code has a Team ID")
            require("linker-signed" not in flags, f"{binary.name}: still only linker-signed")
            require("runtime" not in flags, f"{binary.name}: ad-hoc Hardened Runtime breaks library validation")
        else:
            require(fields.get("Authority", [""])[0].startswith("Developer ID Application:"),
                    f"{binary.name}: not signed with Developer ID")
            require(fields.get("TeamIdentifier", ["not set"]) != ["not set"], f"{binary.name}: no Team ID")
            require("Timestamp" in fields, f"{binary.name}: no secure timestamp")
            if binary in (main, worker):
                require("runtime" in flags, f"{binary.name}: Hardened Runtime missing")
    require(signature(main).get("Identifier") == [BUNDLE_ID], "main executable signing identifier mismatch")
    require(signature(worker).get("Identifier") == [WORKER_IDENTIFIER], "worker signing identifier mismatch")
    if mode != "adhoc":
        teams = {tuple(signature(binary)["TeamIdentifier"]) for binary in (main, worker, *frameworks)}
        require(len(teams) == 1, "bundled code is signed by more than one Team ID")
    bundle = run(["codesign", "-dvvv", str(app)]).stderr
    require(re.search(r"^Sealed Resources version=2 ", bundle, re.M), "bundle resources are not sealed")
    require(re.search(r"^Info\.plist entries=\d+$", bundle, re.M), "Info.plist is not bound to the signature")
    result = run(["codesign", "--verify", "--strict", "--deep", "--verbose=2", str(app)])
    require(result.returncode == 0, f"codesign verification failed: {result.stderr.strip()}")


def check_worker_runtime(worker):
    # dyld resolves every load command before main(); these exit codes prove the relocated
    # libraries load and the worker's startup policy is intact. No authenticator is touched.
    for arguments, environment, expected in (
        (["--anything"], {}, WORKER_EXIT_USAGE),
        ([], {"FIDO_DEBUG": "1"}, WORKER_EXIT_CONFIG),
        ([], {}, WORKER_EXIT_ORDERLY),
    ):
        result = run([str(worker), *arguments], env=environment, stdin=subprocess.DEVNULL, timeout=20)
        require(result.returncode == expected,
                f"bundled worker exit {result.returncode} != {expected}: {result.stderr.strip()[:400]}")


def check(app, *, signature_mode, expected_version, frontend_dist=None, execute_worker=True):
    app = app.resolve(strict=True)
    require(app.suffix == ".app" and app.is_dir(), "not an application bundle")
    info = check_info(app, expected_version)
    main, worker, frameworks = check_tree(app)
    arch, minimum = check_linkage(main, worker, frameworks, info)
    check_symbols(main, worker, frameworks)
    assets = check_frontend(main, frontend_dist) if frontend_dist else 0
    check_signatures(app, main, worker, frameworks, signature_mode)
    if execute_worker:
        check_worker_runtime(worker)
    return {
        "bundle_identifier": BUNDLE_ID, "version": expected_version, "architecture": arch,
        "minimum_system_version": info["LSMinimumSystemVersion"], "newest_code_minos": minimum,
        "main_executable": f"Contents/MacOS/{MAIN_EXECUTABLE}", "worker": f"Contents/MacOS/{WORKER}",
        "bundled_libraries": [path.name for path in frameworks], "embedded_frontend_assets": assets,
        "signature": signature_mode, "worker_executed": execute_worker,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument("--signature", choices=("adhoc", "developer-id"), default="adhoc")
    parser.add_argument("--frontend-dist", type=Path)
    parser.add_argument("--no-execute-worker", action="store_true")
    arguments = parser.parse_args()
    version = json.loads((ROOT / "src-tauri/tauri.conf.json").read_text())["version"]
    try:
        summary = check(arguments.app, signature_mode=arguments.signature, expected_version=version,
                        frontend_dist=arguments.frontend_dist, execute_worker=not arguments.no_execute_worker)
    except CheckError as error:
        raise SystemExit(f"FAIL: {error}")
    print("PASS: macOS bundle structure, linkage and signature shape")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
