#!/usr/bin/env python3
"""Deterministic structural checks for an assembled macOS Fido Manager.app.

Uses only non-secret tools (plistlib, otool, nm, lipo, codesign). Proves layout, worker
placement, native linkage and signature *shape*; it never proves notarization or authenticity.
"""

import argparse
import json
import importlib.util
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("macos_authority_policy", ROOT / "scripts/macos-authority-policy.py")
authority_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authority_policy)
BUNDLE_ID = "eu.fidomanager.desktop"
PRODUCT_NAME = "Fido Manager"
MAIN_EXECUTABLE = "fidomanager-app"
WORKER = "fido-worker"
WORKER_IDENTIFIER = BUNDLE_ID + "." + WORKER
IDENTITY_SYMBOL = "fidomanager_libfido2_1_17_0_credman_limit"
# M7.1: the bundle carries no third-party dylibs at all; libfido2, OpenSSL and libcbor are static.
DEPLOYMENT_TARGET = "11.0"
NOTICES = "THIRD_PARTY_NOTICES.md"
SYSTEM_PREFIXES = ("/usr/lib/", "/System/Library/")
FORBIDDEN_LINKAGE = re.compile(
    r"/opt/homebrew|/usr/local|/opt/local|libfido2|libcrypto|libssl|libcbor|@rpath|@loader_path|@executable_path"
)
# Statically linked native symbols the worker must define and must never import at run time.
NATIVE_IMPORT = re.compile(
    r"^\s+U _(?:fido_|fidomanager_|cbor_|EVP_|OPENSSL_|OSSL_|OpenSSL_|CRYPTO_|ERR_|BN_|EC_|ECDSA_|ECDH_|RSA_|HMAC|RAND_)", re.M)
WORKER_STATIC_SYMBOLS = (IDENTITY_SYMBOL, "fido_init", "fido_dev_get_puat", "cbor_load", "cbor_serialize_alloc",
                         "EVP_sha256", "OPENSSL_init_crypto")
# OpenSSL configuration locations that must never be compiled into the worker.
FORBIDDEN_OPENSSLDIRS = (b"/opt/homebrew/etc/openssl", b"/usr/local/etc/openssl", b"/usr/local/ssl", b"/opt/local/etc/openssl")
PRIVATE_OPENSSLDIR = b'OPENSSLDIR: "/var/empty/fidomanager-openssl"'
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
    require(not (contents / "Frameworks").exists(), "Contents/Frameworks must not exist (no bundled dylibs)")
    allowed = {"Contents/Info.plist", "Contents/PkgInfo", f"Contents/MacOS/{MAIN_EXECUTABLE}",
               f"Contents/MacOS/{WORKER}", "Contents/Resources/icon.icns", f"Contents/Resources/{NOTICES}",
               "Contents/_CodeSignature/CodeResources"}
    directories = {"Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"}
    for path in sorted(app.rglob("*")):
        relative = path.relative_to(app).as_posix()
        require(not path.is_symlink(), f"symlink in bundle: {relative}")
        if WORKER in path.name and relative != f"Contents/MacOS/{WORKER}":
            raise CheckError(f"duplicate or misplaced worker: {relative}")
        if path.is_dir():
            require(relative in directories, f"unexpected directory: {relative}")
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
    notices = contents / "Resources" / NOTICES
    require(notices.is_file(), "third-party notices missing from Contents/Resources")
    require(notices.read_bytes() == (ROOT / NOTICES).read_bytes(),
            "packaged third-party notices do not match the reviewed repository copy")
    code = sorted(path for path in app.rglob("*") if path.is_file() and is_mach_o(path))
    require(code == sorted([contents / "MacOS" / MAIN_EXECUTABLE, worker]),
            "unexpected Mach-O set in bundle (exactly fidomanager-app and fido-worker allowed)")
    return contents / "MacOS" / MAIN_EXECUTABLE, worker


def check_linkage(main, worker, info):
    archs = set()
    newest = "0"
    for binary in (main, worker):
        archs.add(output(["lipo", "-archs", str(binary)]).strip())
        newest = max(newest, minimum_os(binary), key=version_tuple)
        text = output(["otool", "-l", str(binary)])
        commands = re.findall(r"^\s*cmd (\S+)$", text, re.M)
        for forbidden in ("LC_RPATH", "LC_DYLD_ENVIRONMENT"):
            require(forbidden not in commands, f"{binary.name}: forbidden {forbidden}")
        loaders = re.findall(r"cmd LC_LOAD_DYLINKER\n.*\n\s*name (\S+)", text)
        require(loaders == ["/usr/lib/dyld"], f"{binary.name}: unexpected dynamic loader {loaders}")
        for dep in dependencies(binary):
            require(not FORBIDDEN_LINKAGE.search(dep), f"{binary.name}: forbidden dependency {dep}")
            require(dep.startswith(SYSTEM_PREFIXES), f"{binary.name}: non-system dependency {dep}")
        for line in output(["otool", "-D", str(binary)]).splitlines()[1:]:
            require(not FORBIDDEN_LINKAGE.search(line), f"{binary.name}: forbidden install name {line}")
    require(len(archs) == 1, f"mixed architectures in bundle: {sorted(archs)}")
    system = set(dependencies(worker))
    require(system == WORKER_SYSTEM_DEPENDENCIES, f"worker system linkage changed: {sorted(system)}")
    minimum = info.get("LSMinimumSystemVersion", "0")
    require(version_tuple(minimum) >= version_tuple(newest),
            f"LSMinimumSystemVersion {minimum} is below bundled code minimum {newest}")
    # The declared floor is reviewed; a dependency must never silently raise it.
    require(minimum == DEPLOYMENT_TARGET,
            f"LSMinimumSystemVersion {minimum} is not the declared deployment target {DEPLOYMENT_TARGET}")
    return archs.pop(), newest


def check_symbols(main, worker):
    worker_symbols = output(["nm", "-g", str(worker)])
    require(not NATIVE_IMPORT.search(worker_symbols),
            "worker has unresolved FIDO/OpenSSL/libcbor symbols (must be statically linked)")
    for symbol in WORKER_STATIC_SYMBOLS:
        require(re.search(r"\bT _" + symbol + r"$", worker_symbols, re.M),
                f"worker does not statically define {symbol}")
    data = worker.read_bytes()
    for forbidden in FORBIDDEN_OPENSSLDIRS:
        require(forbidden not in data, f"worker embeds an external OpenSSL directory {forbidden.decode()}")
    for found in re.findall(rb'(?:OPENSSLDIR|ENGINESDIR|MODULESDIR): "([^"]*)"', data):
        require(found.startswith(b"/var/empty/fidomanager-openssl"),
                f"worker embeds a non-private OpenSSL directory {found.decode(errors='replace')}")
    require(not re.search(r"\b[TU] _(?:fido_|fidomanager_libfido2_)", output(["nm", "-g", str(main)])),
            f"{main.name} must not define or import native FIDO symbols")


def check_frontend(main, dist):
    binary = main.read_bytes()
    assets = sorted(path.relative_to(dist).as_posix() for path in dist.rglob("*") if path.is_file())
    require("index.html" in assets, "frontend dist has no index.html")
    for asset in assets:
        require(("/" + asset).encode() in binary, f"production frontend asset not embedded: {asset}")
    return len(assets)


def check_signatures(app, main, worker, mode):
    authority_policy.check_source()
    for binary in (main, worker):
        fields = signature(binary)
        granted = entitlements(binary)
        for key in FORBIDDEN_ENTITLEMENTS:
            require(key not in granted, f"{binary.name}: forbidden entitlement {key}")
        flags = " ".join(fields.get("CodeDirectory v", []))
        if mode == "adhoc":
            require(fields.get("Signature") == ["adhoc"], f"{binary.name}: expected ad-hoc signature")
            require(fields.get("TeamIdentifier") == ["not set"], f"{binary.name}: ad-hoc code has a Team ID")
            require("linker-signed" not in flags, f"{binary.name}: still only linker-signed")
            require("runtime" not in flags, f"{binary.name}: ad-hoc Hardened Runtime breaks library validation")
        else:
            require(fields.get("Authority", [""])[0].startswith("Developer ID Application:"),
                    f"{binary.name}: not signed with Developer ID")
            require(fields.get("TeamIdentifier") == [authority_policy.TEAM], f"{binary.name}: unreviewed Team ID")
            require("Timestamp" in fields, f"{binary.name}: no secure timestamp")
            if binary in (main, worker):
                require("runtime" in flags, f"{binary.name}: Hardened Runtime missing")
        expected = authority_policy.DEVELOPER_GRANTS if mode == "developer-id" and binary == main else {}
        require(authority_policy.exact(granted) if expected else not granted,
                f"{binary.name}: unexpected entitlements {sorted(granted)}")
    require((authority_policy.MARKER in main.read_bytes()) == (mode == "developer-id"),
            "main executable shared-authority feature does not match signing channel")
    require(authority_policy.MARKER not in worker.read_bytes(), "worker contains shared authority")
    require(signature(main).get("Identifier") == [BUNDLE_ID], "main executable signing identifier mismatch")
    require(signature(worker).get("Identifier") == [WORKER_IDENTIFIER], "worker signing identifier mismatch")
    if mode != "adhoc":
        teams = {tuple(signature(binary)["TeamIdentifier"]) for binary in (main, worker)}
        require(len(teams) == 1, "bundled code is signed by more than one Team ID")
    bundle = run(["codesign", "-dvvv", str(app)]).stderr
    require(re.search(r"^Sealed Resources version=2 ", bundle, re.M), "bundle resources are not sealed")
    require(re.search(r"^Info\.plist entries=\d+$", bundle, re.M), "Info.plist is not bound to the signature")
    result = run(["codesign", "--verify", "--strict", "--deep", "--verbose=2", str(app)])
    require(result.returncode == 0, f"codesign verification failed: {result.stderr.strip()}")


def check_worker_runtime(worker):
    # dyld resolves every load command before main(); these exit codes prove the worker loads with
    # only system libraries and its startup policy is intact. No authenticator is touched.
    for arguments, environment, expected in (
        (["--anything"], {}, WORKER_EXIT_USAGE),
        ([], {"FIDO_DEBUG": "1"}, WORKER_EXIT_CONFIG),
        ([], {}, WORKER_EXIT_ORDERLY),
    ):
        result = run([str(worker), *arguments], env=environment, stdin=subprocess.DEVNULL, timeout=20)
        require(result.returncode == expected,
                f"bundled worker exit {result.returncode} != {expected}: {result.stderr.strip()[:400]}")
    check_worker_openssl_independence(worker)


HOSTILE_MODULE = r"""#include <fcntl.h>
#include <unistd.h>
__attribute__((constructor)) static void loaded(void) {
    int fd = open(MARKER, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}
int OSSL_provider_init(void) { return 0; }
"""


def check_worker_openssl_independence(worker):
    """Start the worker under hostile OpenSSL configuration/module variables and working directory.

    The worker does not initialise OpenSSL before a protocol request, so this proves startup
    independence; the private archive's own build-time probe proves libcrypto ignores the same
    hostile inputs (see scripts/build-native-deps.py). DYLD_* injection is out of scope here: it is
    blocked by Hardened Runtime in the Developer ID release gate, and the app clears the worker's
    environment.
    """
    with tempfile.TemporaryDirectory(prefix="fidomanager-hostile-openssl-") as temporary:
        hostile = Path(temporary)
        marker = hostile / "module-was-loaded"
        (hostile / "module.c").write_text(HOSTILE_MODULE)
        compiled = run(["xcrun", "clang", "-dynamiclib", f'-DMARKER="{marker}"', str(hostile / "module.c"),
                        "-o", str(hostile / "hostile.dylib")])
        require(compiled.returncode == 0, f"cannot build hostile OpenSSL module fixture: {compiled.stderr.strip()}")
        configuration = ("openssl_conf = openssl_init\n[openssl_init]\nproviders = providers\n"
                         f"[providers]\nhostile = hostile\n[hostile]\nmodule = {hostile / 'hostile.dylib'}\n"
                         "activate = 1\n")
        for name in ("openssl.cnf", "hostile.cnf"):
            (hostile / name).write_text(configuration)
        for name in ("legacy.dylib", "fips.dylib", "default.dylib"):
            (hostile / name).write_bytes((hostile / "hostile.dylib").read_bytes())
        environment = {"OPENSSL_CONF": str(hostile / "hostile.cnf"), "OPENSSL_MODULES": str(hostile),
                       "OPENSSL_ENGINES": str(hostile), "OPENSSL_CONF_INCLUDE": str(hostile)}
        result = run([str(worker)], env=environment, cwd=str(hostile), stdin=subprocess.DEVNULL, timeout=20)
        require(result.returncode == WORKER_EXIT_ORDERLY,
                f"worker under hostile OpenSSL environment exit {result.returncode}: {result.stderr.strip()[:400]}")
        require(not marker.exists(), "worker loaded an external OpenSSL module")


def check(app, *, signature_mode, expected_version, frontend_dist=None, execute_worker=True):
    app = app.resolve(strict=True)
    require(app.suffix == ".app" and app.is_dir(), "not an application bundle")
    info = check_info(app, expected_version)
    main, worker = check_tree(app)
    arch, minimum = check_linkage(main, worker, info)
    check_symbols(main, worker)
    assets = check_frontend(main, frontend_dist) if frontend_dist else 0
    check_signatures(app, main, worker, signature_mode)
    if execute_worker:
        check_worker_runtime(worker)
    return {
        "bundle_identifier": BUNDLE_ID, "version": expected_version, "architecture": arch,
        "minimum_system_version": info["LSMinimumSystemVersion"], "newest_code_minos": minimum,
        "main_executable": f"Contents/MacOS/{MAIN_EXECUTABLE}", "worker": f"Contents/MacOS/{WORKER}",
        "bundled_libraries": [], "frameworks_directory": False,
        "worker_dynamic_dependencies": sorted(dependencies(worker)),
        "third_party_notices": f"Contents/Resources/{NOTICES}", "embedded_frontend_assets": assets,
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
