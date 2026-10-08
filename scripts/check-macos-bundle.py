#!/usr/bin/env python3
"""Deterministic structural checks for an assembled macOS Fido Manager.app.

Uses only non-secret tools (plistlib, otool, nm, lipo, codesign). Proves layout, worker
placement, native linkage and signature *shape*; it never proves notarization or authenticity.
"""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import tempfile

from release_metadata import (CheckError, require, hex_value, read_regular, digest,
                              identity_record, publisher_requirement, parse_json, keys)

ROOT = Path(__file__).resolve().parents[1]
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
MACH_O_MAGIC = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
WORKER_EXIT_USAGE, WORKER_EXIT_ORDERLY, WORKER_EXIT_CONFIG = 64, 0, 78


def run(command, **options):
    options.setdefault("env", {**os.environ, "LC_ALL": "C", "LANG": "C"})
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


def signature(binary, arch=None):
    result = run(["codesign", "-dvvv", *(["--arch", arch] if arch else []), str(binary)])
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


class UniquePlist(dict):
    def __setitem__(self, key, value):
        require(key not in self, f"duplicate Info.plist key: {key}")
        super().__setitem__(key, value)


def check_info(app, expected_version):
    info = plistlib.loads(read_regular(app / "Contents/Info.plist"), dict_type=UniquePlist)
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


def check_tree(app, mode="adhoc", stapled=False):
    require(not stapled or mode == "developer-id", "stapling requires Developer ID mode")
    require(not app.is_symlink(), "symlink bundle root")
    contents = app / "Contents"
    require(not (contents / "Frameworks").exists(), "Contents/Frameworks must not exist (no bundled dylibs)")
    allowed = {"Contents/Info.plist", "Contents/PkgInfo", f"Contents/MacOS/{MAIN_EXECUTABLE}",
               f"Contents/MacOS/{WORKER}", "Contents/Resources/icon.icns", f"Contents/Resources/{NOTICES}",
               "Contents/_CodeSignature/CodeResources"}
    if mode == "developer-id":
        allowed.add("Contents/Resources/release-worker-identity.json")
    if stapled:
        allowed.add("Contents/CodeResources")
        require((app / "Contents/CodeResources").is_file(), "stapled bundle ticket missing")
    directories = {"Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"}
    for path in sorted(app.rglob("*")):
        relative = path.relative_to(app).as_posix()
        require(not path.is_symlink(), f"symlink in bundle: {relative}")
        if WORKER in path.name and relative != f"Contents/MacOS/{WORKER}":
            raise CheckError(f"duplicate or misplaced worker: {relative}")
        if path.is_dir():
            require(relative in directories, f"unexpected directory: {relative}")
        else:
            require(stat.S_ISREG(path.lstat().st_mode) and path.lstat().st_nlink == 1,
                    f"not a single regular file: {relative}")
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


def check_signatures(app, main, worker, mode, expected_team_id=None):
    for binary in (main, worker):
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
            check_developer_signature(fields, expected_team_id, binary.name)
            require(re.search(r"flags=0x10000\(runtime\)", flags),
                    f"{binary.name}: Hardened Runtime flags mismatch")
            identifier = BUNDLE_ID if binary == main else WORKER_IDENTIFIER
            check_requirement(binary, publisher_requirement(identifier, expected_team_id))
            check_designated_requirement(binary, identifier, expected_team_id)
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


RID_KEY = "FidoManagerReleaseWorkerIdentitySHA256"
MARKER = b"FIDOMANAGER-RELEASE-ENFORCING-MARKER/"


def check_developer_signature(fields, team, label):
    publisher_requirement(BUNDLE_ID, team)
    authorities = fields.get("Authority", [])
    require(len(authorities) == 3 and
            re.fullmatch(r"Developer ID Application: .+ \(" + re.escape(team) + r"\)", authorities[0]) and
            authorities[1:] == ["Developer ID Certification Authority", "Apple Root CA"],
            f"{label}: not signed with Developer ID authority chain for expected Team ID")
    require(fields.get("TeamIdentifier") == [team], f"{label}: wrong Team ID")
    timestamp = fields.get("Timestamp", [])
    require(len(timestamp) == 1 and timestamp[0].strip() and timestamp[0].lower() not in ("none", "not set"),
            f"{label}: no secure timestamp (Signed Time is not trusted)")
    parsed_timestamp = False
    for format in ("%b %d, %Y at %H:%M:%S", "%b %d, %Y at %I:%M:%S %p"):
        try:
            datetime.strptime(timestamp[0], format)
            parsed_timestamp = True
        except ValueError:
            pass
    require(parsed_timestamp, f"{label}: malformed secure timestamp")
    require("Signed Time" not in fields and "Signature" not in fields,
            f"{label}: conflicting signature/timestamp evidence")


def check_requirement(binary, requirement, arch=None):
    result = run(["codesign", "--verify", "--strict", *(["--arch", arch] if arch else []),
                  "-R=" + requirement, str(binary)])
    require(result.returncode == 0, f"{binary.name}: explicit signing requirement failed: {result.stderr.strip()}")


def check_designated_requirement(binary, identifier, team):
    """Parse the small Apple DR grammar, never substring-match a possibly weakened OR expression.

    Accept reordered conjunctions and Apple's documented optional Mac App Store branch; the
    separate explicit publisher requirement always excludes Store signatures (ADR-017 E1).
    Unknown syntax fails closed until a real-output fixture receives review.
    """
    result = run(["codesign", "-d", "-r-", str(binary)])
    require(result.returncode == 0, "cannot read designated requirement")
    lines = [line.removeprefix("designated => ") for line in (result.stdout + "\n" + result.stderr).splitlines()
             if line.startswith("designated => ")]
    require(len(lines) == 1, "missing or ambiguous designated requirement")
    text = lines[0]
    atom = (r'anchor apple generic|identifier "[a-zA-Z0-9.-]+"|'
            r'certificate (?:1|leaf)\[field\.[0-9.]+\](?: exists)?|'
            r'certificate leaf\[subject\.OU\] = (?:"[A-Z0-9]{10}"|[A-Z0-9]{10})')
    token = re.compile(r"\s*(" + atom + r"|\(|\)|and\b|or\b)\s*")
    tokens, offset = [], 0
    while offset < len(text):
        found = token.match(text, offset)
        require(found is not None, "unsupported designated requirement syntax")
        tokens.append(found[1].replace(" exists", ""))
        offset = found.end()
    require(len(tokens) <= 64, "designated requirement too complex")
    pos = 0

    def factor():
        nonlocal pos
        require(pos < len(tokens), "incomplete designated requirement")
        current = tokens[pos]
        pos += 1
        if current == "(":
            value = expression()
            require(pos < len(tokens) and tokens[pos] == ")", "unbalanced designated requirement")
            pos += 1
            return value
        require(current not in ("and", "or", ")"), "invalid designated requirement atom")
        if current.startswith("certificate leaf[subject.OU]"):
            current = current.replace('"', '')
        return {frozenset([current])}

    def conjunction():
        nonlocal pos
        value = factor()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1
            right = factor()
            value = {a | b for a in value for b in right}
            require(len(value) <= 4, "too many designated requirement alternatives")
        return value

    def expression():
        nonlocal pos
        value = conjunction()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1
            value |= conjunction()
            require(len(value) <= 4, "too many designated requirement alternatives")
        return value

    actual = expression()
    require(pos == len(tokens), "trailing designated requirement syntax")
    common = {"anchor apple generic", f'identifier "{identifier}"'}
    developer = frozenset(common | {"certificate 1[field.1.2.840.113635.100.6.2.6]",
                                    "certificate leaf[field.1.2.840.113635.100.6.1.13]",
                                    f"certificate leaf[subject.OU] = {team}"})
    store = frozenset(common | {"certificate leaf[field.1.2.840.113635.100.6.1.9]"})
    require(actual in ({developer}, {developer, store}), "designated requirement identity/clauses mismatch")
    return text


def check_release_identity(app, main, worker, info, version, commit, team, arch):
    rid = info.get(RID_KEY)
    require(hex_value(rid), "missing or malformed release identity Info.plist digest")
    data = read_regular(app / "Contents/Resources/release-worker-identity.json", 4096)
    require(digest(data) == rid, "identity record digest differs from Info.plist")
    record = identity_record(data, version, commit, team)
    identity = record["worker"]
    require(identity["file_sha256"] == digest(read_regular(worker, 256 * 1024 * 1024)),
            "worker file SHA-256 mismatch")
    require(identity["slices"][0]["arch"] == arch, "worker slice architecture mismatch")
    for item in identity["slices"]:
        fields = signature(worker, item["arch"])
        require(fields.get("CDHash") == [item["cdhash"]] and
                fields.get("CandidateCDHashFull sha256") == [item["cdhash_sha256"]],
                "worker CDHash mismatch")
        check_requirement(worker, publisher_requirement(WORKER_IDENTIFIER, team) +
                          f' and cdhash H"{item["cdhash"]}"', item["arch"])
    expected = f"{MARKER.decode()}1;team={team};version={version};commit={commit};end".encode()
    binary = main.read_bytes()
    starts = [match.start() for match in re.finditer(re.escape(MARKER), binary)]
    require(len(starts) == 1 and binary[starts[0]:starts[0] + len(expected)] == expected,
            "missing, malformed or conflicting release-enforcement marker")
    require(identity["build_id"].encode() in worker.read_bytes(), "worker compiled build identity missing")
    return {"record_sha256": rid, "worker_file_sha256": identity["file_sha256"],
            "cdhash": {item["arch"]: item["cdhash"] for item in identity["slices"]}}


def check_staple(path, team):
    result = run(["xcrun", "stapler", "validate", str(path)])
    require(result.returncode == 0 and "The validate action worked!" in result.stdout,
            f"{path.name}: stapler validation failed")
    options = ["--type", "execute"] if path.suffix == ".app" else ["--type", "open", "--context", "context:primary-signature"]
    result = run(["spctl", "--assess", *options, "-vvv", str(path)])
    text = result.stdout + "\n" + result.stderr
    require(result.returncode == 0 and re.search(r"^.*: accepted$", text, re.M) and
            re.search(r"^source=Notarized Developer ID$", text, re.M), f"{path.name}: Gatekeeper assessment failed")
    if path.suffix == ".app":
        require(re.search(r"^origin=Developer ID Application: .+ \(" + re.escape(team) + r"\)$", text, re.M),
                "Gatekeeper origin mismatch")


def tree_digest(app):
    """Compare mounted app bytes and executable modes with the already checked app."""
    return {p.relative_to(app).as_posix(): (digest(read_regular(p, 256 * 1024 * 1024)),
                                          stat.S_IMODE(p.stat().st_mode) & 0o777)
            for p in app.rglob("*") if not p.is_dir()}


def check_dmg(dmg, app, team, stapled):
    read_regular(dmg, 512 * 1024 * 1024)
    fields = signature(dmg)
    check_developer_signature(fields, team, dmg.name)
    require(fields.get("Identifier") == [BUNDLE_ID + ".dmg"], "DMG signing identifier mismatch")
    require(not entitlements(dmg), "DMG has entitlements")
    check_requirement(dmg, publisher_requirement(BUNDLE_ID + ".dmg", team))
    check_designated_requirement(dmg, BUNDLE_ID + ".dmg", team)
    image = plistlib.loads(output(["hdiutil", "imageinfo", "-plist", str(dmg)]).encode())
    require(image.get("Format") == "UDZO", "DMG must be UDZO")
    output(["hdiutil", "verify", str(dmg)])
    if stapled:
        check_staple(dmg, team)
    with tempfile.TemporaryDirectory(prefix="fidomanager-dmg-check-") as directory:
        mount = Path(directory).resolve() / "volume"
        mount.mkdir()
        attached = False
        try:
            output(["hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", str(mount), str(dmg)])
            attached = True
            require({p.name for p in mount.iterdir()} == {"Fido Manager.app", "Applications"}, "unexpected DMG tree")
            applications = mount / "Applications"
            require(applications.is_symlink() and os.readlink(applications) == "/Applications", "DMG Applications link mismatch")
            bundled = mount / "Fido Manager.app"
            check_tree(bundled, "developer-id", stapled)
            require(tree_digest(bundled) == tree_digest(app), "DMG app differs from verified app")
        finally:
            if attached:
                output(["hdiutil", "detach", str(mount)])


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


def check(app, *, signature_mode, expected_version, frontend_dist=None, execute_worker=True,
          expected_team_id=None, expected_commit=None, stapled=False, dmg=None, pre_staple_cdhashes=None):
    require(signature_mode in ("adhoc", "developer-id"), "invalid signature mode")
    if signature_mode == "developer-id":
        publisher_requirement(BUNDLE_ID, expected_team_id)
        require(hex_value(expected_commit, 40), "explicit expected source commit required")
    else:
        require(not stapled and dmg is None, "release stapling/DMG checks require Developer ID mode")
    require(not app.is_symlink(), "symlink bundle root")
    app = app.resolve(strict=True)
    require(app.suffix == ".app" and app.is_dir(), "not an application bundle")
    main, worker = check_tree(app, signature_mode, stapled)
    info = check_info(app, expected_version)
    if signature_mode == "adhoc":
        require(RID_KEY not in info, "release identity digest forbidden in ad-hoc bundle")
    arch, minimum = check_linkage(main, worker, info)
    check_symbols(main, worker)
    assets = check_frontend(main, frontend_dist) if frontend_dist else 0
    check_signatures(app, main, worker, signature_mode, expected_team_id)
    release = None
    if signature_mode == "developer-id":
        release = check_release_identity(app, main, worker, info, expected_version,
                                         expected_commit, expected_team_id, arch)
        if stapled:
            keys(pre_staple_cdhashes, "fidomanager-app fido-worker" + (" dmg" if dmg is not None else ""),
                 "pre-staple cdhash evidence")
            for binary in (main, worker):
                keys(pre_staple_cdhashes[binary.name], arch, "pre-staple architecture")
                expected = pre_staple_cdhashes[binary.name][arch]
                require(hex_value(expected, 40) and signature(binary, arch).get("CDHash") == [expected],
                        f"{binary.name}: cdhash changed after stapling")
            if dmg is not None:
                expected = pre_staple_cdhashes["dmg"]
                require(hex_value(expected, 40) and signature(dmg).get("CDHash") == [expected],
                        "DMG cdhash changed after stapling")
            check_staple(app, expected_team_id)
        if dmg is not None:
            check_dmg(dmg, app, expected_team_id, stapled)
    if execute_worker:
        check_worker_runtime(worker)
    code_evidence = None
    if signature_mode == "developer-id":
        code_evidence = {
            "team_id": expected_team_id, "release_identity": release,
            "file_sha256": {binary.name: digest(read_regular(binary, 256 * 1024 * 1024)) for binary in (main, worker)},
            "system_dependencies": {binary.name: dependencies(binary) for binary in (main, worker)},
            "cdhash": {binary.name: {arch: signature(binary, arch)["CDHash"][0]} for binary in (main, worker)},
            "dmg_cdhash": signature(dmg)["CDHash"][0] if dmg is not None else None,
        }
    return {
        "code_evidence": code_evidence,
        "bundle_identifier": BUNDLE_ID, "version": expected_version, "architecture": arch,
        "minimum_system_version": info["LSMinimumSystemVersion"], "newest_code_minos": minimum,
        "main_executable": f"Contents/MacOS/{MAIN_EXECUTABLE}", "worker": f"Contents/MacOS/{WORKER}",
        "bundled_libraries": [], "frameworks_directory": False,
        "worker_dynamic_dependencies": sorted(dependencies(worker)),
        "third_party_notices": f"Contents/Resources/{NOTICES}", "embedded_frontend_assets": assets,
        "signature": signature_mode, "worker_executed": execute_worker,
        "release_identity": release, "stapled": stapled,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument("--signature", choices=("adhoc", "developer-id"), default="adhoc")
    parser.add_argument("--expected-team-id")
    parser.add_argument("--expected-commit", help="peeled source commit from trusted release context")
    parser.add_argument("--stapled", action="store_true")
    parser.add_argument("--dmg", type=Path)
    parser.add_argument("--pre-staple-cdhashes", type=Path, help="trusted pre-staple observations; required with --stapled")
    parser.add_argument("--frontend-dist", type=Path)
    parser.add_argument("--no-execute-worker", action="store_true")
    arguments = parser.parse_args()
    version = json.loads((ROOT / "src-tauri/tauri.conf.json").read_text())["version"]
    try:
        summary = check(arguments.app, signature_mode=arguments.signature, expected_version=version,
                        frontend_dist=arguments.frontend_dist, execute_worker=not arguments.no_execute_worker,
                        expected_team_id=arguments.expected_team_id, expected_commit=arguments.expected_commit,
                        stapled=arguments.stapled, dmg=arguments.dmg,
                        pre_staple_cdhashes=parse_json(read_regular(arguments.pre_staple_cdhashes)) if arguments.pre_staple_cdhashes else None)
    except (CheckError, OSError, ValueError, plistlib.InvalidFileException) as error:
        raise SystemExit(f"FAIL: {error}")
    print("PASS: macOS bundle structure, linkage and signature shape")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
