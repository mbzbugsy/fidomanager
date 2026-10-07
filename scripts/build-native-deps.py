#!/usr/bin/env python3
"""Checksum-pinned private static OpenSSL (libcrypto) and libcbor builds for the macOS worker.

Reviewed inputs live in native/<name>/source.lock.json. Archives are fetched over HTTPS only,
size-bounded and checksum-verified before use, then unpacked by a strict extractor that accepts
only regular files and directories beneath the single expected archive root. Every build
configures from freshly extracted source; nothing is cached between builds and no Homebrew or
system copy of either library is consulted.
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
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
SOURCES = ROOT / "target/native-sources"
DEPENDENCIES = ("openssl", "libcbor")
TARGETS = {"aarch64-apple-darwin": "arm64", "x86_64-apple-darwin": "x86_64"}
DEPLOYMENT_TARGET = "11.0"
SOURCE_DATE_EPOCH = "1781654400"
# Root-owned and not creatable by users: OPENSSLDIR/ENGINESDIR/MODULESDIR compile to this prefix.
OPENSSL_PREFIX = "/var/empty/fidomanager-openssl"
OPENSSL_CONFIGURE_TARGETS = {"arm64": "darwin64-arm64", "x86_64": "darwin64-x86_64"}
# Mandatory M7.1 policy: static only, no loadable providers or engines, no DSO loader and no
# implicit configuration loading. The remaining switches only drop products the worker never uses.
OPENSSL_POLICY = ("no-shared", "no-module", "no-engine", "no-dso", "no-autoload-config")
OPENSSL_OPTIONS = OPENSSL_POLICY + ("no-legacy", "no-apps", "no-tests", "no-docs", "no-ui-console")
OPENSSL_POLICY_MACROS = ("OPENSSL_NO_AUTOLOAD_CONFIG", "OPENSSL_NO_DSO", "OPENSSL_NO_ENGINE")
LIBCBOR_OPTIONS = (
    "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=OFF", "-DWITH_TESTS=OFF",
    "-DWITH_EXAMPLES=OFF", "-DBUILD_TESTING=OFF", "-DSANITIZE=OFF", "-DCOVERAGE=OFF",
    # Upstream enables LTO for Release; LLVM bitcode members would hide object provenance.
    "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=OFF",
)
# Host toolchain selection only. Everything else (CC, CFLAGS, PKG_CONFIG_*, OPENSSL_*, CMAKE_*,
# MAKEFLAGS, CROSS_COMPILE, ...) is dropped so the reviewed configuration is the only input.
HOST_ENVIRONMENT = ("PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL", "LANG", "SDKROOT", "DEVELOPER_DIR")
LOCK_KEYS = {
    "name": str, "version": str, "upstream_tag": str, "upstream_commit": str, "url": str,
    "archive_file": str, "archive_sha256": str, "archive_max_bytes": int, "archive_root": str,
    "extracted_max_bytes": int, "extracted_max_entries": int, "required_files": list,
    "version_file": str, "version_markers": list, "license_file": str, "license_spdx": str,
    "license_sha256": str, "archive_name": str,
}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def lock(name, native=None):
    if name not in DEPENDENCIES:
        raise RuntimeError(f"Unknown native dependency {name}")
    spec = json.loads(((native or NATIVE) / name / "source.lock.json").read_text())
    for key, kind in LOCK_KEYS.items():
        if not isinstance(spec.get(key), kind):
            raise RuntimeError(f"{name} source lock lacks {key}")
    if spec["name"] != name or not spec["url"].startswith("https://"):
        raise RuntimeError(f"{name} source lock is not an HTTPS pin for {name}")
    if not re.fullmatch(r"[0-9a-f]{64}", spec["archive_sha256"]) or not re.fullmatch(r"[0-9a-f]{40}", spec["upstream_commit"]):
        raise RuntimeError(f"{name} source lock digest/revision is malformed")
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.tar\.gz", spec["archive_file"]) or "/" in spec["archive_root"]:
        raise RuntimeError(f"{name} source lock names an unsafe path")
    if not re.fullmatch(r"libfidomanager_[a-z0-9_]+\.a", spec["archive_name"]):
        raise RuntimeError(f"{name} private archive name is not project-unique")
    return spec


def source_archive(spec):
    return SOURCES / spec["archive_file"]


def checked_archive(spec, archive=None):
    archive = Path(archive or source_archive(spec))
    if not archive.is_file():
        raise RuntimeError(f"Pinned {spec['name']} source missing: run python3 scripts/build-libfido2.py fetch")
    if archive.stat().st_size > spec["archive_max_bytes"]:
        raise RuntimeError(f"Pinned {spec['name']} source exceeds its size bound")
    if sha256(archive) != spec["archive_sha256"]:
        raise RuntimeError(f"Pinned {spec['name']} source checksum mismatch")
    return archive


class HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, request, fp, code, message, headers, url):
        if not url.startswith("https://"):
            raise RuntimeError("Refusing non-HTTPS redirect for pinned source")
        return super().redirect_request(request, fp, code, message, headers, url)


def download(url, destination, limit):
    if not url.startswith("https://"):
        raise RuntimeError("Pinned sources are fetched over HTTPS only")
    opener = urllib.request.build_opener(HttpsOnlyRedirects)
    with opener.open(url, timeout=120) as response, destination.open("xb") as output:
        if not response.geturl().startswith("https://"):
            raise RuntimeError("Pinned source download left HTTPS")
        declared = response.headers.get("Content-Length")
        if declared is not None and int(declared) > limit:
            raise RuntimeError("Source download exceeds bound")
        total = 0
        while chunk := response.read(65536):
            total += len(chunk)
            if total > limit:
                raise RuntimeError("Source download exceeds bound")
            output.write(chunk)


def fetch(name):
    spec = lock(name)
    archive = source_archive(spec)
    if archive.exists():
        checked_archive(spec)
        print(f"Pinned {name} {spec['version']} source cache verified")
        return
    archive.parent.mkdir(parents=True, exist_ok=True)
    # Download privately; publish into the cache only after the pinned digest matches.
    with tempfile.TemporaryDirectory(dir=archive.parent) as temporary:
        candidate = Path(temporary) / "source.tar.gz"
        download(spec["url"], candidate, spec["archive_max_bytes"])
        checked_archive(spec, candidate)
        candidate.replace(archive)
    print(f"Pinned {name} {spec['version']} source fetched and verified")


def extract(spec, destination, archive=None, native=None):
    """Unpack the verified archive's single root into destination (which must not exist)."""
    archive = checked_archive(spec, archive)
    destination.mkdir(parents=True, exist_ok=False)
    root = spec["archive_root"]
    total = entries = 0
    seen = set()
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            entries += 1
            if entries > spec["extracted_max_entries"]:
                raise RuntimeError("Extracted source exceeds entry bound")
            name = member.name
            if name == root:
                if not member.isdir():
                    raise RuntimeError("Unexpected source archive root")
                continue
            if not name.startswith(root + "/"):
                raise RuntimeError("Unexpected source archive root")
            relative = name[len(root) + 1:]
            parts = relative.split("/")
            if any(part in ("", ".", "..") for part in parts) or "\\" in relative or "\0" in relative:
                raise RuntimeError("Unsafe source archive path")
            if relative in seen:
                raise RuntimeError("Duplicate source archive entry")
            seen.add(relative)
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                total += member.size
                if total > spec["extracted_max_bytes"]:
                    raise RuntimeError("Extracted source exceeds size bound")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as data, target.open("xb") as output:
                    shutil.copyfileobj(data, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                # Symlinks, hard links, devices and FIFOs are never materialised or followed.
                raise RuntimeError("Links and special files are not permitted in pinned source")
    for required in spec["required_files"]:
        path = destination / required
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"Unexpected {spec['name']} source shape: {required} missing")
    version = (destination / spec["version_file"]).read_text()
    if not all(marker in version for marker in spec["version_markers"]):
        raise RuntimeError(f"Unexpected {spec['name']} upstream version")
    license_text = (destination / spec["license_file"]).read_bytes()
    reviewed = ((native or NATIVE) / spec["name"] / "LICENSE.upstream").read_bytes()
    if hashlib.sha256(license_text).hexdigest() != spec["license_sha256"] or license_text != reviewed:
        raise RuntimeError(f"Upstream {spec['name']} license differs from the reviewed copy")
    return destination


def build_environment(inherited, sdk=None):
    environment = {name: inherited[name] for name in HOST_ENVIRONMENT if name in inherited}
    environment.update(ZERO_AR_DATE="1", SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH,
                       MACOSX_DEPLOYMENT_TARGET=DEPLOYMENT_TARGET, LC_ALL="C")
    if sdk:
        environment["SDKROOT"] = sdk
    return environment


def toolchain():
    def xcrun(*arguments):
        return subprocess.check_output(["xcrun", "--sdk", "macosx", *arguments], text=True).strip()
    compiler = xcrun("--find", "clang")
    return {
        "cc": compiler, "cxx": xcrun("--find", "clang++"), "sdk": xcrun("--show-sdk-path"),
        "sdk_version": xcrun("--show-sdk-version"),
        "compiler": subprocess.check_output([compiler, "--version"], text=True).splitlines()[0],
    }


def jobs():
    return str(max(1, min(os.cpu_count() or 2, 8)))


def archive_members(archive):
    return [name for name in subprocess.check_output(["ar", "-t", str(archive)], text=True).splitlines()
            if name and not name.startswith("__.SYMDEF")]


def verify_archive(archive, architecture, forbidden=()):
    """Every member must be a real Mach-O object for the architecture with minos <= 11.0."""
    members = archive_members(archive)
    commands = subprocess.check_output(["otool", "-l", str(archive)], text=True, stderr=subprocess.STDOUT)
    if "is not an object file" in commands or not members:
        raise RuntimeError(f"{archive.name} contains non-Mach-O (for example LLVM bitcode) members")
    versions = re.findall(r"^\s*minos (\S+)$", commands, re.M)
    if len(versions) != len(members) or set(versions) != {DEPLOYMENT_TARGET}:
        raise RuntimeError(f"{archive.name} objects do not all target macOS {DEPLOYMENT_TARGET}: {sorted(set(versions))}")
    archs = subprocess.check_output(["lipo", "-archs", str(archive)], text=True).split()
    if archs != [architecture]:
        raise RuntimeError(f"{archive.name} architecture {archs} != {architecture}")
    data = archive.read_bytes()
    for text in ("/opt/homebrew", "/usr/local/", "/opt/local/", *forbidden):
        if text.encode() in data:
            raise RuntimeError(f"{archive.name} embeds a forbidden path: {text}")
    return len(members)


def run(command, **options):
    subprocess.run([str(part) for part in command], check=True, **options)


def disabled_openssl_features(source, environment):
    script = 'use configdata; print join("\\n", sort keys %disabled), "\\n";'
    output = subprocess.check_output(["/usr/bin/perl", "-I.", "-e", script], cwd=source, env=environment, text=True)
    return set(output.split())


HOSTILE_OPENSSL_CONF = """openssl_conf = openssl_init
[openssl_init]
alg_section = evp_properties
[evp_properties]
default_properties = fips=yes
"""

OPENSSL_PROBE = r"""#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1 && !OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 3;
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (md == NULL)
        return 2;
    EVP_MD_free(md);
    printf("%s\n%s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_DIR));
    return 0;
}
"""


def probe_openssl_configuration(work, include, archive, architecture, tools, environment, version):
    """Prove from the built archive itself that no configuration file is loaded implicitly."""
    if architecture != {"arm64": "arm64", "x86_64": "x86_64"}.get(platform.machine()):
        return "not executed (cross-architecture build)"
    probe_dir = work / "openssl-probe"
    probe_dir.mkdir()
    (probe_dir / "probe.c").write_text(OPENSSL_PROBE)
    hostile = probe_dir / "hostile.cnf"
    hostile.write_text(HOSTILE_OPENSSL_CONF)
    binary = probe_dir / "probe"
    run([tools["cc"], "-arch", architecture, f"-mmacosx-version-min={DEPLOYMENT_TARGET}", "-I", include,
         probe_dir / "probe.c", archive, "-o", binary], env=environment)
    probe_env = {"PATH": "/usr/bin:/bin", "OPENSSL_CONF": str(hostile)}
    implicit = subprocess.run([str(binary)], env=probe_env, capture_output=True, text=True, timeout=30)
    explicit = subprocess.run([str(binary), "load"], env=probe_env, capture_output=True, text=True, timeout=30)
    lines = implicit.stdout.splitlines()
    if (implicit.returncode != 0 or len(lines) != 2 or not lines[0].startswith(f"OpenSSL {version} ")
            or lines[1] != f'OPENSSLDIR: "{OPENSSL_PREFIX}"'):
        raise RuntimeError(f"Private OpenSSL consulted an external configuration implicitly: {implicit.returncode} {implicit.stdout!r}")
    if explicit.returncode != 2:
        raise RuntimeError("OpenSSL configuration probe control failed; the hostile configuration was not effective")
    return "implicit use ignored hostile OPENSSL_CONF; explicit load control rejected it"


def build_openssl(spec, work, output, architecture, tools, environment):
    source = extract(spec, work / "openssl-source")
    configure = ["/usr/bin/perl", "Configure", OPENSSL_CONFIGURE_TARGETS[architecture], f"CC={tools['cc']}",
                 f"--prefix={OPENSSL_PREFIX}", f"--openssldir={OPENSSL_PREFIX}", "--libdir=lib",
                 *OPENSSL_OPTIONS, f"-mmacosx-version-min={DEPLOYMENT_TARGET}"]
    run(configure, cwd=source, env=environment)
    disabled = disabled_openssl_features(source, environment)
    required = {option[3:] for option in OPENSSL_POLICY}
    if not required <= disabled:
        raise RuntimeError(f"OpenSSL policy features not disabled: {sorted(required - disabled)}")
    run(["make", f"-j{jobs()}", "build_generated", "libcrypto.a"], cwd=source, env=environment)
    configuration = (source / "include/openssl/configuration.h").read_text()
    for macro in OPENSSL_POLICY_MACROS:
        if not re.search(r"^#\s*define " + macro + r"\b", configuration, re.M):
            raise RuntimeError(f"Private OpenSSL configuration lacks {macro}")
    include = work / "include"
    (include / "openssl").mkdir(parents=True, exist_ok=True)
    for header in sorted((source / "include/openssl").glob("*.h")):
        shutil.copyfile(header, include / "openssl" / header.name)
    archive = output / spec["archive_name"]
    shutil.copyfile(source / "libcrypto.a", archive)
    objects = verify_archive(archive, architecture, forbidden=(str(work),))
    data = archive.read_bytes()
    if f'OPENSSLDIR: "{OPENSSL_PREFIX}"'.encode() not in data or b"/usr/local/ssl" in data:
        raise RuntimeError("Private OpenSSL OPENSSLDIR is not the reviewed non-writable prefix")
    probe = probe_openssl_configuration(work, include, archive, architecture, tools, environment, spec["version"])
    return {
        "configure_target": OPENSSL_CONFIGURE_TARGETS[architecture],
        "build_options": [*OPENSSL_OPTIONS, f"-mmacosx-version-min={DEPLOYMENT_TARGET}"],
        "openssldir": OPENSSL_PREFIX, "policy_features_disabled": sorted(required),
        "autoload_config_probe": probe, "object_count": objects,
    }


def build_libcbor(spec, work, output, architecture, tools, environment):
    source = extract(spec, work / "libcbor-source")
    build = work / "libcbor-build"
    staging = work / "libcbor-install"
    flags = f"-ffile-prefix-map={source}=/libcbor -ffile-prefix-map={build}=/libcbor-build"
    run(["cmake", "-S", source, "-B", build, "-G", "Unix Makefiles", f"-DCMAKE_C_COMPILER={tools['cc']}",
         f"-DCMAKE_CXX_COMPILER={tools['cxx']}", f"-DCMAKE_OSX_ARCHITECTURES={architecture}",
         f"-DCMAKE_OSX_DEPLOYMENT_TARGET={DEPLOYMENT_TARGET}", f"-DCMAKE_C_FLAGS={flags}",
         *LIBCBOR_OPTIONS], env=environment)
    run(["cmake", "--build", build, "--target", "cbor", "--parallel", jobs()], env=environment)
    run(["cmake", "--install", build, "--prefix", staging], env=environment)
    include = work / "include"
    include.mkdir(exist_ok=True)
    shutil.copyfile(staging / "include/cbor.h", include / "cbor.h")
    shutil.copytree(staging / "include/cbor", include / "cbor")
    if list((staging / "lib").glob("*.dylib")):
        raise RuntimeError("libcbor produced a shared library")
    archive = output / spec["archive_name"]
    shutil.copyfile(staging / "lib/libcbor.a", archive)
    objects = verify_archive(archive, architecture, forbidden=(str(work),))
    return {"build_options": [*LIBCBOR_OPTIONS, f"-DCMAKE_OSX_DEPLOYMENT_TARGET={DEPLOYMENT_TARGET}"],
            "object_count": objects}


def write_pkgconfig(directory, include, output, tools):
    """Private .pc files; PKG_CONFIG_LIBDIR then makes them the only ones libfido2 can see."""
    for path in (include, output):
        if re.search(r"[\s\"'\\$]", str(path)):
            raise RuntimeError("Private native build path contains characters unsafe for pkg-config")
    directory.mkdir(parents=True, exist_ok=True)
    zlib_header = Path(tools["sdk"]) / "usr/include/zlib.h"
    zlib_version = re.search(r'^#define ZLIB_VERSION "([^"]+)"', zlib_header.read_text(), re.M).group(1)
    entries = {
        "libcrypto": (lock("openssl")["version"], f"-I{include}", f"-L{output} -lfidomanager_crypto"),
        "libcbor": (lock("libcbor")["version"], f"-I{include}", f"-L{output} -lfidomanager_cbor"),
        # zlib remains the macOS system library (/usr/lib/libz.1.dylib from the SDK).
        "zlib": (zlib_version, "", "-lz"),
    }
    for name, (version, cflags, libs) in entries.items():
        (directory / f"{name}.pc").write_text(
            f"Name: {name}\nDescription: FidoManager reviewed private dependency\n"
            f"Version: {version}\nCflags: {cflags}\nLibs: {libs}\n")
    return {"zlib": f"macOS SDK system zlib {zlib_version} (/usr/lib/libz.1.dylib)"}


def build(work, output, target):
    """Build both private archives into output; headers and .pc files are written under work."""
    if platform.system() != "Darwin" or target not in TARGETS:
        raise RuntimeError("Private native dependency builds are currently enabled only for macOS")
    architecture = TARGETS[target]
    for path in (work, output):
        if re.search(r"[\s\"'\\$]", str(path)):
            raise RuntimeError("Private native build directories must not contain whitespace or quotes")
    tools = toolchain()
    environment = build_environment(os.environ, tools["sdk"])
    work.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    metadata = {}
    for name, builder in (("openssl", build_openssl), ("libcbor", build_libcbor)):
        spec = lock(name)
        details = builder(spec, work, output, architecture, tools, environment)
        metadata[name] = {
            "version": spec["version"], "upstream_tag": spec["upstream_tag"],
            "upstream_commit": spec["upstream_commit"], "source_url": spec["url"],
            "source_archive_sha256": spec["archive_sha256"], "license_spdx": spec["license_spdx"],
            "license_sha256": spec["license_sha256"], "architecture": architecture,
            "deployment_target": DEPLOYMENT_TARGET, "compiler": tools["compiler"],
            "sdk_version": tools["sdk_version"], "static_archive": spec["archive_name"],
            "static_archive_sha256": sha256(output / spec["archive_name"]), **details,
        }
    system = write_pkgconfig(work / "pkgconfig", work / "include", output, tools)
    return {"include": work / "include", "pkgconfig": work / "pkgconfig", "metadata": metadata,
            "system": system, "toolchain": tools, "environment": environment}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fetch")
    build_command = commands.add_parser("build")
    build_command.add_argument("--out-dir", type=Path, required=True)
    build_command.add_argument("--target", required=True)
    args = parser.parse_args()
    if args.command == "fetch":
        for name in DEPENDENCIES:
            fetch(name)
    else:
        directory = args.out_dir.resolve()
        result = build(directory / "work", directory, args.target)
        (directory / "dependencies.json").write_text(json.dumps(result["metadata"], indent=2) + "\n")
        print(json.dumps(result["metadata"], indent=2))


if __name__ == "__main__":
    main()
