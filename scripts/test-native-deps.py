#!/usr/bin/env python3
"""Deterministic tests for pinned OpenSSL/libcbor source inputs, extraction and notices; no network."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deps = load("native_dependencies", "build-native-deps.py")
libfido2 = load("native_builder", "build-libfido2.py")
NOTICES = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
# openbsd-compat files whose implementations libfido2 compiles for macOS (test-libfido2.py checks
# the archive against this set) and the number of leading lines forming each upstream notice.
COMPAT_NOTICES = {"freezero.c": 15, "recallocarray.c": 16, "explicit_bzero.c": 6, "bsd-getpagesize.c": 1}


def rejects(message, function, *arguments, **options):
    try:
        function(*arguments, **options)
    except (RuntimeError, OSError) as error:
        if message not in str(error):
            raise AssertionError(f"expected {message!r}, got {error!r}")
    else:
        raise AssertionError(f"accepted input that must fail with {message!r}")


def member(name, kind=tarfile.REGTYPE, data=b"", linkname=""):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    info.size = len(data) if kind == tarfile.REGTYPE else 0
    info.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
    return info, (io.BytesIO(data) if kind == tarfile.REGTYPE else None)


LICENSE = b"reviewed license\n"


def well_formed(root="pkg-1.0"):
    return [
        member(root, tarfile.DIRTYPE),
        member(root + "/VERSION", data=b"version 1.0\n"),
        member(root + "/LICENSE", data=LICENSE),
        member(root + "/src", tarfile.DIRTYPE),
        member(root + "/src/a.c", data=b"int a;\n"),
    ]


def fixture(directory, label, members, **overrides):
    """Write a crafted archive plus a lock that pins its exact digest."""
    archive = directory / f"{label}.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        for info, data in members:
            output.addfile(info, data)
    spec = {
        "name": "libcbor", "version": "1.0", "upstream_tag": "v1.0", "upstream_commit": "0" * 40,
        "url": "https://example.invalid/pkg.tar.gz", "archive_file": f"{label}.tar.gz",
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "archive_max_bytes": 65536,
        "archive_root": "pkg-1.0", "extracted_max_bytes": 4096, "extracted_max_entries": 16,
        "required_files": ["VERSION", "LICENSE", "src/a.c"], "version_file": "VERSION",
        "version_markers": ["version 1.0\n"], "license_file": "LICENSE", "license_spdx": "MIT",
        "license_sha256": hashlib.sha256(LICENSE).hexdigest(), "archive_name": "libfidomanager_test.a",
    }
    spec.update(overrides)
    return spec, archive


def extraction_tests(work):
    native = work / "native"
    (native / "libcbor").mkdir(parents=True)
    (native / "libcbor/LICENSE.upstream").write_bytes(LICENSE)
    counter = iter(range(1000))

    def extract(spec, archive):
        return deps.extract(spec, work / f"out-{next(counter)}", archive, native=native)

    spec, archive = fixture(work, "good", well_formed())
    extracted = extract(spec, archive)
    assert (extracted / "src/a.c").read_bytes() == b"int a;\n" and not (extracted / "pkg-1.0").exists()

    root = "pkg-1.0"
    cases = [
        ("Unexpected source archive root", [*well_formed(), member("other/file", data=b"x")]),
        ("Unexpected source archive root", [member(root, data=b"not a directory")]),
        ("Unexpected source archive root", [*well_formed(), member("/etc/passwd", data=b"x")]),
        ("Unexpected source archive root", [*well_formed(), member("pkg-1.0-evil/file", data=b"x")]),
        ("Unsafe source archive path", [*well_formed(), member(root + "/../escape", data=b"x")]),
        ("Unsafe source archive path", [*well_formed(), member(root + "/src/../../escape", data=b"x")]),
        ("Unsafe source archive path", [*well_formed(), member(root + "/./dot", data=b"x")]),
        ("Unsafe source archive path", [*well_formed(), member(root + "/back\\slash", data=b"x")]),
        ("Links and special files", [*well_formed(), member(root + "/link", tarfile.SYMTYPE, linkname="/etc/passwd")]),
        ("Links and special files", [*well_formed(), member(root + "/rel", tarfile.SYMTYPE, linkname="src/a.c")]),
        ("Links and special files", [*well_formed(), member(root + "/hard", tarfile.LNKTYPE, linkname=root + "/src/a.c")]),
        ("Links and special files", [*well_formed(), member(root + "/dev", tarfile.CHRTYPE)]),
        ("Links and special files", [*well_formed(), member(root + "/blk", tarfile.BLKTYPE)]),
        ("Links and special files", [*well_formed(), member(root + "/fifo", tarfile.FIFOTYPE)]),
        ("Duplicate source archive entry", [*well_formed(), member(root + "/src/a.c", data=b"int b;\n")]),
        ("Extracted source exceeds size bound", [*well_formed(), member(root + "/big", data=b"x" * 5000)]),
        ("Extracted source exceeds entry bound",
         [*well_formed(), *(member(f"{root}/f{index}", data=b"x") for index in range(16))]),
        ("source shape: src/a.c missing", well_formed()[:4]),
    ]
    for index, (message, members) in enumerate(cases):
        spec, archive = fixture(work, f"bad-{index}", members)
        rejects(message, extract, spec, archive)

    spec, archive = fixture(work, "version", well_formed(), version_markers=["version 2.0\n"])
    rejects("Unexpected libcbor upstream version", extract, spec, archive)
    spec, archive = fixture(work, "license", well_formed(), license_sha256="0" * 64)
    rejects("license differs from the reviewed copy", extract, spec, archive)
    (native / "libcbor/LICENSE.upstream").write_bytes(b"paraphrased license\n")
    spec, archive = fixture(work, "license-copy", well_formed())
    rejects("license differs from the reviewed copy", extract, spec, archive)
    (native / "libcbor/LICENSE.upstream").write_bytes(LICENSE)

    # Checksum is verified before any byte is extracted; corruption, absence and size all fail.
    spec, archive = fixture(work, "digest", well_formed())
    corrupt = work / "corrupt.tar.gz"
    data = bytearray(archive.read_bytes())
    data[len(data) // 2] ^= 0xFF
    corrupt.write_bytes(bytes(data))
    rejects("checksum mismatch", extract, spec, corrupt)
    rejects("source missing", extract, spec, work / "absent.tar.gz")
    spec, archive = fixture(work, "oversize", well_formed(), archive_max_bytes=16)
    rejects("exceeds its size bound", extract, spec, archive)
    print(f"PASS: strict extractor rejected {len(cases) + 6} malformed, unsafe or unpinned archives")


def lock_tests(work):
    for name in deps.DEPENDENCIES:
        spec = deps.lock(name)
        assert spec["url"].startswith("https://") and spec["archive_root"] and spec["version"] in spec["url"] + spec["upstream_tag"]
    native = work / "locks"
    for mutate, message in (
        (lambda spec: spec.update(url="http://example.invalid/openssl.tar.gz"), "not an HTTPS pin"),
        (lambda spec: spec.update(archive_sha256="latest"), "malformed"),
        (lambda spec: spec.pop("archive_sha256"), "lacks archive_sha256"),
        (lambda spec: spec.update(archive_file="../openssl.tar.gz"), "unsafe path"),
        (lambda spec: spec.update(archive_name="libcrypto.a"), "not project-unique"),
        (lambda spec: spec.update(name="libcbor"), "not an HTTPS pin for openssl"),
    ):
        spec = deps.lock("openssl")
        mutate(spec)
        shutil.rmtree(native, ignore_errors=True)
        (native / "openssl").mkdir(parents=True)
        (native / "openssl/source.lock.json").write_text(json.dumps(spec))
        rejects(message, deps.lock, "openssl", native=native)
    rejects("Unknown native dependency", deps.lock, "zlib")
    rejects("HTTPS only", deps.download, "http://example.invalid/x.tar.gz", work / "never", 1)
    rejects("non-HTTPS redirect", deps.HttpsOnlyRedirects().redirect_request,
            None, None, 302, "Found", {}, "http://example.invalid/x.tar.gz")
    assert set(deps.OPENSSL_POLICY) == {"no-shared", "no-module", "no-engine", "no-dso", "no-autoload-config"}
    assert set(deps.OPENSSL_POLICY) <= set(deps.OPENSSL_OPTIONS)
    assert all(option.startswith("no-") for option in deps.OPENSSL_OPTIONS), "OpenSSL options may only disable"
    assert "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=OFF" in deps.LIBCBOR_OPTIONS
    assert "-DBUILD_SHARED_LIBS=OFF" in deps.LIBCBOR_OPTIONS and deps.DEPLOYMENT_TARGET == "11.0"
    print("PASS: source locks are HTTPS + SHA-256 pins; mutable/unsafe lock edits and HTTP downloads rejected")


def pinned_source_tests(work):
    for name in deps.DEPENDENCIES:
        spec = deps.lock(name)
        if not deps.source_archive(spec).is_file():
            raise SystemExit(f"FAIL: pinned {name} source missing; run python3 scripts/build-libfido2.py fetch")
        deps.extract(spec, work / f"pinned-{name}")
        shutil.rmtree(work / f"pinned-{name}")
    print("PASS: pinned OpenSSL 3.5.9 and libcbor 0.14.0 archives verify and extract with the expected shape")


def environment_tests():
    hostile = {name: "untrusted" for name in (
        "CC", "CXX", "CFLAGS", "CPPFLAGS", "LDFLAGS", "CPATH", "C_INCLUDE_PATH", "LIBRARY_PATH",
        "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR", "OPENSSL_CONF", "OPENSSL_MODULES",
        "OPENSSL_ENGINES", "CROSS_COMPILE", "AR", "RANLIB", "PERL", "MAKEFLAGS", "CMAKE_PREFIX_PATH",
        "CMAKE_TOOLCHAIN_FILE", "DYLD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "MACOSX_DEPLOYMENT_TARGET")}
    host = {"PATH": "/host/bin", "HOME": "/host/home", "TMPDIR": "/host/tmp", "SDKROOT": "/host/sdk",
            "DEVELOPER_DIR": "/host/Xcode"}
    environment = deps.build_environment({**hostile, **host})
    assert all(name not in environment for name in hostile if name != "MACOSX_DEPLOYMENT_TARGET")
    assert all(environment[name] == value for name, value in host.items())
    assert environment["MACOSX_DEPLOYMENT_TARGET"] == "11.0" and environment["ZERO_AR_DATE"] == "1"
    assert libfido2.native_build_environment({**hostile, **host}) == environment
    print("PASS: native build environment is an explicit allowlist; compiler/pkg-config/OpenSSL overrides dropped")


def notice_tests():
    for name in ("libfido2", *deps.DEPENDENCIES):
        text = (ROOT / "native" / name / "LICENSE.upstream").read_text()
        assert "```text\n" + text + "```\n" in NOTICES, f"{name} license is not reproduced verbatim"
    for name in deps.DEPENDENCIES:
        assert hashlib.sha256((ROOT / "native" / name / "LICENSE.upstream").read_bytes()).hexdigest() \
            == deps.lock(name)["license_sha256"]
    spec, archive, _ = libfido2.checked_inputs()
    prefix = "libfido2-" + spec["revision"] + "/openbsd-compat/"
    with tarfile.open(archive) as source:
        for file, lines in COMPAT_NOTICES.items():
            header = "".join(source.extractfile(prefix + file).read().decode().splitlines(keepends=True)[:lines])
            assert "```text\n" + header + "```\n" in NOTICES, f"{file} notice is not reproduced verbatim"
    print("PASS: THIRD_PARTY_NOTICES.md reproduces libfido2, OpenSSL, libcbor and compiled compat notices verbatim")


def main():
    with tempfile.TemporaryDirectory(prefix="fidomanager-native-deps-") as temporary:
        work = Path(temporary)
        lock_tests(work)
        extraction_tests(work)
        pinned_source_tests(work)
    environment_tests()
    notice_tests()


if __name__ == "__main__":
    main()
