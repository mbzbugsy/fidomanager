"""Strict data primitives shared by candidate-side release verification (never the signer)."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat


class CheckError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CheckError(message)


def hex_value(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def keys(value, expected, label):
    require(isinstance(value, dict) and set(value) == set(expected.split()), f"{label}: incorrect fields")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(CheckError(f"invalid JSON: {value}")))
    except (ValueError, UnicodeError) as error:
        raise CheckError(f"invalid UTF-8 JSON: {error}") from error


def read_regular(path, limit=16 * 1024 * 1024):
    """Single bounded read; reject links (including ancestors), devices and hardlinks."""
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), f"symlink: {parent}")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, f"not a single regular file: {path}")
            require(info.st_size <= limit, f"file too large: {path}")
            data = source.read(limit + 1)
            require(len(data) <= limit and len(data) == info.st_size, f"file changed or too large: {path}")
            return data
    except OSError as error:
        raise CheckError(f"cannot read {path}: {error}") from error


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_record(path):
    # Payloads are bounded to the ADR's 256 MiB handoff size, with room for archive overhead.
    data = read_regular(path, 512 * 1024 * 1024)
    return {"sha256": digest(data), "size": len(data)}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode()


def publisher_requirement(identifier, team):
    require(re.fullmatch(r"[A-Z0-9]{10}", team or ""), "explicit expected Team ID required")
    require(re.fullmatch(r"[a-zA-Z0-9.-]+", identifier), "invalid signing identifier")
    return (f'anchor apple generic and identifier "{identifier}" and '
            'certificate 1[field.1.2.840.113635.100.6.2.6] and '
            'certificate leaf[field.1.2.840.113635.100.6.1.13] and '
            f'certificate leaf[subject.OU] = "{team}"')


def identity_record(data, version, commit, team):
    require(len(data) <= 4096, "identity record exceeds 4 KiB")
    record = parse_json(data)
    keys(record, "schema release worker", "identity record")
    require(record["schema"] == "fidomanager.release-worker-identity/1", "identity record schema")
    keys(record["release"], "version source_commit", "release")
    require(record["release"] == {"version": version, "source_commit": commit}, "identity release mismatch")
    require(hex_value(commit, 40), "invalid expected source commit")
    worker = record["worker"]
    keys(worker, "path identifier team_id build_id file_sha256 slices", "worker identity")
    require(worker["path"] == "Contents/MacOS/fido-worker" and
            worker["identifier"] == "eu.fidomanager.desktop.fido-worker" and
            worker["team_id"] == team, "worker identity mismatch")
    require(worker["build_id"] == f"{version}+{commit}", "worker build identity mismatch")
    require(hex_value(worker["file_sha256"]), "invalid worker SHA-256")
    require(isinstance(worker["slices"], list) and len(worker["slices"]) == 1,
            "single-architecture release required (M7.1)")
    for item in worker["slices"]:
        keys(item, "arch cdhash cdhash_sha256", "worker slice")
        require(item["arch"] in ("arm64", "x86_64") and hex_value(item["cdhash"], 40) and
                hex_value(item["cdhash_sha256"]) and item["cdhash_sha256"].startswith(item["cdhash"]),
                "invalid worker slice hashes or architecture")
    return record


# Bounds for the stapled app ZIP (ADR-017 6.5 handoff bounds: 256 MiB of files, 1024 entries).
ZIP_MAX_BYTES = 512 * 1024 * 1024
ZIP_MAX_ENTRIES = 1024
ZIP_MAX_TOTAL = 256 * 1024 * 1024
_ZIP_ALLOWED_FLAGS = 0x0008 | 0x0800  # data descriptor, UTF-8 names; encryption and others fail


def _u16(data, offset):
    require(offset + 2 <= len(data), "truncated ZIP structure")
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32(data, offset):
    require(offset + 4 <= len(data), "truncated ZIP structure")
    return int.from_bytes(data[offset:offset + 4], "little")


def _zip_member_name(raw):
    try:
        name = raw.decode("utf-8")
    except UnicodeError as error:
        raise CheckError("ZIP entry name is not UTF-8") from error
    require(name and not name.startswith("/") and "\\" not in name and
            not any(ord(c) < 32 or ord(c) == 127 for c in name), f"unsafe ZIP entry name: {name!r}")
    parts = name[:-1].split("/") if name.endswith("/") else name.split("/")
    require(all(part not in ("", ".", "..") for part in parts), f"unsafe ZIP entry path: {name!r}")
    return name


def zip_app_tree(data, app_name):
    """Parse a stapled app ZIP fully in memory and return its exact tree; never extract or execute.

    Every byte of the archive must be accounted for: local entries are contiguous from offset 0,
    the central directory follows them, and the end record has no comment or trailing data. Local
    and central names, flags, methods, CRCs and sizes must agree, so a reader that uses either
    directory sees the same members. Only stored/deflated regular files and directories with Unix
    modes are accepted; links, special files, AppleDouble side files, ZIP64, encryption, duplicate
    or case/Unicode-colliding names and anything outside `<app_name>/` fail closed.
    """
    import unicodedata
    import zlib
    require(len(data) <= ZIP_MAX_BYTES, "app ZIP too large")
    require(len(data) >= 22 and data[-22:-18] == b"PK\x05\x06", "app ZIP must end with an end record and no comment")
    eocd = len(data) - 22
    require(_u16(data, eocd + 4) == 0 and _u16(data, eocd + 6) == 0, "multi-disk ZIP")
    count, total_count = _u16(data, eocd + 8), _u16(data, eocd + 10)
    cd_size, cd_offset = _u32(data, eocd + 12), _u32(data, eocd + 16)
    require(_u16(data, eocd + 20) == 0, "ZIP comment not allowed")
    require(count == total_count and 0 < count <= ZIP_MAX_ENTRIES and 0xFFFF not in (count, total_count) and
            0xFFFFFFFF not in (cd_size, cd_offset), "unsupported ZIP entry count or ZIP64")
    require(cd_offset + cd_size == eocd, "ZIP central directory is not immediately before the end record")
    entries, offset = [], cd_offset
    for _ in range(count):
        require(data[offset:offset + 4] == b"PK\x01\x02", "malformed ZIP central directory")
        made_by, flags, method = _u16(data, offset + 4), _u16(data, offset + 8), _u16(data, offset + 10)
        crc, csize, usize = _u32(data, offset + 16), _u32(data, offset + 20), _u32(data, offset + 24)
        name_len, extra_len, comment_len = _u16(data, offset + 28), _u16(data, offset + 30), _u16(data, offset + 32)
        disk, external, local = _u16(data, offset + 34), _u32(data, offset + 38), _u32(data, offset + 42)
        raw_name = data[offset + 46:offset + 46 + name_len]
        require(len(raw_name) == name_len and comment_len == 0 and disk == 0, "malformed ZIP central entry")
        require(made_by >> 8 == 3, "ZIP entry without Unix attributes")
        require(flags & ~_ZIP_ALLOWED_FLAGS == 0 and method in (0, 8), "encrypted or unsupported ZIP entry")
        require(0xFFFFFFFF not in (csize, usize, local), "ZIP64 not supported")
        entries.append({"name": _zip_member_name(raw_name), "raw": raw_name, "flags": flags, "method": method,
                        "crc": crc, "csize": csize, "usize": usize, "mode": external >> 16, "local": local})
        offset += 46 + name_len + extra_len + comment_len
    require(offset == eocd, "ZIP central directory size mismatch")
    position, total, folded = 0, 0, set()
    files, directories = {}, set()
    prefix = app_name + "/"
    for entry in sorted(entries, key=lambda item: item["local"]):
        require(entry["local"] == position and data[position:position + 4] == b"PK\x03\x04",
                "ZIP local entries are not contiguous from offset zero")
        require(_u16(data, position + 6) == entry["flags"] and _u16(data, position + 8) == entry["method"],
                "ZIP local/central header mismatch")
        name_len, extra_len = _u16(data, position + 26), _u16(data, position + 28)
        require(data[position + 30:position + 30 + name_len] == entry["raw"], "ZIP local/central name mismatch")
        start = position + 30 + name_len + extra_len
        end = start + entry["csize"]
        require(end <= cd_offset, "ZIP entry overlaps the central directory")
        if entry["flags"] & 0x0008:
            descriptor = end + (4 if data[end:end + 4] == b"PK\x07\x08" else 0)
            require((_u32(data, descriptor), _u32(data, descriptor + 4), _u32(data, descriptor + 8)) ==
                    (entry["crc"], entry["csize"], entry["usize"]), "ZIP data descriptor mismatch")
            position = descriptor + 12
        else:
            require((_u32(data, position + 14), _u32(data, position + 18), _u32(data, position + 22)) ==
                    (entry["crc"], entry["csize"], entry["usize"]), "ZIP local/central size or CRC mismatch")
            position = end
        require(position <= cd_offset, "ZIP entry overlaps the central directory")
        name = entry["name"]
        key = unicodedata.normalize("NFC", name).casefold()
        require(key not in folded, f"duplicate or colliding ZIP entry: {name!r}")
        folded.add(key)
        mode = entry["mode"]
        require(mode & 0o7000 == 0, f"setuid/setgid/sticky ZIP entry: {name!r}")
        if name.endswith("/"):
            require(stat.S_ISDIR(mode) and entry["usize"] == 0, f"ZIP directory entry is not a directory: {name!r}")
            require(name == prefix or name.startswith(prefix), f"ZIP entry outside the app: {name!r}")
            if name != prefix:
                directories.add(name[len(prefix):-1])
            continue
        require(stat.S_ISREG(mode), f"ZIP entry is not a regular file: {name!r}")
        require(name.startswith(prefix), f"ZIP entry outside the app: {name!r}")
        total += entry["usize"]
        require(total <= ZIP_MAX_TOTAL, "app ZIP content too large")
        compressed = data[start:end]
        if entry["method"] == 0:
            require(entry["csize"] == entry["usize"], "stored ZIP entry size mismatch")
            content = compressed
        else:
            inflater = zlib.decompressobj(-15)
            try:
                content = inflater.decompress(compressed, entry["usize"] + 1)
            except zlib.error as error:
                raise CheckError(f"corrupt ZIP entry: {name!r}") from error
            require(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,
                    f"ZIP entry has trailing or truncated data: {name!r}")
        require(len(content) == entry["usize"] and zlib.crc32(content) == entry["crc"], f"ZIP entry CRC/size mismatch: {name!r}")
        files[name[len(prefix):]] = {"sha256": digest(content), "mode": stat.S_IMODE(mode) & 0o777}
    require(position == cd_offset, "unaccounted bytes before the ZIP central directory")
    for relative in files:
        parts = relative.split("/")
        directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
    return {"files": files, "directories": sorted(directories)}
