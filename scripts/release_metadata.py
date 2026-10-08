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
