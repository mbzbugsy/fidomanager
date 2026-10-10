#!/usr/bin/env python3
"""Release eligibility preflight for the protected macOS release workflow (ADR-017 section 7.1).

This is release control-plane code, trusted at the same level as `release-macos.yml`: both come
from the same reviewed commit and are under the same CODEOWNERS rule (ADR-017 7.5). It never signs,
notarizes, publishes or touches a credential, and it holds no Team ID or signer pin of its own.

Isolation contract (the `preflight` job runs it as `python3 -I -S scripts/release-preflight.py`):

- one self-contained file, standard library only; it imports nothing from the repository;
- no network access: GitHub API responses are fetched by the workflow with its read-only token
  (`contents: read`, `checks: read`) and passed in as files;
- it reads git objects of the peeled release commit only (never the working tree), through `git`
  plumbing commands with system/global configuration and replace objects disabled;
- it runs no build tooling, package manager or candidate binary.

Every rule fails closed: missing, pending, skipped, ambiguous, malformed or unverifiable evidence
makes the release ineligible (exit status 1). Outputs are written only after every rule passed.

Subcommands:

  eligibility       the full section 7.1 eligibility check for the current tag-push run
  workflow-policy   only the workflow pin policy for a workflow file (authoring aid; no identity)

Intended use in the future `preflight` job (not enabled by this file):

  git fetch --no-tags origin "+refs/tags/$GITHUB_REF_NAME:refs/tags/$GITHUB_REF_NAME" \\
      "+refs/heads/main:refs/remotes/origin/main"        # keep the annotated tag object
  gh api "repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA/check-runs?filter=latest&per_page=100" \\
      > check-runs.json
  status=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $GH_TOKEN" \\
      "https://api.github.com/repos/$GITHUB_REPOSITORY/releases/tags/$GITHUB_REF_NAME")
  gh api repos/mbzbugsy/fidomanager-release-signer > signer-repository.json
  gh api "repos/mbzbugsy/fidomanager-release-signer/compare/$PIN...$DEFAULT_BRANCH" \\
      > signer-compare.json    # $PIN from `workflow-policy`, $DEFAULT_BRANCH from the line above
  python3 -I -S scripts/release-preflight.py eligibility --check-runs check-runs.json \\
      --release-status "$status" --signer-repository signer-repository.json \\
      --signer-compare signer-compare.json --identity-out release-identity.json \\
      --github-output "$GITHUB_OUTPUT" --step-summary "$GITHUB_STEP_SUMMARY"
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

REPOSITORY = "mbzbugsy/fidomanager"
WORKFLOW_PATH = ".github/workflows/release-macos.yml"
MAIN_REF = "refs/remotes/origin/main"
SIGNER_REPOSITORY = "mbzbugsy/fidomanager-release-signer"
API_ROOT = "https://api.github.com"
# ci.yml jobs (ADR-017 7.1). All must be present, in one check suite, and every run of that
# suite must have concluded `success`.
CI_JOBS = ("validation", "macos-native-auth", "macos-packaging")
# The only external actions the release workflow may use, each at a full commit SHA (ADR-017 6.4).
ALLOWED_ACTIONS = (
    "actions/attest-build-provenance",
    "actions/checkout",
    "actions/create-github-app-token",
    "actions/download-artifact",
    "actions/upload-artifact",
)
APP_TOKEN_ACTION = "actions/create-github-app-token"
APP_TOKEN_JOB = "policy-check"
RELEASE_TRIGGER = {"push": {"tags": ["v[0-9]+.[0-9]+.[0-9]+*"]}}
SCHEMA = "fidomanager.release-preflight/1"

SHA1 = re.compile(r"[0-9a-f]{40}")
# Stricter than the trigger glob: SemVer core with an optional pre-release, no build metadata.
TAG = re.compile(
    r"v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)"
)
BRANCH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
DIGITS = re.compile(r"[1-9][0-9]{0,19}")
PINNED_ACTION = re.compile(r"([a-z0-9-]+/[a-z0-9._-]+)@([0-9a-f]{40})")
MAX_EVIDENCE = 8 * 1024 * 1024
MAX_SOURCE_FILE = 1024 * 1024
MAX_WORKFLOW = 256 * 1024


class PreflightError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise PreflightError(message)


def is_sha1(value):
    return isinstance(value, str) and SHA1.fullmatch(value) is not None


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


# --------------------------------------------------------------------------------------------
# Strict JSON


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value):
    raise PreflightError(f"non-standard JSON constant: {value}")


def parse_json(data, label):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (ValueError, UnicodeError) as error:
        raise PreflightError(f"{label}: invalid UTF-8 JSON: {error}") from error


def read_evidence(path, label):
    """One bounded read of a regular, unlinked evidence file; symlinks are never followed."""
    return parse_json(read_regular(path, label, MAX_EVIDENCE), label)


def read_regular(path, label, limit):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise PreflightError(f"{label}: cannot open {path}: {error}") from error
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode), f"{label}: not a regular file: {path}")
        data = source.read(limit + 1)
    require(len(data) <= limit, f"{label}: file too large")
    return data


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode()


# --------------------------------------------------------------------------------------------
# Git (read-only plumbing on the local clone)


class Git:
    def __init__(self, repo, executable="git"):
        self.repo = str(repo)
        self.executable = executable
        # A fresh environment: no inherited GIT_DIR/GIT_* redirection, no system or global
        # configuration, and no replace refs that could make an object look like another.
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            "HOME": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }

    def run(self, *args, ok=(0,)):
        try:
            result = subprocess.run(
                [self.executable, "-C", self.repo, "--no-pager", "--literal-pathspecs",
                 "-c", "core.fsmonitor=false", *args],
                env=self.env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise PreflightError(f"git {args[0]}: {error}") from error
        require(result.returncode in ok,
                f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}")
        return result

    def text(self, *args):
        return self.run(*args).stdout.decode("utf-8", errors="replace").strip()

    def rev(self, name):
        result = self.run("rev-parse", "--verify", "--quiet", name, ok=(0, 1))
        require(result.returncode == 0, f"cannot resolve {name}")
        value = result.stdout.decode().strip()
        require(is_sha1(value), f"{name} does not resolve to a SHA-1 object name")
        return value

    def object_type(self, sha):
        return self.text("cat-file", "-t", sha)

    def tag_headers(self, sha):
        raw = self.run("cat-file", "tag", sha).stdout
        header, _, _ = raw.partition(b"\n\n")
        fields = {}
        for line in header.decode("utf-8", errors="replace").split("\n"):
            name, _, value = line.partition(" ")
            if name in ("object", "type", "tag"):
                require(name not in fields, f"tag object repeats the {name} header")
                fields[name] = value
        require(set(fields) == {"object", "type", "tag"}, "tag object headers are incomplete")
        return fields

    def is_ancestor(self, commit, ref):
        result = self.run("merge-base", "--is-ancestor", commit, ref, ok=(0, 1))
        return result.returncode == 0

    def blob(self, commit, path):
        """Bytes of a regular file in `commit`'s tree; symlinks and submodules are rejected."""
        listing = self.run("ls-tree", "-z", "--full-tree", commit, "--", path).stdout
        entries = [entry for entry in listing.split(b"\0") if entry]
        require(len(entries) == 1, f"{path} is missing from release commit {commit}")
        meta, _, name = entries[0].partition(b"\t")
        fields = meta.decode("ascii", errors="replace").split(" ")
        require(len(fields) == 3 and name == path.encode() and fields[1] == "blob" and
                fields[0] in ("100644", "100755") and is_sha1(fields[2]),
                f"{path} is not a regular file in release commit {commit}")
        size = self.text("cat-file", "-s", fields[2])
        require(size.isdigit() and int(size) <= MAX_SOURCE_FILE, f"{path} is too large")
        data = self.run("cat-file", "blob", fields[2]).stdout
        require(len(data) == int(size), f"{path}: short read")
        return data

    def text_file(self, commit, path):
        try:
            return self.blob(commit, path).decode("utf-8")
        except UnicodeError as error:
            raise PreflightError(f"{path}: not UTF-8") from error


# --------------------------------------------------------------------------------------------
# Run identity (GitHub-provided environment of the tag-push run)

IDENTITY_ENV = (
    "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_REF_TYPE", "GITHUB_REF_NAME",
    "GITHUB_SHA", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
)


def check_run_identity(env):
    missing = [name for name in IDENTITY_ENV if not env.get(name)]
    require(not missing, f"missing run identity: {', '.join(missing)}")
    require(env["GITHUB_REPOSITORY"] == REPOSITORY,
            f"repository is {env['GITHUB_REPOSITORY']!r}, expected {REPOSITORY!r}")
    require(env["GITHUB_EVENT_NAME"] == "push", "release runs only on a tag push")
    require(env["GITHUB_REF_TYPE"] == "tag", "release ref is not a tag")
    tag = env["GITHUB_REF_NAME"]
    match = TAG.fullmatch(tag)
    require(match is not None, f"tag {tag!r} is not a vMAJOR.MINOR.PATCH[-PRERELEASE] release tag")
    require(env["GITHUB_REF"] == f"refs/tags/{tag}", "GITHUB_REF does not name the release tag")
    require(is_sha1(env["GITHUB_SHA"]), "GITHUB_SHA is not a 40-hex commit")
    require(env["GITHUB_WORKFLOW_SHA"] == env["GITHUB_SHA"],
            "workflow SHA differs from the tagged commit")
    expected_ref = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/tags/{tag}"
    require(env["GITHUB_WORKFLOW_REF"] == expected_ref,
            f"workflow ref is {env['GITHUB_WORKFLOW_REF']!r}, expected {expected_ref!r}")
    require(DIGITS.fullmatch(env["GITHUB_RUN_ID"]) and DIGITS.fullmatch(env["GITHUB_RUN_ATTEMPT"]),
            "invalid run ID or attempt")
    return {
        "tag": tag,
        "version": match.group(1),
        "commit": env["GITHUB_SHA"],
        "workflow_ref": expected_ref,
        "workflow_sha": env["GITHUB_WORKFLOW_SHA"],
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": env["GITHUB_RUN_ATTEMPT"],
    }


# --------------------------------------------------------------------------------------------
# Tag and history


def check_tag(git, tag, expected_commit):
    tag_object = git.rev(f"refs/tags/{tag}")
    require(git.object_type(tag_object) == "tag",
            f"{tag} is a lightweight tag; releases require an annotated tag")
    headers = git.tag_headers(tag_object)
    require(headers["tag"] == tag, f"tag object is named {headers['tag']!r}, not {tag!r}")
    require(headers["type"] == "commit", "tag object must point directly at a commit")
    peeled = git.rev(f"refs/tags/{tag}^{{commit}}")
    require(headers["object"] == peeled, "tag object does not point at its peeled commit")
    require(peeled == expected_commit,
            f"tag peels to {peeled}, but the run is for {expected_commit}")
    return tag_object


def check_main_history(git, commit):
    git.rev(MAIN_REF)
    require(git.is_ancestor(commit, MAIN_REF),
            f"release commit {commit} is not in reviewed main history ({MAIN_REF})")


# --------------------------------------------------------------------------------------------
# Version consistency (read from the release commit, not the working tree)

_TOML_SEGMENT = r"""(?:[A-Za-z0-9_-]+|'[^'\n]*'|"[^"\\\n]*")"""
TOML_HEADER = re.compile(
    rf"(\[?)\[\s*({_TOML_SEGMENT}(?:\s*\.\s*{_TOML_SEGMENT})*)\s*\](\]?)\s*(?:#.*)?")
TOML_KEY = re.compile(r"([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)\s*=\s*(.*)")
TOML_STRING = re.compile(r'"([^"\\]*)"\s*(?:#.*)?')
TOML_STRINGS = re.compile(r"'[^'\n]*'|\"(?:[^\"\\\n]|\\.)*\"")
TOML_MEMBER = re.compile(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*")
INHERITED_VERSION = (
    re.compile(r"version\.workspace\s*=\s*true\s*(?:#.*)?"),
    re.compile(r"version\s*=\s*\{\s*workspace\s*=\s*true\s*\}\s*(?:#.*)?"),
)


def _array_depth(text):
    bare = TOML_STRINGS.sub("", text)
    return bare.count("[") - bare.count("]")


def toml_tables(text, label):
    """A deliberately narrow TOML reader: {table path: [[key path, value, line], ...]}.

    Table and key paths are tuples of unquoted segments, so `[a."b"]` and `[a . b]` are the same
    table, as in TOML. Anything it cannot read unambiguously (multi-line strings, quoted keys,
    unbalanced headers) fails, rather than risk reading a different value than Cargo does.
    Multi-line arrays are joined into their key's value.
    """
    require('"""' not in text and "'''" not in text, f"{label}: multi-line strings are not supported")
    tables = {(): []}
    current = ()
    depth = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if depth:
            depth += _array_depth(stripped)
            tables[current][-1][1] += "\n" + stripped
            continue
        if stripped.startswith("["):
            match = TOML_HEADER.fullmatch(stripped)
            require(match and bool(match.group(1)) == bool(match.group(3)),
                    f"{label}: unsupported table header {stripped!r}")
            path = tuple(segment[1:-1] if segment[0] in "'\"" else segment
                         for segment in re.findall(_TOML_SEGMENT, match.group(2)))
            current = (("[]",) if match.group(1) else ()) + path
            require(current not in tables or match.group(1),
                    f"{label}: duplicate table {stripped!r}")
            tables.setdefault(current, [])
            continue
        match = TOML_KEY.fullmatch(stripped)
        require(match is not None, f"{label}: unsupported line {stripped!r}")
        value = match.group(2).strip()
        tables[current].append([tuple(match.group(1).split(".")), value, stripped])
        if value.startswith("["):
            depth = _array_depth(value)
    require(depth == 0, f"{label}: unterminated array")
    return tables


def version_definitions(tables, owner):
    """Every key that could define `<owner>.version`, including dotted keys and inline tables."""
    target = owner + ("version",)
    found = []
    for table, entries in tables.items():
        for key, value, line in entries:
            full = table + key
            common = min(len(full), len(target))
            if full[:common] == target[:common]:
                found.append((table, key, value, line))
    return found


def cargo_workspace(git, commit):
    tables = toml_tables(git.text_file(commit, "Cargo.toml"), "Cargo.toml")
    definitions = version_definitions(tables, ("workspace", "package"))
    require(len(definitions) == 1 and definitions[0][:2] == (("workspace", "package"), ("version",)),
            "Cargo.toml: exactly one `version` in [workspace.package] is required")
    match = TOML_STRING.fullmatch(definitions[0][2])
    require(match is not None, "Cargo.toml: workspace version must be a plain string")
    members = [value for key, value, _ in tables.get(("workspace",), []) if key == ("members",)]
    require(len(members) == 1 and members[0].startswith("[") and members[0].endswith("]"),
            "Cargo.toml: [workspace] members list not found")
    body = members[0][1:-1]
    names = re.findall(r'"([^"\\]*)"', body)
    leftover = re.sub(r'"[^"\\]*"|,|\s|#[^\n]*', "", body)
    require(names and not leftover, "Cargo.toml: unsupported workspace members list")
    for member in names:
        require(TOML_MEMBER.fullmatch(member), f"Cargo.toml: unsupported workspace member {member!r}")
    return match.group(1), names


def member_inherits_version(git, commit, member):
    label = f"{member}/Cargo.toml"
    definitions = version_definitions(toml_tables(git.text_file(commit, label), label), ("package",))
    require(len(definitions) == 1 and definitions[0][0] == ("package",) and
            any(pattern.fullmatch(definitions[0][3]) for pattern in INHERITED_VERSION),
            f"{label}: package version must be inherited (version.workspace = true)")


def check_versions(git, commit, version):
    found = {}
    for path in ("package.json", "src-tauri/tauri.conf.json"):
        document = parse_json(git.blob(commit, path), path)
        require(isinstance(document, dict) and isinstance(document.get("version"), str),
                f"{path}: string version is required")
        found[path] = document["version"]
    found["Cargo.toml"], members = cargo_workspace(git, commit)
    for path, value in found.items():
        require(value == version, f"version mismatch: tag says {version}, {path} says {value}")
    for member in members:
        member_inherits_version(git, commit, member)
    return found


# --------------------------------------------------------------------------------------------
# CI for the exact commit (check-runs API response)


def check_ci(data, commit):
    require(isinstance(data, dict) and set(data) == {"total_count", "check_runs"},
            "check-runs evidence: unexpected shape")
    runs = data["check_runs"]
    require(isinstance(runs, list) and is_int(data["total_count"]),
            "check-runs evidence: unexpected shape")
    require(data["total_count"] == len(runs) and len(runs) <= 100,
            "check-runs evidence is incomplete (paginated or truncated)")
    by_suite = {}
    seen_ids = set()
    for run in runs:
        require(isinstance(run, dict), "check run: not an object")
        run_id, name = run.get("id"), run.get("name")
        require(is_int(run_id) and run_id > 0 and run_id not in seen_ids and isinstance(name, str),
                "check run: invalid or duplicate id/name")
        seen_ids.add(run_id)
        require(run.get("head_sha") == commit, f"check run {run_id} is for another commit")
        require(run.get("url") == f"{API_ROOT}/repos/{REPOSITORY}/check-runs/{run_id}",
                f"check run {run_id} does not belong to {REPOSITORY}")
        app, suite = run.get("app"), run.get("check_suite")
        require(isinstance(app, dict) and isinstance(app.get("slug"), str) and
                isinstance(suite, dict) and is_int(suite.get("id")),
                f"check run {run_id}: missing app or check suite")
        if app["slug"] == "github-actions":
            by_suite.setdefault(suite["id"], []).append(run)
    suites = [suite for suite, members in by_suite.items()
              if any(run["name"] in CI_JOBS for run in members)]
    require(suites, f"no CI check runs for {commit}")
    require(len(suites) == 1, "CI check runs are split across several check suites (ambiguous)")
    suite = suites[0]
    ids = {}
    for run in by_suite[suite]:
        require(run["name"] not in ids, f"CI job {run['name']!r} appears more than once")
        require(run.get("status") == "completed",
                f"CI job {run['name']!r} is {run.get('status')!r}, not completed")
        require(run.get("conclusion") == "success",
                f"CI job {run['name']!r} concluded {run.get('conclusion')!r}, not success")
        ids[run["name"]] = run["id"]
    absent = [job for job in CI_JOBS if job not in ids]
    require(not absent, f"CI jobs missing for {commit}: {', '.join(absent)}")
    return {"check_suite_id": suite, "check_runs": {job: ids[job] for job in sorted(ids)}}


def check_release_absent(status):
    require(status != 200, "a release already exists for this tag")
    require(status == 404, f"release lookup returned HTTP {status}; cannot prove the tag is unused")


# --------------------------------------------------------------------------------------------
# Strict YAML subset for the workflow file
#
# GitHub parses the workflow; this reader only has to see the same `uses:` and checkout settings.
# It therefore accepts a small block-style subset and rejects everything else (anchors, aliases,
# tags, flow mappings, multi-line plain or quoted scalars, quoted or complex keys, tabs, several
# documents). Block scalars (`run: |`) are opaque.


class Quoted(str):
    """A scalar that was written in quotes (as opposed to a plain scalar such as `false`)."""


class Block(str):
    """An opaque block scalar."""


_EMPTY = object()
_YAML_KEY = re.compile(r"([A-Za-z0-9_][A-Za-z0-9_-]*):(?: (.*))?")
_FORBIDDEN_START = set("&*!%@`?{}[],|>#'\"")


class _Line:
    __slots__ = ("number", "indent", "text")

    def __init__(self, number, indent, text):
        self.number, self.indent, self.text = number, indent, text


def _yaml_fail(number, message):
    raise PreflightError(f"workflow line {number}: {message}")


def _is_item(text):
    return text == "-" or text.startswith("- ")


def _quoted(text, number):
    quote = text[0]
    out, i = [], 1
    while i < len(text):
        char = text[i]
        if quote == "'" and char == "'":
            if text[i + 1:i + 2] == "'":
                out.append("'")
                i += 2
                continue
            return Quoted("".join(out)), text[i + 1:]
        if quote == '"':
            if char == "\\":
                _yaml_fail(number, "escape sequences in double-quoted scalars are not supported")
            if char == '"':
                return Quoted("".join(out)), text[i + 1:]
        out.append(char)
        i += 1
    _yaml_fail(number, "unterminated quoted scalar")


def _trailing(rest, number):
    if rest and not rest.isspace() and not re.match(r"\s+#", rest):
        _yaml_fail(number, "unexpected text after scalar")


def _flow_sequence(text, number):
    require(text.endswith("]"), f"workflow line {number}: unsupported flow sequence")
    body = text[1:-1].strip()
    items = []
    while body:
        if body[0] in "'\"":
            value, body = _quoted(body, number)
        else:
            value, _, body = body.partition(",")
            value = value.strip()
            if not value or any(c in _FORBIDDEN_START or c in "[]{}" for c in value) or ": " in value:
                _yaml_fail(number, "unsupported flow sequence item")
            items.append(value)
            body = body.strip()
            continue
        items.append(value)
        body = body.strip()
        if body:
            if not body.startswith(","):
                _yaml_fail(number, "unsupported flow sequence")
            body = body[1:].strip()
            if not body:
                _yaml_fail(number, "trailing comma in flow sequence")
    return items


def _scalar(raw, number):
    text = (raw or "").strip()
    if not text or text.startswith("#"):
        return _EMPTY
    if text[0] in "'\"":
        value, rest = _quoted(text, number)
        _trailing(rest, number)
        return value
    comment = re.search(r"\s#", text)
    if comment:
        text = text[:comment.start()].rstrip()
    if re.fullmatch(r"[|>][+-]?", text):
        return Block()
    if text.startswith("["):
        return _flow_sequence(text, number)
    if text == "{}":
        return {}
    if text[0] in _FORBIDDEN_START or _is_item(text) or ": " in text or text.endswith(":"):
        _yaml_fail(number, f"unsupported YAML value {text!r}")
    return text


def _split_key(text, number):
    match = _YAML_KEY.fullmatch(text)
    if match is None:
        _yaml_fail(number, f"unsupported YAML line {text!r}")
    return match.group(1), match.group(2)


def _innermost(text, column, number):
    """Descend through `- ` prefixes; return (parent column, raw value or None)."""
    while _is_item(text):
        rest = text[1:].lstrip(" ")
        if not rest or rest.startswith("#"):
            return column, None
        offset = len(text) - len(rest)
        if _is_item(rest):
            _yaml_fail(number, "nested compact sequences are not supported")
        if _YAML_KEY.fullmatch(rest) is None:
            return column, rest
        column, text = column + offset, rest
    _, raw = _split_key(text, number)
    return column, raw


def _logical_lines(source):
    require("\r" not in source and "\ufeff" not in source, "workflow: CR or BOM is not supported")
    raw = source.split("\n")
    lines, i = [], 0
    while i < len(raw):
        line, number = raw[i], i + 1
        i += 1
        if not line.strip() or line.lstrip(" ").startswith("#"):
            continue
        if "\t" in line:
            _yaml_fail(number, "tabs are not supported outside block scalars")
        text = line.rstrip(" ")
        indent = len(text) - len(text.lstrip(" "))
        text = text[indent:]
        if indent == 0 and (text.startswith("---") or text.startswith("...") or text.startswith("%")):
            _yaml_fail(number, "directives and multiple documents are not supported")
        lines.append(_Line(number, indent, text))
        parent, value = _innermost(text, indent, number)
        if value is not None and isinstance(_scalar(value, number), Block):
            content = None
            while i < len(raw):
                body = raw[i]
                if body.strip():
                    depth = len(body) - len(body.lstrip(" "))
                    if depth <= parent:
                        break
                    if content is None:
                        content = depth
                    elif depth < content:
                        _yaml_fail(i + 1, "block scalar line is less indented than its content")
                i += 1
    return lines


class WorkflowYaml:
    def __init__(self, source):
        self.lines = _logical_lines(source)

    def parse(self):
        require(self.lines and self.lines[0].indent == 0, "workflow: empty or indented document")
        node, i = self._block(0, 0)
        if i != len(self.lines):
            _yaml_fail(self.lines[i].number, "unexpected content")
        return node

    def _block(self, i, indent):
        if _is_item(self.lines[i].text):
            return self._sequence(i, indent)
        return self._mapping(i, indent)

    def _mapping(self, i, indent):
        result = {}
        lines = self.lines
        while i < len(lines) and lines[i].indent == indent and not _is_item(lines[i].text):
            line = lines[i]
            key, raw = _split_key(line.text, line.number)
            if key in result:
                _yaml_fail(line.number, f"duplicate key {key!r}")
            value = _scalar(raw, line.number)
            i += 1
            if value is _EMPTY:
                if i < len(lines) and lines[i].indent > indent:
                    value, i = self._block(i, lines[i].indent)
                elif i < len(lines) and lines[i].indent == indent and _is_item(lines[i].text):
                    value, i = self._sequence(i, indent)
                else:
                    value = None
            result[key] = value
        if i < len(lines) and lines[i].indent > indent:
            _yaml_fail(lines[i].number, "unexpected indentation")
        return result, i

    def _sequence(self, i, indent):
        items = []
        lines = self.lines
        while i < len(lines) and lines[i].indent == indent and _is_item(lines[i].text):
            line = lines[i]
            rest = line.text[1:].lstrip(" ")
            column = indent + len(line.text) - len(rest)
            if not rest or rest.startswith("#"):
                i += 1
                if i < len(lines) and lines[i].indent > indent:
                    item, i = self._block(i, lines[i].indent)
                else:
                    item = None
            elif _is_item(rest):
                _yaml_fail(line.number, "nested compact sequences are not supported")
            elif _YAML_KEY.fullmatch(rest):
                lines[i] = _Line(line.number, column, rest)
                item, i = self._mapping(i, column)
            else:
                item = _scalar(rest, line.number)
                i += 1
            items.append(item)
        if i < len(lines) and lines[i].indent > indent:
            _yaml_fail(lines[i].number, "unexpected indentation")
        return items, i


def parse_workflow(source):
    return WorkflowYaml(source).parse()


# --------------------------------------------------------------------------------------------
# Workflow policy (ADR-017 6.4 and 7.1)


def _uses_locations(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uses":
                yield path
            yield from _uses_locations(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _uses_locations(value, path + (index,))


def check_workflow_policy(source):
    require(isinstance(source, str) and len(source) <= MAX_WORKFLOW, "workflow: missing or too large")
    tree = parse_workflow(source)
    require(isinstance(tree, dict), "workflow: top level must be a mapping")
    require(tree.get("on") == RELEASE_TRIGGER,
            "workflow trigger must be exactly a push of tags 'v[0-9]+.[0-9]+.[0-9]+*'")
    require(tree.get("permissions") == {}, "workflow must declare top-level `permissions: {}`")
    jobs = tree.get("jobs")
    require(isinstance(jobs, dict) and jobs, "workflow has no jobs")

    allowed_locations = set()
    signer_pins = []
    actions = []
    for job_id, job in jobs.items():
        require(isinstance(job, dict), f"job {job_id!r} is not a mapping")
        require("uses" not in job, f"job {job_id!r} calls a reusable workflow; none is allowed")
        steps = job.get("steps")
        require(isinstance(steps, list) and steps, f"job {job_id!r} has no steps")
        for index, step in enumerate(steps):
            where = f"job {job_id!r} step {index + 1}"
            require(isinstance(step, dict), f"{where} is not a mapping")
            if "uses" not in step:
                continue
            allowed_locations.add(("jobs", job_id, "steps", index))
            uses = step["uses"]
            match = PINNED_ACTION.fullmatch(uses) if isinstance(uses, str) else None
            require(match is not None, f"{where}: `uses: {uses}` is not owner/repo@<40-hex commit SHA>")
            action = match.group(1)
            require(action in ALLOWED_ACTIONS, f"{where}: action {action!r} is not allowed")
            require(action != APP_TOKEN_ACTION or job_id == APP_TOKEN_JOB,
                    f"{where}: {APP_TOKEN_ACTION} is allowed only in job {APP_TOKEN_JOB!r}")
            actions.append(uses)
            if action != "actions/checkout":
                continue
            options = step.get("with")
            require(isinstance(options, dict) and type(options.get("persist-credentials")) is str
                    and options["persist-credentials"] == "false",
                    f"{where}: checkout must set `persist-credentials: false`")
            repository = options.get("repository")
            if repository is None or repository == REPOSITORY:
                continue
            require(repository == SIGNER_REPOSITORY, f"{where}: checkout of {repository!r} is not allowed")
            ref = options.get("ref")
            require(is_sha1(ref), f"{where}: signer checkout ref must be a full 40-hex commit SHA")
            signer_pins.append(ref)
    for location in _uses_locations(tree):
        require(location in allowed_locations, f"workflow: `uses` at an unsupported place {location}")
    require(signer_pins, f"workflow does not check out {SIGNER_REPOSITORY} at a pinned commit")
    require(len(set(signer_pins)) == 1, "workflow pins the signer at more than one commit")
    return {"signer_sha": signer_pins[0], "actions": sorted(set(actions))}


# --------------------------------------------------------------------------------------------
# Signer pin reachability (repository and compare API responses)


def check_signer(pin, repository, compare):
    require(isinstance(repository, dict) and repository.get("full_name") == SIGNER_REPOSITORY,
            "signer repository evidence is for another repository")
    branch = repository.get("default_branch")
    require(isinstance(branch, str) and BRANCH.fullmatch(branch) and ".." not in branch,
            "signer repository evidence has no valid default branch")
    require(isinstance(compare, dict), "signer compare evidence: unexpected shape")
    require(compare.get("url") == f"{API_ROOT}/repos/{SIGNER_REPOSITORY}/compare/{pin}...{branch}",
            f"signer compare evidence is not {pin}...{branch} in {SIGNER_REPOSITORY}")
    base, merge_base = compare.get("base_commit"), compare.get("merge_base_commit")
    require(isinstance(base, dict) and base.get("sha") == pin,
            "signer compare evidence has another base commit")
    require(isinstance(merge_base, dict) and merge_base.get("sha") == pin and
            compare.get("status") in ("ahead", "identical") and compare.get("behind_by") == 0,
            f"signer pin {pin} is not on {SIGNER_REPOSITORY}@{branch}")
    return branch


# --------------------------------------------------------------------------------------------
# Eligibility


def eligibility(git, env, check_runs, release_status, signer_repository, signer_compare):
    identity = check_run_identity(env)
    commit = identity["commit"]
    tag_object = check_tag(git, identity["tag"], commit)
    check_main_history(git, commit)
    ci = check_ci(check_runs, commit)
    check_release_absent(release_status)
    check_versions(git, commit, identity["version"])
    policy = check_workflow_policy(git.text_file(commit, WORKFLOW_PATH))
    branch = check_signer(policy["signer_sha"], signer_repository, signer_compare)
    return {
        "schema": SCHEMA,
        "repository": REPOSITORY,
        "tag": identity["tag"],
        "tag_object": tag_object,
        "commit": commit,
        "version": identity["version"],
        "workflow_ref": identity["workflow_ref"],
        "workflow_sha": identity["workflow_sha"],
        "signer": {"repository": SIGNER_REPOSITORY, "sha": policy["signer_sha"],
                   "default_branch": branch},
        "actions": policy["actions"],
        "ci": ci,
        "run_id": identity["run_id"],
        "run_attempt": identity["run_attempt"],
    }


def github_outputs(identity, identity_sha256):
    outputs = {
        "tag": identity["tag"],
        "tag_object": identity["tag_object"],
        "commit": identity["commit"],
        "version": identity["version"],
        "workflow_ref": identity["workflow_ref"],
        "workflow_sha": identity["workflow_sha"],
        "signer_sha": identity["signer"]["sha"],
        "ci_check_suite_id": str(identity["ci"]["check_suite_id"]),
        "ci_check_run_ids": ",".join(str(identity["ci"]["check_runs"][job]) for job in CI_JOBS),
        "identity_sha256": identity_sha256,
    }
    for key, value in outputs.items():
        require(re.fullmatch(r"[A-Za-z0-9._/@:,+-]+", value), f"unsafe output value for {key}")
    return "".join(f"{key}={value}\n" for key, value in outputs.items())


def step_summary(identity, identity_sha256):
    ci = identity["ci"]["check_runs"]
    rows = [
        ("Tag", identity["tag"]),
        ("Tag object", identity["tag_object"]),
        ("Peeled commit", identity["commit"]),
        ("Version", identity["version"]),
        ("Workflow ref", identity["workflow_ref"]),
        ("Workflow SHA", identity["workflow_sha"]),
        ("Signer", f"{identity['signer']['repository']}@{identity['signer']['sha']}"),
        ("CI", "success: " + ", ".join(f"{job} ({ci[job]})" for job in CI_JOBS)),
        ("Run", f"{identity['run_id']} attempt {identity['run_attempt']}"),
        ("Identity SHA-256", identity_sha256),
    ]
    body = "".join(f"| {name} | `{value}` |\n" for name, value in rows)
    return "## Release preflight: eligible\n\n| Field | Value |\n| --- | --- |\n" + body


def _append(path, text):
    with open(path, "a", encoding="utf-8") as sink:
        sink.write(text)


def main(argv=None, env=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("eligibility", help="full ADR-017 7.1 eligibility check")
    check.add_argument("--repo", type=Path, default=Path("."))
    check.add_argument("--check-runs", required=True, type=Path,
                       help="GET /repos/{repo}/commits/{sha}/check-runs?filter=latest&per_page=100")
    check.add_argument("--release-status", required=True, type=int,
                       help="HTTP status of GET /repos/{repo}/releases/tags/{tag}")
    check.add_argument("--signer-repository", required=True, type=Path,
                       help=f"GET /repos/{SIGNER_REPOSITORY}")
    check.add_argument("--signer-compare", required=True, type=Path,
                       help=f"GET /repos/{SIGNER_REPOSITORY}/compare/{{pin}}...{{default_branch}}")
    check.add_argument("--identity-out", type=Path)
    check.add_argument("--github-output", type=Path)
    check.add_argument("--step-summary", type=Path)
    policy = commands.add_parser("workflow-policy", help="pin policy of one workflow file only")
    policy.add_argument("workflow", type=Path)
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    try:
        if args.command == "workflow-policy":
            data = read_regular(args.workflow, "workflow", MAX_WORKFLOW)
            try:
                text = data.decode("utf-8")
            except UnicodeError as error:
                raise PreflightError("workflow: not UTF-8") from error
            print(json.dumps(check_workflow_policy(text), indent=2, sort_keys=True))
            return 0
        identity = eligibility(
            Git(args.repo), env,
            read_evidence(args.check_runs, "check-runs"),
            args.release_status,
            read_evidence(args.signer_repository, "signer repository"),
            read_evidence(args.signer_compare, "signer compare"),
        )
        record = canonical(identity)
        identity_sha256 = hashlib.sha256(record).hexdigest()
        outputs = github_outputs(identity, identity_sha256)
        if args.identity_out:
            args.identity_out.write_bytes(record)
        if args.github_output:
            _append(args.github_output, outputs)
        if args.step_summary:
            _append(args.step_summary, step_summary(identity, identity_sha256))
        sys.stdout.write(record.decode())
        return 0
    except PreflightError as error:
        print(f"release preflight: INELIGIBLE: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
