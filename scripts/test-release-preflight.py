#!/usr/bin/env python3
"""Deterministic regression tests for release-preflight.py (ADR-017 7.1).

Credential-free and offline: every repository is a temporary local git repository, and every
GitHub API response is a synthetic fixture. All commit SHAs used for actions and the signer pin
are obviously synthetic test values, never real pins.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release-preflight.py"
spec = importlib.util.spec_from_file_location("release_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)
PreflightError = preflight.PreflightError

# Synthetic 40-hex values (test-only; not real action or signer commits).
CHECKOUT = "1a" * 20
DOWNLOAD = "2b" * 20
APP_TOKEN = "3c" * 20
UPLOAD = "4d" * 20
SIGNER_PIN = "5e" * 20
TAG = "v1.2.3"
VERSION = "1.2.3"

WORKFLOW = f"""\
# Synthetic test fixture only. This is not the production release workflow.
name: Release (macOS)

on:
  push:
    tags: ['v[0-9]+.[0-9]+.[0-9]+*']

permissions: {{}}

concurrency:
  group: release-${{{{ github.ref }}}}
  cancel-in-progress: false

jobs:
  preflight:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: read
    outputs:
      commit: ${{{{ steps.eligibility.outputs.commit }}}}
    steps:
      - name: Checkout
        uses: actions/checkout@{CHECKOUT} # synthetic
        with:
          persist-credentials: false
          fetch-depth: 0
      - name: Eligibility
        id: eligibility
        env:
          GH_TOKEN: ${{{{ github.token }}}}
        run: |
          # uses: actions/cache@v4 in a script is data, not a step
          python3 -I -S scripts/release-preflight.py eligibility \\
            --check-runs check-runs.json

  policy-check:
    runs-on: ubuntu-latest
    permissions: {{}}
    environment: macos-release-policy
    steps:
      - id: token
        uses: actions/create-github-app-token@{APP_TOKEN}
        with:
          permission-administration: read

  sign-notarize:
    needs: [preflight, policy-check]
    runs-on: macos-latest
    environment: macos-release
    permissions: {{}}
    steps:
    - name: Signing driver at the pinned commit
      uses: actions/checkout@{CHECKOUT}
      with:
        repository: mbzbugsy/fidomanager-release-signer
        ref: {SIGNER_PIN}
        path: signer
        persist-credentials: false
    - uses: "actions/download-artifact@{DOWNLOAD}"
      with:
        name: build-output
    - run: >-
        echo "uses: anything@main"
    - uses: actions/upload-artifact@{UPLOAD}
      with:
        name: signed
"""

CARGO = f"""\
[workspace]
members = [
    "crates/alpha",
    "src-tauri", # the app
]
resolver = "2"

[workspace.package]
version = "{VERSION}"
edition = "2024"

[workspace.dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
"""

MEMBER = """\
[package]
name = "{name}"
version.workspace = true
edition.workspace = true

[dependencies]
serde = {{ workspace = true }}
"""


def base_files():
    return {
        "package.json": json.dumps({"name": "fidomanager", "version": VERSION}, indent=2) + "\n",
        "src-tauri/tauri.conf.json": json.dumps({"productName": "Fido Manager", "version": VERSION}) + "\n",
        "Cargo.toml": CARGO,
        "crates/alpha/Cargo.toml": MEMBER.format(name="alpha"),
        "src-tauri/Cargo.toml": MEMBER.format(name="fidomanager-app"),
        ".github/workflows/release-macos.yml": WORKFLOW,
    }


GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": os.devnull,
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "Fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}


class Repo:
    def __init__(self, path):
        self.path = Path(path)
        self.path.mkdir(parents=True)
        self.git("init", "-q", "-b", "main")

    def git(self, *args, stdin=None):
        result = subprocess.run(
            ["git", "-C", str(self.path), "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
            env=GIT_ENV, input=stdin, capture_output=True, check=True,
        )
        return result.stdout.decode().strip()

    def commit(self, files, message="release", remove=()):
        for name, content in files.items():
            target = self.path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        for name in remove:
            self.git("rm", "-q", "--", name)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def tag(self, name=TAG, commit="HEAD"):
        self.git("tag", "-a", name, "-m", f"Release {name}", commit)
        return self.git("rev-parse", f"refs/tags/{name}")

    def publish_main(self, commit="HEAD"):
        self.git("update-ref", "refs/remotes/origin/main", commit)


def make_release(directory, files=None, remove=()):
    repo = Repo(directory)
    content = base_files()
    content.update(files or {})
    for name in remove:
        del content[name]
    commit = repo.commit(content)
    repo.publish_main()
    tag_object = repo.tag()
    return repo, commit, tag_object


def run_env(commit, tag=TAG):
    return {
        "GITHUB_REPOSITORY": "mbzbugsy/fidomanager",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": f"refs/tags/{tag}",
        "GITHUB_REF_TYPE": "tag",
        "GITHUB_REF_NAME": tag,
        "GITHUB_SHA": commit,
        "GITHUB_WORKFLOW_REF": f"mbzbugsy/fidomanager/.github/workflows/release-macos.yml@refs/tags/{tag}",
        "GITHUB_WORKFLOW_SHA": commit,
        "GITHUB_RUN_ID": "987654321",
        "GITHUB_RUN_ATTEMPT": "1",
    }


def check_run(run_id, name, commit, suite=700, status="completed", conclusion="success",
              app="github-actions"):
    return {
        "id": run_id,
        "name": name,
        "head_sha": commit,
        "status": status,
        "conclusion": conclusion,
        "url": f"https://api.github.com/repos/mbzbugsy/fidomanager/check-runs/{run_id}",
        "app": {"slug": app},
        "check_suite": {"id": suite},
    }


def check_runs(commit, extra=()):
    runs = [
        check_run(101, "validation", commit),
        check_run(102, "macos-native-auth", commit),
        check_run(103, "macos-packaging", commit),
        # The release run's own, still running, preflight job is in another suite and ignored.
        check_run(201, "preflight", commit, suite=800, status="in_progress", conclusion=None),
        *extra,
    ]
    return {"total_count": len(runs), "check_runs": runs}


def signer_repository(branch="main"):
    return {"full_name": "mbzbugsy/fidomanager-release-signer", "default_branch": branch}


def signer_compare(pin=SIGNER_PIN, branch="main", status="ahead", merge_base=None, behind_by=0):
    return {
        "url": f"https://api.github.com/repos/mbzbugsy/fidomanager-release-signer/compare/{pin}...{branch}",
        "status": status,
        "ahead_by": 3 if status == "ahead" else 0,
        "behind_by": behind_by,
        "base_commit": {"sha": pin},
        "merge_base_commit": {"sha": merge_base or pin},
    }


class Case(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def release(self, files=None, remove=()):
        self.count = getattr(self, "count", 0) + 1
        self.repo, self.commit, self.tag_object = make_release(
            self.dir / f"repo{self.count}", files, remove)
        return self.repo

    def evaluate(self, env=None, runs=None, status=404, repository=None, compare=None):
        return preflight.eligibility(
            preflight.Git(self.repo.path),
            env if env is not None else run_env(self.commit),
            runs if runs is not None else check_runs(self.commit),
            status,
            repository if repository is not None else signer_repository(),
            compare if compare is not None else signer_compare(),
        )

    def ineligible(self, pattern, **kwargs):
        with self.assertRaisesRegex(PreflightError, pattern):
            self.evaluate(**kwargs)


class EligibleRelease(Case):
    def test_complete_evidence_is_eligible_and_names_the_exact_tuple(self):
        self.release()
        identity = self.evaluate()
        self.assertEqual(identity["tag"], TAG)
        self.assertEqual(identity["tag_object"], self.tag_object)
        self.assertNotEqual(identity["tag_object"], self.commit)
        self.assertEqual(identity["commit"], self.commit)
        self.assertEqual(identity["version"], VERSION)
        self.assertEqual(identity["workflow_sha"], self.commit)
        self.assertEqual(identity["signer"], {"repository": "mbzbugsy/fidomanager-release-signer",
                                              "sha": SIGNER_PIN, "default_branch": "main"})
        self.assertEqual(identity["ci"], {"check_suite_id": 700, "check_runs": {
            "macos-native-auth": 102, "macos-packaging": 103, "validation": 101}})
        self.assertEqual(identity["run_id"], "987654321")

    def test_earlier_main_commit_is_eligible(self):
        self.release()
        self.repo.commit({"later.txt": "after the release\n"}, "later")
        self.repo.publish_main()
        self.assertEqual(self.evaluate()["commit"], self.commit)

    def test_identity_is_deterministic(self):
        self.release()
        self.assertEqual(preflight.canonical(self.evaluate()), preflight.canonical(self.evaluate()))


class TagAndHistory(Case):
    def test_lightweight_tag(self):
        self.release()
        self.repo.git("tag", "-d", TAG)
        self.repo.git("tag", TAG, self.commit)
        self.ineligible("lightweight tag")

    def test_missing_tag(self):
        self.release()
        self.repo.git("tag", "-d", TAG)
        self.ineligible("cannot resolve refs/tags/v1.2.3")

    def test_tag_object_named_differently(self):
        self.release()
        self.repo.git("tag", "-d", TAG)
        other = self.repo.tag("v1.2.4")
        self.repo.git("update-ref", f"refs/tags/{TAG}", other)
        self.ineligible("tag object is named 'v1.2.4'")

    def test_tag_of_a_tag(self):
        self.release()
        self.repo.git("tag", "-a", "inner", "-m", "inner", self.commit)
        self.repo.git("tag", "-d", TAG)
        self.repo.git("tag", "-a", TAG, "-m", "outer", "inner")
        self.ineligible("point directly at a commit")

    def test_tag_peels_to_another_commit_than_the_run(self):
        self.release()
        moved = self.repo.commit({"moved.txt": "x\n"}, "moved")
        self.repo.publish_main()
        self.repo.git("tag", "-d", TAG)
        self.repo.tag(TAG, moved)
        self.ineligible("tag peels to")

    def test_commit_not_on_main(self):
        self.release()
        self.repo.git("checkout", "-q", "--orphan", "other")
        unrelated = self.repo.commit({"orphan.txt": "x\n"}, "orphan")
        self.repo.publish_main(unrelated)
        self.ineligible("not in reviewed main history")

    def test_commit_ahead_of_main(self):
        repo = Repo(self.dir / "ahead")
        base = repo.commit({"README": "base\n"}, "base")
        self.commit = repo.commit(base_files(), "unreviewed release")
        repo.publish_main(base)
        self.tag_object = repo.tag()
        self.repo = repo
        self.ineligible("not in reviewed main history")

    def test_main_ref_missing(self):
        self.release()
        self.repo.git("update-ref", "-d", "refs/remotes/origin/main")
        self.ineligible("cannot resolve refs/remotes/origin/main")

    def test_replace_objects_are_ignored(self):
        self.release()
        other = self.repo.commit({"other.txt": "x\n"}, "other")
        self.repo.git("replace", self.commit, other)
        self.assertEqual(self.evaluate()["commit"], self.commit)


class RunIdentity(Case):
    def setUp(self):
        super().setUp()
        self.release()

    def with_env(self, **changes):
        env = run_env(self.commit)
        env.update(changes)
        return env

    def test_missing_variable(self):
        env = run_env(self.commit)
        del env["GITHUB_WORKFLOW_SHA"]
        self.ineligible("missing run identity: GITHUB_WORKFLOW_SHA", env=env)

    def test_other_repository(self):
        self.ineligible("repository is", env=self.with_env(GITHUB_REPOSITORY="fork/fidomanager"))

    def test_not_a_push(self):
        self.ineligible("tag push", env=self.with_env(GITHUB_EVENT_NAME="workflow_dispatch"))

    def test_branch_ref(self):
        self.ineligible("not a tag", env=self.with_env(GITHUB_REF_TYPE="branch"))

    def test_ref_does_not_name_tag(self):
        self.ineligible("GITHUB_REF", env=self.with_env(GITHUB_REF="refs/tags/v9.9.9"))

    def test_invalid_tag_names(self):
        for tag in ("v1.2", "1.2.3", "v01.2.3", "v1.2.3+build", "v1.2.3-", "v1.2.3-rc..1"):
            with self.subTest(tag=tag):
                self.ineligible("not a vMAJOR", env=run_env(self.commit, tag))

    def test_workflow_sha_differs(self):
        self.ineligible("workflow SHA differs", env=self.with_env(GITHUB_WORKFLOW_SHA="f" * 40))

    def test_workflow_ref_other_file(self):
        self.ineligible("workflow ref is", env=self.with_env(
            GITHUB_WORKFLOW_REF="mbzbugsy/fidomanager/.github/workflows/ci.yml@refs/tags/v1.2.3"))

    def test_workflow_ref_other_ref(self):
        self.ineligible("workflow ref is", env=self.with_env(
            GITHUB_WORKFLOW_REF="mbzbugsy/fidomanager/.github/workflows/release-macos.yml@refs/heads/main"))

    def test_short_sha(self):
        self.ineligible("40-hex", env=self.with_env(GITHUB_SHA=self.commit[:12],
                                                    GITHUB_WORKFLOW_SHA=self.commit[:12]))


class ContinuousIntegration(Case):
    def setUp(self):
        super().setUp()
        self.release()

    def runs_with(self, mutate):
        runs = check_runs(self.commit)
        mutate(runs["check_runs"])
        runs["total_count"] = len(runs["check_runs"])
        return runs

    def test_missing_job(self):
        runs = self.runs_with(lambda items: items.pop(1))
        self.ineligible("CI jobs missing .*macos-native-auth", runs=runs)

    def test_no_ci_at_all(self):
        runs = self.runs_with(lambda items: [items.pop(0) for _ in range(3)])
        self.ineligible("no CI check runs", runs=runs)

    def test_pending_and_unsuccessful_conclusions(self):
        cases = [("queued", None), ("in_progress", None), ("completed", "failure"),
                 ("completed", "skipped"), ("completed", "neutral"), ("completed", "cancelled"),
                 ("completed", "timed_out"), ("completed", "action_required"), ("completed", None)]
        for status, conclusion in cases:
            with self.subTest(status=status, conclusion=conclusion):
                runs = self.runs_with(lambda items: items[2].update(status=status, conclusion=conclusion))
                self.ineligible("CI job 'macos-packaging'", runs=runs)

    def test_any_failed_job_in_the_ci_suite(self):
        runs = self.runs_with(lambda items: items.append(
            check_run(104, "extra", self.commit, conclusion="failure")))
        self.ineligible("CI job 'extra' concluded 'failure'", runs=runs)

    def test_ci_split_across_suites(self):
        runs = self.runs_with(lambda items: items[0].update(check_suite={"id": 701}))
        self.ineligible("several check suites", runs=runs)

    def test_duplicate_job(self):
        runs = self.runs_with(lambda items: items.append(check_run(105, "validation", self.commit)))
        self.ineligible("appears more than once", runs=runs)

    def test_other_app_cannot_supply_ci(self):
        runs = self.runs_with(lambda items: items[0].update(app={"slug": "imposter"}))
        self.ineligible("CI jobs missing .*validation", runs=runs)

    def test_check_run_for_another_commit(self):
        runs = self.runs_with(lambda items: items[1].update(head_sha="e" * 40))
        self.ineligible("another commit", runs=runs)

    def test_check_run_from_another_repository(self):
        runs = self.runs_with(lambda items: items[1].update(
            url="https://api.github.com/repos/fork/fidomanager/check-runs/102"))
        self.ineligible("does not belong", runs=runs)

    def test_truncated_or_paginated_evidence(self):
        runs = check_runs(self.commit)
        runs["total_count"] += 1
        self.ineligible("incomplete", runs=runs)

    def test_malformed_evidence(self):
        for runs in ({}, {"total_count": 0}, {"total_count": 1, "check_runs": [None]},
                     {"total_count": True, "check_runs": []},
                     {"total_count": 0, "check_runs": [], "extra": 1}):
            with self.subTest(runs=runs):
                with self.assertRaises(PreflightError):
                    self.evaluate(runs=runs)

    def test_invalid_ids(self):
        for value in (True, 0, -1, "101", None):
            with self.subTest(value=value):
                runs = self.runs_with(lambda items: items[0].update(id=value))
                self.ineligible("invalid or duplicate id", runs=runs)

    def test_duplicate_ids(self):
        runs = self.runs_with(lambda items: items.append(copy.deepcopy(items[1])))
        self.ineligible("invalid or duplicate id", runs=runs)


class ExistingRelease(Case):
    def test_existing_release(self):
        self.release()
        self.ineligible("already exists", status=200)

    def test_unverifiable_lookup(self):
        self.release()
        for status in (0, 301, 401, 403, 500, 502):
            with self.subTest(status=status):
                self.ineligible("cannot prove the tag is unused", status=status)


class Versions(Case):
    def test_package_json_mismatch(self):
        self.release({"package.json": json.dumps({"version": "1.2.4"})})
        self.ineligible("package.json says 1.2.4")

    def test_tauri_mismatch(self):
        self.release({"src-tauri/tauri.conf.json": json.dumps({"version": "1.2.3-rc.1"})})
        self.ineligible("tauri.conf.json says 1.2.3-rc.1")

    def test_tauri_version_not_a_string(self):
        self.release({"src-tauri/tauri.conf.json": json.dumps({"version": "../package.json"})})
        self.ineligible("tauri.conf.json says")
        self.release({"src-tauri/tauri.conf.json": json.dumps({"productName": "x"})})
        self.ineligible("string version is required")

    def test_cargo_workspace_mismatch(self):
        self.release({"Cargo.toml": CARGO.replace(f'version = "{VERSION}"', 'version = "1.3.0"')})
        self.ineligible("Cargo.toml says 1.3.0")

    def test_prerelease_tag_requires_prerelease_versions(self):
        self.release()
        self.repo.git("tag", "-a", "v1.2.3-rc.1", "-m", "rc", self.commit)
        self.ineligible("version mismatch", env=run_env(self.commit, "v1.2.3-rc.1"))

    def test_member_with_own_version(self):
        self.release({"crates/alpha/Cargo.toml": MEMBER.format(name="alpha").replace(
            "version.workspace = true", f'version = "{VERSION}"')})
        self.ineligible("crates/alpha/Cargo.toml: package version must be inherited")

    def test_member_inline_workspace_form_is_accepted(self):
        self.release({"crates/alpha/Cargo.toml": MEMBER.format(name="alpha").replace(
            "version.workspace = true", "version = { workspace = true }")})
        self.assertEqual(self.evaluate()["version"], VERSION)

    def test_quoted_target_tables_are_read(self):
        member = MEMBER.format(name="alpha") + (
            "\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n"
            "\n[target.'cfg(target_os = \"macos\")'.dependencies]\nobjc = { version = \"0.2\" }\n")
        self.release({"crates/alpha/Cargo.toml": member})
        self.assertEqual(self.evaluate()["version"], VERSION)

    def test_member_version_hidden_in_quoted_header(self):
        member = MEMBER.format(name="alpha") + '\n["package"]\nversion = "9.9.9"\n'
        self.release({"crates/alpha/Cargo.toml": member})
        self.ineligible("duplicate table")

    def test_real_repository_manifests_are_readable(self):
        git = preflight.Git(ROOT)
        head = git.rev("HEAD")
        version = json.loads(git.blob(head, "package.json"))["version"]
        self.assertEqual(preflight.check_versions(git, head, version)["Cargo.toml"], version)

    def test_ambiguous_cargo_definitions(self):
        variants = {
            "dotted duplicate": CARGO.replace("[workspace]\n", f'[workspace]\npackage.version = "{VERSION}"\n'),
            "inline table": CARGO.replace("[workspace]\n", f'[workspace]\npackage = {{ version = "{VERSION}" }}\n'),
            "duplicate key": CARGO.replace('edition = "2024"', f'edition = "2024"\nversion = "{VERSION}"'),
            "quoted key": CARGO.replace('edition = "2024"', 'edition = "2024"\n"version" = "9.9.9"'),
            "quoted header alias": CARGO + '["workspace".package]\nrust-version = "1.85"\n',
            "spaced header alias": CARGO + "[ workspace . package ]\nrust-version = \"1.85\"\n",
            "unbalanced header": CARGO.replace("[workspace.package]", "[[workspace.package]"),
            "multi-line string": CARGO + 'description = """x"""\n',
            "member glob": CARGO.replace('"crates/alpha"', '"crates/*"'),
            "duplicate table": CARGO + "[workspace.package]\n",
            "not a string": CARGO.replace(f'version = "{VERSION}"', "version = 1"),
        }
        for label, text in variants.items():
            with self.subTest(label=label):
                self.release({"Cargo.toml": text})
                with self.assertRaises(PreflightError):
                    self.evaluate()

    def test_brackets_inside_strings_do_not_shift_tables(self):
        cargo = CARGO.replace("[workspace.package]",
                              '[workspace.metadata]\nopen = ["[", "]]"]\nnext = [\n  "[",\n]\n\n[workspace.package]')
        self.release({"Cargo.toml": cargo})
        self.assertEqual(self.evaluate()["version"], VERSION)

    def test_member_manifest_missing(self):
        self.release(remove=["crates/alpha/Cargo.toml"])
        self.ineligible("crates/alpha/Cargo.toml is missing")

    def test_version_file_is_a_symlink(self):
        repo = Repo(self.dir / "symlink")
        files = base_files()
        del files["package.json"]
        repo.commit(files)
        (repo.path / "real.json").write_text(files["src-tauri/tauri.conf.json"])
        os.symlink("real.json", repo.path / "package.json")
        self.commit = repo.commit({}, "symlink")
        repo.publish_main()
        self.tag_object = repo.tag()
        self.repo = repo
        self.ineligible("package.json is not a regular file")

    def test_duplicate_json_keys(self):
        self.release({"package.json": '{"version": "1.2.3", "version": "1.2.3"}'})
        self.ineligible("duplicate JSON key")

    def test_working_tree_is_not_read(self):
        self.release()
        (self.repo.path / "package.json").write_text(json.dumps({"version": "9.9.9"}))
        self.assertEqual(self.evaluate()["version"], VERSION)


def workflow_policy(text):
    return preflight.check_workflow_policy(text)


class WorkflowPolicy(unittest.TestCase):
    def rejected(self, text, pattern):
        with self.assertRaisesRegex(PreflightError, pattern):
            workflow_policy(text)

    def test_fixture_passes(self):
        result = workflow_policy(WORKFLOW)
        self.assertEqual(result["signer_sha"], SIGNER_PIN)
        self.assertEqual(result["actions"], sorted({
            f"actions/checkout@{CHECKOUT}", f"actions/download-artifact@{DOWNLOAD}",
            f"actions/create-github-app-token@{APP_TOKEN}", f"actions/upload-artifact@{UPLOAD}"}))

    def test_unpinned_uses(self):
        for ref in ("v4", "main", CHECKOUT[:39], CHECKOUT.upper(), CHECKOUT + "0",
                    "${{ env.SHA }}"):
            with self.subTest(ref=ref):
                self.rejected(WORKFLOW.replace(f"actions/upload-artifact@{UPLOAD}",
                                               f"actions/upload-artifact@{ref}"),
                              "not owner/repo@<40-hex|unsupported|unexpected")

    def test_local_and_docker_actions(self):
        for uses in ("./.github/actions/sign", "docker://alpine:3", f"actions/checkout/sub@{CHECKOUT}"):
            with self.subTest(uses=uses):
                self.rejected(WORKFLOW.replace(f"actions/upload-artifact@{UPLOAD}", uses),
                              "not owner/repo@")

    def test_action_not_allowed(self):
        for action in ("actions/cache", "actions/setup-node", "evil/checkout", "Actions/checkout"):
            with self.subTest(action=action):
                self.rejected(WORKFLOW.replace("actions/upload-artifact", action),
                              "not allowed|not owner/repo@")

    def test_reusable_workflow(self):
        text = WORKFLOW + f"  reuse:\n    uses: mbzbugsy/x/.github/workflows/y.yml@{CHECKOUT}\n"
        self.rejected(text, "reusable workflow")

    def test_app_token_outside_policy_check(self):
        text = WORKFLOW.replace("  policy-check:", "  other-job:").replace(
            "needs: [preflight, policy-check]", "needs: [preflight]")
        self.rejected(text, "allowed only in job 'policy-check'")

    def test_checkout_credentials(self):
        cases = {
            "missing": WORKFLOW.replace("          persist-credentials: false\n          fetch-depth: 0\n",
                                        "          fetch-depth: 0\n"),
            "true": WORKFLOW.replace("          persist-credentials: false\n          fetch-depth",
                                     "          persist-credentials: true\n          fetch-depth"),
            "quoted": WORKFLOW.replace("          persist-credentials: false\n          fetch-depth",
                                       "          persist-credentials: 'false'\n          fetch-depth"),
            "expression": WORKFLOW.replace("          persist-credentials: false\n          fetch-depth",
                                           "          persist-credentials: ${{ false }}\n          fetch-depth"),
            "no with": WORKFLOW.replace(
                "        with:\n          persist-credentials: false\n          fetch-depth: 0\n", ""),
            "signer": WORKFLOW.replace("        path: signer\n        persist-credentials: false\n",
                                       "        path: signer\n"),
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                self.assertNotEqual(text, WORKFLOW)
                self.rejected(text, "persist-credentials: false")

    def test_signer_pin(self):
        for ref in ("main", "refs/heads/main", SIGNER_PIN[:7], SIGNER_PIN.upper(), "v1.0.0",
                    "${{ vars.SIGNER_SHA }}"):
            with self.subTest(ref=ref):
                self.rejected(WORKFLOW.replace(f"ref: {SIGNER_PIN}", f"ref: {ref}"),
                              "full 40-hex commit SHA")

    def test_signer_missing_or_inconsistent(self):
        self.rejected(WORKFLOW.replace("        repository: mbzbugsy/fidomanager-release-signer\n"
                                       f"        ref: {SIGNER_PIN}\n", ""),
                      "does not check out mbzbugsy/fidomanager-release-signer")
        second = WORKFLOW + (
            "  verify:\n    runs-on: macos-latest\n    steps:\n"
            f"      - uses: actions/checkout@{CHECKOUT}\n        with:\n"
            "          repository: mbzbugsy/fidomanager-release-signer\n"
            f"          ref: {'6' * 40}\n          persist-credentials: false\n")
        self.rejected(second, "more than one commit")

    def test_checkout_of_other_repository(self):
        self.rejected(WORKFLOW.replace("repository: mbzbugsy/fidomanager-release-signer",
                                       "repository: someone/fidomanager-release-signer"),
                      "is not allowed")

    def test_trigger_and_permissions(self):
        self.rejected(WORKFLOW.replace("on:\n  push:", "on:\n  pull_request_target:\n  push:"),
                      "workflow trigger")
        self.rejected(WORKFLOW.replace("    tags: ['v[0-9]+.[0-9]+.[0-9]+*']",
                                       "    tags: ['v*']"), "workflow trigger")
        self.rejected(WORKFLOW.replace("    tags: ['v[0-9]+.[0-9]+.[0-9]+*']",
                                       "    tags: ['v[0-9]+.[0-9]+.[0-9]+*']\n    branches: [main]"),
                      "workflow trigger")
        self.rejected(WORKFLOW.replace("permissions: {}\n\nconcurrency",
                                       "permissions:\n  contents: write\n\nconcurrency"),
                      "permissions: {}")

    def test_uses_hidden_in_unsupported_yaml(self):
        cases = {
            "flow mapping step": WORKFLOW + "  extra:\n    steps:\n      - {uses: actions/cache@v4}\n",
            "anchor": WORKFLOW.replace("    - uses: actions/upload-artifact", "    - uses: &a actions/upload-artifact"),
            "alias": WORKFLOW + "  extra:\n    steps:\n      - uses: *a\n",
            "tag": WORKFLOW.replace("    - uses: actions/upload-artifact", "    - uses: !!str actions/upload-artifact"),
            "quoted key": WORKFLOW.replace("    - uses: actions/upload-artifact", '    - "uses": actions/upload-artifact'),
            "escaped key": WORKFLOW.replace("    - uses: actions/upload-artifact", '    - "u\\x73es": actions/upload-artifact'),
            "escaped value": WORKFLOW.replace(f'"actions/download-artifact@{DOWNLOAD}"',
                                              f'"actions/download-artifact\\x40{DOWNLOAD}"'),
            "complex key": WORKFLOW + "  extra:\n    steps:\n      - ? uses\n        : actions/cache@v4\n",
            "merge key": WORKFLOW + "  extra:\n    <<: {}\n",
            "tab": WORKFLOW.replace("    - uses: actions/upload-artifact", "    -\tuses: actions/upload-artifact"),
            "second document": WORKFLOW + "---\njobs: {}\n",
            "duplicate key": WORKFLOW.replace("    steps:\n    - name: Signing",
                                              "    steps: []\n    steps:\n    - name: Signing"),
            "multi-line plain": WORKFLOW.replace(f"    - uses: actions/upload-artifact@{UPLOAD}\n",
                                                 f"    - uses: actions/upload-artifact@\n        {UPLOAD}\n"),
            "uses in odd place": WORKFLOW.replace("        name: signed\n",
                                                  f"        name: signed\n        uses: actions/cache@{UPLOAD}\n"),
            "indentation": WORKFLOW.replace("      with:\n        name: signed",
                                            "      with:\n        name: signed\n         extra: x"),
            "nested sequence": WORKFLOW + "  extra:\n    steps:\n      - - uses: actions/cache@v4\n",
            "directive": "%YAML 1.2\n" + WORKFLOW,
            "crlf": WORKFLOW.replace("\n", "\r\n"),
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                self.assertNotEqual(text, WORKFLOW)
                with self.assertRaises(PreflightError):
                    workflow_policy(text)

    def test_block_scalar_content_is_opaque(self):
        # Already in the fixture: a `uses:` line inside `run: |` and `run: >-` is script text.
        tree = preflight.parse_workflow(WORKFLOW)
        steps = tree["jobs"]["sign-notarize"]["steps"]
        self.assertIsInstance(steps[2]["run"], preflight.Block)
        self.assertEqual(set(steps[2]), {"run"})

    def test_block_scalar_cannot_hide_structure(self):
        text = WORKFLOW.replace(
            "    - run: >-\n        echo \"uses: anything@main\"\n",
            "    - run: |\n          echo one\n        uses: actions/cache@v4\n")
        self.assertNotEqual(text, WORKFLOW)
        self.rejected(text, "less indented")

    def test_adr_trigger_snippet_matches_policy(self):
        adr = (ROOT / "docs/adr/ADR-017-MACOS-RELEASE-SIGNING.md").read_text()
        snippet = adr.split("### 7.1 Trigger and preconditions", 1)[1].split("```yaml\n", 1)[1].split("```", 1)[0]
        tree = preflight.parse_workflow(snippet)
        self.assertEqual(tree["on"], preflight.RELEASE_TRIGGER)
        self.assertEqual(tree["permissions"], {})

    def test_real_ci_workflow_parses_but_is_not_a_release_workflow(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        tree = preflight.parse_workflow(source)
        self.assertEqual(set(tree["jobs"]), {"validation", "macos-native-auth", "macos-packaging"})
        self.rejected(source, "workflow trigger")

    def test_missing_workflow_in_release_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, commit, _ = make_release(Path(directory) / "repo",
                                           remove=[".github/workflows/release-macos.yml"])
            with self.assertRaisesRegex(PreflightError, "release-macos.yml is missing"):
                preflight.eligibility(preflight.Git(repo.path), run_env(commit), check_runs(commit),
                                      404, signer_repository(), signer_compare())


class SignerPin(Case):
    def setUp(self):
        super().setUp()
        self.release()

    def test_not_on_default_branch(self):
        for compare in (signer_compare(status="diverged", merge_base="6" * 40, behind_by=2),
                        signer_compare(status="behind", behind_by=1),
                        signer_compare(merge_base="6" * 40)):
            with self.subTest(status=compare["status"]):
                self.ineligible("is not on mbzbugsy/fidomanager-release-signer@main", compare=compare)

    def test_evidence_for_another_pin_branch_or_repository(self):
        self.ineligible(re.escape(f"is not {SIGNER_PIN}...main"), compare=signer_compare(pin="6" * 40))
        self.ineligible("is not", compare=signer_compare(branch="develop"))
        self.ineligible("another repository",
                        repository={"full_name": "fork/fidomanager-release-signer", "default_branch": "main"})
        compare = signer_compare()
        compare["url"] = compare["url"].replace("mbzbugsy/", "fork/")
        self.ineligible("is not", compare=compare)
        compare = signer_compare()
        compare["base_commit"] = {"sha": "6" * 40}
        self.ineligible("another base commit", compare=compare)

    def test_default_branch_follows_repository_evidence(self):
        identity = self.evaluate(repository=signer_repository("trunk"),
                                 compare=signer_compare(branch="trunk"))
        self.assertEqual(identity["signer"]["default_branch"], "trunk")

    def test_malformed_evidence(self):
        for repository in ({}, {"full_name": "mbzbugsy/fidomanager-release-signer"},
                           signer_repository("../main"), signer_repository("")):
            with self.subTest(repository=repository):
                with self.assertRaises(PreflightError):
                    self.evaluate(repository=repository)
        self.ineligible("unexpected shape", compare=[])


class CommandLine(Case):
    def write(self, name, value):
        path = self.dir / name
        path.write_text(json.dumps(value))
        return path

    def run_cli(self, *extra, env_changes=None):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **run_env(self.commit),
               **(env_changes or {})}
        args = [
            sys.executable, "-I", "-S", str(SCRIPT), "eligibility", "--repo", str(self.repo.path),
            "--check-runs", str(self.write("runs.json", check_runs(self.commit))),
            "--release-status", "404",
            "--signer-repository", str(self.write("repo.json", signer_repository())),
            "--signer-compare", str(self.write("compare.json", signer_compare())),
            *extra,
        ]
        return subprocess.run(args, env=env, capture_output=True, text=True, cwd=self.dir)

    def test_eligible_run_writes_outputs(self):
        self.release()
        output, summary, identity = self.dir / "out", self.dir / "summary.md", self.dir / "identity.json"
        result = self.run_cli("--github-output", str(output), "--step-summary", str(summary),
                              "--identity-out", str(identity))
        self.assertEqual(result.returncode, 0, result.stderr)
        record = identity.read_bytes()
        self.assertEqual(result.stdout.encode(), record)
        lines = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(lines["commit"], self.commit)
        self.assertEqual(lines["tag_object"], self.tag_object)
        self.assertEqual(lines["signer_sha"], SIGNER_PIN)
        self.assertEqual(lines["ci_check_run_ids"], "101,102,103")
        self.assertEqual(lines["identity_sha256"], preflight.hashlib.sha256(record).hexdigest())
        self.assertIn(f"`{self.commit}`", summary.read_text())

    def test_ineligible_run_fails_closed_without_outputs(self):
        self.release()
        output = self.dir / "out"
        result = self.run_cli("--github-output", str(output),
                              env_changes={"GITHUB_WORKFLOW_SHA": "f" * 40})
        self.assertEqual(result.returncode, 1)
        self.assertIn("INELIGIBLE: workflow SHA differs", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(output.exists())

    def test_missing_or_symlinked_evidence(self):
        self.release()
        result = self.run_cli("--check-runs", str(self.dir / "absent.json"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("check-runs: cannot open", result.stderr)
        target = self.write("real.json", check_runs(self.commit))
        os.symlink(target, self.dir / "link.json")
        result = self.run_cli("--check-runs", str(self.dir / "link.json"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("check-runs: cannot open", result.stderr)

    def test_missing_arguments_are_rejected(self):
        result = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "eligibility"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)

    def test_workflow_policy_command(self):
        path = self.dir / "release-macos.yml"
        path.write_text(WORKFLOW)
        result = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "workflow-policy", str(path)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["signer_sha"], SIGNER_PIN)
        path.write_text(WORKFLOW.replace(f"@{UPLOAD}", "@v4"))
        result = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "workflow-policy", str(path)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("INELIGIBLE", result.stderr)


if __name__ == "__main__":
    unittest.main()
