#!/usr/bin/env python3
"""Adversarial deterministic provenance fixtures. All signing/notary/CI claims are SYNTHETIC.

Passing these tests proves local consistency policy, never Apple or GitHub authenticity.
"""
import copy
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from release_metadata import canonical, digest, CheckError, parse_json, publisher_requirement, read_regular

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("provenance", ROOT / "scripts/release-provenance.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


APP_FILES = {
    "Contents/Info.plist": (b"SYNTHETIC Info.plist", 0o644),
    "Contents/MacOS/fidomanager-app": (b"SYNTHETIC app executable", 0o755),
    "Contents/MacOS/fido-worker": (b"SYNTHETIC worker executable", 0o755),
    "Contents/Resources/release-worker-identity.json": (b"SYNTHETIC identity record\n", 0o644),
    "Contents/Resources/THIRD_PARTY_NOTICES.md": (b"SYNTHETIC notices", 0o644),
    "Contents/_CodeSignature/CodeResources": (b"SYNTHETIC seal", 0o644),
    "Contents/CodeResources": (b"SYNTHETIC stapled ticket", 0o644),
}
APP_DIRECTORIES = ["Contents", "Contents/MacOS", "Contents/Resources", "Contents/_CodeSignature"]


def make_app_zip(files=None, extra=(), directories=True, mode_override=None):
    """SYNTHETIC ditto-shaped ZIP (Unix attributes, keepParent); not an Apple-produced archive."""
    files = APP_FILES if files is None else files
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        def add(name, data, mode):
            info = zipfile.ZipInfo(name, (2026, 10, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_STORED if name.endswith("/") else zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
        if directories:
            for directory in [""] + APP_DIRECTORIES:
                add(f"{p.APP_NAME}/{directory}/".replace("//", "/"), b"", stat.S_IFDIR | 0o755)
        for name, (data, mode) in files.items():
            add(f"{p.APP_NAME}/{name}", data, stat.S_IFREG | (mode_override or {}).get(name, mode))
        for name, data, mode in extra:
            add(name, data, mode)
    return buffer.getvalue()


def app_tree():
    return {"files": {name: {"sha256": digest(data), "mode": mode} for name, (data, mode) in APP_FILES.items()},
            "directories": sorted(APP_DIRECTORIES)}


def fixture(directory):
    commit = "a" * 40
    context = {"repository": p.REPOSITORY, "tag": "v0.1.0", "tag_object_sha": "b" * 40,
               "commit_sha": commit, "version": "0.1.0", "arch": "arm64", "deployment_target": "11.0",
               "eligibility": {"on_main": True, "ci": {"workflow": ".github/workflows/ci.yml", "head_sha": commit,
                                "check_runs": {"validation": 1, "macos-native-auth": 2, "macos-packaging": 3}, "conclusion": "success"},
                               "immutable_releases": {"enabled": True, "response_sha256": "c" * 64}},
               "workflow": {"ref": f"{p.REPOSITORY}/{p.WORKFLOW}@refs/tags/v0.1.0", "sha": commit, "run_id": 42, "run_attempt": 1},
               "signer": {"repository": p.SIGNER, "sha": "d" * 40}}
    identity = {"architecture": "arm64", "deployment_target": "11.0", "fuzz": False, "compiler": "SYNTHETIC clang",
                "openssl_api_compat": "0x10100000L", "dependencies": {},
                "deterministic_controls": {"ZERO_AR_DATE": "1", "SOURCE_DATE_EPOCH": "1781654400"}}
    for name in ("libfido2", "openssl", "libcbor"):
        lock = p.read_json(ROOT / "native" / name / "source.lock.json")
        built = {"version": lock["version"], "source_archive_sha256": lock["archive_sha256"],
                 "static_archive_sha256": "1" * 64, "deployment_target": "11.0", "architecture": "arm64"}
        if name == "libfido2":
            identity.update(**built, revision=lock["revision"], patch_sha256=lock["patch_sha256"])
        else:
            built.update({key: lock[key] for key in ("upstream_tag", "upstream_commit", "license_spdx", "license_sha256")})
            built["sdk_version"] = "SYNTHETIC SDK"
            built["build_options"] = ["-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=OFF"]
            if name == "openssl":
                built.update(openssldir="/var/empty/fidomanager-openssl", build_options=["no-shared", "no-module", "no-engine", "no-dso", "no-autoload-config", "no-legacy", "no-apps", "no-tests", "no-docs", "no-ui-console", "-mmacosx-version-min=11.0"])
            identity["dependencies"][name] = built
    summary = {"architecture": "arm64", "developer_id_signed": False, "notarized": False,
               "third_party_notices_sha256": digest(read_regular(ROOT / "THIRD_PARTY_NOTICES.md")),
               "native_dependencies": {"libfido2": {k: identity[k] for k in ("version", "revision", "source_archive_sha256", "patch_sha256", "static_archive_sha256", "deployment_target")},
                                       **identity["dependencies"]}}
    dmg, app_zip, _ = p.names(context)
    (directory / dmg).write_bytes(b"SYNTHETIC DMG; not Apple signed")
    (directory / app_zip).write_bytes(make_app_zip())
    worker_sha = digest(APP_FILES["Contents/MacOS/fido-worker"][0])
    record_sha = digest(APP_FILES["Contents/Resources/release-worker-identity.json"][0])
    chain = {"D0": "0" * 64, "D1": worker_sha, "D2": "2" * 64, "D3": digest((directory / app_zip).read_bytes()),
             "D4": "4" * 64, "D5": digest((directory / dmg).read_bytes())}
    cdhash = {"fidomanager-app": {"arm64": "e" * 40}, "fido-worker": {"arm64": "f" * 40}}
    notarization = {"stapled": ["app", "dmg"]}
    for name, d in (("app", "D2"), ("dmg", "D4")):
        log = {"jobId": "SYNTHETIC-" + name, "status": "Accepted", "issues": None, "sha256": chain[d],
               "ticketContents": [{"arch": "arm64", "cdhash": h["arm64"]} for h in cdhash.values()]}
        if name == "dmg":
            log["ticketContents"].append({"cdhash": "9" * 40})
        raw = canonical(log)
        (directory / f"notary-{name}.json").write_bytes(raw)
        notarization[name] = {"submission_id": log["jobId"], "status": "Accepted", "log_sha256": digest(raw)}
    manifest = {"schema": "fidomanager.release-manifest/1", "product": "Fido Manager", "version": "0.1.0", "tag": "v0.1.0",
                "source": {"repository": p.REPOSITORY, "commit": commit, "tag_object": context["tag_object_sha"]},
                "build": {"workflow": p.WORKFLOW, "workflow_sha": commit, "run_id": 42, "run_attempt": 1,
                          **{k: "SYNTHETIC" for k in ("runner_image", "macos_sdk", "xcode", "rust", "cargo", "node", "pnpm", "tauri_cli", "tauri", "tauri_build")},
                          "target": "aarch64-apple-darwin", "deployment_target": "11.0", "reproducibility": "traceable"},
                "build_tools": {"cmake": "SYNTHETIC", "pkg-config": "SYNTHETIC"},
                "third_party_notices": {"path": "Contents/Resources/THIRD_PARTY_NOTICES.md", "sha256": summary["third_party_notices_sha256"],
                                        "scope": "native libraries only (libfido2, OpenSSL, libcbor)"},
                "signing": {"team_id": "TESTTEAM01", "identity_sha1": "3" * 40, "authority": "Developer ID Application: Synthetic (TESTTEAM01)",
                            "hardened_runtime": True, "entitlements": {}, "cdhash": cdhash,
                            "worker_publisher_requirement": publisher_requirement("eu.fidomanager.desktop.fido-worker", "TESTTEAM01"),
                            "release_worker_identity": {"sha256": record_sha, "worker_file_sha256": chain["D1"]}, "signer": context["signer"]},
                "notarization": notarization, "digest_chain": chain}
    manifest["build"].update(node="24.21.0", pnpm="10.17.1", tauri_cli="2.12.0", tauri="2.12.0", tauri_build="2.7.0", macos_sdk="SYNTHETIC SDK")
    inputs = {"target": "aarch64-apple-darwin", "cargo_lock_sha256": digest(read_regular(ROOT / "Cargo.lock")),
              "cargo_metadata": {"packages": [{"name": name, "version": "0.1.0", "source": None, "license": "Apache-2.0"} for name in p.EXECUTABLES]},
              "cargo_trees": {name: f"{name} v0.1.0 (/synthetic/build)\n" for name in p.EXECUTABLES},
              "frontend": {"pnpm_lock_sha256": digest(read_regular(ROOT / "pnpm-lock.yaml")),
                           "packages": [{"name": "@tauri-apps/api", "version": "2.12.0", "license": "Apache-2.0 OR MIT"}],
                           "assets": {"index.html": "a" * 64}}}
    system = ["/usr/lib/libz.1.dylib", "/usr/lib/libiconv.2.dylib", "/usr/lib/libSystem.B.dylib",
              "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
              "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"]
    code = {"schema": p.CODE_EVIDENCE_SCHEMA, "stapled": True, "version": context["version"],
            "source_commit": commit, "app_tree": app_tree(), "dmg_sha256": chain["D5"],
            "file_sha256": {"fidomanager-app": digest(APP_FILES["Contents/MacOS/fidomanager-app"][0]), "fido-worker": chain["D1"]},
            "system_dependencies": {"fidomanager-app": ["/usr/lib/libSystem.B.dylib"], "fido-worker": system}, "dmg_cdhash": "9" * 40}
    code.update(team_id="TESTTEAM01", cdhash=cdhash,
                release_identity={"record_sha256": record_sha, "worker_file_sha256": chain["D1"], "cdhash": cdhash["fido-worker"]})
    return context, manifest, inputs, canonical(identity), canonical(summary), code


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.args = fixture(self.directory)
        self.d7 = p.generate(self.directory, *self.args)

    def verify(self, d7=None, context=None):
        c, _, inputs, identity, summary, code = self.args
        return p.verify(self.directory, d7 or self.d7, context or c, inputs, identity, summary, code)

    def rewrite(self, name, mutate):
        path = self.directory / name
        obj = parse_json(path.read_bytes())
        mutate(obj)
        path.write_bytes(canonical(obj))

    def test_roundtrip_and_determinism(self):
        self.assertEqual(self.verify(), self.d7)
        other = self.directory / "other"
        other.mkdir()
        other_args = fixture(other)
        self.assertEqual(p.generate(other, *other_args), self.d7)
        for path in other.iterdir():
            self.assertEqual(path.read_bytes(), (self.directory / path.name).read_bytes())

    def test_acyclic_exact_digest_sets(self):
        auth = p.read_json(self.directory / "release-authorization.json")
        sums = (self.directory / "SHA256SUMS").read_text()
        self.assertEqual(len(sums.splitlines()), 6)
        self.assertNotIn("release-authorization", sums)
        self.assertNotIn("SHA256SUMS", sums)
        self.assertEqual(auth["sha256sums"], p.file_record(self.directory / "SHA256SUMS"))
        self.assertEqual(set(auth["assets"]), set(p.names(self.args[0])) | {"release-manifest.json", "notary-app.json", "notary-dmg.json"})

    def test_each_asset_byte_tamper(self):
        for path in self.directory.iterdir():
            original = path.read_bytes()
            with self.subTest(asset=path.name):
                path.write_bytes(original + b" ")
                with self.assertRaises(CheckError):
                    self.verify()
                path.write_bytes(original)

    def test_external_d7_required(self):
        for d7 in ("", "x" * 64, "A" * 64, "0" * 64):
            with self.subTest(d7=d7), self.assertRaises(CheckError):
                p.verify(self.directory, d7, self.args[0], *self.args[2:])

    def test_wholesale_replacement_does_not_self_authorize(self):
        path = self.directory / "release-authorization.json"
        self.rewrite(path.name, lambda a: a["workflow"].update(run_id=43))
        with self.assertRaisesRegex(CheckError, "D7 mismatch"):
            self.verify()
        with self.assertRaisesRegex(CheckError, "trusted context"):
            self.verify(digest(path.read_bytes()))

    def test_authorization_mutations_even_with_recomputed_digest(self):
        path = self.directory / "release-authorization.json"
        original = path.read_bytes()
        for mutate in (lambda a: a.update(schema="old"), lambda a: a.update(extra=True),
                       lambda a: a["assets"].update({"../escape": {"sha256": "0" * 64, "size": 0}}),
                       lambda a: a["assets"].pop("notary-app.json"), lambda a: a["sha256sums"].update(size=1),
                       lambda a: a["worker_identity"].update(record_sha256="0" * 64),
                       lambda a: a["notarization"].update(app_submission="other")):
            self.rewrite(path.name, mutate)
            with self.assertRaises(CheckError):
                self.verify(digest(path.read_bytes()))
            path.write_bytes(original)

    def test_context_eligibility_mutations(self):
        for mutate in (lambda c: c.update(deployment_target="12.0"), lambda c: c.update(tag="v9.0.0"),
                       lambda c: c["workflow"].update(sha="0" * 40), lambda c: c["workflow"].update(run_attempt=True),
                       lambda c: c["signer"].update(repository=p.REPOSITORY), lambda c: c["eligibility"].update(on_main=False),
                       lambda c: c["eligibility"]["ci"].update(conclusion="pending"),
                       lambda c: c["eligibility"]["ci"]["check_runs"].pop("validation"),
                       lambda c: c["eligibility"]["immutable_releases"].update(enabled=False)):
            context = copy.deepcopy(self.args[0])
            mutate(context)
            with self.assertRaises(CheckError):
                p.validate_context(context)

    def test_manifest_semantics(self):
        path = self.directory / "release-manifest.json"
        original = path.read_bytes()
        for mutate in (lambda m: m["digest_chain"].update(D3="0" * 64),
                       lambda m: m["signing"].update(hardened_runtime=False),
                       lambda m: m["signing"].update(entitlements={"debug": True}),
                       lambda m: m["signing"]["release_worker_identity"].update(worker_file_sha256="0" * 64),
                       lambda m: m["native"]["openssl"].update(version="0"),
                       lambda m: m["build"].update(reproducibility="bit-reproducible"),
                       lambda m: m["build"].update(node="0.0.0"),
                       lambda m: m["notarization"].update(stapled=["app"])):
            self.rewrite(path.name, mutate)
            with self.assertRaises(CheckError):
                self.verify()
            path.write_bytes(original)

    def test_notary_mutations(self):
        original = (self.directory / "notary-app.json").read_bytes()
        evidence = self.args[1]["notarization"]["app"]
        for mutate in (lambda l: l.update(status="Invalid"), lambda l: l.update(issues=[{"severity": "warning"}]),
                       lambda l: l.pop("issues"), lambda l: l.pop("sha256"), lambda l: l.update(sha256="0" * 64),
                       lambda l: l.update(jobId="wrong"), lambda l: l.update(ticketContents=[])):
            obj = parse_json(original)
            mutate(obj)
            data = canonical(obj)
            e = {**evidence, "log_sha256": digest(data)}
            with self.assertRaises(CheckError):
                p.notary_log(data, e, "2" * 64, {("arm64", "e" * 40), ("arm64", "f" * 40)})

    def test_duplicate_json_and_nonfinite(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff'):
            with self.assertRaises(CheckError):
                parse_json(data)

    def test_asset_path_substitution(self):
        path = self.directory / "SHA256SUMS"
        raw = path.read_bytes()
        path.unlink()
        target = self.directory / "outside"
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises(CheckError):
            self.verify()
        path.unlink()
        os.link(target, path)
        target.unlink()  # this now has one link again; add a second name outside the asset set
        other = Path(self.temp.name).parent / (Path(self.temp.name).name + "-hardlink")
        os.link(path, other)
        self.addCleanup(other.unlink)
        with self.assertRaises(CheckError):
            self.verify()

    def test_extra_and_missing_assets(self):
        extra = self.directory / "release-attestations.sigstore.jsonl"
        extra.write_bytes(b"not a real attestation")
        with self.assertRaisesRegex(CheckError, "unexpected or missing"):
            self.verify()
        extra.unlink()
        (self.directory / "notary-app.json").unlink()
        with self.assertRaises(CheckError):
            self.verify()

    def test_sbom_is_per_executable_with_native_and_external_systems(self):
        bom = p.read_json(self.directory / p.names(self.args[0])[2])
        deps = {item["ref"]: item["dependsOn"] for item in bom["dependencies"]}
        self.assertIn("native:openssl", deps["fido-worker"])
        self.assertNotIn("native:openssl", deps["fidomanager-app"])
        self.assertIn("npm:@tauri-apps/api@2.12.0", deps["fidomanager-app"])
        self.assertNotIn("npm:@tauri-apps/api@2.12.0", deps["fido-worker"])
        for item in bom["components"]:
            if item["bom-ref"].startswith("system:"):
                self.assertEqual(item["scope"], "excluded")
                self.assertNotIn("version", item)

    def test_sbom_inputs_reject_wrong_locks_and_unbundled_invention(self):
        native = p.native_metadata(self.args[3], self.args[4], "arm64")
        for mutate in (lambda i: i.update(cargo_lock_sha256="0" * 64),
                       lambda i: i["frontend"].update(pnpm_lock_sha256="0" * 64),
                       lambda i: i["frontend"]["packages"][0].update(version="9.9.9"),
                       lambda i: i["cargo_trees"].update({"fido-worker": ""}),
                       lambda i: i["cargo_metadata"]["packages"].append(i["cargo_metadata"]["packages"][0])):
            inputs = copy.deepcopy(self.args[2])
            mutate(inputs)
            with self.assertRaises(CheckError):
                p.sbom(inputs, native, self.args[0], self.args[5])

    def test_native_pins_and_package_summary(self):
        for field, value in (("fuzz", True), ("patch_sha256", "0" * 64), ("static_archive_sha256", "x")):
            identity = parse_json(self.args[3])
            identity[field] = value
            with self.assertRaises(CheckError):
                p.native_metadata(canonical(identity), self.args[4], "arm64")
        summary = parse_json(self.args[4])
        summary["notarized"] = True
        with self.assertRaises(CheckError):
            p.native_metadata(self.args[3], canonical(summary), "arm64")

    @unittest.skipUnless((ROOT / "target/macos-package/sbom-inputs.json").exists(), "real Build SBOM inputs not collected")
    def test_real_build_inputs_and_frontend_assets(self):
        inputs = p.read_json(ROOT / "target/macos-package/sbom-inputs.json")
        native = p.native_metadata(self.args[3], self.args[4], "arm64")
        bom = p.sbom(inputs, native, self.args[0], self.args[5])
        self.assertGreater(len(bom["components"]), 20)
        for name, expected in inputs["frontend"]["assets"].items():
            self.assertEqual(digest(read_regular(ROOT / "dist" / name)), expected)
        self.assertEqual(set(inputs["frontend"]["assets"]),
                         {path.relative_to(ROOT / "dist").as_posix() for path in (ROOT / "dist").rglob("*") if path.is_file()})

    @unittest.skipUnless((ROOT / "target/macos-package/package-summary.json").exists(), "real package summary not built")
    def test_real_native_build_identity_matches_package(self):
        identities = list((ROOT / "target/aarch64-apple-darwin/release/build").glob("fido-libfido2-*/out/private-libfido2/build-identity.json"))
        self.assertEqual(len(identities), 1)
        result = p.native_metadata(read_regular(identities[0]), read_regular(ROOT / "target/macos-package/package-summary.json"), "arm64")
        self.assertEqual(result["libfido2"]["version"], "1.17.0")

    def test_consistent_forged_sbom_and_checksums_still_rejected(self):
        # Even an externally pinned record must satisfy the inventory contract against Build inputs.
        name = p.names(self.args[0])[2]
        self.rewrite(name, lambda b: b.update(components=[]))
        auth_path = self.directory / "release-authorization.json"
        auth = p.read_json(auth_path)
        auth["assets"][name] = p.file_record(self.directory / name)
        self.rewrite("release-manifest.json", lambda m: m["sbom"].update(sha256=auth["assets"][name]["sha256"]))
        auth["assets"]["release-manifest.json"] = p.file_record(self.directory / "release-manifest.json")
        (self.directory / "SHA256SUMS").write_bytes(p.checksums(auth["assets"]))
        auth["sha256sums"] = p.file_record(self.directory / "SHA256SUMS")
        auth_path.write_bytes(canonical(auth))
        with self.assertRaisesRegex(CheckError, "content/consistency"):
            self.verify(digest(auth_path.read_bytes()))

    def test_final_asset_set_keeps_attestation_outside_hash_graph(self):
        attestation = self.directory / "release-attestations.sigstore.jsonl"
        attestation.write_bytes(b"SYNTHETIC opaque attestation; not authenticated by this tool")
        p.verify(self.directory, self.d7, self.args[0], *self.args[2:], with_attestation=True)
        self.assertNotIn(attestation.name, (self.directory / "SHA256SUMS").read_text())
        attestation.unlink()
        with self.assertRaises(CheckError):
            p.verify(self.directory, self.d7, self.args[0], *self.args[2:], with_attestation=True)

    def test_generation_rolls_back_after_partial_promotion(self):
        staging_input = self.directory / "rollback"
        staging_input.mkdir()
        arguments = fixture(staging_input)
        initial = {path.name for path in staging_input.iterdir()}
        actual_link = os.link
        calls = 0

        def fail_second_link(source, destination):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic second artifact failure")
            return actual_link(source, destination)

        with patch.object(p.os, "link", side_effect=fail_second_link):
            with self.assertRaisesRegex(OSError, "synthetic second artifact failure"):
                p.generate(staging_input, *arguments)
        self.assertEqual({path.name for path in staging_input.iterdir()}, initial)

    def code_with(self, mutate):
        code = copy.deepcopy(self.args[5])
        mutate(code)
        return code

    def test_code_evidence_bound_to_trusted_context_and_payloads(self):
        # Every case is evidence a stale, unstapled or mismatched checker run could produce.
        for label, mutate, message in (
                ("unstapled", lambda c: c.update(stapled=False), "stapled verification"),
                ("stapled not boolean", lambda c: c.update(stapled="true"), "stapled verification"),
                ("other version", lambda c: c.update(version="0.0.9"), "different release version"),
                ("other commit", lambda c: c.update(source_commit="c" * 40), "different release version or source commit"),
                ("stale schema", lambda c: c.update(schema="fidomanager.code-evidence/0"), "schema"),
                ("missing field", lambda c: c.pop("dmg_sha256"), "incorrect fields"),
                ("other DMG", lambda c: c.update(dmg_sha256="0" * 64), r"\(D5\)"),
                ("absent DMG digest", lambda c: c.update(dmg_sha256=None), r"\(D5\)"),
                ("app tree without ticket", lambda c: c["app_tree"]["files"].pop("Contents/CodeResources"), "not stapled"),
                ("app tree other worker", lambda c: c["app_tree"]["files"]["Contents/MacOS/fido-worker"].update(sha256="0" * 64),
                 "checked executables"),
                ("app tree other record", lambda c: c["app_tree"]["files"]["Contents/Resources/release-worker-identity.json"].update(sha256="0" * 64),
                 "release identity record"),
                ("app tree other resource", lambda c: c["app_tree"]["files"]["Contents/Info.plist"].update(sha256="0" * 64),
                 r"\(D3\)"),
                ("app tree other mode", lambda c: c["app_tree"]["files"]["Contents/Info.plist"].update(mode=0o755), r"\(D3\)"),
                ("app tree extra directory", lambda c: c["app_tree"].update(directories=sorted(APP_DIRECTORIES + ["Contents/Extra"])),
                 r"\(D3\)")):
            with self.subTest(label), self.assertRaisesRegex(CheckError, message):
                c, _, inputs, identity, summary, _ = self.args
                p.verify(self.directory, self.d7, c, inputs, identity, summary, self.code_with(mutate))

    def test_generate_rejects_unbound_evidence(self):
        directory = self.directory / "fresh"
        directory.mkdir()
        context, manifest, inputs, identity, summary, code = fixture(directory)
        code["stapled"] = False
        with self.assertRaisesRegex(CheckError, "stapled"):
            p.generate(directory, context, manifest, inputs, identity, summary, code)
        self.assertEqual({path.name for path in directory.iterdir()},
                         set(p.names(context)[:2]) | {"notary-app.json", "notary-dmg.json"})

    def test_context_version_must_match_reviewed_checkout(self):
        context = copy.deepcopy(self.args[0])
        context.update(version="9.9.9", tag="v9.9.9")
        context["workflow"]["ref"] = f"{p.REPOSITORY}/{p.WORKFLOW}@refs/tags/v9.9.9"
        with self.assertRaisesRegex(CheckError, "reviewed checkout"):
            p.validate_context(context)

    def assert_zip_rejected(self, data, message):
        with self.assertRaisesRegex(CheckError, message):
            p.check_code_evidence(self.args[5], self.args[0], data, self.args[5]["dmg_sha256"])

    def test_app_zip_positive_shapes(self):
        p.check_code_evidence(self.args[5], self.args[0], make_app_zip(), self.args[5]["dmg_sha256"])
        p.check_code_evidence(self.args[5], self.args[0], make_app_zip(directories=False), self.args[5]["dmg_sha256"])

        class Unseekable(io.RawIOBase):  # forces ZIP data descriptors, as streaming archivers write
            def __init__(self):
                self.data = bytearray()
            def writable(self):
                return True
            def write(self, chunk):
                self.data += chunk
                return len(chunk)
        stream = Unseekable()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, (data, mode) in APP_FILES.items():
                info = zipfile.ZipInfo(f"{p.APP_NAME}/{name}", (2026, 10, 1, 0, 0, 0))
                info.create_system, info.external_attr, info.compress_type = 3, (stat.S_IFREG | mode) << 16, zipfile.ZIP_DEFLATED
                with archive.open(info, "w") as member:
                    member.write(data)
        data = bytes(stream.data)
        self.assertTrue(data[6] & 0x08, "fixture must use a data descriptor")
        p.check_code_evidence(self.args[5], self.args[0], data, self.args[5]["dmg_sha256"])

    def test_app_zip_content_rejections(self):
        tampered = dict(APP_FILES, **{"Contents/Info.plist": (b"SYNTHETIC other plist", 0o644)})
        missing = {k: v for k, v in APP_FILES.items() if k != "Contents/Resources/THIRD_PARTY_NOTICES.md"}
        prefix = p.APP_NAME + "/"
        for label, data in (
                ("tampered file", make_app_zip(tampered)),
                ("missing file", make_app_zip(missing)),
                ("extra file", make_app_zip(extra=[(prefix + "Contents/Resources/extra", b"x", stat.S_IFREG | 0o644)])),
                ("mode change", make_app_zip(mode_override={"Contents/Info.plist": 0o755})),
                ("extra empty directory", make_app_zip(extra=[(prefix + "Contents/Extra/", b"", stat.S_IFDIR | 0o755)]))):
            with self.subTest(label):
                self.assert_zip_rejected(data, r"\(D3\)")
        for label, extra, message in (
                ("symlink", (prefix + "Contents/Resources/link", b"/etc/passwd", stat.S_IFLNK | 0o777), "not a regular file"),
                ("fifo", (prefix + "Contents/Resources/fifo", b"", stat.S_IFIFO | 0o644), "not a regular file"),
                ("setuid", (prefix + "Contents/Resources/suid", b"x", stat.S_IFREG | stat.S_ISUID | 0o755), "setuid"),
                ("traversal", (prefix + "Contents/../../escape", b"x", stat.S_IFREG | 0o644), "unsafe ZIP entry path"),
                ("absolute", ("/tmp/escape", b"x", stat.S_IFREG | 0o644), "unsafe ZIP entry name"),
                ("backslash", (prefix + "Contents\\x", b"x", stat.S_IFREG | 0o644), "unsafe ZIP entry name"),
                ("outside app", ("Other.app/Contents/x", b"x", stat.S_IFREG | 0o644), "outside the app"),
                ("AppleDouble sequester", ("__MACOSX/" + prefix + "._Contents", b"x", stat.S_IFREG | 0o644), "outside the app"),
                ("AppleDouble side file", (prefix + "Contents/._Info.plist", b"x", stat.S_IFREG | 0o644), r"\(D3\)"),
                ("case collision", (prefix + "Contents/info.plist", b"x", stat.S_IFREG | 0o644), "colliding"),
                ("directory file type", (prefix + "Contents/Resources/dir/", b"", stat.S_IFREG | 0o644), "not a directory")):
            with self.subTest(label):
                self.assert_zip_rejected(make_app_zip(extra=[extra]), message)

    @staticmethod
    def insert_hidden_bytes(data, at, junk=b"HIDDEN"):
        """Insert bytes at `at` and repair every offset so only the gap itself is abnormal."""
        eocd = len(data) - 22
        cd_offset = int.from_bytes(data[eocd + 16:eocd + 20], "little")
        out = bytearray(data[:at] + junk + data[at:])
        shift = lambda value: value + len(junk) if value >= at else value
        cd = shift(cd_offset)
        position = cd
        while out[position:position + 4] == b"PK\x01\x02":
            local = int.from_bytes(out[position + 42:position + 46], "little")
            out[position + 42:position + 46] = shift(local).to_bytes(4, "little")
            lengths = sum(int.from_bytes(out[position + k:position + k + 2], "little") for k in (28, 30, 32))
            position += 46 + lengths
        out[-6:-2] = cd.to_bytes(4, "little")
        return bytes(out)

    def test_app_zip_hidden_bytes_rejected(self):
        good = make_app_zip()
        second = good.index(b"PK\x03\x04", 4)
        central = good.index(b"PK\x01\x02")
        for label, at in (("between entries", second), ("before central directory", central)):
            with self.subTest(label):
                self.assert_zip_rejected(self.insert_hidden_bytes(good, at), "contiguous|unaccounted")
        # Sanity: the repair itself is correct when the gap is empty.
        p.check_code_evidence(self.args[5], self.args[0], self.insert_hidden_bytes(good, central, b""), self.args[5]["dmg_sha256"])

    def test_app_zip_unicode_normalization_collision(self):
        prefix = p.APP_NAME + "/Contents/Resources/"
        extra = [(prefix + "caf\u00e9", b"x", stat.S_IFREG | 0o644), (prefix + "cafe\u0301", b"y", stat.S_IFREG | 0o644)]
        self.assert_zip_rejected(make_app_zip(extra=extra), "colliding")

    def test_app_zip_structure_rejections(self):
        good = make_app_zip()
        commented = io.BytesIO(good)
        with zipfile.ZipFile(commented, "a") as archive:
            archive.comment = b"hidden"
        nonunix = io.BytesIO()
        with zipfile.ZipFile(nonunix, "w") as archive:
            info = zipfile.ZipInfo(p.APP_NAME + "/Contents/Info.plist")
            info.create_system, info.external_attr = 0, 0
            archive.writestr(info, b"x")
        first_central = good.index(b"PK\x01\x02")
        encrypted = bytearray(good)
        encrypted[first_central + 8] |= 0x01
        encrypted[6] |= 0x01
        mismatched_name = bytearray(good)
        mismatched_name[30] ^= 0x20  # local name differs from central name
        corrupt = bytearray(good)
        last_file = good.rindex(b"PK\x03\x04")
        corrupt[last_file + 30 + int.from_bytes(good[last_file + 26:last_file + 28], "little") + 2] ^= 0xFF
        for label, data, message in (
                ("trailing data", good + b"junk", "end record"),
                ("prepended data", b"MZ" + good, "contiguous|central directory"),
                ("comment", commented.getvalue(), "end record|comment"),
                ("non-Unix attributes", nonunix.getvalue(), "Unix attributes"),
                ("encrypted", bytes(encrypted), "encrypted"),
                ("local/central name mismatch", bytes(mismatched_name), "name mismatch"),
                ("corrupt deflate", bytes(corrupt), "corrupt|CRC|trailing|truncated"),
                ("empty", b"", "end record")):
            with self.subTest(label):
                self.assert_zip_rejected(data, message)

    def test_no_overwrite(self):
        before = (self.directory / "release-authorization.json").read_bytes()
        with self.assertRaises(CheckError):
            p.generate(self.directory, *self.args)
        self.assertEqual(before, (self.directory / "release-authorization.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
