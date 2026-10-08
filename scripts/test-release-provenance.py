#!/usr/bin/env python3
"""Adversarial deterministic provenance fixtures. All signing/notary/CI claims are SYNTHETIC.

Passing these tests proves local consistency policy, never Apple or GitHub authenticity.
"""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

from release_metadata import canonical, digest, CheckError, parse_json, publisher_requirement, read_regular

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("provenance", ROOT / "scripts/release-provenance.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


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
    (directory / app_zip).write_bytes(b"SYNTHETIC ZIP; not notarized")
    chain = {"D0": "0" * 64, "D1": "1" * 64, "D2": "2" * 64, "D3": digest((directory / app_zip).read_bytes()),
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
                            "release_worker_identity": {"sha256": "6" * 64, "worker_file_sha256": chain["D1"]}, "signer": context["signer"]},
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
    code = {"file_sha256": {"fidomanager-app": "7" * 64, "fido-worker": chain["D1"]},
            "system_dependencies": {"fidomanager-app": ["/usr/lib/libSystem.B.dylib"], "fido-worker": system}, "dmg_cdhash": "9" * 40}
    code.update(team_id="TESTTEAM01", cdhash=cdhash,
                release_identity={"record_sha256": "6" * 64, "worker_file_sha256": chain["D1"], "cdhash": cdhash["fido-worker"]})
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

    def test_no_overwrite(self):
        before = (self.directory / "release-authorization.json").read_bytes()
        with self.assertRaises(CheckError):
            p.generate(self.directory, *self.args)
        self.assertEqual(before, (self.directory / "release-authorization.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
