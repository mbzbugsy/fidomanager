#!/usr/bin/env python3
"""Synthetic policy tests. Mocked codesign/stapler output is NOT genuine Apple signing evidence."""
import copy
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import shutil
import tempfile
import unittest
from unittest.mock import patch

from release_metadata import canonical, digest, CheckError, publisher_requirement

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("checker", ROOT / "scripts/check-macos-bundle.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
TEAM, COMMIT, VERSION = "TESTTEAM01", "a" * 40, "0.1.0"


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name) / "Fido Manager.app"
        for directory in ("MacOS", "Resources", "_CodeSignature"):
            (self.app / "Contents" / directory).mkdir(parents=True)
        self.main = self.app / "Contents/MacOS/fidomanager-app"
        self.worker = self.app / "Contents/MacOS/fido-worker"
        self.marker = f'{c.MARKER.decode()}1;team={TEAM};version={VERSION};commit={COMMIT};end'.encode()
        self.main.write_bytes(c.MACH_O_MAGIC[0] + self.marker)
        self.worker.write_bytes(c.MACH_O_MAGIC[0] + f'{VERSION}+{COMMIT}'.encode())
        self.worker.chmod(0o755)
        self.main.chmod(0o755)
        for name, source in (("icon.icns", ROOT / "src-tauri/icons/icon.icns"), (c.NOTICES, ROOT / c.NOTICES)):
            (self.app / "Contents/Resources" / name).write_bytes(source.read_bytes())
        (self.app / "Contents/_CodeSignature/CodeResources").write_bytes(b"synthetic seal")
        self.record = {"schema": "fidomanager.release-worker-identity/1", "release": {"version": VERSION, "source_commit": COMMIT},
                       "worker": {"path": "Contents/MacOS/fido-worker", "identifier": c.WORKER_IDENTIFIER, "team_id": TEAM,
                                  "build_id": f"{VERSION}+{COMMIT}", "file_sha256": digest(self.worker.read_bytes()),
                                  "slices": [{"arch": "arm64", "cdhash": "b" * 40, "cdhash_sha256": "b" * 64}]}}
        self.info = {"CFBundleIdentifier": c.BUNDLE_ID, "CFBundleName": c.PRODUCT_NAME,
                     "CFBundleDisplayName": c.PRODUCT_NAME, "CFBundlePackageType": "APPL",
                     "CFBundleExecutable": c.MAIN_EXECUTABLE, "CFBundleShortVersionString": VERSION,
                     "CFBundleVersion": VERSION, "CFBundleIconFile": "icon.icns", "LSMinimumSystemVersion": "11.0"}
        self.fields = {"Authority": [f"Developer ID Application: Synthetic Test ({TEAM})", "Developer ID Certification Authority", "Apple Root CA"],
                       "TeamIdentifier": [TEAM], "Timestamp": ["Oct 8, 2026 at 12:00:00"],
                       "CodeDirectory v": ["20500 size=123 flags=0x10000(runtime)"],
                       "CDHash": ["b" * 40], "CandidateCDHashFull sha256": ["b" * 64]}
        self.write_record()

    @property
    def record_path(self):
        return self.app / "Contents/Resources/release-worker-identity.json"

    def write_record(self, data=None):
        raw = canonical(self.record) if data is None else data
        self.record_path.write_bytes(raw)
        self.info[c.RID_KEY] = digest(raw)
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps(self.info))

    def identity(self):
        with patch.object(c, "signature", return_value=self.fields), patch.object(c, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            result = c.check_release_identity(self.app, self.main, self.worker, self.info, VERSION, COMMIT, TEAM, "arm64")
            self.assertIn('and cdhash H"' + 'b' * 40 + '"', run.call_args.args[0][-2])
            return result

    def test_positive_unstapled_and_stapled(self):
        c.check_tree(self.app, "developer-id")
        self.identity()
        (self.app / "Contents/CodeResources").write_bytes(b"synthetic ticket")
        c.check_tree(self.app, "developer-id", True)
        with self.assertRaisesRegex(CheckError, "unexpected bundle entry"):
            c.check_tree(self.app, "developer-id")

    def test_missing_or_malformed_staple_tree(self):
        with self.assertRaisesRegex(CheckError, "ticket missing"):
            c.check_tree(self.app, "developer-id", True)
        (self.app / "Contents/CodeResources").mkdir()
        with self.assertRaises(CheckError):
            c.check_tree(self.app, "developer-id", True)

    def test_signature_mutations(self):
        c.check_developer_signature(self.fields, TEAM, "fixture")
        for key, value in (("TeamIdentifier", ["OTHERTEAM1"]), ("Authority", self.fields["Authority"][:1]),
                           ("Authority", ["Apple Development: Test", *self.fields["Authority"][1:]]),
                           ("Timestamp", []), ("Timestamp", [""]), ("Timestamp", ["none"]), ("Timestamp", ["garbage"]),
                           ("Timestamp", ["one", "two"]), ("Signed Time", ["today"]), ("Signature", ["adhoc"])):
            with self.subTest(key=key, value=value):
                fields = {**self.fields, key: value}
                with self.assertRaises(CheckError):
                    c.check_developer_signature(fields, TEAM, "fixture")
        fields = {k: v for k, v in self.fields.items() if k != "Timestamp"}
        fields["Signed Time"] = ["Oct 8, 2026"]
        with self.assertRaisesRegex(CheckError, "no secure timestamp"):
            c.check_developer_signature(fields, TEAM, "fixture")

    def test_designated_requirement_parser(self):
        good = publisher_requirement(c.WORKER_IDENTIFIER, TEAM)
        common = f'identifier "{c.WORKER_IDENTIFIER}" and anchor apple generic'
        dev = f'certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = {TEAM}'
        for text in (good, common + " and (" + dev + ")", common + " and (certificate leaf[field.1.2.840.113635.100.6.1.9] or " + dev + ")"):
            with patch.object(c, "run", return_value=subprocess.CompletedProcess([], 0, "designated => " + text, "")):
                c.check_designated_requirement(self.worker, c.WORKER_IDENTIFIER, TEAM)
        for text in (good.replace(TEAM, "OTHERTEAM1"), good.replace("fido-worker", "other"), good + " or anchor apple generic",
                     good.replace(" and certificate 1[field.1.2.840.113635.100.6.2.6]", ""), good + " garbage",
                     '(' + good, good + '\ndesignated => ' + good):
            with self.subTest(requirement=text), patch.object(c, "run", return_value=subprocess.CompletedProcess([], 0, "designated => " + text, "")):
                with self.assertRaises(CheckError):
                    c.check_designated_requirement(self.worker, c.WORKER_IDENTIFIER, TEAM)

    # Representative of `codesign -d -r-` output shape (TN3127): existence tests are printed as
    # `/* exists */` comments and "Executable=" goes to stderr. Synthetic Team ID; not a real signature.
    REAL_DEVELOPER_ID_DR = ('designated => identifier "{id}" and anchor apple generic and '
                            'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
                            'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and '
                            'certificate leaf[subject.OU] = {team}')
    REAL_DEFAULT_DR = ('designated => anchor apple generic and identifier "{id}" and '
                       '(certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or '
                       'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
                       'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and '
                       'certificate leaf[subject.OU] = {team})')

    def check_dr(self, stdout, identifier=None):
        identifier = identifier or c.WORKER_IDENTIFIER
        stderr = "Executable=/private/var/folders/x/Fido Manager.app/Contents/MacOS/fido-worker\n"
        with patch.object(c, "run", return_value=subprocess.CompletedProcess([], 0, stdout + "\n", stderr)):
            return c.check_designated_requirement(self.worker, identifier, TEAM)

    def test_real_codesign_designated_requirement_syntax(self):
        for template in (self.REAL_DEVELOPER_ID_DR, self.REAL_DEFAULT_DR):
            self.check_dr(template.format(id=c.WORKER_IDENTIFIER, team=TEAM))
            self.check_dr(template.format(id=c.BUNDLE_ID, team=TEAM), c.BUNDLE_ID)
            self.check_dr(template.format(id=c.BUNDLE_ID + ".dmg", team=TEAM), c.BUNDLE_ID + ".dmg")
        real = self.REAL_DEFAULT_DR.format(id=c.WORKER_IDENTIFIER, team=TEAM)
        dev = self.REAL_DEVELOPER_ID_DR.format(id=c.WORKER_IDENTIFIER, team=TEAM)
        for label, text in (
                ("weakening OR", real + " or anchor apple generic"),
                ("weakening OR inside group", real.replace("(certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or ",
                                                           "(anchor apple or certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or ")),
                ("store-only", real.replace(" or certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and "
                                            "certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and "
                                            f"certificate leaf[subject.OU] = {TEAM}", "")),
                ("other Team ID", real.replace(TEAM, "OTHERTEAM1")),
                ("other identifier", real.replace("fido-worker", "other")),
                ("missing Developer ID CA", dev.replace("certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and ", "")),
                ("missing Developer ID leaf", dev.replace("certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and ", "")),
                ("other comment", dev.replace("/* exists */", "/* anything */", 1)),
                ("comment hides clause", dev.replace("/* exists */", "/* exists */ /* or anchor apple generic */", 1)),
                ("unterminated comment", dev.replace("/* exists */", "/* exists", 1)),
                ("negation", dev.replace("anchor apple generic", "! anchor apple generic")),
                ("second designated line", dev + "\n" + dev)):
            with self.subTest(label), self.assertRaises(CheckError):
                self.check_dr(text)

    def test_signature_validation_uses_strict_tools(self):
        for failure in (None, "explicit", "deep", "runtime", "entitlement", "identifier", "no-plist-binding", "no-sealed-resources"):
            commands = []
            def run(command):
                commands.append(command)
                target = Path(command[-1])
                identifier = c.WORKER_IDENTIFIER if target == self.worker else c.BUNDLE_ID
                result = subprocess.CompletedProcess(command, 0, "", "")
                if "--verify" in command:
                    if (failure == "explicit" and any(arg.startswith("-R=") for arg in command)) or (failure == "deep" and "--deep" in command):
                        result.returncode = 1
                    return result
                if "-r-" in command:
                    result.stdout = "designated => " + publisher_requirement(identifier, TEAM)
                elif "--entitlements" in command:
                    if failure == "entitlement":
                        result.stdout = plistlib.dumps({"debug": True}).decode()
                else:
                    fields = {**self.fields, "Identifier": [identifier]}
                    if failure == "runtime":
                        fields["CodeDirectory v"] = ["20500 flags=0x0(none)"]
                    if failure == "identifier":
                        fields["Identifier"] = ["other"]
                    result.stderr = "\n".join(key + "=" + value for key, values in fields.items() for value in values)
                    if failure != "no-sealed-resources":
                        result.stderr += "\nSealed Resources version=2 rules=13 files=3"
                    if failure != "no-plist-binding":
                        result.stderr += "\nInfo.plist entries=10"
                    result.stderr += "\n"
                return result
            with self.subTest(failure=failure), patch.object(c, "run", side_effect=run):
                if failure:
                    message = {"no-plist-binding": "Info.plist is not bound", "no-sealed-resources": "not sealed"}.get(failure, "")
                    with self.assertRaisesRegex(CheckError, message):
                        c.check_signatures(self.app, self.main, self.worker, "developer-id", TEAM)
                else:
                    c.check_signatures(self.app, self.main, self.worker, "developer-id", TEAM)
                    self.assertTrue(any("--strict" in cmd and "--deep" in cmd for cmd in commands))
                    self.assertEqual(sum(any(arg.startswith("-R=") for arg in cmd) for cmd in commands), 2)

    def test_identity_schema_mutations(self):
        original = copy.deepcopy(self.record)
        for mutate in (lambda r: r.update(extra=1), lambda r: r.update(schema="other"),
                       lambda r: r["release"].update(source_commit="c" * 40),
                       lambda r: r["worker"].update(team_id="OTHERTEAM1"),
                       lambda r: r["worker"].update(build_id="old"),
                       lambda r: r["worker"].update(file_sha256="0" * 64),
                       lambda r: r["worker"].update(slices=[]),
                       lambda r: r["worker"]["slices"][0].update(cdhash="c" * 40, cdhash_sha256="c" * 64),
                       lambda r: r["worker"]["slices"][0].update(cdhash_sha256="b" * 40 + "c" * 24),
                       lambda r: r["worker"]["slices"][0].update(arch="x86_64")):
            self.record = copy.deepcopy(original)
            mutate(self.record)
            self.write_record()
            with self.assertRaises(CheckError):
                self.identity()
        for raw in (b"{}", b"{", b'\xff', b'{"schema":1,"schema":2}', b' ' * 4097, b'{"x":NaN}'):
            self.write_record(raw)
            with self.assertRaises(CheckError):
                self.identity()

    def test_record_bytes_not_reserialized(self):
        self.record_path.write_bytes(self.record_path.read_bytes() + b" ")
        with self.assertRaisesRegex(CheckError, "digest differs"):
            self.identity()

    def test_missing_record_or_digest(self):
        for value in (None, 0, "A" * 64, "0" * 63):
            self.info[c.RID_KEY] = value
            with self.assertRaisesRegex(CheckError, "malformed"):
                self.identity()
        self.write_record()
        self.record_path.unlink()
        with self.assertRaises(CheckError):
            self.identity()

    def test_marker_and_worker_build_id(self):
        for marker in (b"", self.marker.replace(TEAM.encode(), b"OTHERTEAM1"), self.marker[:-1], self.marker + self.marker,
                       self.marker.replace(COMMIT.encode(), b"c" * 40), self.marker.replace(b"version=0.1.0", b"version=9.0.0")):
            self.main.write_bytes(c.MACH_O_MAGIC[0] + marker)
            with self.assertRaisesRegex(CheckError, "marker"):
                self.identity()
        self.main.write_bytes(c.MACH_O_MAGIC[0] + self.marker)
        self.worker.write_bytes(c.MACH_O_MAGIC[0])
        self.record["worker"]["file_sha256"] = digest(self.worker.read_bytes())
        self.write_record()
        with self.assertRaisesRegex(CheckError, "compiled build identity"):
            self.identity()

    def test_tree_extra_symlink_and_special(self):
        extra = self.app / "Contents/Resources/extra"
        for create in (lambda: extra.write_bytes(b""), lambda: extra.mkdir(), lambda: extra.symlink_to(self.worker)):
            create()
            with self.assertRaises(CheckError):
                c.check_tree(self.app, "developer-id")
            if extra.is_dir() and not extra.is_symlink():
                extra.rmdir()
            else:
                extra.unlink()
        self.record_path.unlink()
        self.record_path.symlink_to(self.worker)
        with self.assertRaises(CheckError):
            c.check_tree(self.app, "developer-id")
        with self.assertRaises(CheckError):
            self.identity()

    def test_adhoc_rejects_release_metadata(self):
        with self.assertRaises(CheckError):
            c.check_tree(self.app)
        self.record_path.unlink()
        c.check_tree(self.app)
        (self.app / "Contents/CodeResources").write_bytes(b"ticket")
        with self.assertRaises(CheckError):
            c.check_tree(self.app)

    def test_invalid_metadata_never_executes_worker(self):
        with patch.object(c, "check_worker_runtime") as execute, patch.object(c, "check_linkage", return_value=("arm64", "11.0")), \
                patch.object(c, "check_symbols"), patch.object(c, "check_signatures"):
            self.info[c.RID_KEY] = "0" * 64
            (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps(self.info))
            with self.assertRaises(CheckError):
                c.check(self.app, signature_mode="developer-id", expected_version=VERSION,
                        expected_team_id=TEAM, expected_commit=COMMIT)
            execute.assert_not_called()

    def test_pre_staple_cdhash_binding_before_execution(self):
        (self.app / "Contents/CodeResources").write_bytes(b"SYNTHETIC ticket")
        with patch.object(c, "check_linkage", return_value=("arm64", "11.0")), patch.object(c, "check_symbols"), \
                patch.object(c, "check_signatures"), patch.object(c, "signature", return_value=self.fields), \
                patch.object(c, "check_requirement"), patch.object(c, "check_staple"), \
                patch.object(c, "dependencies", return_value=[]), patch.object(c, "check_worker_runtime") as execute:
            arguments = dict(signature_mode="developer-id", expected_version=VERSION, expected_team_id=TEAM,
                             expected_commit=COMMIT, stapled=True, execute_worker=False)
            evidence = {name: {"arm64": "b" * 40} for name in ("fidomanager-app", "fido-worker")}
            c.check(self.app, **arguments, pre_staple_cdhashes=evidence)
            for bad in (None, {}, {**evidence, "fidomanager-app": {"arm64": "c" * 40}}):
                with self.assertRaises(CheckError):
                    c.check(self.app, **arguments, pre_staple_cdhashes=bad)
            execute.assert_not_called()

    def release_check(self, dmg, evidence, dmg_check=None):
        (self.app / "Contents/CodeResources").write_bytes(b"SYNTHETIC ticket")
        with patch.object(c, "check_linkage", return_value=("arm64", "11.0")), patch.object(c, "check_symbols"), \
                patch.object(c, "check_signatures"), patch.object(c, "signature", return_value=self.fields), \
                patch.object(c, "check_requirement"), patch.object(c, "check_staple"), \
                patch.object(c, "dependencies", return_value=[]), patch.object(c, "check_worker_runtime") as execute, \
                patch.object(c, "check_dmg", side_effect=dmg_check) as checked_dmg:
            try:
                return c.check(self.app, signature_mode="developer-id", expected_version=VERSION, expected_team_id=TEAM,
                               expected_commit=COMMIT, stapled=True, execute_worker=False, dmg=dmg,
                               pre_staple_cdhashes=evidence), checked_dmg
            finally:
                execute.assert_not_called()

    def test_dmg_cdhash_changed_after_stapling(self):
        dmg = Path(self.temp.name) / "FidoManager-0.1.0-arm64.dmg"
        dmg.write_bytes(b"SYNTHETIC DMG")
        evidence = {name: {"arm64": "b" * 40} for name in ("fidomanager-app", "fido-worker")}
        for bad in ({**evidence, "dmg": "c" * 40}, {**evidence, "dmg": "B" * 40}, evidence):
            with self.subTest(evidence=bad), self.assertRaises(CheckError) as caught:
                self.release_check(dmg, bad)
            if "dmg" in bad:
                self.assertIn("DMG cdhash changed after stapling", str(caught.exception))

    def test_code_evidence_binds_exact_checked_dmg_release_and_app_tree(self):
        dmg = Path(self.temp.name) / "FidoManager-0.1.0-arm64.dmg"
        original = b"SYNTHETIC DMG bytes"
        dmg.write_bytes(original)
        seen = []

        def capture(path, app, team, stapled):
            seen.append(path)
            self.assertNotEqual(path, dmg)
            self.assertEqual(path.read_bytes(), original)
            self.assertTrue(stapled)
        evidence = {name: {"arm64": "b" * 40} for name in ("fidomanager-app", "fido-worker", "dmg")}
        evidence["dmg"] = "b" * 40
        summary, _ = self.release_check(dmg, evidence, capture)
        code = summary["code_evidence"]
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists(), "private DMG copy must be removed")
        self.assertEqual((code["schema"], code["stapled"], code["version"], code["source_commit"], code["dmg_sha256"]),
                         (c.CODE_EVIDENCE_SCHEMA, True, VERSION, COMMIT, digest(original)))
        self.assertEqual(code["app_tree"], c.app_tree(self.app))
        self.assertIn("Contents/CodeResources", code["app_tree"]["files"])
        self.assertEqual(code["app_tree"]["files"]["Contents/MacOS/fido-worker"]["sha256"], code["file_sha256"]["fido-worker"])

        def mutate(path, app, team, stapled):  # the checked bytes must be the recorded bytes
            path.write_bytes(b"SWAPPED during verification")
        with self.assertRaisesRegex(CheckError, "changed during verification"):
            self.release_check(dmg, evidence, mutate)

    def test_unstapled_evidence_is_marked_unstapled(self):
        with patch.object(c, "check_linkage", return_value=("arm64", "11.0")), patch.object(c, "check_symbols"), \
                patch.object(c, "check_signatures"), patch.object(c, "signature", return_value=self.fields), \
                patch.object(c, "check_requirement"), patch.object(c, "dependencies", return_value=[]):
            summary = c.check(self.app, signature_mode="developer-id", expected_version=VERSION, expected_team_id=TEAM,
                              expected_commit=COMMIT, execute_worker=False)
        self.assertIs(summary["code_evidence"]["stapled"], False)
        self.assertIsNone(summary["code_evidence"]["dmg_sha256"])

    def test_dmg_symlink_input_rejected(self):
        target = Path(self.temp.name) / "real.dmg"
        target.write_bytes(b"SYNTHETIC")
        link = Path(self.temp.name) / "link.dmg"
        link.symlink_to(target)
        with self.assertRaisesRegex(CheckError, "symlink"):
            self.release_check(link, {})

    def test_duplicate_plist_key_rejected(self):
        data = plistlib.dumps(self.info).replace(b"<dict>", b"<dict><key>CFBundleIdentifier</key><string>other</string>", 1)
        (self.app / "Contents/Info.plist").write_bytes(data)
        with self.assertRaisesRegex(CheckError, "duplicate Info.plist"):
            c.check_info(self.app, VERSION)

    def test_dmg_commands_tree_binding_and_cleanup(self):
        dmg = Path(self.temp.name) / "fixture.dmg"
        dmg.write_bytes(b"SYNTHETIC, NOT SIGNED")
        fields = {**self.fields, "Identifier": [c.BUNDLE_ID + ".dmg"]}
        for change in (None, "extra", "different-app", "bad-applications", "empty-dir", "mode"):
            commands = []
            def output(command):
                commands.append(command)
                if command[:2] == ["hdiutil", "imageinfo"]:
                    return plistlib.dumps({"Format": "UDZO"}).decode()
                if command[:2] == ["hdiutil", "attach"]:
                    mount = Path(command[command.index("-mountpoint") + 1])
                    shutil.copytree(self.app, mount / self.app.name)
                    (mount / "Applications").symlink_to("/Applications" if change != "bad-applications" else "/tmp")
                    if change == "extra":
                        (mount / "extra").write_bytes(b"bad")
                    if change == "empty-dir":
                        (mount / self.app.name / "Contents/Resources/Extra").mkdir()
                    if change == "mode":
                        (mount / self.app.name / "Contents/Resources/icon.icns").chmod(0o600)
                    if change == "different-app":
                        (mount / self.app.name / "Contents/Resources/release-worker-identity.json").write_bytes(b"{}")
                return ""
            with patch.object(c, "signature", return_value=fields), patch.object(c, "entitlements", return_value={}), \
                    patch.object(c, "check_requirement"), patch.object(c, "check_designated_requirement"), \
                    patch.object(c, "check_staple") as staple, patch.object(c, "output", side_effect=output):
                if change is None:
                    c.check_dmg(dmg, self.app, TEAM, False)
                    staple.assert_not_called()
                else:
                    with self.assertRaises(CheckError):
                        c.check_dmg(dmg, self.app, TEAM, False)
                self.assertEqual(commands[-1][:2], ["hdiutil", "detach"])
                self.assertIn("-readonly", next(cmd for cmd in commands if cmd[1] == "attach"))

    def test_dmg_stapler_and_gatekeeper_fail_closed(self):
        dmg = Path(self.temp.name) / "FidoManager-0.1.0-arm64.dmg"
        dmg.write_bytes(b"SYNTHETIC")
        valid = subprocess.CompletedProcess([], 0, "The validate action worked!", "")
        with patch.object(c, "run", side_effect=[subprocess.CompletedProcess([], 65, "", "does not have a ticket stapled")]):
            with self.assertRaisesRegex(CheckError, "stapler validation failed"):
                c.check_staple(dmg, TEAM)
        with patch.object(c, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaisesRegex(CheckError, "stapler validation failed"):
                c.check_staple(dmg, TEAM)
        for assessment in ((3, f"{dmg}: rejected\nsource=Unnotarized Developer ID"), (0, f"{dmg}: accepted\nsource=Developer ID"),
                           (0, f"{dmg}: rejected\nsource=Notarized Developer ID"), (1, f"{dmg}: accepted\nsource=Notarized Developer ID")):
            calls = []
            def run(command, assessment=assessment):
                calls.append(command)
                return valid if command[1] == "stapler" else subprocess.CompletedProcess(command, assessment[0], "", assessment[1])
            with self.subTest(assessment=assessment), patch.object(c, "run", side_effect=run):
                with self.assertRaisesRegex(CheckError, "Gatekeeper assessment failed"):
                    c.check_staple(dmg, TEAM)
                self.assertEqual(calls[1][:5], ["spctl", "--assess", "--type", "open", "--context"])
        with patch.object(c, "run", side_effect=[valid, subprocess.CompletedProcess([], 0, "", f"{dmg}: accepted\nsource=Notarized Developer ID")]):
            c.check_staple(dmg, TEAM)

    def test_stapler_and_gatekeeper_fail_closed(self):
        for responses in ((1, "The validate action worked!", ""), (0, "", "")):
            with patch.object(c, "run", return_value=subprocess.CompletedProcess([], *responses)):
                with self.assertRaises(CheckError):
                    c.check_staple(self.app, TEAM)
        valid = subprocess.CompletedProcess([], 0, "The validate action worked!", "")
        for assessment in ("app: rejected\nsource=Notarized Developer ID", "app: accepted\nsource=Developer ID", "app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Other (OTHERTEAM1)"):
            with patch.object(c, "run", side_effect=[valid, subprocess.CompletedProcess([], 0, "", assessment)]):
                with self.assertRaises(CheckError):
                    c.check_staple(self.app, TEAM)
        with patch.object(c, "run", side_effect=[valid, subprocess.CompletedProcess([], 0, "", f'app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Test ({TEAM})')]):
            c.check_staple(self.app, TEAM)


if __name__ == "__main__":
    unittest.main()
