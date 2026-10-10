#!/usr/bin/env python3
"""Credential-free G5 policy/checker/signing command negative controls; no codesign invoked."""
import copy
import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load("policy", "macos-authority-policy.py")
checker = load("main_checker", "check-macos-authority-main.py")
signer = load("signer", "sign-macos-bundle.py")


class PolicyTests(unittest.TestCase):
    def test_reviewed_source_policy(self):
        policy.check_source()

    def test_extra_missing_wrong_or_mistyped_grants(self):
        for store in (False, True):
            valid = copy.deepcopy(policy.STORE_GRANTS if store else policy.DEVELOPER_GRANTS)
            self.assertTrue(policy.exact(valid, store=store))
            invalid = [dict(valid, extra=True), {}, {**valid, policy.GROUP_KEY: ["wrong"]},
                       {**valid, policy.GROUP_KEY: [policy.GROUP, policy.GROUP]},
                       {**valid, policy.GROUP_KEY: policy.GROUP}]
            if store:
                invalid += [{**valid, "com.apple.security.app-sandbox": 1},
                            {**valid, "com.apple.security.device.usb": False}]
            for grants in invalid:
                self.assertFalse(policy.exact(grants, store=store), grants)
        self.assertFalse(policy.exact(policy.STORE_GRANTS))
        self.assertFalse(policy.exact(policy.DEVELOPER_GRANTS, store=True))

    def test_production_main_checker_negatives(self):
        with tempfile.TemporaryDirectory(prefix="g5-checker-") as temporary:
            binary = Path(temporary) / "synthetic"
            binary.write_bytes(policy.MARKER)
            for store in (False, True):
                valid = {"TeamIdentifier": [policy.TEAM], "Identifier": [policy.STORE_ID if store else policy.DEVELOPER_ID],
                         "Authority": ["Apple Distribution: synthetic" if store else "Developer ID Application: synthetic"],
                         "CodeDirectory v": ["runtime"]}
                grants = policy.STORE_GRANTS if store else policy.DEVELOPER_GRANTS
                for key, value in [(None, None), ("TeamIdentifier", ["OTHERTEAM0"]), ("Identifier", ["wrong"]),
                                   ("Authority", ["adhoc"]), ("CodeDirectory v", ["no flags"])]:
                    fields = {**valid, **({key: value} if key else {})}
                    with patch.object(checker.base, "signature", return_value=fields), \
                         patch.object(checker.base, "entitlements", return_value=grants), \
                         patch.object(checker.base, "run") as run:
                        run.return_value.returncode = 0
                        if key:
                            with self.assertRaises(checker.base.CheckError):
                                checker.check(binary, store=store)
                            run.assert_not_called()
                        else:
                            checker.check(binary, store=store)
                            command = run.call_args.args[0]
                            self.assertIn('anchor apple generic', command[-2])
                            self.assertIn(f'identifier "{valid["Identifier"][0]}"', command[-2])
                            self.assertIn(f'subject.OU] = "{policy.TEAM}"', command[-2])
                            run.return_value.returncode = 1
                            with self.assertRaisesRegex(checker.base.CheckError, "verification failed"):
                                checker.check(binary, store=store)
                with patch.object(checker.base, "signature", return_value=valid), \
                     patch.object(checker.base, "entitlements", return_value={**grants, "extra": True}):
                    with self.assertRaises(checker.base.CheckError):
                        checker.check(binary, store=store)

    def test_signer_scopes_group_to_production_main(self):
        with tempfile.TemporaryDirectory(prefix="g5-signer-") as temporary:
            app = Path(temporary) / "Synthetic.app"
            code = app / "Contents/MacOS"
            code.mkdir(parents=True)
            main, worker = code / "fidomanager-app", code / "fido-worker"
            magic = b"\xcf\xfa\xed\xfe"
            worker.write_bytes(magic)
            (app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": policy.DEVELOPER_ID,
                "CFBundleExecutable": main.name}))
            for production in (False, True):
                main.write_bytes(magic + (policy.MARKER if production else b""))
                with patch.object(signer.subprocess, "run") as run:
                    signer.sign(app, f"Developer ID Application: SYNTHETIC ({policy.TEAM})" if production else "-")
                    commands = [call.args[0] for call in run.call_args_list]
                    self.assertNotIn("--entitlements", commands[0])
                    self.assertEqual("--entitlements" in commands[1], production)
                    self.assertEqual(commands[1][-1], str(app.resolve()))
                    if production:
                        self.assertIn(str(policy.DIRECTORY / "developer-id-app.entitlements"), commands[1])
                with patch.object(signer.subprocess, "run") as run:
                    with self.assertRaisesRegex(RuntimeError, "flavor"):
                        signer.sign(app, "-" if production else f"Developer ID Application: SYNTHETIC ({policy.TEAM})")
                    run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
