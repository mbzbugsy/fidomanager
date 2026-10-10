#!/usr/bin/env python3
"""Negative regression controls for the MAS.1 evidence parser; no app/container access."""

import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("mas1", Path(__file__).with_name("test-macos-sandbox-recovery.py"))
mas1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mas1)

GOOD = 'MAS1_EVIDENCE {"event":"kernel","sandboxed":1,"cs_status":0,"cs_flags":65537}\n'
PASSED = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 178 filtered out;\n"


class EvidenceTests(unittest.TestCase):
    def result(self, text, code=0):
        return subprocess.CompletedProcess([], code, text, "")

    def test_empty_filter_is_not_a_pass(self):
        with self.assertRaises(mas1.Failure):
            mas1.validate_success(self.result(GOOD + "test result: ok. 0 passed; 0 failed;"), "reload:dispatch")

    def test_live_process_without_completed_assertions_is_not_a_pass(self):
        with self.assertRaises(mas1.Failure):
            mas1.validate_success(self.result(GOOD), "reload:dispatch")

    def test_unsandboxed_report_is_not_a_pass(self):
        with self.assertRaises(mas1.Failure):
            mas1.validate_success(self.result(GOOD.replace('"sandboxed":1', '"sandboxed":0') + PASSED), "reload:dispatch")

    def test_missing_runtime_or_failed_csops_is_not_a_pass(self):
        for text in (GOOD.replace("65537", "1"), GOOD.replace('"cs_status":0', '"cs_status":-1')):
            with self.subTest(text=text), self.assertRaises(mas1.Failure):
                mas1.validate_success(self.result(text + PASSED), "reload:dispatch")

    def test_failed_process_is_not_a_pass(self):
        with self.assertRaises(mas1.Failure):
            mas1.validate_success(self.result(GOOD + PASSED, 101), "reload:dispatch")

    def test_missing_or_ambiguous_record_is_not_a_pass(self):
        for rows in ([], [{"event": "record"}, {"event": "record"}]):
            with self.subTest(rows=rows), self.assertRaises(mas1.Failure):
                mas1.select(rows, "record")

    def test_actual_single_test_evidence_is_accepted(self):
        self.assertEqual(len(mas1.validate_success(self.result(GOOD + PASSED), "reload:dispatch")), 1)

    def test_credentials_are_refused_before_building(self):
        for variable in ("APPLE_SIGNING_IDENTITY", "APPLE_UNKNOWN_CREDENTIAL", "TAURI_SIGNING_PRIVATE_KEY"):
            with self.subTest(variable=variable), patch.object(mas1.platform, "system", return_value="Darwin"), \
                    patch.dict(mas1.os.environ, {variable: "not-a-real-secret"}, clear=True), \
                    patch.object(mas1, "run") as command, self.assertRaises(mas1.Failure):
                mas1.build()
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
