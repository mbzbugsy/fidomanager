#!/usr/bin/env python3
"""Negative regression controls for the MAS.1 evidence parser; no app/container access."""

import importlib.util
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("mas1", Path(__file__).with_name("test-macos-sandbox-recovery.py"))
mas1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mas1)

GOOD = 'MAS1_EVIDENCE {"event":"kernel","pid":1,"sandboxed":1,"cs_status":0,"cs_flags":65537}\n'
AUTHORITY = {"event": "authority", "case": "dispatch", "initialization": "loaded", "admission": "Barrier",
             "journal_present": True, "phase": "dispatch_capable", "poisoned": False}
RECORD = {"event": "record", "step": "reload:dispatch", "admission": "Barrier"}


def output(rows):
    return "".join("MAS1_EVIDENCE " + json.dumps(row) + "\n" for row in rows)


EVIDENCE = output([AUTHORITY, RECORD])
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
            mas1.validate_success(self.result(GOOD + EVIDENCE + PASSED, 101), "reload:dispatch")

    def test_missing_or_ambiguous_record_is_not_a_pass(self):
        for rows in ([], [{"event": "record"}, {"event": "record"}]):
            with self.subTest(rows=rows), self.assertRaises(mas1.Failure):
                mas1.select(rows, "record")

    def test_actual_single_test_evidence_is_accepted(self):
        self.assertEqual(len(mas1.validate_success(self.result(GOOD + EVIDENCE + PASSED), "reload:dispatch")), 3)

    def test_loaded_barrier_cannot_be_replaced_by_initialization_failure(self):
        bad = dict(AUTHORITY, initialization="unavailable", journal_present=False, phase=None, poisoned=None)
        with self.assertRaises(mas1.Failure):
            mas1.validate_success(self.result(GOOD + output([bad, RECORD]) + PASSED), "reload:dispatch")

    def test_missing_or_wrong_authority_admission_is_not_a_pass(self):
        for rows in ([RECORD], [dict(AUTHORITY, admission="Open"), RECORD],
                     [dict(AUTHORITY, phase=None), RECORD], [AUTHORITY, AUTHORITY, RECORD]):
            with self.subTest(rows=rows), self.assertRaises(mas1.Failure):
                mas1.validate_success(self.result(GOOD + output(rows) + PASSED), "reload:dispatch")

    def test_wrong_record_admission_is_not_a_pass(self):
        with self.assertRaises(mas1.Failure):
            mas1.validate_success(self.result(GOOD + output([AUTHORITY, dict(RECORD, admission="Open")]) + PASSED),
                                 "reload:dispatch")

    def test_negative_matrix_requires_exact_initialization_outcomes(self):
        rows = [{"event": "authority", "case": case, "initialization": init, "admission": admission,
                 "journal_present": init == "loaded", "phase": phase, "poisoned": poisoned}
                for case, (init, admission, phase, poisoned) in mas1.expected_authorities("negative:matrix").items()]
        mas1.validate_admissions(rows, "negative:matrix")
        for case in ("malformed", "permissive-namespace"):
            changed = copy.deepcopy(rows)
            row = next(row for row in changed if row["case"] == case)
            if row["initialization"] == "loaded":
                row.update(initialization="unavailable", journal_present=False, poisoned=None)
            else:
                row.update(initialization="loaded", journal_present=True, poisoned=True)
            with self.subTest(case=case), self.assertRaises(mas1.Failure):
                mas1.validate_admissions(changed, "negative:matrix")

    def test_holding_writer_requires_valid_kernel_and_admission(self):
        rows = [json.loads(GOOD.split("MAS1_EVIDENCE ")[1]), AUTHORITY, dict(RECORD, step="seed:dispatch")]
        mas1.validate_holding(rows, "seed:dispatch", 1)
        for key, value in (("sandboxed", 0), ("cs_status", -1), ("cs_flags", 1), ("pid", 9)):
            changed = copy.deepcopy(rows)
            changed[0][key] = value
            with self.subTest(key=key), self.assertRaises(mas1.Failure):
                mas1.validate_holding(changed, "seed:dispatch", 1)
        with self.assertRaises(mas1.Failure):
            mas1.validate_holding(rows[1:], "seed:dispatch", 1)
        with self.assertRaises(mas1.Failure):
            mas1.validate_holding(rows[:-1], "seed:dispatch", 1)

    def test_inherited_child_requires_separate_valid_kernel_evidence(self):
        kernel = json.loads(GOOD.split("MAS1_EVIDENCE ")[1])
        rows = [kernel, dict(kernel, pid=2),
                dict(AUTHORITY, case="lock", admission="Open", phase=None),
                {"event": "lock-held", "child_pid": 2}, {"event": "child-ready", "pid": 2}]
        mas1.validate_holding(rows, "hold:lock", 1)
        for key, value in (("sandboxed", 0), ("cs_status", -1), ("cs_flags", 1), ("pid", 9)):
            changed = copy.deepcopy(rows)
            changed[1][key] = value
            with self.subTest(key=key), self.assertRaises(mas1.Failure):
                mas1.validate_holding(changed, "hold:lock", 1)
        for changed in (rows[:1] + rows[2:], rows[:2] + [dict(kernel, pid=2)] + rows[2:]):
            with self.subTest(rows=changed), self.assertRaises(mas1.Failure):
                mas1.validate_holding(changed, "hold:lock", 1)

    def test_credentials_are_refused_before_building(self):
        for variable in ("APPLE_SIGNING_IDENTITY", "APPLE_UNKNOWN_CREDENTIAL", "TAURI_SIGNING_PRIVATE_KEY"):
            with self.subTest(variable=variable), patch.object(mas1.platform, "system", return_value="Darwin"), \
                    patch.dict(mas1.os.environ, {variable: "not-a-real-secret"}, clear=True), \
                    patch.object(mas1, "run") as command, self.assertRaises(mas1.Failure):
                mas1.build()
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
