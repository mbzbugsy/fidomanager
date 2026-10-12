#!/usr/bin/env python3
"""MAS.2 data-contract, checker and evidence parser controls. Signing/tool calls mocked only."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load('mas_policy', 'mas-worker-policy.py')
checker = load('mas_checker', 'check-macos-mas-worker.py')
runner = load('mas_runner', 'test-macos-mas-worker.py')
COMMIT = '0123456789abcdef0123456789abcdef01234567'


def header():
    data = bytearray(32)
    data[:4] = bytes.fromhex('cffaedfe')
    data[4:8] = (0x0100000c).to_bytes(4, 'little')
    data[12:16] = (2).to_bytes(4, 'little')
    return bytes(data)


class PolicyTests(unittest.TestCase):
    def test_source_and_release_binding(self):
        policy.check_source()
        value = policy.contract('0.1.0', COMMIT)
        self.assertEqual(value['worker_identifier'], f'eu.fidomanager.desktop.mas.fido-worker.0.1.0.{COMMIT}.mas')
        self.assertEqual(value['team_id'], '7VGK9SN42B')
        self.assertEqual(value['worker_build_id'], f'0.1.0+{COMMIT}.mas')
        self.assertNotIn('subject.OU', value['publisher_requirement'])
        self.assertIn('certificate leaf[field.1.2.840.113635.100.6.1.9]', value['publisher_requirement'])
        for version in ('1.2', '01.2.3', '1.2.3.mas', '1.2.3" or anchor apple', '1.2.3-beta'):
            with self.assertRaises(ValueError):
                policy.contract(version, COMMIT)
        for commit in ('development', 'unprovisioned', 'a'*39, 'A'*40):
            with self.assertRaises(ValueError):
                policy.contract('0.1.0', commit)

    def test_typed_exact_grants_and_thin_header(self):
        self.assertTrue(policy.exact_grants(policy.GRANTS))
        for bad in ({}, {**policy.GRANTS, 'extra': True}, {**policy.GRANTS, 'com.apple.security.inherit': 1},
                    {**policy.GRANTS, 'com.apple.security.inherit': False}):
            self.assertFalse(policy.exact_grants(bad))
        self.assertTrue(policy.thin_arm64(header()))
        for offset, replacement in ((0, bytes.fromhex('cafebabe')), (0, bytes.fromhex('cafebabf')),
                                    (4, (0x01000007).to_bytes(4, 'little')), (8, (2).to_bytes(4, 'little'))):
            bad = bytearray(header())
            bad[offset:offset+4] = replacement
            self.assertFalse(policy.thin_arm64(bad))

    def test_post_apple_checker_negative_controls(self):
        with tempfile.TemporaryDirectory(prefix='mas2-checker-') as temporary:
            binary = Path(temporary).resolve() / 'Synthetic.app/Contents/MacOS/fido-worker'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(header() + f'0.1.0+{COMMIT}.mas'.encode())
            binary.chmod(0o755)
            valid = {'Identifier': [policy.identifier('0.1.0', COMMIT)], 'TeamIdentifier': [policy.g5.TEAM],
                     'CodeDirectory v': ['20500 flags=0x10000(runtime)']}
            negatives = [('Identifier', [policy.identifier('0.0.9', COMMIT)]), ('TeamIdentifier', ['OTHERTEAM0']),
                         ('TeamIdentifier', ['not set']), ('CodeDirectory v', ['flags=0x10002(adhoc,runtime)']),
                         ('CodeDirectory v', ['flags=0x0(none)']), ('CodeDirectory v', ['flags=0x10000(runtime) flags=0x10000(runtime)'])]
            for key, value in [(None, None), *negatives]:
                fields = {**valid, **({key: value} if key else {})}
                with patch.object(checker.base, 'signature', return_value=fields), \
                     patch.object(checker.base, 'entitlements', return_value=policy.GRANTS), \
                     patch.object(checker.base, 'run') as tool:
                    tool.return_value.returncode = 0
                    if key:
                        with self.assertRaises(checker.base.CheckError):
                            checker.check(binary, '0.1.0', COMMIT)
                        tool.assert_not_called()
                    else:
                        checker.check(binary, '0.1.0', COMMIT)
                        self.assertIn('-R=' + policy.requirement('0.1.0', COMMIT), tool.call_args.args[0])
                        tool.return_value.returncode = 1
                        with self.assertRaisesRegex(checker.base.CheckError, 'publisher/release'):
                            checker.check(binary, '0.1.0', COMMIT)


def matrix():
    rows = [{'event': 'kernel', 'pid': 1, 'sandboxed': 1, 'cs_status': 0, 'cs_flags': 0x10201}]
    for name in sorted(runner.CASES):
        row = {'event': 'case', 'case': name, 'accepted': name in ('correct-release', 'independent-per-spawn-tokens'),
               'hello': name in ('correct-release', 'build-id-consistency'), 'contained': True,
               'latched': name not in ('correct-release', 'independent-per-spawn-tokens', 'no-unsigned-fallback')}
        if name == 'correct-release': row['child_pid'] = 2
        if name == 'independent-per-spawn-tokens':
            row.update(child_pids=[3, 4], static_a='a'*40, static_b='b'*40,
                       cross_hash_rejected=True, foreign_token_rejected=True)
        rows.append(row)
    rows.append({'event': 'complete', 'real_recovery_accessed': False, 'physical_fido_operations': False})
    children = [{'event': 'child-kernel', 'pid': pid, 'sandboxed': 1, 'cs_status': 0, 'cs_flags': 0x10201} for pid in (2, 3, 4)]
    return rows, children


def result(rows, children, summary='test result: ok. 1 passed; 0 failed; 0 ignored;'):
    return subprocess.CompletedProcess([], 0, '\n'.join('MAS2_EVIDENCE '+json.dumps(row) for row in rows)+'\n'+summary,
                                       '\n'.join('MAS2_CHILD_EVIDENCE '+json.dumps(row) for row in children))


class EvidenceTests(unittest.TestCase):
    def test_positive_model_and_negative_evidence_controls(self):
        rows, children = matrix()
        runner.validate(result(rows, children), 'matrix')
        negatives = []
        bad = copy.deepcopy(rows); bad.pop(1); negatives.append((bad, children))
        bad = copy.deepcopy(rows); bad[1]['case'] = 'unknown'; negatives.append((bad, children))
        bad = copy.deepcopy(rows); bad[0]['sandboxed'] = True; negatives.append((bad, children))
        bad = copy.deepcopy(rows); bad[0]['cs_flags'] = 1; negatives.append((bad, children))
        bad = copy.deepcopy(rows); bad[-1]['real_recovery_accessed'] = True; negatives.append((bad, children))
        bad = copy.deepcopy(rows); next(row for row in bad if row.get('case') == 'static-to-spawn-swap')['hello'] = True; negatives.append((bad, children))
        bad = copy.deepcopy(rows); next(row for row in bad if row.get('case') == 'older-release')['latched'] = False; negatives.append((bad, children))
        bad = copy.deepcopy(rows); next(row for row in bad if row.get('case') == 'independent-per-spawn-tokens')['static_b'] = 'a'*40; negatives.append((bad, children))
        bad = copy.deepcopy(children); bad[0]['cs_status'] = 1; negatives.append((rows, bad))
        bad = copy.deepcopy(children); bad[0]['cs_flags'] = 0x10001; negatives.append((rows, bad))
        negatives.extend([(rows, []), (rows, children[:2]), (rows, children+[children[0]])])
        for parents, guests in negatives:
            with self.assertRaises(RuntimeError): runner.validate(result(parents, guests), 'matrix')
        for summary in ('test result: ok. 0 passed; 0 failed; 0 ignored;', 'test result: ok. 11 passed; 0 failed; 0 ignored;'):
            with self.assertRaises(RuntimeError): runner.validate(result(rows, children, summary), 'matrix')


if __name__ == '__main__':
    unittest.main()
