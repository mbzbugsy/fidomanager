#!/usr/bin/env python3
"""MAS.2 POST-Apple-signing worker checker only. Never signs, executes or accepts ad-hoc code.
Not a store MAIN/bundle, TestFlight acceptance or production launch gate.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load('bundle_checker', 'check-macos-bundle.py')
policy = load('mas_policy', 'mas-worker-policy.py')


def check(binary, version, commit):
    policy.check_source()
    expected = policy.contract(version, commit)
    binary = binary.absolute()
    base.require(binary == binary.resolve(strict=True), 'symlinked worker path')
    original = binary.lstat()
    mode = original.st_mode
    base.require(stat.S_ISREG(mode) and not mode & 0o022 and mode & 0o111, 'unsafe worker file')
    base.require(binary.name == 'fido-worker' and binary.parent.name == 'MacOS'
                 and binary.parent.parent.name == 'Contents'
                 and binary.parent.parent.parent.suffix == '.app', 'unexpected MAS worker layout')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(binary, flags)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        base.require(stat.S_ISREG(opened.st_mode) and not opened.st_mode & 0o022
                     and opened.st_mode & 0o111
                     and (opened.st_dev, opened.st_ino) == (original.st_dev, original.st_ino), 'worker changed during open')
        base.require(policy.thin_arm64(source.read(32)), 'MAS worker must be thin arm64')
        source.seek(0)
        data = source.read(256 * 1024 * 1024 + 1)
    base.require(len(data) <= 256 * 1024 * 1024, 'worker too large')
    # Protected-pipeline consistency, NOT a substitute for the publisher requirement below.
    base.require(expected['worker_build_id'].encode() in data, 'MAS compiled build identity missing')
    fields = base.signature(binary)
    base.require(fields.get('Identifier') == [expected['worker_identifier']], 'wrong release worker identifier')
    base.require(fields.get('TeamIdentifier') == [policy.g5.TEAM], 'wrong CodeDirectory Team ID')
    flags = re.findall(r'flags=0x([0-9a-f]+)\(', ' '.join(fields.get('CodeDirectory v', [])))
    base.require(len(flags) == 1, 'missing or ambiguous signature flags')
    flags = int(flags[0], 16)
    base.require(flags & policy.RUNTIME and not flags & ~policy.ALLOWED_FLAGS, 'unvalidated MAS signature flags')
    base.require(policy.exact_grants(base.entitlements(binary)), 'worker requires exact sandbox/inherit grants')
    result = base.run(['codesign', '--verify', '--strict', '--all-architectures',
                       f'-R={expected["publisher_requirement"]}', str(binary)])
    base.require(result.returncode == 0, 'Apple MAS publisher/release requirement failed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    check(args.binary, args.version, args.source_commit)
    print('PASS: MAS worker static policy only; signed runtime/TestFlight gates remain separate')
