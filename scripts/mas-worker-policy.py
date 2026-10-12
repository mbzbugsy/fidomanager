#!/usr/bin/env python3
"""Data-only MAS.2 signing contract. No certificate/profile access, signing or execution.

Protected signing must independently bind these trusted release inputs to the compiled artifact
before assigning the identifier. This output/byte marker is NOT authenticity by itself.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("g5_policy", ROOT / "scripts/macos-authority-policy.py")
g5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g5)
PREFIX = "eu.fidomanager.desktop.mas.fido-worker"
GRANTS = {"com.apple.security.app-sandbox": True, "com.apple.security.inherit": True}
RUNTIME = 0x10000
ALLOWED_FLAGS = RUNTIME | 0x200


def identifier(version, commit):
    if (type(version) is not str or type(commit) is not str
            or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version)
            or not re.fullmatch(r'[0-9a-f]{40}', commit)):
        raise ValueError("MAS identity requires canonical X.Y.Z and full lowercase source commit")
    return f"{PREFIX}.{version}.{commit}.mas"


def requirement(version, commit):
    return (f'anchor apple generic and identifier "{identifier(version, commit)}" '
            'and certificate leaf[field.1.2.840.113635.100.6.1.9]')


def exact_grants(value):
    return type(value) is dict and value == GRANTS and all(type(value[key]) is bool for key in GRANTS)


def thin_arm64(header):
    return (len(header) == 32 and header[:4] == bytes.fromhex('cffaedfe')
            and header[4:8] == (0x0100000c).to_bytes(4, 'little')
            and header[8:12] == bytes(4) and header[12:16] == (2).to_bytes(4, 'little'))


def check_source():
    g5.check_source()
    source = (ROOT / "crates/fido-service/src/mas_worker_policy.rs").read_text()
    assert f'WORKER_PREFIX: &str = "{PREFIX}"' in source
    assert 'certificate leaf[field.1.2.840.113635.100.6.1.9]' in source
    for package in ('fido-platform', 'fido-service', 'fido-worker'):
        text = (ROOT / f"crates/{package}/Cargo.toml").read_text()
        assert re.search(r'^macos-mas-signing\s*=', text, re.M)
        assert not re.search(r'^default\s*=.*macos-mas-signing', text, re.M)
    worker = (ROOT / "crates/fido-worker/Cargo.toml").read_text()
    assert "macos-code-signing" not in worker and "macos-shared-authority" not in worker


def contract(version, commit):
    return {"channel": "mas", "version": version, "source_commit": commit,
            "worker_identifier": identifier(version, commit), "team_id": g5.TEAM,
            "worker_build_id": f"{version}+{commit}.mas", "worker_entitlements": GRANTS,
            "publisher_requirement": requirement(version, commit),
            "architecture": "thin-arm64", "runtime_required": True, "allowed_signature_flags": ALLOWED_FLAGS,
            "apple_signed_validation": "BLOCKED (M1-M6)", "store_main_validation": "BLOCKED (G1/G5)"}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    check_source()
    print(json.dumps(contract(args.version, args.source_commit), indent=2))
