#!/usr/bin/env python3
"""Verify G5 production MAIN signature policy only. Not a store worker/bundle acceptance gate."""
import argparse
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bundle_checker", ROOT / "scripts/check-macos-bundle.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
policy = base.authority_policy


def check(binary, *, store):
    policy.check_source()
    fields = base.signature(binary)
    base.require(fields.get("TeamIdentifier") == [policy.TEAM], "unreviewed main Team ID")
    expected = policy.STORE_ID if store else policy.DEVELOPER_ID
    base.require(fields.get("Identifier") == [expected], "wrong production main identifier")
    authority = fields.get("Authority", [""])[0]
    family = ("Apple Distribution:", "3rd Party Mac Developer Application:") if store else ("Developer ID Application:",)
    base.require(authority.startswith(family), "wrong main certificate family")
    base.require("runtime" in " ".join(fields.get("CodeDirectory v", [])), "main Hardened Runtime missing")
    base.require(policy.exact(base.entitlements(binary), store=store), "main grants differ from exact G5 policy")
    base.require(policy.MARKER in binary.read_bytes(), "main lacks production shared authority")
    requirement = f'anchor apple generic and identifier "{expected}" and certificate leaf[subject.OU] = "{policy.TEAM}"'
    if not store:
        # Same Developer ID publisher OIDs as ADR-017/runtime worker_authenticity.
        requirement += (' and certificate 1[field.1.2.840.113635.100.6.2.6]'
                        ' and certificate leaf[field.1.2.840.113635.100.6.1.13]')
    verified = base.run(["codesign", "--verify", "--strict", f"-R={requirement}", str(binary)])
    base.require(verified.returncode == 0, "main signature verification failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--channel", choices=("developer-id", "store"), required=True)
    args = parser.parse_args()
    check(args.binary, store=args.channel == "store")
    print("PASS: G5 main signature policy only; worker/store distribution validation remains separate")
