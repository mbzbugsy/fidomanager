#!/usr/bin/env python3
"""Exact maintainer-approved G5 source policy; checks only repository data, never credentials."""
import json
from pathlib import Path
import plistlib
import re

ROOT = Path(__file__).resolve().parents[1]
TEAM = "7VGK9SN42B"
GROUP = "7VGK9SN42B.eu.fidomanager.authority"
DEVELOPER_ID = "eu.fidomanager.desktop"
STORE_ID = "eu.fidomanager.desktop.mas"
MARKER = b"FIDOMANAGER-SHARED-AUTHORITY/1"
DIRECTORY = ROOT / "packaging/macos-production"
GROUP_KEY = "com.apple.security.application-groups"
DEVELOPER_GRANTS = {GROUP_KEY: [GROUP]}
STORE_GRANTS = {**DEVELOPER_GRANTS, "com.apple.security.app-sandbox": True,
                "com.apple.security.device.usb": True, "com.apple.security.network.client": True}


def exact(grants, *, store=False):
    expected = STORE_GRANTS if store else DEVELOPER_GRANTS
    # bool/int equality must not admit integer 1 as a boolean entitlement.
    return (type(grants) is dict and grants == expected
            and all(type(grants[key]) is type(value) for key, value in expected.items())
            and type(grants[GROUP_KEY]) is list
            and all(type(value) is str for value in grants[GROUP_KEY]))


def check_source():
    source = (ROOT / "crates/fido-service/src/worker_authenticity.rs").read_text()
    assert re.search(r'MACOS_RELEASE_TEAM_ID: Option<&str> = Some\("' + TEAM + r'"\)', source)
    assert f'APP_IDENTIFIER: &str = "{DEVELOPER_ID}"' in source
    policy = (ROOT / "crates/fido-service/src/shared_authority_policy.rs").read_text()
    assert f'GROUP_IDENTIFIER: &str = "{GROUP}"' in policy
    assert f'STORE_IDENTIFIER: &str = "{STORE_ID}"' in policy
    assert sorted(path.name for path in DIRECTORY.iterdir()) == ["developer-id-app.entitlements", "store-app.entitlements"]
    for name, identifier, store, features in (
        ("developer-id", DEVELOPER_ID, False, ["macos-release-signing"]),
        ("store", STORE_ID, True, ["macos-app-sandbox", "macos-shared-authority"]),
    ):
        path = DIRECTORY / f"{name}-app.entitlements"
        assert exact(plistlib.loads(path.read_bytes()), store=store), f"unexpected {name} app grants"
        config = json.loads((ROOT / f"src-tauri/tauri.macos-{name}.conf.json").read_text())
        assert config == {"$schema": "https://schema.tauri.app/config/2", "identifier": identifier,
            "build": {"features": features}, "bundle": {"macOS": {"signingIdentity": None,
            "entitlements": f"../packaging/macos-production/{path.name}"}}}, "production overlay contains unreviewed configuration"
        assert config["identifier"] == identifier
        assert config["build"]["features"] == features
        assert config["bundle"]["macOS"] == {"signingIdentity": None,
            "entitlements": f"../packaging/macos-production/{path.name}"}
    app = (ROOT / "src-tauri/Cargo.toml").read_text()
    assert re.search(r'macos-release-signing\s*=\s*\["fido-service/macos-release-signing", "macos-shared-authority"\]', app)
    assert re.search(r'macos-shared-authority\s*=\s*\["fido-service/macos-shared-authority"\]', app)
    assert not re.search(r'^default\s*=.*macos-(?:shared-authority|release-signing|app-sandbox)', app, re.M)
    assert "objc2-foundation" not in (ROOT / "crates/fido-platform/Cargo.toml").read_text(), "Foundation belongs only to authority service"
    worker = (ROOT / "crates/fido-worker/Cargo.toml").read_text()
    assert not re.search(r'macos-(?:shared-authority|app-group)', worker), "worker must not acquire group access"


if __name__ == "__main__":
    check_source()
    print("PASS: exact G5 production identities, grants, channel features and worker boundary")
