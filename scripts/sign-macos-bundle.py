#!/usr/bin/env python3
"""Sign an assembled Fido Manager.app inside-out with an explicit identity.

M7.0/M7.1 run this only with the ad-hoc identity ("-"). Ad-hoc signing seals the bundle so that
`codesign --verify --strict --deep` and Gatekeeper-independent structure checks are meaningful,
but it is not authenticity: there is no certificate and no Team ID.

Hardened Runtime is applied only for a real Developer ID identity. Under Hardened Runtime, library
validation requires every loaded non-platform library to carry the process's Team ID. Since M7.1
the bundle contains no dylibs at all (libfido2, OpenSSL and libcbor are statically linked into the
worker), so only the two executables and the bundle seal are signed. The broad
`com.apple.security.cs.disable-library-validation` entitlement is forbidden.

Developer ID main code receives only the exact approved App Group grant. Workers and ad-hoc
code receive no entitlements. Existing signatures are replaced (`--force`), which also drops
any entitlements a previous signer may have embedded.
"""

import argparse
import importlib.util
from pathlib import Path
import plistlib
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("macos_authority_policy", ROOT / "scripts/macos-authority-policy.py")
authority_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authority_policy)

DEVELOPER_ID = re.compile(r"^(?:Developer ID Application: .+ \([A-Z0-9]{10}\)|[0-9A-F]{40})$")


def mach_o(path):
    with path.open("rb") as source:
        magic = source.read(4)
    return magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")


def codesign(path, identity, *, runtime, identifier=None, entitlements=None):
    command = ["codesign", "--force", "--sign", identity]
    if identity == "-":
        command.append("--timestamp=none")
    else:
        command.append("--timestamp")
    if runtime:
        command += ["--options", "runtime"]
    if identifier:
        command += ["--identifier", identifier]
    if entitlements:
        command += ["--entitlements", str(entitlements)]
    subprocess.run([*command, str(path)], check=True)


def sign(app, identity):
    if identity != "-" and not DEVELOPER_ID.match(identity):
        raise RuntimeError("Only the ad-hoc identity or a Developer ID Application identity is accepted")
    app = app.resolve(strict=True)
    contents = app / "Contents"
    info = plistlib.loads((contents / "Info.plist").read_bytes())
    bundle_id = info["CFBundleIdentifier"]
    main = contents / "MacOS" / info["CFBundleExecutable"]
    runtime = identity != "-"

    nested = [path for path in sorted(app.rglob("*")) if path.is_file() and not path.is_symlink() and mach_o(path)]
    helpers = [path for path in nested if path.parent == contents / "MacOS" and path != main]
    unexpected = set(nested) - set(helpers) - {main}
    if unexpected or (contents / "Frameworks").exists():
        raise RuntimeError("Unexpected nested code or Contents/Frameworks (the bundle carries no dylibs): "
                           + ", ".join(str(path.relative_to(app)) for path in sorted(unexpected)))

    authority_policy.check_source()
    if bundle_id != authority_policy.DEVELOPER_ID:
        raise RuntimeError("unreviewed Developer ID bundle identifier")
    if (authority_policy.MARKER in main.read_bytes()) != runtime:
        raise RuntimeError("shared authority binary flavor does not match signing channel")
    if any(authority_policy.MARKER in helper.read_bytes() for helper in helpers):
        raise RuntimeError("worker must not contain shared authority")
    # Inside-out: helper executables, then the bundle (main executable + seal).
    for helper in helpers:
        codesign(helper, identity, runtime=runtime, identifier=f"{bundle_id}.{helper.name}")
    codesign(app, identity, runtime=runtime, entitlements=
             authority_policy.DIRECTORY / "developer-id-app.entitlements" if runtime else None)
    subprocess.run(["codesign", "--verify", "--strict", "--deep", "--verbose=2", str(app)], check=True)
    kind = "ad-hoc (no Team ID, no Hardened Runtime; NOT release signing)" if identity == "-" else "Developer ID + Hardened Runtime"
    print(f"Signed inside-out: {len(helpers)} helper(s), bundle; no dylibs; {kind}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("app", type=Path)
    parser.add_argument("--identity", required=True, help='"-" for ad-hoc; Developer ID only in the protected release workflow')
    arguments = parser.parse_args()
    sign(arguments.app, arguments.identity)
