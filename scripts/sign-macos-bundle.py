#!/usr/bin/env python3
"""Sign an assembled Fido Manager.app inside-out with an explicit identity.

M7.0 runs this only with the ad-hoc identity ("-"). Ad-hoc signing seals the bundle so that
`codesign --verify --strict --deep` and Gatekeeper-independent structure checks are meaningful,
but it is not authenticity: there is no certificate and no Team ID.

Hardened Runtime is applied only for a real Developer ID identity. Under Hardened Runtime,
library validation requires every bundled dylib to carry the same Team ID as the process, which an
ad-hoc signature cannot provide; the only ad-hoc workaround would be the broad
`com.apple.security.cs.disable-library-validation` entitlement, which this project forbids.

No entitlements are ever applied. Existing signatures are replaced (`--force`), which also drops
any entitlements a previous signer may have embedded.
"""

import argparse
from pathlib import Path
import plistlib
import re
import subprocess

DEVELOPER_ID = re.compile(r"^(?:Developer ID Application: .+ \([A-Z0-9]{10}\)|[0-9A-F]{40})$")


def mach_o(path):
    with path.open("rb") as source:
        magic = source.read(4)
    return magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")


def codesign(path, identity, *, runtime, identifier=None):
    command = ["codesign", "--force", "--sign", identity]
    if identity == "-":
        command.append("--timestamp=none")
    else:
        command.append("--timestamp")
    if runtime:
        command += ["--options", "runtime"]
    if identifier:
        command += ["--identifier", identifier]
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
    frameworks = [path for path in nested if path.parent == contents / "Frameworks"]
    helpers = [path for path in nested if path.parent == contents / "MacOS" and path != main]
    unexpected = set(nested) - set(frameworks) - set(helpers) - {main}
    if unexpected:
        raise RuntimeError("Unexpected nested code outside Contents/MacOS or Contents/Frameworks: "
                           + ", ".join(str(path.relative_to(app)) for path in sorted(unexpected)))
    if any(path.suffix != ".dylib" for path in frameworks):
        raise RuntimeError("Contents/Frameworks may contain only flat .dylib files")

    # Inside-out: libraries, then helper executables, then the bundle (main executable + seal).
    for library in frameworks:
        codesign(library, identity, runtime=False)
    for helper in helpers:
        codesign(helper, identity, runtime=runtime, identifier=f"{bundle_id}.{helper.name}")
    codesign(app, identity, runtime=runtime)
    subprocess.run(["codesign", "--verify", "--strict", "--deep", "--verbose=2", str(app)], check=True)
    kind = "ad-hoc (no Team ID, no Hardened Runtime; NOT release signing)" if identity == "-" else "Developer ID + Hardened Runtime"
    print(f"Signed inside-out: {len(frameworks)} dylib(s), {len(helpers)} helper(s), bundle; {kind}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("app", type=Path)
    parser.add_argument("--identity", required=True, help='"-" for ad-hoc; Developer ID only in the protected release workflow')
    arguments = parser.parse_args()
    sign(arguments.app, arguments.identity)
