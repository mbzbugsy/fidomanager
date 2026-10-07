# ADR-017: macOS Developer ID signing, worker authenticity, notarization and release workflow

Status: **Proposed for independent review** (M7.2 design only). Revision 2: amended after an
independent red-team review. The amendment adds the exact app ↔ worker release binding (D14,
5.8), the signing environment that executes no candidate code (D15, 6.4), and immutable
publication with final asset verification (D16, 7.5–7.6, 9.4). Revision 3: rebased on merged
M7.1. Every statement that earlier revisions made about M7.1's expected output is now checked
against the merged code and labelled [REPO] (section 1.1). Revision 4: closes the final
independent (Astra) review findings. The app now authenticates the **exact** record bytes it keeps
through a digest in the secured `Info.plist` (5.8). The authorization record is authenticated by an
independently conveyed digest and its attestation (7.6). Other changes: per-OS-version dynamic
validation flags (5.2); a least-privilege immutable-release policy check (7.1); an acyclic
`SHA256SUMS` (7.6); release eligibility bound to an exact, CI-green, human-approved commit (7.1);
and a strict extraction contract at the signing boundary (6.5). Revision 5: `publish-final` now
requires the exact draft that `publish-draft` created, bound by the trusted job output
`draft_release_id`, instead of repeating the "no release exists" check that only the pre-draft
phase may make (7.6); the external-action allowlist names the pinned token action (6.4).
Base: main `15ae91c71f1531b26ce3a1ce7367659018c8455d` (PR #33, M7.1 static native dependencies
merged, on top of PR #31, M7.0 packaging foundation).

This ADR changes no code, script or workflow. It creates no certificate, uses no Apple
credential, notarizes nothing and publishes nothing. It does not touch M6/Reset. It is written
against the bundle that merged M7.1 produces (`docs/validation/M7.1-static-native-deps.md`):
libfido2, OpenSSL and libcbor are checksum-pinned private static archives linked into the worker,
the bundle has no third-party dylibs, and `LSMinimumSystemVersion` is 11.0.

ADR-013 to ADR-016 are already reserved by the architecture plan (section 43), so this is
ADR-017. It elaborates plan sections 36 (release pipeline), 37 (macOS signing), 39 (provenance)
and M7.0 section 9, gates 3 and 4. M7.1 section 12 carries those forward as its remaining gates
1–3, which this ADR designs.

The companion validation plan is
[`docs/validation/M7.2-macos-release-validation-plan.md`](../validation/M7.2-macos-release-validation-plan.md).

## Evidence labels

- [APPLE] Behaviour stated in current Apple developer documentation, read for this ADR (the
  sources are listed at the end). It is quoted or closely paraphrased, never extrapolated.
- [GITHUB] Behaviour stated in current GitHub documentation.
- [REPO] Inspected source at the base commit `15ae91c`, which includes M7.1.
- [POLICY] A project decision. It may be stricter than Apple requires.
- [INFERENCE] Reasoning from the above that no document states directly.
- [EMPIRICAL] An assumption that must be proven on real hardware or with a real identity before
  M7.2 can be called done. Each one is listed in section 13.

## 1. Context

What exists at the base commit [REPO]:

- `ProcessWorkerLauncher::beside_current_exe()` resolves `fido-worker` beside the canonical main
  executable. It checks it is a regular, executable, non-world-writable file. That check runs
  **once, when the launcher is built** (`crates/fido-service/src/process_worker.rs`,
  `ResolvedWorkerExecutable::checked`). Each later spawn reuses the stored path without
  re-checking it.
- The spawn clears the environment and passes only `&'static` arguments. On macOS the
  `--authentication` child also gets the CLOEXEC secret socket on fd 3. The parent writes
  `ParentHello` straight after spawn, and the handshake timeout (`handshake_timeout`, default
  3 s) starts after that write.
- `scripts/sign-macos-bundle.py` signs inside-out, never with `--deep`. It accepts only `-` or a
  Developer ID Application identity. It applies `--options runtime` and `--timestamp` to a real
  identity, and never applies entitlements.
- `scripts/check-macos-bundle.py --signature developer-id` asserts these: a Developer ID leaf,
  one Team ID shared by all code, a secure timestamp, Hardened Runtime on main and worker, zero
  entitlements, and the identifiers `eu.fidomanager.desktop` and
  `eu.fidomanager.desktop.fido-worker`. It does **not** assert a specific expected Team ID or a
  designated requirement. Its exact-tree allowlist also rejects a stapled bundle (see 8.3).
  Since M7.1 the checker also rejects `Contents/Frameworks/`, requires exactly two Mach-O files
  and a byte-identical `Contents/Resources/THIRD_PARTY_NOTICES.md`, and **executes the worker**
  by default (exit-code checks, plus a hostile-OpenSSL start that first compiles a test dylib
  with `xcrun clang`). It has a `--no-execute-worker` switch.
- `scripts/package-macos.py` refuses to run when `APPLE_*`, `TAURI_SIGNING_*` or
  `LIBFIDO2_LIB_DIR` is set.
- CI (`.github/workflows/ci.yml`, job `macos-packaging`) builds an ad-hoc bundle and DMG on
  `pull_request` with no secrets and uploads nothing.
- The repository is **public** (checked through the GitHub API). That matters for environment
  secrets, required reviewers and artifact attestations (section 6).

M7.0 recorded this as an open gate: "Today authenticity rests on the bundle seal and Gatekeeper at
app launch. A per-spawn requirement check needs a real Team ID and must land before a signed
release." M7.1 keeps it open as its remaining gate 2.

### 1.1 What merged M7.1 established

Earlier revisions of this ADR had to guess these points. Each is now taken from the merged code
at `15ae91c` [REPO]:

| Point | Merged M7.1 fact | Where |
| --- | --- | --- |
| Bundle tree | `Contents/Info.plist`, `MacOS/fidomanager-app`, `MacOS/fido-worker`, `Resources/icon.icns`, `Resources/THIRD_PARTY_NOTICES.md`, `_CodeSignature/CodeResources`. The checker's allowlist also tolerates an optional `Contents/PkgInfo`; the M7.1 evidence bundle lists none, and this design does not rely on one | `check-macos-bundle.py` `check_tree`; M7.1 doc section 9 |
| Nested code | exactly two Mach-O files; no `Contents/Frameworks/`; no symlinks; any other file name containing `fido-worker` is rejected | `check_tree`; `sign-macos-bundle.py` refuses Frameworks and any Mach-O outside `Contents/MacOS/` |
| Worker linkage | static libfido2 1.17.0 (patched), OpenSSL 3.5.9 and libcbor 0.14.0 from `libfidomanager_{fido2_bounded,crypto,cbor}.a`; dynamic dependencies exactly `/usr/lib/libz.1.dylib`, CoreFoundation, IOKit, `/usr/lib/libiconv.2.dylib`, `/usr/lib/libSystem.B.dylib`; loader `/usr/lib/dyld`; no `LC_RPATH` or `LC_DYLD_ENVIRONMENT` | `crates/fido-libfido2/build.rs`; `check_linkage` (`WORKER_SYSTEM_DEPENDENCIES`) |
| Link provenance | proven from the linker map on the unsigned release worker before it is bundled (every live libfido2, OpenSSL and libcbor definition attributed to the private archives; allowlisted linker inputs) | `verify-libfido2-linkage.py`, called by `package-macos.py` and again by CI |
| Deployment floor | worker built with `MACOSX_DEPLOYMENT_TARGET=11.0`; `LSMinimumSystemVersion` must equal 11.0 and no code may need more | `package-macos.py`; `check_linkage` |
| OpenSSL runtime policy | `OPENSSLDIR` compiled to root-owned `/var/empty/fidomanager-openssl`; no shared, module, engine, DSO or autoload-config | `build-native-deps.py` `OPENSSL_POLICY`; checker `PRIVATE_OPENSSLDIR` |
| Source pins | `native/openssl/source.lock.json` and `native/libcbor/source.lock.json`: name, version, upstream tag and commit, URL, archive SHA-256 and size bounds, licence SPDX and licence-file SHA-256, static archive name. `native/libfido2/source.lock.json` has a different shape: version, revision (commit), URL, archive SHA-256, patch SHA-256, credman source SHA-256s, enumeration limit, identity symbol and archive name, with **no** licence fields. Upstream licences for all three are in `native/<name>/LICENSE.upstream` | lock files |
| Build identity | path-free `build-identity.json` beside the private archives in Cargo's `OUT_DIR/private-libfido2/`, carrying each dependency's version, tag, commit, source and archive SHA-256, licence, compiler, SDK, options and deterministic controls; read back by the linkage verifier | `build-libfido2.py`; `build-native-deps.py` |
| Package summary | `target/macos-package/package-summary.json`: native identities, notices SHA-256, SHA-256 of each bundled Mach-O after the ad-hoc seal, `developer_id_signed: false`, `notarized: false` | `package-macos.py` |
| Notices | `THIRD_PARTY_NOTICES.md` covers libfido2 (with its openbsd-compat notices), OpenSSL and libcbor only; it states that Rust crate and frontend notices are out of its scope | the file; M7.1 gate 5 |
| Architectures | the packager builds for the host only and refuses universal builds; CI packages arm64. x86_64 archives build, but no x86_64 worker is linked or packaged | `package-macos.py` `host_triple`; M7.1 gate 4 |
| Reproducibility | byte-identical archives across separate paths on the same host and toolchain only; not claimed across machines | M7.1 doc section 11, criterion 5 |
| Not yet proven | actual launch on macOS 11; clean-machine runs; Developer ID and Hardened Runtime; OpenSSL PGP signature check (the SHA-256 pin is the gate) | M7.1 gates 1, 3 and 6 |

## 2. Decisions (summary)

| # | Decision | Kind |
| --- | --- | --- |
| D1 | The shipped code set is exactly two Mach-O executables: the main app and `Contents/MacOS/fido-worker`. Tauri adds no other nested code in this configuration. Anything else fails the release. | [POLICY]; matches [REPO] M7.1 checker and signer |
| D2 | Sign inside-out: worker, then the release-worker identity record (D14), then bundle, then DMG. Never sign with `--deep`. | [APPLE] + [POLICY] |
| D3 | Hardened Runtime on both executables. **Zero entitlements** on both. No exception entitlement may be added without its own ADR. | [APPLE] requirement + [POLICY] |
| D4 | Every signature carries a secure timestamp from `timestamp.apple.com`. Without one, signing fails; there is no unsigned fallback. | [APPLE] + [POLICY] |
| D5 | Before **every** spawn, the app validates the worker against a compiled-in **publisher** requirement (Apple-issued Developer ID Application, a fixed Team ID, identifier `eu.fidomanager.desktop.fido-worker`) **and** against the exact per-release worker identity from D14. It validates statically before exec, then dynamically against the running child before any message is sent. | [POLICY], built on [APPLE] APIs |
| D6 | The verification mode is fixed at compile time. Release builds enforce it, and the release checks prove the shipped binary is an enforcing build. Nothing at runtime can select a weaker mode. | [POLICY] |
| D7 | Release builds run only in a dedicated tag-triggered workflow. They are never built from a PR, and a PR artifact is never signed. The protected workflow builds the bundle again from the reviewed tag. | [POLICY] |
| D8 | The protected workflow splits into: a build job with no secrets; a signing/notarization job that holds secrets and **executes no candidate code at all**; a verification job with no secrets; and publication jobs. Jobs hand off by SHA-256 digest. | [POLICY] |
| D9 | Notarize and staple the `.app` (submitted as a zip), then build, sign, notarize and staple the DMG. That is two notarizations. | [APPLE] permits; [POLICY] chooses |
| D10 | Credentials are a Developer ID Application PKCS#12 and an App Store Connect API key. They live only in a protected GitHub Environment with a required reviewer and are imported into an ephemeral keychain that is destroyed in `always()`. | [GITHUB] + [POLICY] |
| D11 | Any failure in signing, notarization, stapling, assessment or digest checks stops the run before anything is published. There is no unsigned, ad-hoc, unnotarized or unstapled fallback. | [POLICY] |
| D12 | Each release ships a manifest, a release-authorization record, `SHA256SUMS`, a CycloneDX SBOM, both notarization logs and a GitHub build-provenance attestation. | [POLICY] |
| D13 | A release becomes public only through a gated publication job, approved by a human after the clean-machine matrix passes. That job publishes only the exact draft the draft job created (`draft_release_id`), re-downloads that draft's actual assets and hard-fails on any digest mismatch with the **authenticated** authorization record (D16). | [POLICY] |
| D14 | **Exact app ↔ worker binding.** After the worker is signed and before the bundle is signed, a trusted driver writes `Contents/Resources/release-worker-identity.json` and puts the SHA-256 of its exact bytes into `Info.plist` as `FidoManagerReleaseWorkerIdentitySHA256`. The bundle signature then binds both. At startup the app reads the record once, hashes those exact bytes, compares the digest with the one in the **secured** `Info.plist` obtained from its own validated code object, and only then parses that same buffer into backend memory. Every spawn requires the exact recorded cdhash, so an older worker from the same publisher is rejected. | [POLICY], built on [APPLE] |
| D15 | **Signing-environment independence.** The credential-bearing job runs only a minimal signing/notarization driver plus Apple OS tools. The driver is checked out from a separate, protected repository at a pinned full commit SHA, never from the candidate commit. The candidate app is handled as data only. | [POLICY] |
| D16 | **Immutable publication.** Publication is bound to an explicit authorization tuple (section 7.6). The authorization record never vouches for itself: its digest `D7` travels through trusted job outputs and its provenance attestation is verified against the exact run before it is used. GitHub immutable releases are required and confirmed by a least-privilege policy check. Every byte-changing step has its own input and output digest (section 9.4). Tags are never moved or reused. | [GITHUB] + [POLICY] |

## 3. Code set and nested code

### 3.1 What gets signed

The merged M7.1 bundle [REPO], plus the two files this design adds (marked "M7.2"):

```text
Fido Manager.app/
  Contents/
    Info.plist                     bound to the bundle signature; LSMinimumSystemVersion 11.0;
                                   M7.2: gains FidoManagerReleaseWorkerIdentitySHA256 (5.8)
    MacOS/fidomanager-app          main executable  (signing id eu.fidomanager.desktop)
    MacOS/fido-worker              helper tool      (signing id eu.fidomanager.desktop.fido-worker);
                                   static libfido2 + OpenSSL + libcbor, system libraries only
    Resources/icon.icns            sealed resource (byte-identical to src-tauri/icons/icon.icns)
    Resources/THIRD_PARTY_NOTICES.md
                                   sealed resource (byte-identical to the repository copy)
    Resources/release-worker-identity.json
                                   M7.2: sealed resource; written by the signing driver after the
                                   worker is signed and before the bundle is signed (section 5.8)
    _CodeSignature/CodeResources   bundle seal
    CodeResources                  M7.2: notarization ticket, added only by `stapler` (section 8.3)
```

- [REPO] There is no `Contents/Frameworks/`. The M7.1 checker's allowlist also accepts an
  optional `Contents/PkgInfo`, which is non-code. The M7.1 evidence bundle has none and this
  design neither adds nor needs one. The driver's tree check uses the same allowlist as the
  checker (PkgInfo optional), so the two cannot disagree about a valid bundle.
- [REPO] Today's checker rejects both M7.2 files as unexpected bundle entries. That is correct for
  the ad-hoc Build output (neither may exist yet). The `--signature developer-id` mode needs an
  explicit allowlist entry for the record, and `--stapled` for the ticket (section 12, step 7).
  The same applies to the new `Info.plist` key: it must be absent from the Build output and
  present, well-formed and equal to the record's SHA-256 in the signed bundle.

- [APPLE] Helper tools belong in `Contents/MacOS/` or `Contents/Helpers/` ("Placing content in a
  bundle"). `Contents/MacOS/fido-worker` is a documented location, so no non-standard layout is
  needed.
- [APPLE] Nonbundled code gets an explicit identifier with `-i`. The recommended form is the
  app's bundle ID plus a suffix ("Creating distribution-signed code for macOS"). The existing
  `eu.fidomanager.desktop.fido-worker` follows this, and TN3127 calls separate identifiers for an
  app and its tool "best practice".
- [REPO] Tauri adds no nested code in this configuration. The bundle overlay allows only
  `targets: ["app"]` and a single `externalBin`. `macOS.frameworks`, `resources`, `plugins` and
  updater artifacts are forbidden by `check-renderer-boundary.mjs`. WKWebView is a system
  framework and runs its content in Apple's own XPC processes, which are not part of our bundle.
  [REPO] Since M7.1 the checker requires the Mach-O set to be exactly {fidomanager-app,
  fido-worker}, and `sign-macos-bundle.py` refuses to sign if `Contents/Frameworks/` exists or
  any Mach-O sits outside `Contents/MacOS/`.
- [POLICY] The release checks require the Mach-O set to be **exactly** {main, worker}. Every
  regular file is checked for Mach-O magic, including fat headers. Any extra code (a framework,
  `.dylib`, `.so`, XPC service or plug-in) fails the release. It is never signed "to make it pass".
- [POLICY] The candidate bundle that arrives from the build job must **not** already contain
  `release-worker-identity.json`. That file is created only by the signing driver. If it is
  present, signing stops.

### 3.2 Signing order and options

[APPLE] "Sign code from the inside out", "Don't pass the `--deep` option to `codesign` when you
sign code", "add the `--timestamp` option", and "If you're signing a main executable for
Developer ID distribution, add the `-o runtime` option". [APPLE] To sign a DMG, use a Developer
ID **Application** identity, a unique identifier and `--timestamp`, on a UDIF read-only
zip-compressed (`UDZO`) image ("Packaging Mac software for distribution").

All of these commands are run by the pinned signing driver (section 6.4), never by candidate
scripts.

```sh
# 1. Worker (nonbundled helper tool)
/usr/bin/codesign --force --sign "$IDENTITY_SHA1" --keychain "$KC" --timestamp \
  --options runtime --identifier eu.fidomanager.desktop.fido-worker \
  "Fido Manager.app/Contents/MacOS/fido-worker"
/usr/bin/codesign --verify --strict -R="=$WORKER_PUBLISHER_REQ" "…/fido-worker"

# 2. Release-worker identity record (section 5.8), derived from the signed worker only
#    for each arch in `lipo -archs`: codesign -d -vvv --arch $ARCH → CDHash, CandidateCDHashFull sha256
#    shasum -a 256 of the signed worker file
#    write Contents/Resources/release-worker-identity.json (0644, regular file, canonical bytes)
#    RID = SHA-256 of exactly those bytes
#    Info.plist: add FidoManagerReleaseWorkerIdentitySHA256 = RID (64 lowercase hex); the driver
#    asserts the key was absent before and that no other key changed (plistlib, data only)

# 3. Bundle (main executable, resource seal incl. the record, Info.plist binding)
/usr/bin/codesign --force --sign "$IDENTITY_SHA1" --keychain "$KC" --timestamp \
  --options runtime "Fido Manager.app"
#    re-read the record from the sealed bundle and confirm that its cdhashes equal the worker's
#    CDHash in the signed bundle and that its SHA-256 equals the plist key;
#    codesign --verify --strict --deep (seal covers record + worker; signature binds Info.plist)

# 4. (after the app is notarized and stapled, section 8) the DMG
/usr/bin/codesign --force --sign "$IDENTITY_SHA1" --keychain "$KC" --timestamp \
  --identifier eu.fidomanager.desktop.dmg "FidoManager-$VERSION-$ARCH.dmg"
```

- The identity is the **SHA-1 fingerprint** of the certificate, pinned as an environment
  variable, not the display name. [APPLE] recommends the hash when names could be ambiguous.
  [POLICY] The fingerprint also binds the job to the one certificate the maintainers approved.
- No `--entitlements`, no `--requirements` (custom DR) and no `--deep` while signing.
  [POLICY] We keep codesign's default Developer ID designated requirement. TN3127 advises against
  hand-writing DRs, and we have no Mac App Store variant that would need a mutually compatible DR.
- `--keychain` restricts the identity search to the ephemeral keychain. [EMPIRICAL E9] Confirm
  that codesign finds the identity there without adding the keychain to the user search list. If
  it does not, add it to the search list for the job and restore the list in `always()`.
- `--options runtime` only. [EMPIRICAL E4] decides whether the worker also needs the `kill`
  code-signature flag (see 5.5). It is added only if Hardened Runtime alone does not set the
  dynamic `kill` status on the running worker.
- Re-signing the bundle in step 3 does not change the worker: the worker is nested code and is
  not re-signed, because there is no `--deep`. So the cdhash in the record stays the worker's
  final cdhash. The driver re-checks this after step 3 and again after stapling.
- [REPO] `sign-macos-bundle.py` implements today's equivalent of steps 1 and 3 for the ad-hoc
  build. It stays the **build-job** (ad-hoc) signer. Developer ID signing moves to the separate
  pinned driver (D15). The candidate's `sign-macos-bundle.py` never runs where the identity is
  available.
- [REPO] The topology fits M7.1's signer: it signs every helper in `Contents/MacOS/` with the
  identifier `<CFBundleIdentifier>.<file name>` (which yields `eu.fidomanager.desktop.fido-worker`),
  then the bundle, then runs `codesign --verify --strict --deep`. The driver keeps that order and
  those identifiers. The one difference is step 2: the record is written between the helper and
  the bundle, so the bundle seal covers it. Re-signing with `--force` replaces the Build job's
  ad-hoc signatures.

### 3.3 Entitlement policy

[POLICY] **Zero entitlements** on the main app and the worker, in every build.

- [APPLE] Hardened Runtime is required for notarization. Exception entitlements are opt-in, and
  Apple says to "use only the entitlements that are absolutely necessary".
- [APPLE] `com.apple.security.get-task-allow` must not be present; the notary service rejects it.
- [REPO] M7.0 local evidence: the main app ran under Hardened Runtime (ad-hoc) with no
  entitlements. The production frontend loaded in WKWebView and drove the worker spawn. So
  `allow-jit`, `allow-unsigned-executable-memory` and `disable-library-validation` are **not**
  needed. Tauri examples that add them do not apply here.
- [INFERENCE] The worker needs no entitlement for USB HID access to FIDO devices: no sandbox, no
  TCC-gated HID class (FIDO usage page `0xF1D0`, not keyboard), and no network.
  [EMPIRICAL E7] Confirm on a clean Mac that no TCC prompt (Input Monitoring or other) appears for
  the signed worker or the app.
- No App Sandbox in this phase (architecture plan section 37, M7.0 section 8). Adopting the
  sandbox later would be a separate ADR.
- [POLICY] Signature checks fail if any entitlement is present (`check-macos-bundle.py` already
  enforces this). They also fail if the code signature flags lack `runtime` on either executable.

## 4. Verification commands and where each runs

"Driver" means the pinned signing driver in the credential-bearing job. It runs only Apple OS
tools and treats the candidate as data (D15). "Verify" is the fresh, secret-free job after signing.
"Build" is the secret-free job before signing. Candidate scripts, including
`check-macos-bundle.py`, run only in Build and Verify. That matters concretely for M7.1's checker:
by default it executes the worker and compiles and loads a test dylib (section 1).

| Check | Command | Runs in | Pass criterion |
| --- | --- | --- | --- |
| Exact tree and Mach-O set | driver's own allowlist walk (no symlinks, regular files, Mach-O magic incl. fat headers), using the M7.1 checker's allowlist (section 3.1) | Driver (pre-sign) and Verify; the M7.1 checker enforces the same in Build | exactly {main, worker} as code; no `Frameworks/`; no pre-existing identity record |
| Build-output consistency | compare each Mach-O's and the notices file's SHA-256 with `package-summary.json` (`bundled_sha256`, `third_party_notices_sha256`) inside the same `build-output.tar` | Driver (pre-sign, data only) | equal; `developer_id_signed` and `notarized` are `false` |
| Enforcing-build marker | byte search of the main binary for the marker (5.6) | Driver (pre-sign, data only) and Verify | present; its Team ID and release ID equal the driver's pinned Team ID and the tag's version/commit |
| Deep strict verify | `codesign --verify --strict --deep --verbose=4 "Fido Manager.app"` | Driver (post-sign) and Verify | exit 0 [APPLE: `--strict` matches notarization's restrictiveness] |
| Signature details | `codesign -dvvv "…/fidomanager-app"` and `"…/fido-worker"` | Driver and Verify | `Authority=Developer ID Application: … (TEAMID)`, then `Developer ID Certification Authority`, then `Apple Root CA`; `TeamIdentifier=$EXPECTED_TEAM_ID`; `Timestamp=` present, **not** `Signed Time=` [APPLE]; `flags=0x10000(runtime)`; expected `Identifier=` |
| Entitlements | `codesign -d --entitlements - --xml <exe>` | Driver and Verify | empty |
| Worker publisher requirement | `codesign --verify --strict -R='=<worker publisher requirement, 5.1>' "…/fido-worker"` | Driver and Verify | `explicit requirement satisfied` |
| Worker exact requirement | same, with `… and cdhash H"<record cdhash>"` | Driver (post-sign) and Verify | satisfied; and **not** satisfied by any other cdhash (Verify negative test) |
| Record ↔ worker | parse `release-worker-identity.json`; compare with `codesign -d -vvv --arch <a>` `CDHash`/`CandidateCDHashFull` and `shasum -a 256` | Driver (post-sign, post-staple) and Verify | all equal |
| App requirement | same, with the app requirement | Driver and Verify | satisfied |
| Default DR shape | `codesign -d -r- <exe>` | Verify | recorded from the **real** Developer ID output and compared with 5.1: the identifier, Team ID and Developer ID clauses match. Whether the output also has a Mac App Store alternative is whatever codesign actually emits; it is recorded, not required [EMPIRICAL E1] |
| Record digest in `Info.plist` | read `FidoManagerReleaseWorkerIdentitySHA256` (plistlib); `shasum -a 256` of the record | Driver (post-sign, post-staple) and Verify | present, 64 lowercase hex, equal to the record's SHA-256 |
| Handoff archive extraction | the driver's own extraction contract (6.5) | Driver, before anything else touches the candidate | every rule in 6.5 holds; otherwise nothing is extracted and the job fails |
| Structural and linkage checks | `check-macos-bundle.py --signature developer-id --stapled --expected-team-id …` | **Verify only** (and the ad-hoc mode in Build) | passes |
| Executing the worker or app | `packaged_worker` test, launch checks, the M7.1 checker's worker-runtime and hostile-OpenSSL checks | **Build (ad-hoc) and Verify only** | never in the Driver |
| Signed worker is the linked worker | on copies, `codesign --remove-signature` of the Build-output worker and of the signed worker, then compare SHA-256 | **Verify** | equal, so the link provenance proven in Build carries over to the signed worker [INFERENCE, EMPIRICAL E19] |
| Gatekeeper | `spctl --assess …` (8.4) | **Verify** | `accepted`, `source=Notarized Developer ID` |

## 5. Worker authenticity before spawn

### 5.1 The requirement

[APPLE] TN3127 gives the Developer ID designated requirement:
`anchor apple generic and identifier "…" and (certificate leaf[field.1.2.840.113635.100.6.1.9]
or certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]
and certificate leaf[subject.OU] = TEAMID)`. The OIDs mean, in order: Mac App Store leaf,
Developer ID CA issuer, Developer ID Application leaf. `subject.OU` holds the Team ID. The OID
checks are meaningful only under `anchor apple generic`.

[POLICY] The worker requirement drops the Mac App Store branch. We do not ship through the Mac
App Store, and accepting a store-signed binary would widen the set of signers for no reason.

```text
anchor apple generic
and identifier "eu.fidomanager.desktop.fido-worker"
and certificate 1[field.1.2.840.113635.100.6.2.6]      /* issuer: Developer ID CA            */
and certificate leaf[field.1.2.840.113635.100.6.1.13]  /* leaf: Developer ID Application     */
and certificate leaf[subject.OU] = "<TEAM_ID>"          /* the project's Team ID               */
```

- `<TEAM_ID>` is a **reviewed constant in source**, for example
  `const MACOS_RELEASE_TEAM_ID: &str = "XXXXXXXXXX";` next to the launcher. It is not a build
  environment variable, not a file read at runtime and not derived from the running app. A Team ID
  is public (it is in every signature), so a constant leaks nothing. The signing driver asserts
  that the certificate's Team ID equals its own pinned Team ID and the marker compiled into the
  candidate (sections 5.6 and 7.4).
- This **publisher** requirement says who signed the worker and which component it is. It does not
  say *which release* of the worker it is. Per spawn it is always combined with the exact cdhash
  from the release-worker identity record (5.3, 5.8): `WORKER_EXACT_REQ = WORKER_PUBLISHER_REQ and
  cdhash H"<expected>"`.
- [APPLE] TN3127 warns not to hand-write requirements. [POLICY] Before the constant is merged, the
  requirement must be checked against the default DR of a real Developer ID-signed worker
  (`codesign -d -r-`). It must be shown to accept that worker and to reject an ad-hoc worker, an
  unsigned worker, a correctly signed binary with a different identifier, and (if the maintainers
  have one) a binary signed by another Team ID. [EMPIRICAL E1]
- [APPLE] Compiling a requirement is relatively expensive, so the launcher compiles it **once** at
  construction with `SecRequirementCreateWithString` and keeps the object. A parse failure means
  the launcher cannot be built, and the app shows the integrity error with no FIDO functionality.
  It never falls back to "no requirement".
- The app also checks itself once at startup, with the same shape and identifier
  `eu.fidomanager.desktop` (`SecCodeCopySelf` + `SecCodeCheckValidity`). This is **not** a
  security boundary, because a tampered app can skip its own check. It catches a misbuilt release
  (an enforcing binary that ended up ad-hoc or re-signed by another team) and fails closed the
  same way.

### 5.2 APIs and flags

[APPLE] Facts the design relies on:

- `SecStaticCodeCreateWithPath` makes a static code object for a file. For a bundle's **main**
  executable it "generally" recognises the whole bundle. `fido-worker` is not the main executable,
  so it should be treated as a single file. [EMPIRICAL E2] confirms that the static object's
  identifier is the worker's. If it were the bundle's, the identifier clause fails closed.
- `SecStaticCodeCheckValidityWithErrors` "checks the validity of all sealed components" and the
  requirement. It "is only secure if the code is not subject to concurrent modification, and the
  outcome is only valid as long as the code remains unmodified."
- `kSecCSCheckAllArchitectures` validates every slice of a universal binary (by default only the
  native one, and slices may have different signers). `kSecCSStrictValidate` adds anti-tamper
  structure checks. `noNetworkAccess` and `enforceRevocationChecks` exist in `SecCSFlags`.
- `SecCodeCopyGuestWithAttributes(NULL, {kSecGuestAttributePid: pid})` gets a dynamic code
  object for a running process from the kernel.
- `SecCodeCheckValidity` "performs dynamic validation". For guest code it checks the dynamic
  validity status reported by the host (the kernel), then validates the requirement. It "is secure
  against attempts to modify the file system source of the code object."
- With `kSecCSDynamicInformation`, `SecCodeCopySigningInformation` returns `kSecCodeInfoStatus`.
  The `kill` status bit "can not be cleared on running code… Running code that has this flag set
  is guaranteed to be valid, because if it were invalid it would have been terminated."
  `kSecCodeInfoFlags` includes the `runtime` signature flag, and `kSecCodeInfoTeamIdentifier` and
  `kSecCodeInfoEntitlementsDict` are available.

Flag choices [POLICY]:

- Static: `kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSRestrictSymlinks |
  noNetworkAccess`.
- Dynamic, macOS 11.3 and later: `noNetworkAccess`.
- Dynamic, macOS 11.0–11.2: **no flags** (`kSecCSDefaultFlags`). The independent review's API
  check reports that `kSecCSNoNetworkAccess` is supported for **dynamic** validation only from
  macOS 11.3. Apple's online page for the Swift constant does not state that split, so the exact
  availability is confirmed against the SDK header during implementation [EMPIRICAL E3]. The
  design never passes a flag where it may be unavailable.
- **The requirement is identical on both paths.** `WORKER_EXACT_REQ` (publisher requirement plus
  the exact cdhash), the identifier, Team ID, `runtime`, entitlement and cdhash checks in steps 3
  and 5, and the startup checks in 5.8 do not change with the OS version. Only the network flag
  differs. The deployment floor stays 11.0.
- **How the path is chosen.** The process asks the OS once at startup through the kernel's
  version API (`sysctlbyname("kern.osproductversion")`, or `NSProcessInfo`
  `operatingSystemVersion`) and stores the result in an immutable value next to the compiled
  requirements. It is not an environment variable, argument, config file, `Info.plist` key or
  renderer input, and there is no "lenient" mode to select. An unparsable version, or one below
  11.0 (such as the `10.16` that macOS reports to software running with `SYSTEM_VERSION_COMPAT`),
  fails closed (no launcher). [EMPIRICAL E3] confirms that the chosen source is not changed by
  `SYSTEM_VERSION_COMPAT` or any other environment variable. [INFERENCE] Even a misreported
  version could only choose between two flag sets with the same requirement; it cannot weaken
  the identity check.
- `noNetworkAccess` because normal FIDO operation must not need the network (section 9 of the
  validation plan). Certificate revocation for the app is Gatekeeper's job at first launch and
  is not repeated per spawn. [EMPIRICAL E3] is a **release gate for both paths**: validation must
  succeed offline with bounded latency on 11.0–11.2 (no flags) and on 11.3 or later
  (`noNetworkAccess`). If either path needs the network or blocks offline, the release stops.
  The answer is not to weaken the requirement, and the floor is not raised silently; any floor
  change is its own reviewed decision. `enforceRevocationChecks` stays off, because it would make
  every spawn depend on OCSP reachability.

Binding [POLICY]: a small macOS-only module in `fido-platform` with direct
`Security.framework` FFI. It needs about seven functions and a few CF types, and is kept in one
reviewed file like the existing `secret_channel`. A pinned `security-framework` crate is
acceptable only if the review prefers it. Either way it is a new security-critical dependency
surface and gets reviewed as one.

### 5.3 Per-spawn algorithm

Validation runs on **every spawn**, including replacements after a crash, timeout or breaker
probe. Spawns are rare (bounded by the ADR-009 backoff and circuit breaker), and the cost is
hashing one binary of a few MB. [EMPIRICAL E5] measures the cost on the slowest supported Mac.
Validation results are never cached. Only the compiled requirements and the startup-authenticated
expected worker identity (`EXPECTED`, section 5.8) are kept in memory.

```text
startup (once, section 5.8):
  EXPECTED = authenticated release-worker identity (identifier, team, build id,
             per-arch cdhash, file SHA-256), held in backend memory only
  WORKER_EXACT_REQ = WORKER_PUBLISHER_REQ and cdhash H"<EXPECTED.cdhash[native arch]>"
  any failure here: no launcher, FIDO disabled (5.7)

launch(generation):
  1. path   = canonical(dir(canonical(current_exe())) / "fido-worker")      # 'static name, as today
  2. require regular file, not symlink, executable, not group/world-writable,
             parent == dir(canonical(current_exe()))                         # re-done per spawn
  3. static = SecStaticCodeCreateWithPath(path)
     SecStaticCodeCheckValidityWithErrors(static, STATIC_FLAGS, WORKER_EXACT_REQ)  # gate before exec
     info   = SecCodeCopySigningInformation(static, signing)
     require info.flags ⊇ runtime, info.team == TEAM_ID, no entitlements,
             info.unique (kSecCodeInfoUnique) == EXPECTED.cdhash[native arch],
             SHA-256(file) == EXPECTED.file_sha256
     # universal builds only (not shipped today, see below)
  4. spawn exactly that path (env cleared, 'static args, fd 3 only in --authentication)
  5. guest  = SecCodeCopyGuestWithAttributes(NULL, {pid: child.pid})         # child unreaped
     SecCodeCheckValidity(guest, DYNAMIC_FLAGS, WORKER_EXACT_REQ)
     dyn    = SecCodeCopySigningInformation(guest, dynamic|signing)
     require dyn.status ⊇ valid (and kill, see 5.5), dyn.team == TEAM_ID,
             dyn.identifier == "eu.fidomanager.desktop.fido-worker", dyn.flags ⊇ runtime,
             dyn.unique (kSecCodeInfoUnique, the running cdhash) == EXPECTED.cdhash[native arch]
  6. only now write ParentHello; the handshake timeout starts as today
  7. after a valid ChildHello: ChildHello.build_id == EXPECTED.build_id       # consistency check only
  on any failure in 3: do not spawn.
  on any failure in 5 or 7: contain() (kill + reap, ADR-009 ordering) before reporting; nothing
  else sent.
```

- The **authority** for "this is the approved worker" is the dynamic cdhash in step 5. The kernel
  enforces the cdhash for the running process: the pages are validated against that CodeDirectory.
  [APPLE] TN3126 says a cdhash "uniquely identifies the code being signed", and
  `kSecCodeInfoUnique` "is tied to the current version of the code". The file SHA-256 in step 3 is
  an extra pre-exec tripwire: it also covers the signature blob. The build-id comparison in step 7
  only catches pipeline mistakes, because by then the cdhash has already fixed the exact bytes.
- Expected values never come from the candidate worker. `EXPECTED` is loaded once at startup from
  the app's own sealed record (5.8). Nothing the worker file, the worker process or the renderer
  says can change it.
- **Universal binaries (future, not implemented now).** M7.1 ships one architecture. A future
  universal worker must (a) pass the publisher requirement on every slice
  (`kSecCSCheckAllArchitectures`), (b) have **each** slice match its **own** recorded `cdhash`,
  checked per slice with `SecStaticCodeCreateWithPathAndAttributes(kSecCodeAttributeArchitecture)`,
  because [APPLE] signing information covers one slice by default, and (c) in step 5, match the
  running process's cdhash against the record entry for the architecture it is **actually
  running**, obtained from the dynamic code object, not assumed from the host.

Why `pid` is safe here [INFERENCE]: Apple generally prefers audit tokens to pids because pids are
reused. Here the pid belongs to **our own child, which we have not reaped**. Until `wait` returns,
the kernel keeps the process (at worst as a zombie) and cannot hand that pid to another process.
So for the whole of step 5 the pid names exactly the process we spawned. This argument holds only
because the launcher owns the `Child` and reaps it only through `contain()`. That invariant
already exists (ADR-009 "a reaped process is never signalled again"), and the implementation must
keep step 5 before any path that could reap.

Steps 1–2 stay even though step 3 exists [POLICY]. They are cheap and cut out whole classes of
input before the Security framework sees it: directories that would be treated as bundles,
symlinks, files outside `Contents/MacOS`, and world-writable files. They are also the only checks
available in unsigned development builds. They move from launcher construction into `launch()`,
so they are re-done on every spawn.

### 5.4 Is the outer bundle seal enough?

No. [INFERENCE from APPLE facts, with an EMPIRICAL residue]:

1. The bundle seal (`_CodeSignature/CodeResources`) records the worker's identity as nested code.
   But nothing re-validates the seal when the app execs the worker. At exec the kernel enforces
   the **worker's own** signature (page hashes against its CodeDirectory). It does not check that
   the worker is the code the bundle sealed. A replaced worker with any valid signature,
   including an ad-hoc one, executes.
2. Hardened Runtime library validation constrains libraries mapped **into** a process. It does not
   constrain which executables that process launches.
3. Gatekeeper assesses the whole bundle at first launch of quarantined software. That is an
   install-time check, not a per-spawn guarantee, and it says nothing about modifications made
   after assessment. Newer macOS adds further launch-time checks and App Management protection
   for app bundles. [POLICY] We treat these as helpful but **do not rely on them**: they depend
   on the OS version and are outside our control.

So the seal and Gatekeeper protect the **distribution**, and the per-spawn requirement protects
the **execution**. The seal does matter at **startup**: there it authenticates the release-worker
identity record (5.8), which then pins the exact worker for every spawn.

### 5.5 TOCTOU between validation and exec

- Window: between step 3 (static validation of the file) and the kernel mapping the file in step
  4, the file could be replaced. [APPLE] says static validation is valid only while the code stays
  unmodified.
- Closure: step 5 validates the **running** process through the kernel's view of it. [APPLE] says
  `SecCodeCheckValidity` is secure against modification of the file-system source. A swap in the
  window therefore fails step 5, and the child is contained before it receives `ParentHello`, a
  request, or any PIN/PUAT material. Secrets are only ever sent after a successful handshake
  (ADR-009, M2).
- Residual (accepted, documented): in a swap race the attacker's binary has **already run** from
  exec until step 5 kills it. It runs as the same user, with stdin/stdout pipes and (in
  authentication mode) the fd-3 socket, but **with no secret yet sent on it**. To win the race the
  attacker must already be able to write to `Contents/MacOS/` as this user. That same write access
  already lets it replace the main executable instead, which the per-spawn check cannot see.
  SECURITY_MODEL treats same-user software as an in-scope actor but says native defences "are not
  a universal defense against every same-user process". So the race window gives the attacker
  nothing that bundle write access does not already give. It is still logged as an integrity
  failure.
- `kill` status: if the running worker carries the `kill` status, pages that fail validation later
  terminate it [APPLE]. [EMPIRICAL E4] checks whether Hardened Runtime alone sets it. If it does
  not, the worker is signed with `--options runtime,kill` and step 5 requires the bit.
- Optional hardening, evaluated during M7.2 implementation and **not** a gate: spawn the worker
  suspended (`posix_spawn` with Apple's `POSIX_SPAWN_START_SUSPENDED` attribute), run step 5 on the
  suspended process, then `SIGCONT` or kill and reap. That would remove even the brief execution in
  the race. It means replacing `std::process::Command` with a `posix_spawn` path, which also
  replaces the `pre_exec` fd-3 hand-off with `posix_spawn_file_actions_adddup2` plus
  `POSIX_SPAWN_CLOEXEC_DEFAULT`. That is a separate reviewable change with its own risks.
  [EMPIRICAL E6] checks whether the Security framework can validate a guest that is suspended
  before dyld has run.
- Launch constraints (macOS 14+: self, parent and responsible constraints in the worker's
  signature) were considered. A parent constraint would stop *other* processes launching our
  worker, which is not the threat here. Apple documents spawn constraints only for `launchd`
  jobs. The deployment target is 11.0. **Not adopted**; this can be revisited if the deployment
  floor rises.

### 5.6 Development builds and how release enforcement is guaranteed

[POLICY]

- `WorkerAuthenticity` is chosen at **compile time**: `DeveloperId { team: MACOS_RELEASE_TEAM_ID,
  identifier: "eu.fidomanager.desktop.fido-worker" }` in release-signing builds, and
  `UnsignedDevelopment` (steps 1–2 only) otherwise. The switch is a Cargo feature,
  `macos-release-signing`, which only the release packaging mode enables. It has no environment,
  argument, config file, Info.plist key or renderer path.
- An enforcing build's main binary embeds a fixed marker string that contains the Team ID
  constant, the release version and the source commit. The signing driver finds the marker by
  **byte search** (data only, D15) and refuses to sign if it is missing, or if its Team ID, version
  or commit differ from the pinned Team ID and the tag's version and commit. Verify re-checks it
  with `check-macos-bundle.py --signature developer-id`. So an ad-hoc-mode binary cannot be shipped
  under a Developer ID signature, an enforcing binary cannot be signed by the wrong team, and a
  binary cannot be signed under another release's tag.
- Ad-hoc CI keeps building non-enforcing bundles (PR CI has no identity). The enforcing code path
  is covered by: unit tests that the requirement **rejects** unsigned and ad-hoc fixtures (runnable
  in ad-hoc CI on macOS), a cdhash-pin test with two ad-hoc binaries (12, step 2), and the
  release verification job. That job runs `packaged_worker` with the enforcing verifier against
  the real signed worker, and against an ad-hoc copy and the previous release's signed worker as
  negatives (section 7.4).
- Renderer-boundary checks are extended to require exactly one `WorkerAuthenticity` construction
  site and exactly one Team ID constant. No Tauri command, event or capability may reference
  them. The renderer cannot influence the path, requirement, Team ID, identity or failure handling.

### 5.7 Failure behaviour

| Event | Behaviour |
| --- | --- |
| Worker missing, not a regular file, symlink, wrong directory, writable by others | `LaunchError::ExecutableRejected` (exists). Nothing spawned. |
| Static validation fails (unsigned, ad-hoc, bad signature, wrong identifier, wrong Team ID, not Developer ID Application, missing `runtime`, entitlements present, **cdhash or file SHA-256 ≠ `EXPECTED`**) | New `LaunchError::WorkerIdentityRejected`. Nothing spawned. |
| Dynamic validation fails after spawn, including a **running cdhash ≠ `EXPECTED`** | Contain (kill + reap) first, then `WorkerIdentityRejected`. No `ParentHello` written. |
| `ChildHello.build_id` ≠ `EXPECTED.build_id` | Contain first, then `WorkerIdentityRejected`. |
| Startup: requirement fails to compile, the app's self-check fails, the release-worker identity record is missing, malformed, unsealed or inconsistent with the seal, or names another release (5.8) | No launcher is built. The app runs without FIDO functionality and shows the integrity error. |

- [POLICY] `WorkerIdentityRejected` is **terminal for the app session**. The supervisor does not
  retry it under backoff, because a signature failure is not transient. FIDO functionality stays
  disabled until the app restarts. Filesystem integrity rejections (`ExecutableRejected` for a
  missing, replaced or unsafe worker) are terminal in the same way.
- [POLICY] The authenticity failure is **latched before containment is attempted**. If `contain()`
  then reports `NotContained` (today `LaunchError::NotContained`), the result carries both facts:
  the identity rejection stays latched and terminal, and the not-contained state is handled as it
  is today. No conversion between launch-error variants, supervisor errors or renderer states may
  clear or overwrite the latch.
- [POLICY] **M5/M6 recovery evidence is never rewritten by an authenticity failure.** When a
  replacement worker fails identity checks after an earlier mutation was left uncertain, that
  mutation stays `OutcomeUnknown`. It is never reclassified as `NotDispatched`, and the mutation
  journal and recovery barrier are kept. A regression test asserts this for credential deletion
  (M5) and, once it exists, Reset (M6) (section 12, step 4).
- The renderer gets one categorical state ("Fido Manager could not verify its own components.
  Reinstall it from the official release.") with no path, OSStatus, Team ID, cdhash or certificate
  detail. Diagnostics may record the OSStatus category locally.
- There is never a fallback to an unsigned, ad-hoc or differently signed worker, to a worker that
  passes only the publisher requirement, to the development mode, or to an in-process path (no
  in-process placement exists; ADR-009).

### 5.8 Exact app ↔ worker release binding

**Gap closed.** The publisher requirement (5.1) authenticates *who* signed the worker and *which
component* it is. On its own it would also accept any **older** worker that the same team signed
with the same identifier: an earlier release, a release candidate, or a version with a known bug.
Nothing re-checks the bundle seal at exec (5.4), and this design does **not** assume that the
seal's nested-code check would reject such a worker either: that depends on what the seal records
for nested code, which is not API (TN3127) [EMPIRICAL E17]. So a publisher-only check would let a
mixed app/worker pair run. D14 binds each app release to the one worker approved for it, and the
**exact cdhash pin** at startup (S7) and per spawn (5.3) is what rejects an older worker.

#### Record

`Contents/Resources/release-worker-identity.json`. It is at most 4 KiB, UTF-8 JSON, parsed with a
strict schema (unknown fields rejected, fixed hex lengths):

```json
{
  "schema": "fidomanager.release-worker-identity/1",
  "release": { "version": "X.Y.Z", "source_commit": "<40-hex>" },
  "worker": {
    "path": "Contents/MacOS/fido-worker",
    "identifier": "eu.fidomanager.desktop.fido-worker",
    "team_id": "XXXXXXXXXX",
    "build_id": "X.Y.Z+<40-hex>",
    "file_sha256": "<64-hex, SHA-256 of the signed worker file>",
    "slices": [
      { "arch": "arm64", "cdhash": "<40-hex CDHash>", "cdhash_sha256": "<64-hex CandidateCDHashFull>" }
    ]
  }
}
```

- `cdhash` is the value `codesign -d -vvv --arch <a>` prints as `CDHash`. It is also what
  `kSecCodeInfoUnique` returns and what the requirement-language `cdhash H"…"` term matches.
  [APPLE] TN3126: for code targeting macOS 10.12 or later there is one SHA-256 code directory, and
  `CDHash` is that hash truncated to 20 bytes. `cdhash_sha256` (`CandidateCDHashFull`) is recorded
  for provenance and is compared in Verify.
- [REPO] M7.1 packages a single host architecture (arm64 in CI) and refuses universal builds, so
  today `slices` has exactly one entry. The list form is kept so that an x86_64 or universal
  release (M7.1 gate 4) needs no schema change; the verifier still requires every slice to match.
- `build_id` is the worker's compiled-in build identity (version + source commit). The build job
  compiles it in, and the worker reports it in `ChildHello`. It is a consistency check, not the
  authority.

#### Creation (signing driver, between worker signing and bundle signing)

1. The driver signs the worker (3.2 step 1) and verifies it against the publisher requirement.
2. For each slice in `lipo -archs`, the driver reads `CDHash` and `CandidateCDHashFull sha256` from
   `codesign -d -vvv --arch`. It hashes the signed worker file. `version` and `source_commit` come
   from the workflow's tag context. `build_id` must equal `version+source_commit`, and the driver
   finds it in the worker binary by byte search; the worker is never executed (D15).
3. The driver writes the record in canonical form (UTF-8, fixed key order, no insignificant
   whitespace, trailing newline) and computes `RID` = SHA-256 of exactly those bytes.
4. The driver adds `FidoManagerReleaseWorkerIdentitySHA256 = RID` (64 lowercase hex) to
   `Contents/Info.plist`. The key must be absent before, and every other key must be unchanged.
5. The driver signs the bundle (3.2 step 3). The record becomes a sealed resource, and the
   `Info.plist`, including the digest, is bound to the signature.
6. After signing, and again after stapling, the driver re-parses the sealed record, checks it
   against the worker's actual `CDHash` in the signed bundle, and checks that the record's SHA-256
   equals the `Info.plist` digest. Any difference fails the job.

The expected identity is derived from the **signed worker as signed by the driver**, inside the
protected job. It is never derived at runtime from whatever worker file happens to be present.

#### Startup authentication in the app (once per process)

```text
S1  self = SecCodeCopySelf(); SecCodeCheckValidity(self, DYNAMIC_FLAGS(os), APP_REQ)
    selfUnique = kSecCodeInfoUnique(self)                         # kernel-backed running identity
S2  bundle = SecCodeCopyStaticCode(self)                          # [APPLE] for bundles: the whole bundle
    require kSecCodeInfoUnique(bundle main executable) == selfUnique
S3  SecStaticCodeCheckValidityWithErrors(bundle,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSRestrictSymlinks |
        kSecCSCheckNestedCode | noNetworkAccess, APP_REQ)
    plist = kSecCodeInfoPList from SecCodeCopySigningInformation(self, …)
            # [APPLE] "the contents of the secured Info.plist file as seen by Code Signing
            # Services"; which code object (self or bundle) and flags give the secured copy is
            # E16, a hard gate
    RID   = plist["FidoManagerReleaseWorkerIdentitySHA256"]
    require RID present, a string, exactly 64 lowercase hex characters
S4  BUF = read record once (O_RDONLY|O_NOFOLLOW, fstat regular file, size ≤ 4 KiB, read fully)
S5  require SHA-256(BUF) == RID                                    # constant-time compare
S6  parse BUF (the same buffer, never re-read) strictly; require identifier == const,
    team_id == TEAM_ID, release.version == compiled-in version,
    release.source_commit == compiled-in commit
S7  worker_static = SecStaticCodeCreateWithPath(worker path)
    require kSecCodeInfoUnique == BUF.slices[arch].cdhash, SHA-256(file) == BUF.file_sha256
S8  EXPECTED = immutable in-memory value parsed from BUF; WORKER_EXACT_REQ compiled from it;
    BUF is kept only as long as parsing needs it; the record file is never read again
```

Any failure means no launcher and FIDO disabled (5.7). Each of these fails closed: app identity
validation fails (S1–S3); the secured plist is missing, unreadable or not a dictionary; the digest
key is missing, not a string, or not 64 lowercase hex characters; the record cannot be opened as a
regular file of at most 4 KiB; `SHA-256(BUF) ≠ RID`; `BUF` fails the strict schema or names
another release; the worker on disk does not match `BUF`.

- **Trust argument.** (1) S1 validates the running main executable dynamically, through the
  kernel, against `APP_REQ`, so the code doing these checks is our Developer ID-signed app.
  (2) `Info.plist` is bound to that signature (the `Info.plist` hash is part of the code
  directory), and `kSecCodeInfoPList` is the plist "as seen by Code Signing Services", not a
  fresh `CFBundle` read. So `RID` is a value the signer put there, not something on disk now
  [APPLE for the key's definition; the exact secured-copy semantics are E16]. (3) The record is
  read **once** into `BUF`, and S5 proves `BUF` is exactly the record the driver hashed. (4) S6
  and S8 parse that same `BUF`. Nothing is re-read, so there is no window between the bytes that
  were authenticated and the bytes that are kept. (5) S7 checks the worker on disk against
  `EXPECTED` once at startup, and 5.3 checks it again on every spawn. The bundle-seal validation
  in S3 is kept as defence in depth. The authenticity of the bytes in `EXPECTED` no longer
  depends on it or on a read–validate–re-read pattern.
- **Race model.** A same-user actor that swaps the record file during startup can make S4 read
  attacker bytes. S5 then fails, because those bytes do not hash to the `RID` signed into the
  plist, unless the actor also controls the plist the code-signing layer reports, which E16
  requires it cannot. Swapping the genuine record back afterwards changes nothing, because the
  file is never read again. The validation plan exercises this race with a test hook (A21).
- **What is still assumed, and gated.** [EMPIRICAL E16, hard release gate] The implementation must
  show on a real Developer ID-signed bundle that the chosen mechanism returns the **signed** plist
  value. Required: (a) with the on-disk `Info.plist` edited after signing, the mechanism either
  still returns the signed value or the S1–S3 validation fails; it never returns the edited value
  as valid; (b) the value is available from the validated code object on 11.0–11.2 and on 11.3 or
  later. If no documented mechanism meets (a) and (b), M7.2 does not ship and the binding is
  redesigned. This ADR does not claim the exact API behaviour before then.
- [EMPIRICAL E17] Confirm on a real signed bundle that `SecCodeCopyStaticCode(self)` returns the
  bundle (Apple documents this for `SecCodeCopyPath`). Record, without relying on it, whether S3
  with `kSecCSCheckNestedCode` fails when (a) the record is edited, (b) the worker is replaced by
  another validly signed worker, and (c) both are replaced together. The rejection of (b) and (c)
  rests on S5–S7 and the per-spawn checks, not on S3.

#### How this stops an older, legitimately signed worker

| Substitution | Where it fails |
| --- | --- |
| Older worker W_old (same Team ID, same identifier, valid Developer ID signature) put in `Contents/MacOS/` after startup | per-spawn step 3: cdhash and file SHA-256 ≠ `EXPECTED`; and if raced in after step 3, step 5: running cdhash ≠ `EXPECTED` and `WORKER_EXACT_REQ` fails. Contained before `ParentHello` |
| W_old put in place before startup | S7: cdhash and file SHA-256 ≠ the authenticated record. No launcher. S3's nested-code check may also fail, but the design does not depend on it (E17) |
| W_old plus a record edited to name W_old's cdhash | Rejected at S3 (the resource seal is broken) or at S5 (the edited record does not hash to the `RID` in the signed `Info.plist`). Either is enough. No launcher, and no `EXPECTED` from the edited bytes |
| W_old plus an edited record swapped in only while S4 reads it | S5 fails on the swapped bytes; the genuine file is never re-read (race model above) |
| W_old plus its own release's record plus that release's seal (i.e. the whole old bundle's signature) | That is no longer a mixed bundle; it is the old **complete app** (below) |

#### Whole-application rollback (explicitly separate)

D14 prevents **mixed** app/worker releases. It does **not** stop someone deliberately installing an
older, complete, legitimately signed and notarized `Fido Manager.app`. That app carries its own
record, which pins its own worker, and it is internally consistent. Rollback protection for whole
applications needs a monotonic security floor: a persisted minimum version, or signed update
metadata once an updater exists (ADR-006/ADR-016). It also has to survive same-user software
deleting that state (SECURITY_MODEL). It is out of scope for M7.2. Older vulnerable releases are
handled by withdrawal and advisories (section 11).

#### Alternatives considered for the binding

| Alternative | Why not |
| --- | --- |
| Derive the expected worker identity from the worker file at runtime | Circular: it accepts whatever worker is present |
| Compile the worker cdhash into the main binary | The worker cdhash exists only after Developer ID signing. Embedding it would mean rebuilding or patching candidate code in the credential-bearing job, which D15 forbids |
| Rely only on the bundle seal's nested-code entry | The seal's internal format is not API (TN3127), and the per-spawn **dynamic** check needs the value in memory. The record is the explicit carrier |
| Read–validate–re-read of the record against the bundle seal (revision 3) | Does not prove the bytes kept in memory are the bytes the seal validated; a timed swap could separate them. Replaced by the plist digest (S3–S5) |
| Put the whole record in `Info.plist` | Possible, because `Info.plist` is bound to the signature. Only the 64-character digest goes there: it keeps the plist that Tauri and LaunchServices interpret almost unchanged, and the record stays easy to generate and audit |

## 6. Apple credential model and secret isolation

### 6.1 Credential types (names only; no values are created or requested here)

| Secret (GitHub Environment `macos-release`) | Content | Used by |
| --- | --- | --- |
| `MACOS_DEVID_APP_P12_BASE64` | Developer ID **Application** certificate and private key, PKCS#12, base64 | sign job only |
| `MACOS_DEVID_APP_P12_PASSWORD` | PKCS#12 import password | sign job only |
| `MACOS_NOTARY_API_KEY_P8_BASE64` | App Store Connect API private key (`AuthKey_<id>.p8`), base64 | sign job only |
| `MACOS_NOTARY_API_KEY_ID` | API key ID | sign job only |
| `MACOS_NOTARY_API_ISSUER_ID` | API issuer UUID | sign job only |

| Environment **variable** (not secret) | Content |
| --- | --- |
| `MACOS_DEVID_APP_SHA1` | SHA-1 fingerprint of the approved Developer ID Application certificate |
| `MACOS_TEAM_ID` | Team ID. Must equal the signing driver's pinned Team ID and the Team ID in the candidate's enforcing marker (which comes from the source constant `MACOS_RELEASE_TEAM_ID`), or the job fails |

- Names deliberately avoid `APPLE_*` and `TAURI_SIGNING_*`. Tauri's bundler signs or notarizes on
  its own when such variables exist, and `package-macos.py` refuses to run when they are set
  [REPO]. Developer ID signing is done only by the pinned signing driver (6.4).
- [APPLE] `notarytool` accepts `--key <p8> --key-id <id> --issuer <uuid>` (TN3147). [POLICY] We
  use an API key rather than an Apple ID with an app-specific password: it is not tied to a
  person's Apple ID, can be revoked on its own, and needs no 2FA plumbing. The key gets the
  lowest App Store Connect role Apple accepts for notarization. [EMPIRICAL E10] Confirm which role
  that is when the key is created.
- [POLICY] No Developer ID **Installer** certificate (no `.pkg`). No Apple Distribution or Apple
  Development identity is ever present in the release keychain. The signer refuses non-Developer
  ID identities [REPO].

### 6.2 GitHub Environment configuration

[GITHUB] Secrets stored in an environment "are only available to workflow jobs that reference the
environment", and with required reviewers "a job cannot access environment secrets until one of
the required reviewers approves it." There can be up to six reviewers, and *prevent self-review*
stops the person who triggered the run from approving it. Environment secrets and required
reviewers are available on all plans for **public** repositories. On GitHub Free a private
repository loses environment secrets.

[POLICY]

- `macos-release` holds the secrets. It has a required reviewer, and its deployment rule allows
  **only tags matching `v*`**. Branches cannot deploy to it.
- `macos-release-publish` and `macos-release-public` hold no secrets. Each has its own required
  reviewer. They gate the job that creates and verifies the draft release, and the job that
  publishes it (7.6).
- *Prevent self-review* is turned on as soon as a second maintainer exists. With a single
  maintainer, the approval is still an explicit human step that cannot be skipped.
- Tag ruleset, `main` ruleset, CODEOWNERS, immutable releases and the signer repository's
  protection are listed together in 7.5.
- If the repository becomes private on a plan without environment secrets, the secrets resolve to
  empty strings. The sign job's first step asserts that every secret is non-empty and fails if any
  is missing (section 10).
- The environment reviewer for `macos-release` approves only if the run's tag, peeled commit,
  workflow SHA and signer SHA (from the `preflight` summary) are the ones expected.

### 6.3 Ephemeral keychain lifecycle (sign job only)

```sh
umask 077
KC="$RUNNER_TEMP/fm-release-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT.keychain-db"
KC_PASS="$(openssl rand -hex 32)"                     # never printed, never persisted
security create-keychain -p "$KC_PASS" "$KC"
security set-keychain-settings -lut 1800 "$KC"        # auto-lock after 30 min
security unlock-keychain -p "$KC_PASS" "$KC"
base64 -d <<<"$P12_B64" > "$RUNNER_TEMP/devid.p12"
security import "$RUNNER_TEMP/devid.p12" -k "$KC" -f pkcs12 -P "$P12_PASS" -T /usr/bin/codesign
rm -f "$RUNNER_TEMP/devid.p12"
security set-key-partition-list -S apple-tool:,apple: -s -k "$KC_PASS" "$KC" >/dev/null
security find-identity -v -p codesigning "$KC"        # must list exactly one identity, == $MACOS_DEVID_APP_SHA1
# … sign / notarize …
# always():
security delete-keychain "$KC"; rm -f "$RUNNER_TEMP"/*.p8 "$RUNNER_TEMP"/devid.p12
```

- The API key `.p8` is written to `$RUNNER_TEMP` with mode 0600, passed by path with `--key`, and
  deleted in `always()`. `notarytool store-credentials` is **not** used, so nothing lands in the
  login or data-protection keychain.
- The driver asserts that the imported certificate's Team ID (`subject.OU`) equals
  `MACOS_TEAM_ID`, which equals its pinned Team ID, and that the fingerprint equals
  `MACOS_DEVID_APP_SHA1`.
- [GITHUB] GitHub-hosted macOS runners give each job a fresh VM. [POLICY] Self-hosted runners are
  never used for any release job.
- Secrets are exposed through `env:` on **the individual steps** that use them, not job-wide.
  Shell tracing (`set -x`) is forbidden in those steps.

### 6.4 Secret isolation: the signing environment executes no candidate code

**Principle (D15).** Inside `sign-notarize`, the candidate app is **data**. The job holding the
Developer ID key, the notary key and the keychain must not execute any of the following:

- `fido-worker` or `fidomanager-app`, in any mode;
- any script from the candidate commit: `sign-macos-bundle.py`, `check-macos-bundle.py`,
  `package-macos.py`, and M7.1's `build-libfido2.py`, `build-native-deps.py`,
  `verify-libfido2-linkage.py`, `test-native-deps.py`, `test-credman-linkage.py` and
  `test-macos-bundle-check.py`, test scripts, `.mjs` checkers;
- Cargo, rustc or build scripts, proc macros, `pnpm`/`npm`/`npx` or any lifecycle hook,
  package-manager installs of any kind (including `brew`). [REPO] Since M7.1,
  `crates/fido-libfido2/build.rs` runs `python3 scripts/build-libfido2.py build`, which configures
  and compiles OpenSSL, libcbor and libfido2 and runs a compiled OpenSSL probe. Any `cargo build`
  therefore executes candidate Python and native build code;
- repository test tooling;
- local or reusable workflows or composite actions taken from the candidate commit
  (`uses: ./…`);
- any interpreter with the candidate tree as its working directory, on `PATH` or on an import path.

It does not even check out the candidate commit. It receives the candidate only as the
digest-verified `build-output.tar` (7.2). The driver's own code extracts it under the contract in
6.5 into a fresh `$RUNNER_TEMP/candidate/`, and from then on only reads it, signs it and packages
it. `D0` proves the archive's bytes are the build job's output. It does not make the contents safe
to extract, which is why 6.5 exists.

**What runs instead.** A minimal **signing driver** and Apple OS tools, all called by absolute path:
`/usr/bin/codesign`, `/usr/bin/security`, `/usr/bin/ditto`, `/usr/bin/hdiutil`,
`/usr/bin/xcrun notarytool`, `/usr/bin/xcrun stapler`, `/usr/bin/lipo`, `/usr/bin/shasum`,
`/usr/bin/plutil`, `/usr/bin/base64`, `/usr/bin/openssl` (only for `rand`).

- `PATH=/usr/bin:/bin:/usr/sbin:/sbin`. `DEVELOPER_DIR` is set to the Xcode path that the driver's
  pinned config names, so `xcrun` resolves Apple's tools and nothing else.
- The driver is one stdlib-only Python 3 file plus a small config file. It runs as
  `/usr/bin/python3 -I -S <driver>/sign_macos.py …`: `-I` ignores `PYTHON*` variables and the user
  site, and `-S` skips `site`. Its working directory is the driver checkout, never the candidate
  tree. It does data-only checks (tree walk, Mach-O magic, `plistlib`, byte search for the
  enforcing marker and `build_id`). It parses `codesign -d` output, signs, writes the identity
  record (5.8), notarizes, staples, builds the DMG and computes digests.
- Behavioural and structural checks that **execute** candidate code or candidate scripts run only
  in `build` (before signing, ad-hoc) and `verify` (after signing, fresh VM, no secrets). That
  includes `check-macos-bundle.py`, the packaged worker handshake and Gatekeeper/launch checks
  (section 4).

**How the driver is pinned independently of the candidate (recommended model, S1).**

- The driver lives in a **separate repository**, proposed as `mbzbugsy/fidomanager-release-signer`.
  That repository has a protected default branch: PR review required, CODEOWNERS, no force-push,
  no deletion. It holds only the driver, its config (Team ID, identifiers, expected tree, Xcode
  path) and its tests.
- `release-macos.yml` checks it out with `actions/checkout@<full SHA>`, using
  `repository: mbzbugsy/fidomanager-release-signer` and `ref: <40-hex commit SHA>` into
  `$RUNNER_TEMP/signer`. That SHA is a literal in the workflow file. `preflight` rejects any
  non-40-hex pin. The driver also asserts that its own `git rev-parse HEAD` equals the pin and that
  this commit is reachable from the signer repository's protected default branch (GitHub REST
  compare).
- Changing the driver therefore takes two reviewed changes: a PR in the signer repository, then a
  CODEOWNERS-reviewed PR in this repository that bumps the pin. Changes to the candidate's code,
  dependencies or build scripts cannot alter the driver's bytes. The build job's output cannot
  reach the driver except as signed data.
- The authorization tuple (7.6) records the signer repository and pinned SHA.

**What the trust in the driver still rests on (stated plainly).** For a tag push, GitHub runs the
workflow file **as it exists at the tagged commit**. So `release-macos.yml`, including the signer
pin, is part of the release *control plane*. It is trusted through repository governance, not
through artifact checks:

- a ruleset on `main` that requires PR review, blocks force-pushes and requires CODEOWNERS review
  for `.github/workflows/**`, `.github/CODEOWNERS` and the release documents (this ADR and the
  validation plan);
- a tag ruleset under which only maintainers can create `v*` tags, and tags can never be updated or
  deleted;
- `preflight`, which proves the tag's commit is on `main`, and the environment reviewer, who sees
  the run's workflow path and commit before approving the secret-bearing job.

**Stronger option (S2, not required for M7.2).** Move the two credentials out of GitHub
Environment secrets into an external secret store that issues them only to a GitHub OIDC token
whose `job_workflow_ref`/`job_workflow_sha` name the signer repository's reusable workflow at an
approved SHA. [GITHUB] documents these claims for jobs that use a reusable workflow. Even a modified
caller workflow could then not obtain the key without invoking exactly the approved signer
revision. This needs external infrastructure and is left as a future hardening.

**Rejected (S0): a repository-owned driver taken from the candidate commit.** It would be modified
by the same PR flow as the code it signs, and would offer no independence from the candidate. If
the maintainers ever choose to keep the driver in this repository, the minimum boundary is: a
dedicated path such as `release/signer/**` under CODEOWNERS and a ruleset; the workflow checking
out that path **at a separately pinned 40-hex SHA** (not `GITHUB_SHA`); and `preflight` failing if
the pinned commit is not on `main`. That boundary is weaker than S1, because one repository's
review governs both.

**Other isolation rules** [POLICY]:

- PR workflows (`pull_request`) never reference either environment. `pull_request_target` and
  `workflow_run` are not used for anything release-related.
- Release jobs use no `actions/cache`. Cache entries written by `main` pushes are readable from tag
  runs, and a poisoned cache must not reach a signed artifact.
- Every external action is pinned to a full commit SHA. The repository setting "Require actions to
  be pinned to a full-length commit SHA" is turned on. [GITHUB] says that setting still allows
  reusable workflows by tag, so `preflight` also rejects any `uses:` in `release-macos.yml` that is
  not `owner/repo/…@<40-hex>`. The release workflow uses only these external actions, each at a
  full 40-hex commit SHA: `actions/checkout`, `actions/upload-artifact`,
  `actions/download-artifact`, `actions/attest-build-provenance`, and
  `actions/create-github-app-token`. The last is used **only** in `policy-check` (7.1), with
  `permission-administration: read` and the token limited to this repository. Adding any other
  action is a workflow change under CODEOWNERS review and changes `workflow.sha` in the tuple.
  It calls no reusable workflows except, under S2, the signer's own at a pinned SHA.
- `attest` and the publication jobs also run no candidate code: no candidate checkout, only pinned
  actions, `gh`/`curl` and `shasum`.
- Every `actions/checkout` step in `release-macos.yml` sets `persist-credentials: false`, as the
  existing `ci.yml` already does [REPO]. `preflight` fails if any checkout step lacks it. Jobs that
  call the API get the token explicitly in the one step that needs it.

### 6.5 Handoff archive and extraction contract (signing boundary)

[POLICY] One format: **`build-output.tar`, an uncompressed POSIX ustar archive containing only
regular files and directories.** The build job creates it from a staging directory with the
system `tar` (`--format ustar`, no extended attributes, ACLs or macOS metadata). The signing
driver never runs `tar`, `ditto`, `unzip` or any other general extractor on it. It parses the
headers with stdlib Python (`tarfile`, read-only, used only to enumerate members and stream
their bytes) and writes every file itself. No compression means there is no decompression bomb,
and the byte bound below applies directly.

Expected layout (single root):

```text
build-output/Fido Manager.app/**          the ad-hoc bundle (M7.1 tree, section 3.1)
build-output/package-summary.json
build-output/build-identity.json
```

The SBOM inputs are a **separate** artifact (`sbom-inputs.tar`, its own digest `D0s`), consumed
only by `verify`. The signer never receives them.

Rules, all checked by the driver **before any byte is written to disk** (it reads the full header
list first, then validates, then materializes):

1. `D0` matches, and the archive is at most **256 MiB**.
2. At most **1024** entries, and the sum of regular-file sizes is at most **256 MiB**.
3. Entry types are only regular file (`0`) and directory (`5`). Symlinks, hard links, character
   and block devices, FIFOs, contiguous files, sockets, and all pax, GNU long-name and other
   extended headers are rejected.
4. Each name is relative and UTF-8, with no leading `/`, no `..`, no `.` component, no empty
   component (`//`), no NUL or control characters, and no backslash. Every path is under
   `build-output/` and matches the layout above. Anything outside the three expected subtrees
   fails.
5. No duplicate paths, including paths that collide after Unicode normalization (NFD) or case
   folding, because the macOS volume may be case-insensitive. A file and a directory with the same
   path also count as a collision.
6. Modes are reduced to `0644` (or `0755` when an execute bit is set) for files and `0755` for
   directories. setuid, setgid and sticky bits fail the archive. Owners, groups and timestamps are
   ignored.
7. Materialization goes into a directory the driver has just created empty with `mkdtemp` under
   `$RUNNER_TEMP`. Parent directories are created with `mkdir` relative to an open directory fd.
   Files are opened with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` relative to their parent's fd. So
   the driver never follows a pre-existing link and never writes outside the candidate root.
8. Afterwards the driver walks the tree with `lstat` and confirms that it contains exactly the
   entries it wrote, all regular files or directories. It then runs the data-only pre-checks
   (7.4 step 3).

Any violation fails the job before the keychain is created. `verify` applies the same contract
when it extracts `build-output.tar` for the E19 comparison. Hostile-archive cases are part of the
driver's own test suite and of the validation plan (Part E).

## 7. Protected release workflow

A new workflow, `.github/workflows/release-macos.yml`. It is **not** created by this ADR.

### 7.1 Trigger and preconditions

```yaml
on:
  push:
    tags: ['v[0-9]+.[0-9]+.[0-9]+*']
permissions: {}                      # every job grants its own minimum
concurrency: { group: release-${{ github.ref }}, cancel-in-progress: false }
```

The `preflight` job (ubuntu; `contents: read`, `checks: read`; no candidate code beyond reading
files with `git` and `jq`) establishes the release identity and its **eligibility**. Being an
ancestor of `main` is a sanity condition, not the authorization.

Release eligibility, all required:

- the ref is an **annotated** tag object (`git cat-file -t` → `tag`). It records the tag object
  SHA and the **peeled** commit SHA (`git rev-parse "$TAG^{commit}"`), and requires the peeled
  commit to equal `GITHUB_SHA`;
- the tag has never been used: no release exists for it (releases API). [GITHUB] Draft releases
  are listed only to callers with push access, which `preflight`'s `contents: read` token does
  not have, so the check that also covers drafts is `publish-draft` step 3 (7.6). The
  tag ruleset forbids updating or deleting tags, and every later job re-checks that the tag still
  peels to the same commit. With immutable releases [GITHUB], a deleted release's tag name cannot
  be reused either;
- the peeled commit is on reviewed `main` history (an ancestor of `origin/main`). It does not have
  to be the current head of `main`: releasing an earlier approved commit is allowed;
- **CI succeeded for that exact commit.** The check runs of the `CI` workflow (`ci.yml`, which
  runs on pushes to `main` [REPO]) for exactly the peeled commit SHA have all concluded `success`,
  with the job names `validation`, `macos-native-auth` and `macos-packaging` all present (checks
  API, `checks: read`). A missing, pending, skipped or failed run stops the release;
- the tag version equals `tauri.conf.json` `version`, the Cargo workspace version and
  `package.json` `version`;
- `github.workflow_ref` is `mbzbugsy/fidomanager/.github/workflows/release-macos.yml@refs/tags/<tag>`,
  and `github.workflow_sha` equals the peeled commit. The workflow revision is therefore the one
  reviewed with that commit on `main`, and it appears in the tuple the human approves;
- every `uses:` in the workflow is pinned to a 40-hex SHA, every checkout sets
  `persist-credentials: false`, and the signer pin is a 40-hex SHA (6.4);
- **human release authorization names the exact tuple.** The `macos-release` environment
  reviewer approves only after checking the `preflight` summary, which shows the tag, tag object,
  peeled commit, workflow ref and SHA, signer SHA, CI result and run ID. The same tuple is
  re-shown and re-approved for `macos-release-publish` and `macos-release-public`, and it is
  written into the authorization record (7.6).

Its outputs (tag, tag object SHA, peeled commit, version, arch, workflow ref and SHA, signer SHA,
CI check-run IDs) are the **release identity**. Every job checks out, downloads or verifies
against these values and nothing else.

**Immutable-release policy check (separate job, `policy-check`).** [GITHUB] The repository
endpoint `GET /repos/{owner}/{repo}/immutable-releases` returns `200` with
`{"enabled": true|false, "enforced_by_owner": …}`, or `404` when immutable releases are not
enabled. The caller "must have admin read access to the repository", and the `GITHUB_TOKEN`
permission list has **no** administration scope. So `preflight`'s token cannot make this call,
and granting the whole workflow more would be wrong. Instead:

- a dedicated `policy-check` job runs on ubuntu with `permissions: {}` and **no checkout at
  all**, so no candidate code can run beside the credential;
- it uses environment `macos-release-policy` (tag-only deployment). That environment holds the
  only credential the check needs: the private key of a dedicated GitHub App installed on this one
  repository with the single permission **Administration: read**. The job mints a short-lived
  installation token limited to that repository and permission with
  `actions/create-github-app-token` pinned to a full commit SHA (6.4), makes the one API call with `curl`, and discards the token. A fine-grained personal access token
  with only Administration: read on this repository is the fallback if an App is not wanted; it is
  long-lived, so it is second choice;
- pass only on HTTP `200` with `enabled == true`. A `404`, any other status, a network error, a
  missing secret or a malformed body is terminal for the run;
- its single output (`immutable_releases=true`, plus the response body's SHA-256) is a required
  input (`needs:`) of `verify`, which records it in the authorization record, and of
  `publish-draft` and `publish-final`, which re-check it. After
  publication, `gh release verify` and the release object's `immutable` field confirm it on the
  actual release (7.6).

### 7.2 Job graph

```text
preflight ─► build ─► sign-notarize ─► verify ─► attest ─► publish-draft ─► [human: Part B matrix] ─► publish-final
 (ubuntu)   (macOS,   (macOS, env       (macOS,   (ubuntu,  (ubuntu, env       on the draft's assets      (ubuntu, env
  contents,  no env,   macos-release;    no env,   id-token,  macos-release-                              macos-release-public,
  checks:    no        driver @ pinned   no        attest-    publish,                                    contents: write)
  read)      secrets)  SHA; candidate    secrets)  ations)    contents: write)
                       = data only)                              ▲                                          ▲
policy-check ────────────────────────────────────────────────────┴──────────────────────────────────────────┘
 (ubuntu, env macos-release-policy, permissions: {}, no checkout; App token with Administration: read only)
```

| Job | Runs | Produces | Never |
| --- | --- | --- | --- |
| `build` | Checks out the peeled commit. Mirrors the M7.1 `macos-packaging` CI job [REPO] with release additions: Node 24.21.0, pnpm 10.17.1, `pnpm install --frozen-lockfile`; `brew install cmake pkg-config` (build tools only; versions recorded); `scripts/build-libfido2.py fetch` (the three locked source archives into `target/native-sources/`, SHA-256-checked); `scripts/test-native-deps.py`; Rust 1.98.1 from `rust-toolchain.toml`; `package-macos.py --dmg` in its release flavor (native builds through `build.rs`, link-map provenance, `minos` 11.0, notices, ad-hoc seal, checker with worker execution, mounted-DMG re-check); `verify-libfido2-linkage.py` on the release worker; `test-macos-bundle-check.py`; `packaged_worker` (ad-hoc, non-enforcing path); clean-tree check; SBOM inputs | `build-output.tar` (ustar, regular files and directories only, layout in 6.5) and its SHA-256 `D0` as a job output: the ad-hoc `.app`, `package-summary.json` and the `build-identity.json` that the linkage verifier read. Separately `sbom-inputs.tar` and `D0s`, for `verify` only. `upload-artifact` retention 1 day. The ad-hoc DMG is a Build check only and is not handed off | sees secrets; signs with Developer ID; uses caches |
| `sign-notarize` | **No candidate checkout.** Checks out the signer repo at the pinned SHA; downloads `build-output.tar` and verifies `D0` before extracting; runs the driver (6.4): data-only pre-checks, ephemeral keychain, sign worker, write the identity record, sign bundle, post-sign data checks, app notarization and staple, DMG build, sign, notarization and staple, digests `D1`–`D6` (9.4) | stapled app zip, stapled DMG, both notary logs, driver report with every digest | executes candidate binaries or scripts; runs pnpm/cargo/npm; uploads anything if any step failed |
| `verify` | Fresh VM, checks out the peeled commit (`persist-credentials: false`), no secrets. Verifies `D3`, `D5` and `D6` against the driver report; quarantine-simulated assessment (validation plan, Part A); `stapler validate`; `spctl`; deep strict verify; publisher and exact requirements; record ↔ worker checks; `check-macos-bundle.py --signature developer-id --stapled`; builds and runs `packaged_worker` **with the enforcing verifier** against the signed worker (positive), plus an ad-hoc copy and, from the second release on, the previous release's worker (negatives); generates the SBOM, the manifest, then `SHA256SUMS`, then `release-authorization.json` last (7.6) | evidence, SBOM, manifest, `SHA256SUMS`, authorization record; **job output `D7`** = SHA-256 of the authorization record, plus `run_id`/`run_attempt` | has secrets |
| `attest` | Checks the authorization record's SHA-256 equals `needs.verify.outputs.D7`, then `actions/attest-build-provenance` over the DMG, the app zip, the SBOM, the manifest, `SHA256SUMS` and the authorization record. [GITHUB] available for public repositories | Sigstore-backed provenance attestations; an attestation bundle file | runs without `verify` passing |
| `publish-draft` | Reviewer approval; requires `policy-check`. Authenticates the authorization record first (7.6: SHA-256 = `D7` from job outputs, attestation verified against the exact run), then verifies every asset against it; requires that **no** release, draft or published, exists for the tag yet; creates a **draft** release on the tag; uploads; **downloads every asset back from that draft, by its ID, through the API and re-verifies** (7.6) | draft release, verified; **job output `draft_release_id`** (the created release's ID) | publishes; overwrites an existing release or asset; takes an expected digest from a downloaded file |
| `publish-final` | Separate reviewer approval, given after the Part B matrix passes on the draft's assets; requires `policy-check` and `publish-draft`. Requires the **exact** draft `needs.publish-draft.outputs.draft_release_id` to exist, still be an unpublished draft on the exact tag, and match the approved tuple; re-authenticates the authorization record against `D7` and its attestation; re-verifies the exact asset set and every asset; publishes that draft; then runs post-publication verification (7.6) | public, immutable release | publishes any release other than `draft_release_id`; publishes anything whose bytes differ from the authenticated authorization record by even one digest |

The handoff between jobs is digest-bound [POLICY]. Each producer writes the SHA-256 of its output to
a job output and to the driver report. Each consumer recomputes it before using the bytes. A
mismatch is a hard failure, never a warning. `actions/download-artifact`'s own integrity
reporting is recorded but is never the binding check. This is not a handoff from an untrusted
producer: every producer is a job of the same protected run, built from the reviewed tag. The
digest protects against an artifact being swapped or corrupted between jobs.

### 7.3 Why build in a separate unprivileged job

The constraint is to rebuild inside the protected workflow and never sign a PR artifact. D7 and D8
satisfy it: the bundle is rebuilt from the tagged commit in this workflow. The build and sign steps
are split into two jobs because the build runs a large third-party code surface (npm lifecycle
scripts, Cargo build scripts, proc macros, native configure scripts). If that code ran in the job
holding the PKCS#12 and API key, it could read them. With the split, the signing VM never executes
it. D15 goes further: the signing VM executes nothing from the candidate at all, not even its own
release scripts. The digest stops anything other than the build job's own output from being signed.

### 7.4 Sequence (sign-notarize and verify)

```text
sign-notarize   (driver @ pinned SHA; candidate = data; OS tools by absolute path)
  1  assert secrets non-empty; assert MACOS_TEAM_ID == driver-config Team ID
  2  verify build-output.tar SHA-256 == D0 (needs.build); extract with the driver's own code under
     the 6.5 contract (all headers validated first) into a fresh mkdtemp candidate directory
  3  data-only pre-checks: exact tree (M7.1 allowlist), Mach-O set, no symlinks, no identity
     record yet, no Frameworks/, Info.plist fields (plistlib; LSMinimumSystemVersion 11.0),
     notices file present, digests equal package-summary.json, enforcing marker bytes:
     Team ID + version + commit match
  4  ephemeral keychain; assert exactly one identity == MACOS_DEVID_APP_SHA1, OU == Team ID
  5  codesign worker (3.2 step 1); publisher requirement satisfied; record D1 = worker file SHA-256
     and per-arch CDHash/CandidateCDHashFull
  6  write Contents/Resources/release-worker-identity.json (5.8); RID = its SHA-256;
     add FidoManagerReleaseWorkerIdentitySHA256 = RID to Info.plist (only that key changes)
  7  codesign bundle (3.2 step 3); codesign --verify --strict --deep; post-sign data checks
     (section 4 "Driver" rows: chain, timestamp, runtime, zero entitlements, identifiers,
     record ↔ worker CDHash, record SHA-256 == Info.plist digest, exact requirement)
  8  ditto -c -k --keepParent app → app-signed.zip; D2 = SHA-256 (notarization input #1)
  9  notarytool submit app-signed.zip --key … --wait --timeout 45m --output-format json
 10  notarytool log <id> notary-app.json; enforce acceptance (8.2) incl. log sha256 == D2
 11  stapler staple app; stapler validate app; re-check record ↔ worker CDHash (unchanged)
 12  ditto -c -k --keepParent stapled app → FidoManager-X.Y.Z-<arch>.app.zip; D3 = SHA-256
 13  stage dir: ditto stapled app + Applications symlink
     hdiutil create -format UDZO -srcfolder stage -volname "Fido Manager" dmg; hdiutil verify
 14  codesign DMG (3.2 step 4); codesign --verify --strict -vvv dmg; D4 = SHA-256 (input #2)
 15  notarytool submit dmg --wait --timeout 45m; log → notary-dmg.json; enforce acceptance
     incl. log sha256 == D4
 16  stapler staple dmg; stapler validate dmg; D5 = SHA-256 of the final DMG
 17  D6 = SHA-256 of each notary log; driver report (all of D0–D6, submission IDs, cdhashes)
 18  upload: stapled app zip (D3), DMG (D5), logs, driver report
 19  always(): delete keychain and key files
verify (fresh VM, no secrets)
  A  verify D3/D5/D6 against the driver report; quarantine-simulated DMG; mount read-only;
     copy app out with ditto
  B  stapler validate, spctl (8.4), codesign deep strict, publisher + exact requirements,
     record ↔ worker (CDHash and CandidateCDHashFull), record SHA-256 == Info.plist digest,
     checker --stapled; extract build-output.tar under 6.5 and run the E19 comparison
  B2 remove-signature comparison of the signed worker with the Build-output worker (section 4)
  C  cargo test -p fido-worker --test packaged_worker -- --ignored with the enforcing verifier:
     positive (the signed worker); negatives (ad-hoc copy; previous release's signed worker,
     from release 2 on)
  D  SBOM, manifest; then SHA256SUMS over the payload/evidence set; then
     release-authorization.json last; D7 = its SHA-256 → job output (7.6)
```

### 7.5 Release control-plane protection

[POLICY] These are one-time repository settings, documented in the M7.2 implementation PR. They
are not changed by this ADR:

- the **immutable releases** repository setting is on. [GITHUB] says that for an immutable release,
  "the assets and associated Git tag cannot be changed after publication", the tag "cannot be
  deleted while the release exists", a deleted release's tag name "cannot be reused", and
  publishing "automatically generates a release attestation";
- tag ruleset: only maintainers create `v*`; no update, no deletion, no force-push;
- `main` ruleset: PR review required; CODEOWNERS review required for `.github/**`, the release
  documents and the release-related scripts;
- the signer repository is protected as in 6.4;
- Actions setting "Require actions to be pinned to a full-length commit SHA" is on, and the
  `preflight` `uses:` scan covers reusable workflows (6.4);
- environments: `macos-release` (secrets, tag-only deployment, required reviewer);
  `macos-release-publish` and `macos-release-public` (no secrets, required reviewer each,
  tag-only deployment); `macos-release-policy` (only the policy-check App key, tag-only
  deployment, used by the `policy-check` job alone, 7.1);
- the policy-check GitHub App is installed on this repository only, with Administration: read
  and no other permission.

### 7.6 Publication authorization and final asset verification

`verify` writes `release-authorization.json`. It is the **authorization tuple**: the only
description of what may be published. It does **not** authenticate itself (see "Root of trust"
below).

**Acyclic construction** (all in `verify`, in this order):

1. The final payload and evidence assets exist: stapled DMG (`D5`), stapled app zip (`D3`), SBOM,
   `release-manifest.json`, `notary-app.json`, `notary-dmg.json`.
2. `SHA256SUMS` is written over **exactly that set**. It does not list itself, and it does not list
   `release-authorization.json`, which does not exist yet.
3. `release-authorization.json` is written **last**. It contains the tuple, the SHA-256 of every
   payload/evidence asset and the SHA-256 of `SHA256SUMS`.
4. `D7` = SHA-256 of `release-authorization.json`, published as a `verify` **job output**.

The authorization record is never listed in `SHA256SUMS`. No other scheme that lists it is
introduced, so nothing is circular. The attestation bundle that `attest` produces afterwards is
self-authenticating through Sigstore and is listed in neither file.

The final release asset set is therefore: the payload/evidence assets, `SHA256SUMS`,
`release-authorization.json`, and the attestation bundle (`release-attestations.sigstore.jsonl`).

```jsonc
{
  "schema": "fidomanager.release-authorization/2",
  "repository": "mbzbugsy/fidomanager",
  "tag": "vX.Y.Z", "tag_object_sha": "<40-hex>", "commit_sha": "<40-hex, peeled>",
  "version": "X.Y.Z", "arch": "arm64", "deployment_target": "11.0",
  "eligibility": {                                   // 7.1; what the human approved
    "on_main": true,
    "ci": { "workflow": ".github/workflows/ci.yml", "head_sha": "<commit_sha>",
            "check_runs": { "validation": 0, "macos-native-auth": 0, "macos-packaging": 0 },
            "conclusion": "success" },
    "immutable_releases": { "enabled": true, "response_sha256": "<from policy-check>" }
  },
  "workflow": { "ref": "mbzbugsy/fidomanager/.github/workflows/release-macos.yml@refs/tags/vX.Y.Z",
                "sha": "<github.workflow_sha == commit_sha>", "run_id": 0, "run_attempt": 1 },
  "signer": { "repository": "mbzbugsy/fidomanager-release-signer", "sha": "<40-hex>" },
  "worker_identity": { "cdhash": { "arm64": "<40-hex>" }, "file_sha256": "<64-hex>",
                       "record_sha256": "<RID>" },
  "assets": {
    "FidoManager-X.Y.Z-arm64.dmg":            { "sha256": "<D5>", "size": 0 },
    "FidoManager-X.Y.Z-arm64.app.zip":        { "sha256": "<D3>", "size": 0 },
    "FidoManager-X.Y.Z-arm64.cdx.json":       { "sha256": "…", "size": 0 },
    "release-manifest.json":                  { "sha256": "…", "size": 0 },
    "notary-app.json":                        { "sha256": "…", "size": 0 },
    "notary-dmg.json":                        { "sha256": "…", "size": 0 }
  },
  "sha256sums": { "sha256": "…", "size": 0 },
  "notarization": { "app_submission": "…", "dmg_submission": "…" }
}
```

**Root of trust for publication.** A downloaded `release-authorization.json` never supplies its
own expected digest. Before any job trusts it, that job:

1. recomputes its SHA-256 and requires it to equal `D7` taken from `needs.verify.outputs` (trusted
   job outputs of the same run, carried by GitHub's run context and never read from a release
   asset or artifact);
2. verifies its provenance attestation with
   `gh attestation verify release-authorization.json --repo mbzbugsy/fidomanager
   --signer-workflow mbzbugsy/fidomanager/.github/workflows/release-macos.yml
   --signer-digest <workflow sha> --source-digest <commit_sha> --source-ref refs/tags/<tag>
   --deny-self-hosted-runners --format json`;
3. checks, from the verified certificate in that JSON output, that the run invocation URI (Fulcio
   OID 1.3.6.1.4.1.57264.1.21) is exactly
   `https://github.com/mbzbugsy/fidomanager/actions/runs/<run_id>/attempts/<run_attempt>`, with the
   run ID and attempt from `verify`'s job outputs. [GITHUB] `gh attestation verify` has no flag for
   the run, and only the certificate, not the user-controllable predicate, is relied on. The exact
   JSON field path is confirmed during the rehearsal (section 12, step 10);
4. checks that the record's `repository`, `tag`, `tag_object_sha`, `commit_sha`, `workflow` and
   `signer` equal the `preflight` outputs and this run's context.

The publication jobs grant `attestations: read` for step 2. `D7` is exactly as trustworthy as the
`verify` job that set it: that job runs only the reviewed tagged commit, holds no secrets and has
no write permission, and its outputs reach later jobs only through GitHub's run context. What `D7`
protects against is the threat the record cannot cover by itself: draft or release assets,
including the record, being replaced together after `verify` finished.

Only after all four does the record become the root that every other asset is checked against:
each asset's SHA-256 and size against the record, and `SHA256SUMS` against the record's
`sha256sums` digest and then line by line against the assets.

**`publish-draft`** (reviewer-gated; `contents: write`; requires `policy-check`; no candidate
code; checkout, if any, with `persist-credentials: false`):

1. Download the `verify` outputs, including the authorization record. Authenticate the record
   (root-of-trust steps 1–4).
2. Verify the payload and evidence assets against the authenticated record: SHA-256 and size of
   each, `SHA256SUMS` against the record's `sha256sums` digest and then line by line, and the
   exact final asset set.
3. Require that **no** release, draft or published, exists for the tag. The job lists the
   repository's releases with its `contents: write` token, which [GITHUB] also lists drafts, and
   requires that none has this `tag_name`. `GET /releases/tags/{tag}` is not enough, because
   [GITHUB] it returns only a published release. This is the only publication step that requires
   absence. It runs once, before the draft exists.
4. Require that the tag object and peeled commit still equal `preflight`'s values. That catches a
   moved tag, even though the ruleset forbids it.
5. Require `policy-check`'s output `immutable_releases=true`.
6. Create a **draft** release on the tag (`draft: true`) and upload exactly the final asset set.
7. Set the job output **`draft_release_id`** to the `id` field of the create-release response.
   It must be a decimal integer, or the job fails. This output is the only handle any later job
   uses for the draft. Like `D7`, it reaches `publish-final` only through GitHub's run context
   (`needs.publish-draft.outputs`), set by a job that runs no candidate code. It is never read from
   a release asset, an artifact or a release listing. It only selects which release is checked
   and published. It vouches for no content: every content check is still made against `D7` and
   the attestation. If any later step of this job fails, the job fails, so `publish-final` (which
   `needs: publish-draft`) never runs.
8. Fetch the draft by that ID (`GET /releases/{draft_release_id}`). Require `draft` true and
   `tag_name` equal to the tag. Download every asset of that release, by asset ID, through the API
   into a fresh directory. Authenticate the downloaded authorization record again (steps 1–4),
   recompute SHA-256 and size of every asset, and compare with it. Check `SHA256SUMS` against it,
   check the tuple, and require exactly the expected asset names. Any mismatch fails hard, and the
   draft is left unpublished for a maintainer to delete. It is never repaired in place.

**Human gate.** A maintainer runs the Part B clean-machine matrix on the DMG and the app zip
downloaded from that draft, checks them against `SHA256SUMS` and the authenticated record, and then
approves `macos-release-public`.

**`publish-final`** (separately reviewer-gated; `contents: write`; requires `policy-check` and
`publish-draft`; no candidate code):

1. Take `draft_release_id` **only** from `needs.publish-draft.outputs.draft_release_id`. This job
   does **not** require that no release exists for the tag: the draft it is about to publish must
   exist. Instead, before anything is published, all of these must hold:
   - `GET /releases/{draft_release_id}` returns a release, and its `id` equals
     `draft_release_id`;
   - it is still a draft (`draft` true) and has not been published (`published_at` is null);
   - its `tag_name` is exactly the expected tag, and it is the only release for that tag (listed
     as in `publish-draft` step 3, drafts included);
   - the tag object and peeled commit still equal `preflight`'s values;
   - its metadata matches the approved tuple and what `publish-draft` created: name, prerelease
     flag and tag;
   - `policy-check`'s output is still `immutable_releases=true`;
   - the authorization record, downloaded from that draft by asset ID, has SHA-256 equal to `D7`
     from `needs.verify.outputs`. Its attestation verifies for the repository, the workflow, the
     workflow SHA, the exact source commit and tag, and the exact run ID and run attempt
     (root-of-trust steps 1–4, including the tuple check);
   - the draft's asset names are exactly the final asset set, with nothing missing and nothing
     extra;
   - every asset, downloaded from that draft by asset ID through the API into a fresh directory,
     matches the authenticated record in SHA-256 and size;
   - `SHA256SUMS` matches the record's `sha256sums` digest, and line by line the payload and
     evidence assets.

   Nothing else is trusted from the earlier job: only `draft_release_id` and `D7`, both through
   the run context. Any failure stops the job before publication, and the draft is left for a
   maintainer. If the release is already published, for example on a re-run after a failure
   between steps 2 and 3, the job stops without changing anything. A maintainer then runs the step
   3 checks by hand, and any failure is handled under section 11.
2. Only then publish that draft: `PATCH /releases/{draft_release_id}` with `draft: false`, and no
   other field changed (draft → published). Step 3 catches any change made between step 1 and
   this call.
3. After publication: download the **published** authorization record and authenticate it again
   (root-of-trust steps 1–4). Run `gh release verify <tag>`, which [GITHUB] says checks that the
   release exists and is immutable, and require the release object's `immutable` field to be
   `true`. Run `gh release verify-asset <tag> <file>` for each locally verified asset. Make one
   more API download with digest comparison against the authenticated record. Confirm that the tag
   still peels to `commit_sha`.
4. A failure **after** publication cannot be undone by the workflow, because immutable releases
   are final by design. It triggers the incident procedure in section 11: an advisory, release
   withdrawal, and a new patch version. It is never silent. Before publication, every check is a
   hard stop.

Tags are never moved or reused. A failed or abandoned run is fixed by a new patch version and a new
tag, never by re-pointing a tag.

## 8. Notarization and stapling

### 8.1 Sequence choice: app first, then DMG

[APPLE] The notary service accepts ZIP, UDIF disk images and flat packages. It "generates a ticket
for the top-level file that you specify, as well as for each nested file." A zip cannot be stapled
("run `stapler` against each item that you added to the archive"). Apple's packaging guidance says
that for nested containers it is enough to "only notarize the outermost container". It also says
that without stapling, "Gatekeeper might block a user from installing or using your product while
their Mac is offline".

[POLICY] We notarize **both**: the app (as a zip), then the DMG. Why:

- Stapling only the DMG leaves the `.app` without a ticket of its own once the user copies it to
  `/Applications`. The app is what gets launched. Whether Gatekeeper accepts a copied-out app
  offline on the strength of the DMG's ticket is exactly what we cannot promise
  ([EMPIRICAL E8]). A ticket stapled to the app removes the question.
- The app cannot be stapled after it is inside a signed DMG without changing the DMG and
  invalidating its signature and ticket. So the app is notarized and stapled first, then put in
  the DMG.
- The DMG is then notarized so that opening it from a quarantined download is assessed as
  notarized, and so that its stapled ticket works offline.
- The cost is a second submission. Apple's guidance is 98% of submissions within 15 minutes and at
  most 75 notarizations a day, so this does not matter at our release rate. The pattern matches
  Apple's own "two rounds of notarization" guidance for installer payloads.

### 8.2 Acceptance criteria and failure behaviour

[APPLE] With `--wait`, `notarytool` returns the final status. `notarytool log <id>` returns a JSON
log with `status`, `issues` and `ticketContents`. Apple advises: "Always check the log file, even if
notarization succeeds."

[POLICY] A submission counts only if **all** of these hold. Otherwise the job fails:

1. `notarytool submit` exits 0 and its JSON status is `Accepted`;
2. the downloaded log's `status` is `Accepted`;
3. `issues` is null or empty. **Warnings fail the release** (stricter than Apple);
4. the log's `sha256` equals the locally computed SHA-256 of the submitted file;
   [EMPIRICAL E11] confirms the field name and that it is always present. If it is absent, the
   binding falls back to the submission ID recorded before upload plus criterion 5;
5. every Mach-O in the submitted artifact (by `cdhash` from `codesign -dvvv`, per architecture)
   appears in `ticketContents`. [EMPIRICAL E11] confirms the format.

Failure modes:

- **Timeout** (`--timeout` reached), network error, HTTP 5xx, `In Progress` at timeout, `Invalid`
  or `Rejected`: the job fails, nothing is uploaded for publication, and the submission ID is
  written to the job summary for diagnosis. There is no automatic retry loop. A maintainer may
  re-run the failed job: it re-downloads the digest-bound build output, signs again and submits
  again (a new submission). There is no "staple later" path and no publishing while notarization
  is pending.
- **Stapling failure** (`stapler staple` or `validate` non-zero, for example because the CloudKit
  ticket is not yet available): the job fails. [POLICY] One bounded retry of `stapler staple`
  after 60 s is allowed, because ticket propagation is the documented online path. A second
  failure is final. An unstapled artifact is never published.
- **spctl not accepted**, or a source other than `Notarized Developer ID`: the job fails.

### 8.3 Stapled bundle layout

[INFERENCE, EMPIRICAL E12] `stapler staple` on a bundle writes the ticket as
`Contents/CodeResources`, outside the signature's sealed resources, so the code signature stays
valid. `check-macos-bundle.py`'s exact-tree allowlist currently rejects that file. M7.2 adds a
`--stapled` mode that requires **exactly** that one extra file and nothing else, and re-verifies
the signature afterwards. The cdhashes of both executables are unchanged by stapling. The driver
asserts this against the pre-staple values and re-checks the sealed release-worker identity record
against the worker's `CDHash`; Verify repeats both checks. The record is a sealed resource inside
`Contents/Resources/`, so the ticket file does not affect it.

### 8.4 Gatekeeper assessment commands

| Artifact | Command | Expected |
| --- | --- | --- |
| `.app` | `spctl --assess --type execute -vvv "Fido Manager.app"` [APPLE form] | `accepted`, `source=Notarized Developer ID`, `origin=Developer ID Application: … (TEAMID)` |
| `.dmg` | `spctl --assess --type open --context context:primary-signature -vvv FidoManager.dmg` | `accepted`, `source=Notarized Developer ID` [EMPIRICAL E13: exact output wording] |
| both | `xcrun stapler validate <path>` | `The validate action worked!` |
| `.dmg` | `hdiutil verify <dmg>` [APPLE] | checksum valid |
| optional | `syspolicy_check distribution "Fido Manager.app"` on runners that have it | no issues; supplementary only, never the gate [EMPIRICAL E13: availability] |

## 9. Release provenance and SBOM

### 9.1 `release-manifest.json` (shipped)

```jsonc
{
  "schema": "fidomanager.release-manifest/1",
  "product": "Fido Manager", "version": "X.Y.Z", "tag": "vX.Y.Z",
  "source": { "repository": "mbzbugsy/fidomanager", "commit": "<40-hex>", "tag_object": "<sha>" },
  "build": {
    "workflow": ".github/workflows/release-macos.yml", "workflow_sha": "<commit>",
    "run_id": 0, "run_attempt": 1, "runner_image": "<ImageOS/ImageVersion>",
    "macos_sdk": "<xcrun --show-sdk-version>", "xcode": "<xcodebuild -version>",
    "rust": "<rustc -Vv>", "cargo": "<cargo -V>", "node": "24.21.0", "pnpm": "10.17.1",
    "tauri_cli": "2.12.0", "tauri": "2.12.0", "tauri_build": "2.7.0",
    "target": "aarch64-apple-darwin", "deployment_target": "11.0",
    "reproducibility": "traceable"            // not claimed bit-reproducible (plan §39)
  },
  "build_tools": { "cmake": "<cmake --version>", "pkg-config": "<pkg-config --version>" },
                                                // Homebrew, unpinned; recorded, not reproduced
  "native": {
    // Pinned values: native/<name>/source.lock.json. Build-time values ("…"):
    // build-identity.json and package-summary.json from the build job (section 1.1).
    "libfido2": { "version": "1.17.0", "revision": "b974e7cf2ee7392134cc12c08b76a068cf250dd8",
                  "source_sha256": "a7c340900cb58b6905e12855944069024f39707f9573d52d4830a4561a50819a",
                  "patch_sha256": "8b416da841fca9268d45aa1f10236270be0983400dc471d2920ff09fc5ce0465",
                  "license": "BSD-2-Clause",   // from LICENSE.upstream / notices; the libfido2 lock has no licence field
                  "openssl_api_compat": "0x10100000L",
                  "static_archive": "libfidomanager_fido2_bounded.a", "static_archive_sha256": "…" },
    "openssl":  { "version": "3.5.9", "tag": "openssl-3.5.9",
                  "commit": "45e844fa2a14ec92d146bd8f5778ac130b6625fb",
                  "source_sha256": "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a",
                  "license": "Apache-2.0", "openssldir": "/var/empty/fidomanager-openssl",
                  "build_options": ["no-shared", "no-module", "no-engine", "no-dso", "no-autoload-config",
                                    "no-legacy", "no-apps", "no-tests", "no-docs", "no-ui-console",
                                    "-mmacosx-version-min=11.0"],
                  "static_archive": "libfidomanager_crypto.a", "static_archive_sha256": "…" },
    "libcbor":  { "version": "0.14.0", "tag": "v0.14.0",
                  "commit": "6730c20ab487c0b4dc5fb3fea918937085355bac",
                  "source_sha256": "82e82efe92a77eb92d290276f627c5cc52e84463981ab695013196b63b7e2f47",
                  "license": "MIT", "lto": false,
                  "static_archive": "libfidomanager_cbor.a", "static_archive_sha256": "…" },
    "compiler": "…", "sdk_version": "…",
    "deterministic_controls": { "SOURCE_DATE_EPOCH": "1781654400", "ZERO_AR_DATE": "1" },
    "build_identity_sha256": "…", "package_summary_sha256": "…"
  },
  "third_party_notices": { "path": "Contents/Resources/THIRD_PARTY_NOTICES.md", "sha256": "…",
                           "scope": "native libraries only (libfido2, OpenSSL, libcbor)" },
  "signing": {
    "team_id": "XXXXXXXXXX", "identity_sha1": "…", "authority": "Developer ID Application: …",
    "hardened_runtime": true, "entitlements": {},
    "cdhash": { "fidomanager-app": { "arm64": "…" }, "fido-worker": { "arm64": "…" } },
    "worker_publisher_requirement": "anchor apple generic and …",
    "release_worker_identity": { "sha256": "<RID, also in Info.plist>", "worker_file_sha256": "…" },
    "signer": { "repository": "mbzbugsy/fidomanager-release-signer", "sha": "<40-hex>" }
  },
  "notarization": {
    "app": { "submission_id": "…", "status": "Accepted", "log_sha256": "…" },
    "dmg": { "submission_id": "…", "status": "Accepted", "log_sha256": "…" },
    "stapled": ["app", "dmg"]
  },
  "artifacts": [ { "name": "FidoManager-X.Y.Z-arm64.dmg", "sha256": "<D5>", "size": 0 },
                 { "name": "FidoManager-X.Y.Z-arm64.app.zip", "sha256": "<D3>", "size": 0 } ],
  "digest_chain": { "D0": "…", "D1": "…", "D2": "…", "D3": "…", "D4": "…", "D5": "…" },  // 9.4
  "sbom": { "name": "FidoManager-X.Y.Z-arm64.cdx.json", "sha256": "…" }
}
```

### 9.2 What ships alongside the release

| Asset | Purpose |
| --- | --- |
| `FidoManager-X.Y.Z-<arch>.dmg` | the signed, notarized, stapled distribution (`D5`) |
| `FidoManager-X.Y.Z-<arch>.app.zip` | the stapled app archive (`D3`), for users and reviewers who want the app without the DMG; it carries its own stapled ticket. Because it ships, it gets its own clean-machine validation (validation plan B23–B28) |
| `SHA256SUMS` | digests of the payload and evidence assets only (DMG, app zip, SBOM, manifest, notary logs); computed after stapling; it lists neither itself nor the authorization record (7.6) |
| `release-manifest.json` | the record in 9.1 |
| `release-authorization.json` | the authorization tuple (7.6), written last; holds every asset digest and the `SHA256SUMS` digest; authenticated by `D7` and its attestation, never by itself |
| `release-attestations.sigstore.jsonl` | the Sigstore bundles from `attest`; self-authenticating, so outside both digest files |
| `FidoManager-X.Y.Z-<arch>.cdx.json` | CycloneDX 1.6 SBOM of the **shipped** artifact |
| `notary-app.json`, `notary-dmg.json` | Apple notarization logs (no secrets; they contain job IDs and cdhashes) |
| GitHub attestations | `gh attestation verify FidoManager-….dmg -R mbzbugsy/fidomanager` binds the digest to this workflow, commit and run; the immutable release adds GitHub's release attestation [GITHUB] |

Inside the bundle, as sealed resources: `Contents/Resources/THIRD_PARTY_NOTICES.md` [REPO, M7.1]
and `release-worker-identity.json` (5.8).

[REPO] The notices file covers only the statically linked native libraries: libfido2 (BSD-2-Clause,
with its openbsd-compat notices), OpenSSL (Apache-2.0) and libcbor (MIT). It says itself that Rust
crate and frontend package notices are outside its scope. This ADR does **not** claim licence
coverage for Rust crates or npm packages. That is M7.1's remaining gate 5 and must be decided
before the first public release (section 12, step 1).

### 9.3 SBOM scope

[POLICY] The SBOM describes what is **in the artifact**, per executable:

- `fidomanager-app`: the Rust crate closure for the target (normal dependencies only, from
  `cargo tree --locked -e normal --target <triple> -p fidomanager-app`), plus the npm
  packages bundled into `dist/` (from the lockfile,
  production dependencies that the Vite build actually bundles).
- `fido-worker`: its Rust crate closure, plus the statically linked libfido2, OpenSSL and libcbor
  with their versions, source digests and patch digests.
- System frameworks are listed as external, unversioned dependencies.
- The OpenSSL and libcbor licences come from their lock files (`license_spdx`,
  `license_sha256`). The libfido2 lock has no licence fields, so its licence (BSD-2-Clause) is
  taken from `native/libfido2/LICENSE.upstream` and the notices file, with that file's SHA-256.
  Listing a Rust or npm component's licence in the SBOM is an inventory, not a redistribution
  notice; it does not close M7.1 gate 5.

[POLICY] It is generated by a small in-repo, reviewed script from `cargo metadata`/`cargo tree`,
the pnpm lockfile and the native lock files. This avoids adding an SBOM tool to the release
supply chain. Its inputs are gathered in `build`, and `verify` assembles it with the final digests
from the driver report. The signing job never runs it (D15).

### 9.4 Digest chain: every transformation has its own input and output digest

Signing, writing the identity record and stapling all **change bytes**. So no single checksum
survives the pipeline, and none is claimed to. Each step that changes bytes is authenticated by the
job that performs it, which verifies its input digest and records its output digest. The final
assets are tied back to the build through code identity (cdhashes) and Apple's notarization
records, not through one file hash.

| Step | Input (verified) | Output (recorded) | What carries identity across the step |
| --- | --- | --- | --- |
| build → hand-off | source at peeled commit | `D0` = SHA-256 of `build-output.tar` (ad-hoc app, 6.5); `D0s` = SHA-256 of `sbom-inputs.tar` (Verify only) | provenance attestation names the commit and run; `D0` authenticates bytes, 6.5 makes extraction safe |
| worker signing | `D0` | `D1` = signed worker file SHA-256 + per-arch `CDHash`/`CandidateCDHashFull` | the worker's cdhash from here on is final |
| record + bundle signing | `D0`, `D1` | sealed app containing the record; per-arch cdhashes of the main executable | the record pins `D1`'s cdhash; the seal covers the record |
| app notarization | `D2` = SHA-256 of `app-signed.zip` | `notary-app.json` (`D6a`) | log `sha256 == D2`; `ticketContents` lists the main and worker cdhashes (8.2) |
| app stapling | sealed app | `D3` = SHA-256 of the stapled app zip | cdhashes unchanged (re-checked); ticket file added outside the seal |
| DMG build + signing | stapled app | `D4` = SHA-256 of the signed, unstapled DMG | DMG signature (identifier `eu.fidomanager.desktop.dmg`) |
| DMG notarization | `D4` | `notary-dmg.json` (`D6b`) | log `sha256 == D4`; ticket covers the DMG and its nested code |
| DMG stapling | signed DMG | `D5` = SHA-256 of the final DMG | DMG cdhash unchanged; ticket stapled |
| checksums | `D3`, `D5`, `D6`, SBOM, manifest | `SHA256SUMS` over exactly those | listed in the authorization record |
| authorization | all of the above and the `SHA256SUMS` digest | `release-authorization.json`; `D7` = its SHA-256, a `verify` job output | `D7` travels only through job outputs; the record's attestation is bound to this exact run (7.6) |
| draft upload → download | `D7` and `draft_release_id` (job outputs), the authenticated record | identical digests re-computed from the **downloaded** draft assets | hard fail on any mismatch; the downloaded record is re-authenticated, never trusted for its own digest |
| publication → download | same | identical digests from the **published** assets; `gh release verify` / `verify-asset` | immutable release + release attestation |

## 10. Fail-closed behaviour (consolidated)

| Condition | Where detected | Behaviour |
| --- | --- | --- |
| Invalid worker signature | app, per spawn (5.3) | No spawn, or contain if after spawn; terminal `WorkerIdentityRejected`; FIDO disabled; no fallback |
| **Older or otherwise different worker signed by the same publisher** | app, per spawn (cdhash ≠ `EXPECTED`, static and dynamic); app startup S7 | same as above; at startup, no launcher |
| **Identity record missing, malformed, edited, swapped during startup, or for another release** | app startup S4–S6 (5.8); driver post-sign and post-staple checks; Verify | app: no launcher, FIDO disabled; release: fails |
| **Secured `Info.plist` missing or malformed; digest key missing, malformed, or ≠ SHA-256 of the record bytes read** | app startup S3–S5; driver; Verify | app: no launcher, FIDO disabled; release: fails |
| Worker authenticity failure and the worker cannot be contained | app (5.7) | authenticity latch stays set and terminal; `NotContained` handled as today; no conversion clears the latch; earlier uncertain M5/M6 mutations stay `OutcomeUnknown` with journal and barrier kept |
| Handoff archive violates the extraction contract (size, entry count, type, path, duplicate, mode) | driver, before writing anything (6.5); Verify | job fails before the keychain exists |
| Missing worker | app (5.3 step 2); driver tree check; Verify | `ExecutableRejected`; release fails |
| Wrong Team ID | app (requirement + `kSecCodeInfoTeamIdentifier`); driver (certificate vs pinned Team ID vs marker); Verify | app: terminal rejection; release: job fails before signing |
| Wrong worker identifier | app (requirement + dynamic info); driver; Verify | same as above |
| Unsigned or extra nested code | driver exact code set; `codesign --verify --strict --deep`; Verify | release fails; never "fixed" by signing the extra code |
| Bundled dylib, `Contents/Frameworks/`, non-system or Homebrew linkage, `minos` above 11.0, or link-map provenance not proven | Build (M7.1 `package-macos.py`, `verify-libfido2-linkage.py`, checker) [REPO]; driver tree check; Verify checker | release fails in Build, before anything reaches the signing job |
| Notices file missing or not byte-identical to the repository copy | Build and Verify (M7.1 checker) [REPO]; driver (presence and digest vs `package-summary.json`) | release fails |
| Signed worker's code differs from the Build-output worker after removing signatures | Verify (section 4) | release fails |
| Hardened Runtime missing | app (`runtime` flag, static and dynamic); driver; Verify | app: rejection; release: fails |
| Entitlements present | app (static info); driver; Verify | app: rejection; release: fails |
| Missing secure timestamp | driver (`Timestamp=` required, `Signed Time=` rejected); Verify | release fails; no retry without a timestamp |
| Candidate code would have to run in the signing job | by construction (6.4): no candidate checkout, no candidate tools on `PATH`, driver from the pinned signer SHA | the step does not exist; a workflow change that adds one needs CODEOWNERS review and changes `workflow.sha` in the tuple |
| Signer checkout ≠ pinned SHA, or the pin is not on the signer's protected branch | driver self-check; preflight | job fails before any secret is used |
| Notarization failed, timed out, transient error, or any warning | driver (8.2) | job fails; nothing uploaded; manual re-run only |
| Stapling failed | driver (8.2) | one bounded retry, then fail |
| Gatekeeper assessment failed | Verify (8.4) | release fails |
| Artifact checksum mismatch at any job boundary | every consumer (9.4) | hard fail; download-tool warnings are never accepted instead |
| Authorization record's SHA-256 ≠ `D7` from job outputs, or its attestation fails (wrong repository, commit, workflow, workflow SHA, run or attempt, or a self-hosted runner) | `attest`; `publish-draft` steps 1 and 8; `publish-final` steps 1 and 3 | before publication: stop, nothing trusted from the record; after publication: incident procedure (11) |
| Draft or published asset differs from the authenticated authorization record or from `SHA256SUMS` | `publish-draft` step 8; `publish-final` steps 1 and 3 | before publication: stop, draft left unpublished; after publication: incident procedure (11) |
| Tag not annotated, not on `main` or reused, or a release already exists for the tag **before the draft is created** | preflight (releases its read-only token can see); `publish-draft` step 3 (drafts included) | stop before building, or before creating the draft |
| Tag moved (tag object or peeled commit ≠ `preflight`) | preflight; `publish-draft` step 4; `publish-final` steps 1 and 3 | before publication: stop; after publication: incident procedure (11) |
| At `publish-final`: no release with ID `draft_release_id`; it is no longer a draft or is already published; its tag or metadata differ from the approved tuple; or another release exists for the tag | `publish-final` step 1 | stop; nothing is published; the draft is left for a maintainer |
| CI for the exact peeled commit missing, pending, skipped or failed | preflight | stop before building |
| Immutable releases not enabled, or `policy-check` cannot confirm it (404, other status, network error, missing App key) | `policy-check`; publish jobs require its output | stop; nothing is published |
| A `uses:` not pinned to a 40-hex SHA, or a checkout without `persist-credentials: false` | preflight | stop |
| Release secret missing or empty | sign job step 1 | job fails before any keychain or network action |
| Certificate fingerprint or Team ID ≠ pinned | sign job step 4 | job fails |
| Release binary built without enforcement | driver marker check (data); Verify | release fails |
| Version mismatch | preflight | workflow stops before building |

Every row is fail-closed. **No row has an automatic downgrade** to ad-hoc, unsigned, unnotarized,
unstapled, publisher-only worker matching, or "publish and fix later".

## 11. Rollback and incident handling

- A failed run publishes nothing. Draft releases from aborted runs are deleted by a maintainer,
  and tags are never moved or reused (ruleset, immutable releases). A fixed release gets a new
  patch version.
- A post-publication verification failure (7.6, `publish-final` step 3) is handled as an incident:
  the release is marked withdrawn with an advisory, and a new patch version is cut. Immutable
  releases cannot be edited in place, by design.
- **Whole-application rollback is separate from the worker binding.** D14 prevents mixed app/worker
  bundles. It does not stop a user or same-user software from installing an older, complete,
  legitimately signed release (5.8). Handling that needs a security floor and is out of scope;
  withdrawn releases and advisories are the mitigation today.
- A defective published release is withdrawn: the release is marked as such, and its assets are
  removed or left with a prominent advisory. There is no updater (ADR-006), so nothing is pushed to
  users, and the advisory is the channel.
- [APPLE] If unauthorized software signed with our key is discovered, Apple can revoke the
  associated notarization tickets ("work with Apple to revoke the tickets"). On a suspected
  certificate or API key compromise: revoke the API key in App Store Connect, revoke the Developer
  ID certificate through the Account Holder, rotate both environment secrets, and update the pinned
  fingerprint variable. The Team ID constant does not change with a new certificate from the same
  team.
- Rotation is an environment change plus a reviewed variable change. The fingerprint pin makes a
  silent certificate swap fail the release.

## 12. Implementation order (M7.1 has merged)

The M7.1 shape check that earlier revisions listed as step 0 is done (section 1.1). In order,
each step reviewable on its own:

1. **Carried-over M7.1 gates that are decisions, not code**: decide whether Rust crate and frontend
   package notices are required for distribution (M7.1 gate 5) and, if so, how they ship; and add
   PGP verification of the OpenSSL release signature as a manual review step whenever
   `native/openssl/source.lock.json` changes (M7.1 gate 6; the SHA-256 pin stays the gate).
2. **Worker verifier** (`fido-platform`, macOS): FFI to `SecStaticCodeCreateWithPath`,
   `SecStaticCodeCheckValidityWithErrors`, `SecCodeCopyGuestWithAttributes`,
   `SecCodeCheckValidity`, `SecCodeCopySigningInformation`, `SecRequirementCreateWithString`,
   `SecCodeCopySelf` and `SecCodeCopyStaticCode`. Add negative tests (unsigned, ad-hoc, wrong
   identifier). Add a cdhash-pin test that runs in ad-hoc CI: two ad-hoc binaries with the same
   identifier, where a test-only requirement pins one cdhash and must reject the other. The
   dynamic flag set is chosen once from the OS version (5.2: no flags on 11.0–11.2,
   `noNetworkAccess` from 11.3); a unit test asserts that the requirement string is identical on
   both paths and that an unparsable OS version fails closed.
3. **Release identity at startup** (5.8): obtain the secured `Info.plist` through the validated
   code object (`kSecCodeInfoPList`, or the mechanism E16 selects), the single read of the record
   into one buffer, the SHA-256 comparison with `FidoManagerReleaseWorkerIdentitySHA256`, the
   strict parser (schema, 4 KiB bound) over **that same buffer**, steps S1–S8, and the in-memory
   `EXPECTED`. A test hook swaps the record file between S4 and any later point, and the test
   asserts that the swap is either rejected at S5 or has no effect on `EXPECTED`. Enforcing builds
   compile in the version and source commit for the S6 comparison. The worker compiles in its
   `build_id` and reports it in `ChildHello` (a protocol field addition, reviewed with ADR-009's
   contract).
4. **Launcher** (`fido-service/process_worker.rs`): move the path checks into `launch()`; add
   static validation against `WORKER_EXACT_REQ` and `EXPECTED` before spawn, and dynamic
   validation including the running cdhash before `ParentHello`; add `WorkerIdentityRejected` and
   make it terminal in the supervisor; add the renderer category. Latch the authenticity failure
   before `contain()`, and keep it when containment reports `NotContained` (5.7). Regression tests:
   (a) an identity failure followed by `NotContained` still reports the latched, terminal identity
   failure; (b) after a credential deletion (M5) left `OutcomeUnknown`, a replacement worker that
   fails identity checks does not turn that outcome into `NotDispatched` and does not remove the
   journal entry or recovery barrier; (c) the same for Reset once M6 lands.
5. **Build flavor**: the `macos-release-signing` Cargo feature and Team ID constant, and the
   enforcing marker (Team ID + version + commit). `package-macos.py` gets a release flavor, and the
   renderer-boundary rules allow a single construction site.
6. **Signing driver** (new repository `mbzbugsy/fidomanager-release-signer`, protected per 6.4):
   stdlib-only Python driver + config; the 6.5 extraction contract; data-only pre-checks; worker
   signing; identity record generation and the `Info.plist` digest key; bundle signing; post-sign
   data checks; notarization with the 8.2 acceptance rules; stapling; DMG; digests `D1`–`D6`;
   driver report. It has its own unit tests on fixtures in its own repository, including the
   hostile-archive cases in validation plan Part E.
7. **Candidate-side checker** (`check-macos-bundle.py`, Build/Verify only): `--expected-team-id`,
   requirement and authority-chain assertions, timestamp wording, enforcing marker, `--stapled`,
   record ↔ worker checks, the `Info.plist` digest key (absent in ad-hoc mode; present and equal
   to the record's SHA-256 in developer-id mode), DMG checks, and new mutation cases (wrong Team ID
   marker, edited record, record digest ≠ plist key, missing or malformed key, worker cdhash ≠
   record, stapled extra file, `Signed Time` only, missing chain). Its
   `check_tree` allowlist gains `Contents/Resources/release-worker-identity.json` **only** in
   `--signature developer-id` mode and `Contents/CodeResources` only with `--stapled`; ad-hoc mode
   keeps rejecting both, which is what makes "no pre-existing record" hold in Build. The existing
   M7.1 checks (no Frameworks, exact Mach-O set, system-only linkage, `OPENSSLDIR`, `minos`
   11.0, byte-identical notices, worker execution) stay unchanged.
8. **Provenance**: `scripts/release-provenance.py` (manifest, SBOM, then `SHA256SUMS`, then the
   authorization record last, and `D7` as a job output; 7.6), run in Verify.
9. **Workflow**: `.github/workflows/release-macos.yml` per section 7 (including `policy-check`,
   the CI-success eligibility check, `persist-credentials: false` on every checkout, and the
   `D7` + attestation verification in the publish jobs), and the documented one-time settings
   (7.5).
10. **Fail-closed rehearsal before any credential exists**: push a pre-release tag to a fork or a
    throwaway repository with no signing secrets. Prove that the sign job fails at the
    secret-presence check and nothing is uploaded or published. Also prove that `preflight`
    rejects an unpinned `uses:`, a checkout without `persist-credentials: false`, a lightweight
    tag, a commit whose CI is not green and a signer pin that is not on the signer's protected
    branch, and that `policy-check` stops the run when immutable releases are off or the App key is
    missing (validation plan Part E). Confirm the JSON field path of the run invocation URI in
    `gh attestation verify` output on a test attestation.
11. **First real run**, only on Nima's explicit go-ahead with credentials provisioned: an `rc` tag,
    a draft release, the full clean-machine matrix
    ([validation plan](../validation/M7.2-macos-release-validation-plan.md)), then
    `publish-final`.
12. Independent security review of 2–9 and of the first run's evidence before M7.2 is merged.

The existing `ci.yml` stays ad-hoc and secret-free. The release workflow is a new file.

## 13. Unresolved empirical questions

None of these has been answered yet: no Developer ID identity, notarization or Gatekeeper run
exists. "Gate" says what an unfavourable or missing answer means:

- **Release gate:** M7.2 does not ship until it is answered favourably.
- **Operational:** it is settled during the rehearsal or the first run, and a documented fallback
  exists.
- **Evidence:** it is measured and recorded, and only a stated threshold turns it into a finding.
- **Optional / non-gating:** it does not block anything.

| ID | Question | How to answer | Gate |
| --- | --- | --- | --- |
| E1 | Does the 5.1 requirement accept the real signed worker and reject ad-hoc, unsigned, wrong-identifier and other-team binaries? What does the real `codesign -d -r-` output contain (including whether it has a Mac App Store alternative)? | First real identity; `codesign -R` and the verifier's unit tests | Release gate |
| E2 | Does `SecStaticCodeCreateWithPath` on `Contents/MacOS/fido-worker` produce a single-file static code object with the worker's identifier? | Signed bundle; log the identifier | Release gate |
| E3 | Does validation succeed offline with bounded latency on **both** dynamic flag paths: no flags on macOS 11.0–11.2, `noNetworkAccess` on 11.3 or later? Confirm from the SDK header that `kSecCSNoNetworkAccess` is unavailable for dynamic validation before 11.3, as the independent review reports | Clean Macs on 11.0–11.2 and on 11.3 or later, network off; SDK header | Release gate (both paths) |
| E4 | Does Hardened Runtime alone set the dynamic `kill` status on the worker? | `SecCodeCopySigningInformation(kSecCSDynamicInformation)` on the running worker | Release gate (decides whether `kill` is added to the signing options) |
| E5 | Per-spawn validation cost on the slowest supported Mac | Measure steps 3 and 5 | Evidence (feeds Part C) |
| E6 | Can a suspended (`POSIX_SPAWN_START_SUSPENDED`) process be validated before dyld has run? | Prototype | Optional hardening |
| E7 | Does any TCC prompt appear for the signed app or worker (HID, Input Monitoring)? | Clean Mac matrix | Release gate |
| E8 | Does an app copied out of a stapled DMG launch offline **without** its own staple? It only explains the D9 choice | Clean Mac, network off | Non-gating (explanatory) |
| E9 | Does `codesign --keychain` find an identity in a keychain that is not in the search list? | First signing run | Operational (fallback in 3.2) |
| E10 | The minimum App Store Connect API key role for `notarytool` | When the key is created | Operational |
| E11 | Do notary logs always include `sha256` and per-arch `cdhash` in `ticketContents`? | First submission | Release gate (8.2 acceptance depends on it) |
| E12 | Does stapling a bundle write exactly `Contents/CodeResources` and leave cdhashes unchanged? | First staple | Release gate |
| E13 | Exact `spctl` output for a notarized DMG; `syspolicy_check` availability on runners | First run | Operational |
| E14 | First-launch Gatekeeper latency of the quarantined app → worker spawn → hello, against the 3 s handshake timeout (online, offline, translocated) | Validation plan, Part C | Evidence: a maximum of **≥ 1.5 s** is a finding |
| E15 | Whether exec of a quarantined nested helper triggers its own Gatekeeper evaluation and how long it takes | Same, with `log stream --predicate 'subsystem == "com.apple.syspolicy"'` | Evidence |
| E16 | Does the selected Security.framework mechanism (`kSecCodeInfoPList` from the validated code object, or another reviewed one) return the **secured, signed** `Info.plist`, so that `FidoManagerReleaseWorkerIdentitySHA256` cannot be supplied by an on-disk edit after signing? Is it available from the validated code object on 11.0–11.2 and on 11.3 or later? | Signed bundle with the on-disk `Info.plist` edited after signing; both OS ranges; Apple documentation or DTS | **Release gate** (correctness of 5.8; not optional) |
| E17 | Does `SecCodeCopyStaticCode(self)` give the whole bundle? What does S3 with `kSecCSCheckNestedCode` report for (a) an edited record, (b) a different validly signed worker, (c) both swapped together? Recorded only, not relied on | Signed bundle, mutated copies | Release gate for the first part; the nested-code results are evidence |
| E18 | Operational only: does the `policy-check` job get `200` with `enabled: true` using an App token with only Administration: read, and does the published release report `immutable: true`? The API endpoint and its permission are settled from documentation (7.1) | Rehearsal and first run | Operational (the check itself is terminal on failure) |
| E19 | Does `codesign --remove-signature` give byte-identical files for the Build-output (ad-hoc) worker and the Developer ID-signed worker, so that the M7.1 link-map provenance demonstrably carries over? If not, which bytes differ, and is an equivalent comparison (for example of `__TEXT`/`__DATA` segments) needed? | First signing run, in Verify | **Release gate** (provenance) |
| E20 | Do the signed app and worker actually launch and pass the per-spawn checks on macOS 11 (the declared floor)? M7.1 checked `minos` and `LSMinimumSystemVersion` statically but launched nothing on macOS 11 (its gate 3) | Validation plan machines M1 and M1b | **Release gate** for claiming macOS 11 support |

## 14. Alternatives rejected

| Alternative | Why rejected |
| --- | --- |
| Sign the artifact from PR CI | A PR can change the build; this violates D7 |
| One job that builds and signs | Third-party build code would run beside the signing key |
| Tauri's built-in signing/notarization (`APPLE_*` variables) | Signing order and options would be out of our control; the env-driven behaviour clashes with the packager's refusal of `APPLE_*` |
| `codesign --deep` to sign | [APPLE] says do not; it applies the same options everywhere |
| Entitlements copied from Tauri templates | Not needed (M7.0 evidence); each weakens the Hardened Runtime |
| Rely on the bundle seal and Gatekeeper alone | No per-exec identity guarantee (5.4) |
| Static validation only | TOCTOU (5.5) |
| Derive the Team ID from the running app | An ad-hoc or re-signed app silently changes what "same team" means; a reviewed constant is explicit |
| Runtime switch for enforcement | A runtime switch becomes a downgrade path |
| Notarize only the DMG | Apple's minimum; leaves the copied-out app without a stapled ticket (D9) |
| Apple ID + app-specific password | Tied to a person; an API key is revocable and scoped on its own |
| Self-hosted macOS runner | Persistent state across jobs; GitHub-hosted VMs are fresh per job |
| Launch constraints (macOS 14+) | Wrong direction for this threat; above the 11.0 deployment floor (5.5) |
| Publisher-only worker requirement | Accepts older signed workers from the same team (5.8) |
| Expected worker identity derived from the worker on disk | Circular (5.8) |
| Run the candidate's `sign-macos-bundle.py`/`check-macos-bundle.py` in the signing job | Candidate code beside the key (D15) |
| Signing driver taken from the candidate commit (S0) | No independence from what it signs (6.4) |
| Trust `download-artifact` integrity warnings alone | Not a hard binding; every consumer recomputes SHA-256 (7.2, 9.4) |
| Publish directly from the build/sign run without re-downloading the release assets | The bytes users receive would never be checked (7.6) |
| Trust a downloaded `release-authorization.json` for its own digest | A wholesale replacement of the draft's assets would replace the record too; `D7` comes from job outputs and the attestation is checked (7.6) |
| `SHA256SUMS` that lists the authorization record while the record lists `SHA256SUMS` | Circular; cannot be generated (7.6) |
| Give `preflight` or the whole workflow administration access for the immutable-release check | `GITHUB_TOKEN` has no such scope, and broad admin access beside candidate code is wrong; a checkout-free job with an App token limited to Administration: read is enough (7.1) |
| Extract the handoff archive with `ditto`, `tar` or `unzip` in the signing job | General extractors follow links, honour special entries and write before validating; the driver's own contract does not (6.5) |
| Raise the deployment floor to 11.3 so `noNetworkAccess` can be used for dynamic validation everywhere | A floor change is its own product decision; the per-version flag choice keeps the requirement identical (5.2) |
| Record ↔ seal agreement by reading, validating and re-reading the record | Cannot prove the retained bytes are the validated ones (5.8) |

## Sources (read for this ADR, October 2026)

- Apple, *SecCodeCheckValidity(_:_:_:)*, *SecStaticCodeCheckValidityWithErrors(_:_:_:_:)*,
  *SecStaticCodeCreateWithPath(_:_:_:)*, *SecCodeCopyGuestWithAttributes(_:_:_:_:)*,
  *SecCSFlags*, *Static Code Validation Flags*, *SecCodeStatus* (`kill`, `hard`),
  *SecCodeSignatureFlags* (`runtime`), *kSecCodeInfoStatus*, *kSecCodeInfoFlags*,
  *kSecCodeInfoEntitlementsDict* — developer.apple.com/documentation/security
- Apple, *TN3127: Inside Code Signing: Requirements*
- Apple, *Hardened Runtime*
- Apple, *Creating distribution-signed code for macOS*
- Apple, *Packaging Mac software for distribution*
- Apple, *Placing content in a bundle*
- Apple, *Notarizing macOS software before distribution*
- Apple, *Customizing the notarization workflow*
- Apple, *Resolving common notarization issues*
- Apple, *TN3147: Migrating to the latest notarization tool*
- Apple, *Applying launch environment and library constraints*
- Apple, *TN3126: Inside Code Signing: Hashes*; *kSecCodeInfoUnique*, *kSecCodeInfoCdHashes*,
  *SecCodeCopyStaticCode(_:_:_:)*, *SecCodeCopyPath(_:_:_:)*, *kSecCSCheckNestedCode*,
  *kSecCSContentInformation*
- GitHub, *Deployments and environments* (reference)
- GitHub, *Immutable releases*; *Verifying the integrity of a release*
- GitHub, *OpenID Connect* reference (`job_workflow_ref`, `job_workflow_sha`, `workflow_sha`)
- GitHub, *Managing GitHub Actions settings for a repository* (full-length SHA pinning)
- GitHub REST, *Check if immutable releases are enabled for a repository*
  (`GET /repos/{owner}/{repo}/immutable-releases`, from the published OpenAPI description); GitHub
  Actions workflow syntax, `permissions` (no administration scope for `GITHUB_TOKEN`);
  `gh attestation verify` manual; Sigstore Fulcio OID reference (Run Invocation URI
  1.3.6.1.4.1.57264.1.21)
- Apple, *kSecCodeInfoPList* ("the contents of the secured `Info.plist` file as seen by Code
  Signing Services"), *noNetworkAccess*
- Repository at `15ae91c`: `docs/validation/M7.1-static-native-deps.md`,
  `scripts/{package-macos,check-macos-bundle,sign-macos-bundle,build-libfido2,build-native-deps,verify-libfido2-linkage}.py`,
  `crates/fido-libfido2/build.rs`, `native/*/source.lock.json`, `THIRD_PARTY_NOTICES.md`,
  `.github/workflows/ci.yml` (`macos-packaging`)
