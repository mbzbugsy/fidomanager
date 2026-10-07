# ADR-017: macOS Developer ID signing, worker authenticity, notarization and release workflow

Status: **Proposed for independent review** (M7.2 design only). Revision 2: amended after an
independent red-team review. The amendment adds the exact app ↔ worker release binding (D14,
5.8), the signing environment that executes no candidate code (D15, 6.4), and immutable
publication with final asset verification (D16, 7.5–7.6, 9.4).
Base: main `d32dcd60fd37cd0bae4702a92447251b709d91dc` (PR #31, M7.0 packaging foundation merged).

This ADR changes no code, script or workflow. It creates no certificate, uses no Apple
credential, notarizes nothing and publishes nothing. It does not touch M6/Reset. It is written
against the M7.0 bundle (`docs/validation/M7.0-macos-packaging-foundation.md`) and **assumes M7.1
lands first**: OpenSSL and libcbor become checksum-pinned private static archives linked into the
worker like libfido2, `Contents/Frameworks/` disappears, and `LSMinimumSystemVersion` returns to
11.0. Where M7.1's result is assumed rather than known, it is labelled [ASSUMPTION-M7.1].

ADR-013 to ADR-016 are already reserved by the architecture plan (section 43), so this is
ADR-017. It elaborates plan sections 36 (release pipeline), 37 (macOS signing), 39 (provenance)
and M7.0 section 9, gates 3 and 4.

The companion validation plan is
[`docs/validation/M7.2-macos-release-validation-plan.md`](../validation/M7.2-macos-release-validation-plan.md).

## Evidence labels

- [APPLE] Behaviour stated in current Apple developer documentation, read for this ADR (the
  sources are listed at the end). It is quoted or closely paraphrased, never extrapolated.
- [GITHUB] Behaviour stated in current GitHub documentation.
- [REPO] Inspected source at the base commit.
- [POLICY] A project decision. It may be stricter than Apple requires.
- [INFERENCE] Reasoning from the above that no document states directly.
- [EMPIRICAL] An assumption that must be proven on real hardware or with a real identity before
  M7.2 can be called done. Each one is listed in section 13.
- [ASSUMPTION-M7.1] Depends on M7.1's final shape.

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
- `scripts/package-macos.py` refuses to run when `APPLE_*`, `TAURI_SIGNING_*` or
  `LIBFIDO2_LIB_DIR` is set.
- CI (`.github/workflows/ci.yml`) builds an ad-hoc bundle and DMG on `pull_request` with no
  secrets and uploads nothing.
- The repository is **public** (checked through the GitHub API). That matters for environment
  secrets, required reviewers and artifact attestations (section 6).

M7.0 recorded this as an open gate: "Today authenticity rests on the bundle seal and Gatekeeper at
app launch. A per-spawn requirement check needs a real Team ID and must land before a signed
release."

## 2. Decisions (summary)

| # | Decision | Kind |
| --- | --- | --- |
| D1 | The shipped code set is exactly two Mach-O executables: the main app and `Contents/MacOS/fido-worker`. Tauri adds no other nested code in this configuration. Anything else fails the release. | [POLICY], [ASSUMPTION-M7.1] |
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
| D13 | A release becomes public only through a gated publication job, approved by a human after the clean-machine matrix passes. That job re-downloads the draft's actual assets and hard-fails on any digest mismatch with the authorization record (D16). | [POLICY] |
| D14 | **Exact app ↔ worker binding.** After the worker is signed and before the bundle is signed, a trusted driver writes `Contents/Resources/release-worker-identity.json`. It records the worker's identifier, build identity, per-architecture cdhash and signed-file SHA-256, and the bundle signature then seals it. At startup the app authenticates that record through its own seal and keeps it in backend memory. Every spawn requires the exact recorded cdhash, so an older worker from the same publisher is rejected. | [POLICY], built on [APPLE] |
| D15 | **Signing-environment independence.** The credential-bearing job runs only a minimal signing/notarization driver plus Apple OS tools. The driver is checked out from a separate, protected repository at a pinned full commit SHA, never from the candidate commit. The candidate app is handled as data only. | [POLICY] |
| D16 | **Immutable publication.** Publication is bound to an explicit authorization tuple (section 7.6). GitHub immutable releases are required. Every byte-changing step has its own input and output digest (section 9.4). Tags are never moved or reused. | [GITHUB] + [POLICY] |

## 3. Code set and nested code

### 3.1 What gets signed

After M7.1 [ASSUMPTION-M7.1]:

```text
Fido Manager.app/
  Contents/
    Info.plist                     bound to the bundle signature
    PkgInfo
    MacOS/fidomanager-app          main executable  (signing id eu.fidomanager.desktop)
    MacOS/fido-worker              helper tool      (signing id eu.fidomanager.desktop.fido-worker)
    Resources/icon.icns            sealed resource
    Resources/release-worker-identity.json
                                   sealed resource; written by the signing driver after the worker
                                   is signed and before the bundle is signed (section 5.8)
    Resources/<third-party notices> sealed resource (M7.0 gate 2; exact names decided with M7.1)
    _CodeSignature/CodeResources   bundle seal
    CodeResources                  notarization ticket, added only by `stapler` (section 8.3)
```

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
  The checker already requires the bundle's Mach-O set to be exactly {main, worker, allowlisted
  dylibs}. After M7.1 the allowlist is empty.
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
#    write Contents/Resources/release-worker-identity.json (0644, regular file)

# 3. Bundle (main executable, resource seal incl. the record, Info.plist binding)
/usr/bin/codesign --force --sign "$IDENTITY_SHA1" --keychain "$KC" --timestamp \
  --options runtime "Fido Manager.app"
#    re-read the record from the sealed bundle and confirm that its cdhashes equal the worker's
#    CDHash in the signed bundle; codesign --verify --strict --deep (seal covers record + worker)

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
`check-macos-bundle.py`, run only in Build and Verify.

| Check | Command | Runs in | Pass criterion |
| --- | --- | --- | --- |
| Exact tree and Mach-O set | driver's own allowlist walk (no symlinks, regular files, Mach-O magic incl. fat headers) | Driver (pre-sign) and Verify | exactly {main, worker} as code; no `Frameworks/` [ASSUMPTION-M7.1]; no pre-existing identity record |
| Enforcing-build marker | byte search of the main binary for the marker (5.6) | Driver (pre-sign, data only) and Verify | present; its Team ID and release ID equal the driver's pinned Team ID and the tag's version/commit |
| Deep strict verify | `codesign --verify --strict --deep --verbose=4 "Fido Manager.app"` | Driver (post-sign) and Verify | exit 0 [APPLE: `--strict` matches notarization's restrictiveness] |
| Signature details | `codesign -dvvv "…/fidomanager-app"` and `"…/fido-worker"` | Driver and Verify | `Authority=Developer ID Application: … (TEAMID)`, then `Developer ID Certification Authority`, then `Apple Root CA`; `TeamIdentifier=$EXPECTED_TEAM_ID`; `Timestamp=` present, **not** `Signed Time=` [APPLE]; `flags=0x10000(runtime)`; expected `Identifier=` |
| Entitlements | `codesign -d --entitlements - --xml <exe>` | Driver and Verify | empty |
| Worker publisher requirement | `codesign --verify --strict -R='=<worker publisher requirement, 5.1>' "…/fido-worker"` | Driver and Verify | `explicit requirement satisfied` |
| Worker exact requirement | same, with `… and cdhash H"<record cdhash>"` | Driver (post-sign) and Verify | satisfied; and **not** satisfied by any other cdhash (Verify negative test) |
| Record ↔ worker | parse `release-worker-identity.json`; compare with `codesign -d -vvv --arch <a>` `CDHash`/`CandidateCDHashFull` and `shasum -a 256` | Driver (post-sign, post-staple) and Verify | all equal |
| App requirement | same, with the app requirement | Driver and Verify | satisfied |
| Default DR shape | `codesign -d -r- <exe>` | Verify | equivalent to the 5.1 requirement plus the default Mac App Store branch codesign adds; the identifier and Team ID match |
| Structural and linkage checks | `check-macos-bundle.py --signature developer-id --stapled --expected-team-id …` | **Verify only** (and the ad-hoc mode in Build) | passes |
| Executing the worker or app | `packaged_worker` test, launch checks | **Build (ad-hoc) and Verify only** | never in the Driver |
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
- Dynamic: `noNetworkAccess`.
- `noNetworkAccess` because normal FIDO operation must not need the network (section 9 of the
  validation plan). Certificate revocation for the app is Gatekeeper's job at first launch and
  is not repeated per spawn. [EMPIRICAL E3] confirms that validation with `noNetworkAccess`
  succeeds offline and takes a bounded time. If the flag turns out to make validation weaker
  than needed, the fallback is the default flags measured offline. `enforceRevocationChecks`
  stays off, because it would make every spawn depend on OCSP reachability.

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
     # universal builds only: repeat per slice with SecStaticCodeCreateWithPathAndAttributes
     # (kSecCodeAttributeArchitecture), since [APPLE] signing info covers one slice by default
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
  disabled until the app restarts.
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
Swapping such a worker into `Contents/MacOS/` breaks the bundle seal, but nothing re-checks the
seal at exec (5.4). So a publisher-only check would let a mixed app/worker pair run. D14 binds each
app release to the one worker approved for it.

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
- `build_id` is the worker's compiled-in build identity (version + source commit). The build job
  compiles it in, and the worker reports it in `ChildHello`. It is a consistency check, not the
  authority.

#### Creation (signing driver, between worker signing and bundle signing)

1. The driver signs the worker (3.2 step 1) and verifies it against the publisher requirement.
2. For each slice in `lipo -archs`, the driver reads `CDHash` and `CandidateCDHashFull sha256` from
   `codesign -d -vvv --arch`. It hashes the signed worker file. `version` and `source_commit` come
   from the workflow's tag context. `build_id` must equal `version+source_commit`, and the driver
   finds it in the worker binary by byte search; the worker is never executed (D15).
3. The driver writes the record and then signs the bundle (3.2 step 3). The record becomes a sealed
   resource.
4. After signing, and again after stapling, the driver re-parses the sealed record and checks it
   against the worker's actual `CDHash` in the signed bundle. Any difference fails the job.

The expected identity is derived from the **signed worker as signed by the driver**, inside the
protected job. It is never derived at runtime from whatever worker file happens to be present.

#### Startup authentication in the app (once per process)

```text
S1  self = SecCodeCopySelf(); SecCodeCheckValidity(self, DYNAMIC_FLAGS, APP_REQ)
    selfUnique = kSecCodeInfoUnique(self)                         # kernel-backed running identity
S2  bundle = SecCodeCopyStaticCode(self)                          # [APPLE] for bundles: the whole bundle
    require kSecCodeInfoUnique(bundle main executable) == selfUnique
S3  R1 = read record (O_RDONLY|O_NOFOLLOW, fstat regular file, size ≤ 4 KiB, read fully)
S4  SecStaticCodeCheckValidityWithErrors(bundle,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSRestrictSymlinks |
        kSecCSCheckNestedCode | noNetworkAccess, APP_REQ)
    # [APPLE] validates "all sealed components, including resources" → the record;
    # kSecCSCheckNestedCode → the worker against the seal's recorded nested-code identity
S5  R2 = read record again the same way; require R2 == R1 byte for byte
S6  parse R1 strictly; require identifier == const, team_id == TEAM_ID,
    release.version == app's compiled-in version, release.source_commit == compiled-in commit
S7  worker_static = SecStaticCodeCreateWithPath(worker path)  (per slice for universal builds)
    require kSecCodeInfoUnique == R1.slices[arch].cdhash, SHA-256(file) == R1.file_sha256
S8  EXPECTED = immutable in-memory value from R1; WORKER_EXACT_REQ compiled from it
    the record file is never read again in this process
```

Any failure means no launcher and FIDO disabled (5.7).

- **Why the record can be trusted.** S1–S2 tie the on-disk bundle to the running, kernel-validated
  main executable. S4 validates the bundle seal, which covers the record as a sealed resource. S5
  ties the bytes we parse to the bytes the seal validated. S7 confirms that the record, the seal
  and the worker on disk all agree. After S8 the expected identity lives only in backend memory.
  No renderer path, environment variable, argument or later file read can change it.
- **Residual.** S3–S5 are a read–validate–re-read pattern on a file. An actor that can write into
  the bundle and time three swaps precisely could present different bytes to the parser and to
  validation. That is the same actor and capability as the 5.5 residual: it can already replace
  the main executable outright, which no in-app check can see. [EMPIRICAL E16] looks for a
  documented API that returns the sealed resource hash, so the in-memory bytes could be compared
  with the seal directly. `kSecCSContentInformation` exists, but Apple calls using it "not
  generally advisable", so this design does not rely on it.
- [EMPIRICAL E17] Confirm on a real signed bundle that `SecCodeCopyStaticCode(self)` returns the
  bundle (Apple documents this for `SecCodeCopyPath`), and that S4 with `kSecCSCheckNestedCode`
  fails when (a) the record is edited, (b) the worker is replaced by another validly signed
  worker, and (c) the record is replaced together with the worker.

#### How this stops an older, legitimately signed worker

| Substitution | Where it fails |
| --- | --- |
| Older worker W_old (same Team ID, same identifier, valid Developer ID signature) put in `Contents/MacOS/` after startup | per-spawn step 3: cdhash and file SHA-256 ≠ `EXPECTED`; and if raced in after step 3, step 5: running cdhash ≠ `EXPECTED` and `WORKER_EXACT_REQ` fails. Contained before `ParentHello` |
| W_old put in place before startup | S4 (nested code no longer matches the seal) and S7 (cdhash ≠ record). No launcher |
| W_old plus a record edited to name W_old's cdhash | S4: the record is a sealed resource, so the edit breaks the bundle seal. No launcher |
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
| Rely only on the bundle seal's nested-code entry | S4 does check it. But the seal's internal format is not API (TN3127), and the per-spawn **dynamic** check needs the value in memory. The record is the explicit carrier, and S4 + S7 prove it agrees with the seal |
| Put the record in `Info.plist` | Possible, because `Info.plist` is bound to the signature. But a separate resource is simpler to generate and audit, and it keeps release metadata out of the plist that Tauri and LaunchServices interpret. Kept as the fallback if E16/E17 favour it |

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
  `package-macos.py`, test scripts, `.mjs` checkers;
- Cargo, rustc or build scripts, proc macros, `pnpm`/`npm`/`npx` or any lifecycle hook,
  package-manager installs of any kind;
- repository test tooling;
- local or reusable workflows or composite actions taken from the candidate commit
  (`uses: ./…`);
- any interpreter with the candidate tree as its working directory, on `PATH` or on an import path.

It does not even check out the candidate commit. It receives the candidate only as the
digest-verified `build-output.tar` (7.2), extracts it with `ditto` into `$RUNNER_TEMP/candidate/`,
and from then on only reads it, signs it and packages it.

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
  not `owner/repo/…@<40-hex>`. The release workflow uses only `actions/checkout`,
  `actions/upload-artifact`, `actions/download-artifact` and `actions/attest-build-provenance`.
  It calls no reusable workflows except, under S2, the signer's own at a pinned SHA.
- `attest` and the publication jobs also run no candidate code: no candidate checkout, only pinned
  actions, `gh`/`curl` and `shasum`.

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

The `preflight` job (ubuntu, `contents: read`, no candidate code beyond reading files with `git`
and `jq`) establishes the release identity. Every later job re-checks it against its own inputs:

- the ref is an **annotated** tag object (`git cat-file -t` → `tag`). It records the tag object
  SHA and the **peeled** commit SHA (`git rev-parse "$TAG^{commit}"`), and requires the peeled
  commit to equal `GITHUB_SHA`;
- the peeled commit is an ancestor of `origin/main`, so only reviewed `main` is released;
- no release, draft or published, already exists for this tag (releases API). With immutable
  releases [GITHUB], a deleted release's tag name cannot be reused either;
- the tag version equals `tauri.conf.json` `version`, the Cargo workspace version and
  `package.json` `version`;
- `github.workflow_ref` is `mbzbugsy/fidomanager/.github/workflows/release-macos.yml@refs/tags/<tag>`.
  The workflow SHA (`github.workflow_sha`) is recorded;
- every `uses:` in the workflow is pinned to a 40-hex SHA, and the signer pin is a 40-hex SHA
  (6.4);
- the repository has immutable releases enabled. It reads the repository setting through the API,
  and if that cannot be confirmed the run stops: fail closed. [EMPIRICAL E18] confirms the API
  surface for this setting.

Its outputs (tag, tag object SHA, peeled commit, version, arch, workflow SHA, signer SHA) are the
**release identity**. Every job checks out, downloads or verifies against these values and nothing
else.

### 7.2 Job graph

```text
preflight ─► build ─► sign-notarize ─► verify ─► attest ─► publish-draft ─► [human: Part B matrix] ─► publish-final
 (ubuntu)   (macOS,   (macOS, env       (macOS,   (ubuntu,  (ubuntu, env       on the draft's assets      (ubuntu, env
  read)      no env,   macos-release;    no env,   id-token,  macos-release-                              macos-release-public,
             no        driver @ pinned   no        attest-    publish,                                    contents: write)
             secrets)  SHA; candidate    secrets)  ations)    contents: write)
                       = data only)
```

| Job | Runs | Produces | Never |
| --- | --- | --- | --- |
| `build` | Checks out the peeled commit. Pinned toolchains (Rust from `rust-toolchain.toml`, Node 24.21.0, pnpm 10.17.1); `pnpm install --frozen-lockfile`; M7.1 native builds from pinned sources; `package-macos.py` release flavor (enforcing build, ad-hoc seal); `check-macos-bundle.py` (ad-hoc + enforcing marker); bundle-checker regressions; packaged worker handshake (ad-hoc, non-enforcing path); SBOM inputs | `build-output.tar` (the ad-hoc `.app` via `ditto` plus build-identity JSON and SBOM inputs) and its SHA-256 `D0` as a job output; `upload-artifact` retention 1 day | sees secrets; signs with Developer ID; uses caches |
| `sign-notarize` | **No candidate checkout.** Checks out the signer repo at the pinned SHA; downloads `build-output.tar` and verifies `D0` before extracting; runs the driver (6.4): data-only pre-checks, ephemeral keychain, sign worker, write the identity record, sign bundle, post-sign data checks, app notarization and staple, DMG build, sign, notarization and staple, digests `D1`–`D7` (9.4) | stapled app zip, stapled DMG, both notary logs, driver report with every digest | executes candidate binaries or scripts; runs pnpm/cargo/npm; uploads anything if any step failed |
| `verify` | Fresh VM, checks out the peeled commit, no secrets. Verifies `D5` and `D7`; quarantine-simulated assessment (validation plan, Part A); `stapler validate`; `spctl`; deep strict verify; publisher and exact requirements; record ↔ worker checks; `check-macos-bundle.py --signature developer-id --stapled`; builds and runs `packaged_worker` **with the enforcing verifier** against the signed worker (positive), plus an ad-hoc copy and, from the second release on, the previous release's worker (negatives); generates the SBOM, the manifest and `release-authorization.json` (7.6) | evidence, SBOM, manifest, authorization record, `SHA256SUMS` | has secrets |
| `attest` | `actions/attest-build-provenance` over the DMG, the app zip, the SBOM, the manifest and the authorization record. [GITHUB] available for public repositories | Sigstore-backed provenance attestations | runs without `verify` passing |
| `publish-draft` | Reviewer approval. Downloads every asset and verifies it against the authorization record; creates a **draft** release on the tag; uploads; **downloads every asset back from the draft through the API and re-verifies its SHA-256** (7.6) | draft release, verified | publishes; overwrites an existing release or asset |
| `publish-final` | Separate reviewer approval, given after the Part B matrix passes on the draft's assets. Re-downloads the draft assets, re-verifies the whole tuple, publishes, then runs post-publication verification (7.6) | public, immutable release | publishes anything whose bytes differ from the authorization record by even one digest |

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
  2  verify build-output.tar SHA-256 == D0 (needs.build); ditto -x into $RUNNER_TEMP/candidate
  3  data-only pre-checks: exact tree, Mach-O set, no symlinks, no identity record yet,
     Info.plist fields (plistlib), enforcing marker bytes: Team ID + version + commit match
  4  ephemeral keychain; assert exactly one identity == MACOS_DEVID_APP_SHA1, OU == Team ID
  5  codesign worker (3.2 step 1); publisher requirement satisfied; record D1 = worker file SHA-256
     and per-arch CDHash/CandidateCDHashFull
  6  write Contents/Resources/release-worker-identity.json (5.8)
  7  codesign bundle (3.2 step 3); codesign --verify --strict --deep; post-sign data checks
     (section 4 "Driver" rows: chain, timestamp, runtime, zero entitlements, identifiers,
     record ↔ worker CDHash, exact requirement)
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
     record ↔ worker (CDHash and CandidateCDHashFull), checker --stapled
  C  cargo test -p fido-worker --test packaged_worker -- --ignored with the enforcing verifier:
     positive (the signed worker); negatives (ad-hoc copy; previous release's signed worker,
     from release 2 on)
  D  SBOM, manifest, SHA256SUMS, release-authorization.json (D7 digests)
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
  tag-only deployment).

### 7.6 Publication authorization and final asset verification

`verify` writes `release-authorization.json`. It is the **authorization tuple**: the only
description of what may be published.

```jsonc
{
  "schema": "fidomanager.release-authorization/1",
  "repository": "mbzbugsy/fidomanager",
  "tag": "vX.Y.Z", "tag_object_sha": "<40-hex>", "commit_sha": "<40-hex, peeled>",
  "version": "X.Y.Z", "arch": "arm64", "deployment_target": "11.0",
  "workflow": { "ref": "mbzbugsy/fidomanager/.github/workflows/release-macos.yml@refs/tags/vX.Y.Z",
                "sha": "<github.workflow_sha>", "run_id": 0, "run_attempt": 1 },
  "signer": { "repository": "mbzbugsy/fidomanager-release-signer", "sha": "<40-hex>" },
  "worker_identity": { "cdhash": { "arm64": "<40-hex>" }, "file_sha256": "<64-hex>" },
  "assets": {
    "FidoManager-X.Y.Z-arm64.dmg":            { "sha256": "<D5>", "size": 0 },
    "FidoManager-X.Y.Z-arm64.app.zip":        { "sha256": "<D3>", "size": 0 },
    "FidoManager-X.Y.Z-arm64.cdx.json":       { "sha256": "…" },
    "release-manifest.json":                  { "sha256": "…" },
    "notary-app.json":                        { "sha256": "…" },
    "notary-dmg.json":                        { "sha256": "…" },
    "SHA256SUMS":                             { "sha256": "…" }
  },
  "notarization": { "app_submission": "…", "dmg_submission": "…" }
}
```

`attest` attests the authorization record together with the assets, so the tuple itself is bound
to this workflow run by Sigstore provenance.

**`publish-draft`** (reviewer-gated; `contents: write`; no candidate code):

1. Download all assets plus the authorization record. Recompute every SHA-256 and compare with the
   record. Check that `repository`, `tag`, `tag_object_sha`, `commit_sha`, `workflow.sha`,
   `run_id` and the signer SHA all equal this run's context and the `preflight` outputs.
2. Fail if any release already exists for the tag, or if the tag object or peeled commit differ
   from `preflight`'s values. That catches a moved tag, even though the ruleset forbids it.
3. Create a **draft** release on the tag and upload exactly the listed assets, plus the
   authorization record itself, so that it is covered by immutability once published.
4. Download every asset **back from the draft release through the API** into a fresh directory.
   Recompute SHA-256 and size, and compare with the record. Require that the draft has exactly the
   listed asset names. Any mismatch fails hard, and the draft is left unpublished for a maintainer
   to delete. It is never repaired in place.

**Human gate.** A maintainer runs the Part B clean-machine matrix on the DMG downloaded from that
draft, checks it against `SHA256SUMS`, and then approves `macos-release-public`.

**`publish-final`** (separately reviewer-gated; `contents: write`; no candidate code):

1. Download the draft's assets again and repeat step 1 and step 4 of `publish-draft` in full.
   Nothing is trusted from the earlier job.
2. Publish the draft (draft → published).
3. After publication: `gh release verify <tag>`, which [GITHUB] says checks that the release
   exists and is immutable. Then `gh release verify-asset <tag> <file>` for each locally verified
   asset, and one more API download with digest comparison. Confirm that the tag still peels to
   `commit_sha`.
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
  "native": {                                   // from source.lock.json + build-identity.json
    "libfido2": { "version": "1.17.0", "revision": "…", "source_sha256": "…", "patch_sha256": "…", "static_archive_sha256": "…" },
    "openssl":  { "version": "…", "source_sha256": "…", "configure": ["no-shared", "…"] },  // [ASSUMPTION-M7.1]
    "libcbor":  { "version": "…", "source_sha256": "…" }                                   // [ASSUMPTION-M7.1]
  },
  "signing": {
    "team_id": "XXXXXXXXXX", "identity_sha1": "…", "authority": "Developer ID Application: …",
    "hardened_runtime": true, "entitlements": {},
    "cdhash": { "fidomanager-app": { "arm64": "…" }, "fido-worker": { "arm64": "…" } },
    "worker_publisher_requirement": "anchor apple generic and …",
    "release_worker_identity": { "sha256": "<of the sealed record>", "worker_file_sha256": "…" },
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
| `FidoManager-X.Y.Z-<arch>.app.zip` | the stapled app archive (`D3`), for users and reviewers who want the app without the DMG; it carries its own stapled ticket |
| `SHA256SUMS` | digests of every other asset; computed after stapling |
| `release-manifest.json` | the record in 9.1 |
| `release-authorization.json` | the authorization tuple (7.6) |
| `FidoManager-X.Y.Z-<arch>.cdx.json` | CycloneDX 1.6 SBOM of the **shipped** artifact |
| `notary-app.json`, `notary-dmg.json` | Apple notarization logs (no secrets; they contain job IDs and cdhashes) |
| GitHub attestations | `gh attestation verify FidoManager-….dmg -R mbzbugsy/fidomanager` binds the digest to this workflow, commit and run; the immutable release adds GitHub's release attestation [GITHUB] |

Inside the bundle: third-party notices for libfido2, OpenSSL and libcbor (M7.0 gate 2), and
`release-worker-identity.json` (5.8), both as sealed resources.

### 9.3 SBOM scope

[POLICY] The SBOM describes what is **in the artifact**, per executable:

- `fidomanager-app`: the Rust crate closure for the target (normal dependencies only, from
  `cargo tree --locked -e normal --target <triple> -p fidomanager-app`), plus the npm
  packages bundled into `dist/` (from the lockfile,
  production dependencies that the Vite build actually bundles).
- `fido-worker`: its Rust crate closure, plus the statically linked libfido2, OpenSSL and libcbor
  with their versions, source digests and patch digests.
- System frameworks are listed as external, unversioned dependencies.

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
| build → hand-off | source at peeled commit | `D0` = SHA-256 of `build-output.tar` (ad-hoc app) | provenance attestation names the commit and run |
| worker signing | `D0` | `D1` = signed worker file SHA-256 + per-arch `CDHash`/`CandidateCDHashFull` | the worker's cdhash from here on is final |
| record + bundle signing | `D0`, `D1` | sealed app containing the record; per-arch cdhashes of the main executable | the record pins `D1`'s cdhash; the seal covers the record |
| app notarization | `D2` = SHA-256 of `app-signed.zip` | `notary-app.json` (`D6a`) | log `sha256 == D2`; `ticketContents` lists the main and worker cdhashes (8.2) |
| app stapling | sealed app | `D3` = SHA-256 of the stapled app zip | cdhashes unchanged (re-checked); ticket file added outside the seal |
| DMG build + signing | stapled app | `D4` = SHA-256 of the signed, unstapled DMG | DMG signature (identifier `eu.fidomanager.desktop.dmg`) |
| DMG notarization | `D4` | `notary-dmg.json` (`D6b`) | log `sha256 == D4`; ticket covers the DMG and its nested code |
| DMG stapling | signed DMG | `D5` = SHA-256 of the final DMG | DMG cdhash unchanged; ticket stapled |
| authorization | `D3`, `D5`, `D6`, SBOM, manifest | `release-authorization.json` (`D7`), attested | the authorization tuple (7.6) |
| draft upload → download | `D3`, `D5`, all assets | identical digests re-computed from the **downloaded** draft assets | hard fail on any mismatch |
| publication → download | same | identical digests from the **published** assets; `gh release verify` / `verify-asset` | immutable release + release attestation |

## 10. Fail-closed behaviour (consolidated)

| Condition | Where detected | Behaviour |
| --- | --- | --- |
| Invalid worker signature | app, per spawn (5.3) | No spawn, or contain if after spawn; terminal `WorkerIdentityRejected`; FIDO disabled; no fallback |
| **Older or otherwise different worker signed by the same publisher** | app, per spawn (cdhash ≠ `EXPECTED`, static and dynamic); app startup S4/S7 | same as above; at startup, no launcher |
| **Identity record missing, malformed, edited, unsealed or for another release** | app startup (5.8); driver post-sign and post-staple checks; Verify | app: no launcher, FIDO disabled; release: fails |
| Missing worker | app (5.3 step 2); driver tree check; Verify | `ExecutableRejected`; release fails |
| Wrong Team ID | app (requirement + `kSecCodeInfoTeamIdentifier`); driver (certificate vs pinned Team ID vs marker); Verify | app: terminal rejection; release: job fails before signing |
| Wrong worker identifier | app (requirement + dynamic info); driver; Verify | same as above |
| Unsigned or extra nested code | driver exact code set; `codesign --verify --strict --deep`; Verify | release fails; never "fixed" by signing the extra code |
| Hardened Runtime missing | app (`runtime` flag, static and dynamic); driver; Verify | app: rejection; release: fails |
| Entitlements present | app (static info); driver; Verify | app: rejection; release: fails |
| Missing secure timestamp | driver (`Timestamp=` required, `Signed Time=` rejected); Verify | release fails; no retry without a timestamp |
| Candidate code would have to run in the signing job | by construction (6.4): no candidate checkout, no candidate tools on `PATH`, driver from the pinned signer SHA | the step does not exist; a workflow change that adds one needs CODEOWNERS review and changes `workflow.sha` in the tuple |
| Signer checkout ≠ pinned SHA, or the pin is not on the signer's protected branch | driver self-check; preflight | job fails before any secret is used |
| Notarization failed, timed out, transient error, or any warning | driver (8.2) | job fails; nothing uploaded; manual re-run only |
| Stapling failed | driver (8.2) | one bounded retry, then fail |
| Gatekeeper assessment failed | Verify (8.4) | release fails |
| Artifact checksum mismatch at any job boundary | every consumer (9.4) | hard fail; download-tool warnings are never accepted instead |
| Draft or published asset differs from the authorization record | `publish-draft` step 4; `publish-final` steps 1 and 3 | before publication: stop, draft left unpublished; after publication: incident procedure (11) |
| Tag moved, not annotated, not on `main`, reused, or release already exists | preflight; publish jobs | stop before building or publishing |
| Immutable releases not enabled or cannot be confirmed | preflight | stop |
| A `uses:` not pinned to a 40-hex SHA | preflight | stop |
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

## 12. What M7.2 implementation should do after M7.1 merges

In order, each step reviewable on its own:

1. Rebase on the M7.1 merge. Confirm that the Mach-O set is {main, worker}, `Contents/Frameworks/`
   is absent, `LSMinimumSystemVersion` is 11.0, and the OpenSSL/libcbor lock and identity files
   exist. Update this ADR's [ASSUMPTION-M7.1] items if anything differs.
2. **Worker verifier** (`fido-platform`, macOS): FFI to `SecStaticCodeCreateWithPath`,
   `SecStaticCodeCheckValidityWithErrors`, `SecCodeCopyGuestWithAttributes`,
   `SecCodeCheckValidity`, `SecCodeCopySigningInformation`, `SecRequirementCreateWithString`,
   `SecCodeCopySelf` and `SecCodeCopyStaticCode`. Add negative tests (unsigned, ad-hoc, wrong
   identifier). Add a cdhash-pin test that runs in ad-hoc CI: two ad-hoc binaries with the same
   identifier, where a test-only requirement pins one cdhash and must reject the other.
3. **Release identity at startup** (5.8): the record parser (strict schema, 4 KiB bound), steps
   S1–S8, and the in-memory `EXPECTED`. Enforcing builds compile in the version and source commit
   for the S6 comparison. The worker compiles in its `build_id` and reports it in `ChildHello`
   (a protocol field addition, reviewed with ADR-009's contract).
4. **Launcher** (`fido-service/process_worker.rs`): move the path checks into `launch()`; add
   static validation against `WORKER_EXACT_REQ` and `EXPECTED` before spawn, and dynamic
   validation including the running cdhash before `ParentHello`; add `WorkerIdentityRejected` and
   make it terminal in the supervisor; add the renderer category.
5. **Build flavor**: the `macos-release-signing` Cargo feature and Team ID constant, and the
   enforcing marker (Team ID + version + commit). `package-macos.py` gets a release flavor, and the
   renderer-boundary rules allow a single construction site.
6. **Signing driver** (new repository `mbzbugsy/fidomanager-release-signer`, protected per 6.4):
   stdlib-only Python driver + config; data-only pre-checks; worker signing; identity record
   generation; bundle signing; post-sign data checks; notarization with the 8.2 acceptance rules;
   stapling; DMG; digests `D1`–`D6`; driver report. It has its own unit tests on fixtures in its
   own repository.
7. **Candidate-side checker** (`check-macos-bundle.py`, Build/Verify only): `--expected-team-id`,
   requirement and authority-chain assertions, timestamp wording, enforcing marker, `--stapled`,
   the identity-record allowlist entry and record ↔ worker checks, DMG checks, notices, and new
   mutation cases (wrong Team ID marker, edited record, worker cdhash ≠ record, stapled extra
   file, `Signed Time` only, missing chain).
8. **Provenance**: `scripts/release-provenance.py` (manifest, SBOM, `SHA256SUMS`, authorization
   record), run in Verify.
9. **Workflow**: `.github/workflows/release-macos.yml` per section 7, and the documented one-time
   settings (7.5).
10. **Fail-closed rehearsal before any credential exists**: push a pre-release tag to a fork or a
    throwaway repository with no secrets. Prove that the sign job fails at the secret-presence
    check and nothing is uploaded or published. Also prove that `preflight` rejects an unpinned
    `uses:`, a lightweight tag and a signer pin that is not on the signer's protected branch.
11. **First real run**, only on Nima's explicit go-ahead with credentials provisioned: an `rc` tag,
    a draft release, the full clean-machine matrix
    ([validation plan](../validation/M7.2-macos-release-validation-plan.md)), then
    `publish-final`.
12. Independent security review of 2–9 and of the first run's evidence before M7.2 is merged.

The existing `ci.yml` stays ad-hoc and secret-free. The release workflow is a new file.

## 13. Unresolved empirical questions

| ID | Question | How to answer |
| --- | --- | --- |
| E1 | Does the 5.1 requirement accept the real signed worker and reject ad-hoc, unsigned, wrong-identifier and other-team binaries? | First real identity; `codesign -R` and the verifier's unit tests |
| E2 | Does `SecStaticCodeCreateWithPath` on `Contents/MacOS/fido-worker` produce a single-file static code object with the worker's identifier? | Signed bundle; log the identifier |
| E3 | Do static and dynamic validation with `noNetworkAccess` succeed offline, with bounded latency? | Clean Mac, network off |
| E4 | Does Hardened Runtime alone set the dynamic `kill` status on the worker? | `SecCodeCopySigningInformation(kSecCSDynamicInformation)` on the running worker |
| E5 | Per-spawn validation cost on the slowest supported Mac | Measure steps 3 and 5 |
| E6 | Can a suspended (`POSIX_SPAWN_START_SUSPENDED`) process be validated before dyld runs? (optional hardening) | Prototype |
| E7 | Does any TCC prompt appear for the signed app or worker (HID, Input Monitoring)? | Clean Mac matrix |
| E8 | Does an app copied out of a stapled DMG launch offline **without** its own staple? (only explains the D9 choice; not a gate) | Clean Mac, network off |
| E9 | Does `codesign --keychain` find an identity in a keychain that is not in the search list? | First signing run |
| E10 | The minimum App Store Connect API key role for `notarytool` | When the key is created |
| E11 | Do notary logs always include `sha256` and per-arch `cdhash` in `ticketContents`? | First submission |
| E12 | Does stapling a bundle write exactly `Contents/CodeResources` and leave cdhashes unchanged? | First staple |
| E13 | Exact `spctl` output for a notarized DMG; `syspolicy_check` availability on runners | First run |
| E14 | First-launch Gatekeeper latency of the quarantined app → worker spawn → hello, against the 3 s handshake timeout (online, offline, translocated) | Validation plan, part C |
| E15 | Whether exec of a quarantined nested helper triggers its own Gatekeeper evaluation and how long it takes | Same, with `log stream --predicate 'subsystem == "com.apple.syspolicy"'` |
| E16 | Is there a documented API that returns the sealed hash of one bundle resource, so the record's in-memory bytes can be compared with the seal directly instead of the S3–S5 re-read pattern? | Apple documentation / DTS; prototype |
| E17 | Does `SecCodeCopyStaticCode(self)` give the whole bundle, and does S4 with `kSecCSCheckNestedCode` reject (a) an edited record, (b) a different validly signed worker, (c) both swapped together? | Signed bundle, mutated copies |
| E18 | Can `preflight` confirm through the API that immutable releases are enabled, and does the release object report immutability after publication? | First rehearsal |

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
