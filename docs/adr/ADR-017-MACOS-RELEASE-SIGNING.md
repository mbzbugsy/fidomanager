# ADR-017: macOS Developer ID signing, worker authenticity, notarization and release workflow

Status: **Proposed for independent review** (M7.2 design only).
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
| D2 | Sign inside-out: worker, then bundle, then DMG. Never sign with `--deep`. | [APPLE] + [POLICY] |
| D3 | Hardened Runtime on both executables. **Zero entitlements** on both. No exception entitlement may be added without its own ADR. | [APPLE] requirement + [POLICY] |
| D4 | Every signature carries a secure timestamp from `timestamp.apple.com`. Without one, signing fails; there is no unsigned fallback. | [APPLE] + [POLICY] |
| D5 | Before **every** spawn, the app validates the worker against a compiled-in code requirement: Apple-issued Developer ID Application, a fixed Team ID, and identifier `eu.fidomanager.desktop.fido-worker`. It validates statically before exec, then dynamically against the running child before any message is sent. | [POLICY], built on [APPLE] APIs |
| D6 | The verification mode is fixed at compile time. Release builds enforce it, and the release checker proves the shipped binary is an enforcing build. Nothing at runtime can select a weaker mode. | [POLICY] |
| D7 | Release builds run only in a dedicated tag-triggered workflow. They are never built from a PR, and a PR artifact is never signed. The protected workflow builds the bundle again from the reviewed tag. | [POLICY] |
| D8 | The protected workflow splits into a build job with no secrets, a signing/notarization job that holds secrets and never runs third-party build code, a verification job with no secrets, and a publication job that creates a **draft** release. Jobs hand off by SHA-256 digest. | [POLICY] |
| D9 | Notarize and staple the `.app` (submitted as a zip), then build, sign, notarize and staple the DMG. That is two notarizations. | [APPLE] permits; [POLICY] chooses |
| D10 | Credentials are a Developer ID Application PKCS#12 and an App Store Connect API key. They live only in a protected GitHub Environment with a required reviewer and are imported into an ephemeral keychain that is destroyed in `always()`. | [GITHUB] + [POLICY] |
| D11 | Any failure in signing, notarization, stapling, assessment or digest checks stops the run before anything is published. There is no unsigned, ad-hoc, unnotarized or unstapled fallback. | [POLICY] |
| D12 | Each release ships a manifest, `SHA256SUMS`, a CycloneDX SBOM, both notarization logs and a GitHub build-provenance attestation. | [POLICY] |
| D13 | Making a release public is a human step, taken after the clean-machine matrix passes. | [POLICY] |

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
- [POLICY] The release check requires the Mach-O set to be **exactly** {main, worker}. Every
  regular file is checked for Mach-O magic, including fat headers. Any extra code (a framework,
  `.dylib`, `.so`, XPC service or plug-in) fails the release. It is never signed "to make it pass".

### 3.2 Signing order and options

[APPLE] "Sign code from the inside out", "Don't pass the `--deep` option to `codesign` when you
sign code", "add the `--timestamp` option", and "If you're signing a main executable for
Developer ID distribution, add the `-o runtime` option". [APPLE] To sign a DMG, use a Developer
ID **Application** identity, a unique identifier and `--timestamp`, on a UDIF read-only
zip-compressed (`UDZO`) image ("Packaging Mac software for distribution").

```sh
# 1. Worker (nonbundled helper tool)
codesign --force --sign "$IDENTITY_SHA1" --keychain "$KC" --timestamp \
  --options runtime --identifier eu.fidomanager.desktop.fido-worker \
  "Fido Manager.app/Contents/MacOS/fido-worker"

# 2. Bundle (main executable, resource seal, Info.plist binding)
codesign --force --sign "$IDENTITY_SHA1" --keychain "$KC" --timestamp \
  --options runtime "Fido Manager.app"

# 3. (after the app is notarized and stapled, section 8) the DMG
codesign --force --sign "$IDENTITY_SHA1" --keychain "$KC" --timestamp \
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
- Signing steps 1 and 2 are what `sign-macos-bundle.py` already does once its Frameworks pass
  becomes empty. M7.2 adds `--keychain` and makes the SHA-1 form mandatory in release mode.

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

## 4. Verification commands (structural, before notarization)

| Check | Command | Pass criterion |
| --- | --- | --- |
| Deep strict verify | `codesign --verify --strict --deep --verbose=4 "Fido Manager.app"` | exit 0 [APPLE: `--strict` matches notarization's restrictiveness] |
| Signature details | `codesign -dvvv "…/fidomanager-app"` and `"…/fido-worker"` | `Authority=Developer ID Application: … (TEAMID)`, then `Developer ID Certification Authority`, then `Apple Root CA`; `TeamIdentifier=$EXPECTED_TEAM_ID`; `Timestamp=` present, **not** `Signed Time=` [APPLE]; `flags=0x10000(runtime)`; expected `Identifier=` |
| Entitlements | `codesign -d --entitlements - --xml <exe>` | empty |
| Worker requirement | `codesign --verify --strict -R='=<worker requirement, 5.1>' "…/fido-worker"` | `explicit requirement satisfied` |
| App requirement | same with the app requirement | satisfied |
| Default DR shape | `codesign -d -r- <exe>` | equivalent to the 5.1 requirement plus the default Mac App Store branch codesign adds; the identifier and Team ID match |
| Mach-O set / linkage | `check-macos-bundle.py --signature developer-id --expected-team-id $EXPECTED_TEAM_ID` | passes; exact code set {main, worker}; no `Frameworks/` [ASSUMPTION-M7.1] |
| Enforcing build | release checker (section 5.6) | main binary carries the enforcing-mode marker and the expected Team ID constant |
| Policy pre-check | `spctl --assess --type execute -vvv "Fido Manager.app"` | before notarization, expected to report "Unnotarized Developer ID" or be rejected; recorded only [APPLE: `spctl` reports how current policy would treat the software] |

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
  is public (it is in every signature), so a constant leaks nothing. The release job asserts that
  the certificate's Team ID equals that constant (section 7).
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
Validation results are never cached. Only the compiled requirement is cached.

```text
launch(generation):
  1. path   = canonical(dir(canonical(current_exe())) / "fido-worker")      # 'static name, as today
  2. require regular file, not symlink, executable, not group/world-writable,
             parent == dir(canonical(current_exe()))                         # re-done per spawn
  3. static = SecStaticCodeCreateWithPath(path)
     SecStaticCodeCheckValidityWithErrors(static, STATIC_FLAGS, WORKER_REQ)  # gate before exec
     info   = SecCodeCopySigningInformation(static, signing)
     require info.flags ⊇ runtime, info.team == TEAM_ID, no entitlements
  4. spawn exactly that path (env cleared, 'static args, fd 3 only in --authentication)
  5. guest  = SecCodeCopyGuestWithAttributes(NULL, {pid: child.pid})         # child unreaped
     SecCodeCheckValidity(guest, DYNAMIC_FLAGS, WORKER_REQ)
     dyn    = SecCodeCopySigningInformation(guest, dynamic|signing)
     require dyn.status ⊇ valid (and kill, see 5.5), dyn.team == TEAM_ID,
             dyn.identifier == "eu.fidomanager.desktop.fido-worker", dyn.flags ⊇ runtime
  6. only now write ParentHello; the handshake timeout starts as today
  on any failure in 3: do not spawn.
  on any failure in 5: contain() (kill + reap, ADR-009 ordering) before reporting; nothing sent.
```

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
the **execution**.

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
  constant. `check-macos-bundle.py --signature developer-id` **requires** the marker, and fails if
  its Team ID differs from the signing certificate's. So an ad-hoc-mode binary cannot be shipped
  under a Developer ID signature, and an enforcing binary cannot be signed by the wrong team.
- Ad-hoc CI keeps building non-enforcing bundles (PR CI has no identity). The enforcing code path
  is covered by: unit tests that the requirement **rejects** unsigned and ad-hoc fixtures (runnable
  in ad-hoc CI on macOS), and the release verification job, which runs `packaged_worker` with the
  enforcing verifier against the real signed worker (section 7.4).
- Renderer-boundary checks are extended to require exactly one `WorkerAuthenticity` construction
  site and exactly one Team ID constant. No Tauri command, event or capability may reference
  them. The renderer cannot influence the path, requirement, Team ID, identity or failure handling.

### 5.7 Failure behaviour

| Event | Behaviour |
| --- | --- |
| Worker missing, not a regular file, symlink, wrong directory, writable by others | `LaunchError::ExecutableRejected` (exists). Nothing spawned. |
| Static validation fails (unsigned, ad-hoc, bad signature, wrong identifier, wrong Team ID, not Developer ID Application, missing `runtime`, entitlements present) | New `LaunchError::WorkerIdentityRejected`. Nothing spawned. |
| Dynamic validation fails after spawn | Contain (kill + reap) first, then `WorkerIdentityRejected`. No `ParentHello` written. |
| Requirement fails to compile, or the app's self-check fails | No launcher is built. The app runs without FIDO functionality and shows the integrity error. |

- [POLICY] `WorkerIdentityRejected` is **terminal for the app session**. The supervisor does not
  retry it under backoff, because a signature failure is not transient. FIDO functionality stays
  disabled until the app restarts.
- The renderer gets one categorical state ("Fido Manager could not verify its own components.
  Reinstall it from the official release.") with no path, OSStatus, Team ID or certificate detail.
  Diagnostics may record the OSStatus category locally.
- There is never a fallback to an unsigned, ad-hoc or differently signed worker, to the
  development mode, or to an in-process path (no in-process placement exists; ADR-009).

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
| `MACOS_TEAM_ID` | Team ID. Must equal the source constant (`MACOS_RELEASE_TEAM_ID`) or the job fails |

- Names deliberately avoid `APPLE_*` and `TAURI_SIGNING_*`. Tauri's bundler signs or notarizes on
  its own when such variables exist, and `package-macos.py` refuses to run when they are set
  [REPO]. Signing stays in our inside-out script.
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
- `macos-release-publish` holds no secrets. It has its own required reviewer and gates the job that
  creates the draft release.
- *Prevent self-review* is turned on as soon as a second maintainer exists. With a single
  maintainer, the approval is still an explicit human step that cannot be skipped.
- Tag ruleset: only maintainers may create `v*` tags, and tags cannot be updated or deleted.
- `CODEOWNERS` requires the maintainer's review on `.github/workflows/release-macos.yml` and on the
  signing, checking and packaging scripts.
- If the repository becomes private on a plan without environment secrets, the secrets resolve to
  empty strings. The sign job's first step asserts that every secret is non-empty and fails if any
  is missing (section 10).

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
- The job asserts that the imported certificate's Team ID (`subject.OU`) equals `MACOS_TEAM_ID`,
  which equals the source constant, and that its fingerprint equals `MACOS_DEVID_APP_SHA1`.
- [GITHUB] GitHub-hosted macOS runners give each job a fresh VM. [POLICY] Self-hosted runners are
  never used for any release job.
- Secrets are exposed through `env:` on **the individual steps** that use them, not job-wide.
  Shell tracing (`set -x`) is forbidden in those steps.

### 6.4 Secret isolation from untrusted code

- [POLICY] PR workflows (`pull_request`) never reference either environment. `pull_request_target`
  and `workflow_run` are not used for anything release-related.
- [POLICY] The job that holds secrets **runs no third-party build code**: no `pnpm install`, no
  `cargo build`/`cargo test`, no `build.rs`, no npm lifecycle scripts. It checks out the tagged
  commit only to run the reviewed Python signing, checking and notarization scripts, which use the
  standard library and Apple's command-line tools. Dependency code (npm postinstall, Cargo build
  scripts, proc macros) runs only in the build and verify jobs, which have no secrets and run on
  different VMs.
- [POLICY] Release jobs use no `actions/cache`. Cache entries written by `main` pushes are readable
  from tag runs, and a poisoned cache must not reach a signed artifact.
- [POLICY] Every action is pinned to a full commit SHA (existing CI practice). The release workflow
  is plain `run:` steps plus `actions/checkout`, `actions/upload-artifact`,
  `actions/download-artifact` and `actions/attest-build-provenance`.

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

The `preflight` job (ubuntu, `contents: read`) checks that:

- the tag is annotated and its commit is an ancestor of `origin/main`, so only reviewed `main` is
  released;
- the tag version equals `tauri.conf.json` `version`, the Cargo workspace version and
  `package.json` `version`;
- the commit is the checked-out `GITHUB_SHA`. This SHA is passed to every later job, and each job
  checks out exactly that SHA with `persist-credentials: false`.

### 7.2 Job graph

```text
preflight ──► build ──► sign-notarize ──► verify ──► attest ──► publish-draft
 (ubuntu)    (macOS,    (macOS, env        (macOS,    (ubuntu,   (ubuntu, env
  read)       no env,    macos-release,     no env,    id-token,  macos-release-publish,
              no         secrets; NO        no         attest-    contents: write)
              secrets)   3rd-party code)    secrets)   ations)
```

| Job | Runs | Produces | Never |
| --- | --- | --- | --- |
| `build` | Pinned toolchains (Rust from `rust-toolchain.toml`, Node 24.21.0, pnpm 10.17.1); `pnpm install --frozen-lockfile`; M7.1 native builds from pinned sources; `package-macos.py --release-flavor` (enforcing build, ad-hoc seal); `check-macos-bundle.py` (ad-hoc + enforcing marker); bundle-checker regressions; packaged worker handshake (ad-hoc, non-enforcing path); SBOM inputs (`cargo metadata`, per-binary `cargo tree`, pnpm lockfile, native `source.lock.json`/`build-identity.json`) | `build-output.tar` (the ad-hoc `.app` via `ditto` plus build-identity JSON) with its SHA-256 as a job output; `upload-artifact` retention 1 day | sees secrets; signs with Developer ID; uses caches |
| `sign-notarize` | Download; **verify SHA-256 equals `build`'s output before extracting**; secret presence check; ephemeral keychain; Developer ID sign (worker, bundle); structural checks with `--expected-team-id`; app notarization and staple; DMG build, sign, notarize, staple; final digests | signed, notarized, stapled `.app` (as a `ditto` zip) and `.dmg`; both notary logs; digests | runs pnpm/cargo/npm; uploads anything if any step failed |
| `verify` | Fresh VM. Download; verify digests; quarantine-simulated assessment (validation plan, part A); `stapler validate`; `spctl`; deep strict verify; requirement checks; `check-macos-bundle.py --signature developer-id --stapled`; build and run `packaged_worker` **with the enforcing verifier** against the signed worker | pass/fail evidence (job summary and an artifact) | has secrets |
| `attest` | `actions/attest-build-provenance` on the DMG and the manifest. [GITHUB] available for public repositories | Sigstore-backed provenance attestation | runs without `verify` passing |
| `publish-draft` | Reviewer approval; download; verify every digest against `SHA256SUMS`; create a **draft** GitHub Release with the assets | draft release | makes the release public; overwrites an existing release or tag asset |

The handoff between jobs is digest-bound [POLICY]. Each producer writes the SHA-256 of its tarball
or DMG to a job output, and each consumer recomputes it before use. `upload-artifact` digests are
recorded too, but the repo-computed digest is the binding one. This is not a handoff from an
untrusted producer: every producer is a job of the same protected run, built from the reviewed
tag. The digest protects against an artifact being swapped or corrupted between jobs.

### 7.3 Why build in a separate unprivileged job

The user's constraint is to rebuild inside the protected workflow and never sign a PR artifact.
D7 and D8 satisfy it: the bundle is rebuilt from the tagged commit in this workflow. The build and
sign steps are split into two jobs because the build runs a large third-party code surface (npm
lifecycle scripts, Cargo build scripts, proc macros, native configure scripts). If that code ran
in the job holding the PKCS#12 and API key, it could read them. With the split, the signing VM
never executes it. The digest stops anything other than the build job's own output from being
signed.

### 7.4 Sequence (sign-notarize and verify)

```text
sign-notarize
  1  assert secrets non-empty; assert MACOS_TEAM_ID == source constant
  2  verify build-output.tar SHA-256 == needs.build.outputs.sha256; extract with ditto
  3  ephemeral keychain; assert exactly one identity == MACOS_DEVID_APP_SHA1
  4  sign-macos-bundle.py --identity $MACOS_DEVID_APP_SHA1 --keychain $KC
  5  check-macos-bundle.py --signature developer-id --expected-team-id $MACOS_TEAM_ID
     (+ enforcing marker, exact code set, DRs, chain, timestamp, runtime, zero entitlements)
  6  ditto -c -k --keepParent "Fido Manager.app" app.zip           [APPLE: zip for .app]
  7  notarytool submit app.zip --key … --wait --timeout 45m --output-format json
  8  notarytool log <id> notary-app.json; enforce acceptance (8.2)
  9  stapler staple "Fido Manager.app"; stapler validate "Fido Manager.app"
 10  spctl --assess --type execute -vvv "Fido Manager.app"  → accepted, source=Notarized Developer ID
 11  check-macos-bundle.py … --stapled                            (signature unchanged by staple)
 12  stage dir: ditto stapled app + Applications symlink
     hdiutil create -format UDZO -srcfolder stage -volname "Fido Manager" dmg
     hdiutil verify dmg                                           [APPLE]
 13  codesign DMG (3.2); codesign --verify --strict -vvv dmg
 14  notarytool submit dmg --wait --timeout 45m; log → notary-dmg.json; enforce acceptance
 15  stapler staple dmg; stapler validate dmg
 16  spctl --assess --type open --context context:primary-signature -vvv dmg → accepted
 17  SHA-256 of final dmg (computed AFTER stapling) and of the stapled app zip
 18  always(): delete keychain and key files
verify (fresh VM, no secrets)
  A  digests; quarantine-simulated DMG; mount read-only; copy app out with ditto
  B  stapler validate, spctl, codesign deep strict, requirement checks, checker --stapled
  C  cargo test -p fido-worker --test packaged_worker -- --ignored  with the enforcing verifier
     (positive: real signed worker accepted; negative: ad-hoc copy of the worker rejected)
```

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
the signature afterwards. The cdhashes of both executables are unchanged by stapling; the checker
asserts this against the pre-staple values.

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
    "cdhash": { "fidomanager-app": "…", "fido-worker": "…" },
    "worker_requirement": "anchor apple generic and …"
  },
  "notarization": {
    "app": { "submission_id": "…", "status": "Accepted", "log_sha256": "…" },
    "dmg": { "submission_id": "…", "status": "Accepted", "log_sha256": "…" },
    "stapled": ["app", "dmg"]
  },
  "artifacts": [ { "name": "FidoManager-X.Y.Z-arm64.dmg", "sha256": "…", "size": 0 } ],
  "sbom": { "name": "FidoManager-X.Y.Z-arm64.cdx.json", "sha256": "…" }
}
```

### 9.2 What ships alongside the release

| Asset | Purpose |
| --- | --- |
| `FidoManager-X.Y.Z-<arch>.dmg` | the signed, notarized, stapled distribution |
| `SHA256SUMS` | digests of every other asset; computed after stapling |
| `release-manifest.json` | the record in 9.1 |
| `FidoManager-X.Y.Z-<arch>.cdx.json` | CycloneDX 1.6 SBOM of the **shipped** artifact |
| `notary-app.json`, `notary-dmg.json` | Apple notarization logs (no secrets; they contain job IDs and cdhashes) |
| GitHub attestation | `gh attestation verify FidoManager-….dmg -R mbzbugsy/fidomanager` binds the digest to this workflow, commit and run |

Inside the bundle: third-party notices for libfido2, OpenSSL and libcbor (M7.0 gate 2), as sealed
resources.

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
supply chain. It runs in the `build` job, and `sign-notarize` only adds the final digests.

## 10. Fail-closed behaviour (consolidated)

| Condition | Where detected | Behaviour |
| --- | --- | --- |
| Invalid worker signature | app, per spawn (5.3) | No spawn, or contain if after spawn; terminal `WorkerIdentityRejected`; FIDO disabled; no fallback |
| Missing worker | app (5.3 step 2); release checker | `ExecutableRejected`; release fails |
| Wrong Team ID | app (requirement + `kSecCodeInfoTeamIdentifier`); sign job (certificate vs constant); checker | app: terminal rejection; release: job fails before signing |
| Wrong worker identifier | app (requirement + dynamic info); checker | same as above |
| Unsigned or extra nested code | checker exact code set; `codesign --verify --strict --deep` | release fails; never "fixed" by signing the extra code |
| Hardened Runtime missing | app (`runtime` flag, static and dynamic); checker | app: rejection; release: fails |
| Entitlements present | app (static info); checker | app: rejection; release: fails |
| Missing secure timestamp | checker (`Timestamp=` required, `Signed Time=` rejected) | release fails; no retry without a timestamp |
| Notarization failed, timed out, transient error, or any warning | sign job (8.2) | job fails; nothing uploaded; manual re-run only |
| Stapling failed | sign job (8.2) | one bounded retry, then fail |
| Gatekeeper assessment failed | sign and verify jobs (8.4) | release fails |
| Artifact checksum mismatch | every job boundary; publish job against `SHA256SUMS` | job fails; no publication |
| Release secret missing or empty | sign job step 1 | job fails before any keychain or network action |
| Certificate fingerprint or Team ID ≠ pinned | sign job step 3 | job fails |
| Release binary built without enforcement | checker marker (5.6) | release fails |
| Tag not on `main`, version mismatch | preflight | workflow stops before building |

Every row is fail-closed. **No row has an automatic downgrade** to ad-hoc, unsigned, unnotarized,
unstapled or "publish and staple later".

## 11. Rollback and incident handling

- A failed run publishes nothing. Draft releases from aborted runs are deleted by a maintainer,
  and tags are never moved or reused (ruleset). A fixed release gets a new patch version.
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
   `SecCodeCheckValidity`, `SecCodeCopySigningInformation`, `SecRequirementCreateWithString` and
   `SecCodeCopySelf`. Add negative tests (unsigned, ad-hoc, wrong identifier) that run in ad-hoc
   CI.
3. **Launcher** (`fido-service/process_worker.rs`): move the path checks into `launch()`; add
   static validation before spawn and dynamic validation before `ParentHello`; add
   `WorkerIdentityRejected` and make it terminal in the supervisor; add the renderer category;
   add the app self-check at startup.
4. **Build flavor**: the `macos-release-signing` Cargo feature and Team ID constant, the enforcing
   marker, a `package-macos.py` release flavor, and renderer-boundary rules for the single
   construction site.
5. **Signer**: `--keychain`, the SHA-1-only identity in release mode, and DMG signing. Add `kill`
   only if E4 requires it.
6. **Checker**: `--expected-team-id`, requirement and authority-chain assertions, timestamp
   wording, the enforcing marker, `--stapled`, DMG checks, notices, and new mutation cases (wrong
   Team ID marker, stapled extra file, `Signed Time` only, missing chain).
7. **Notarization script**: `scripts/notarize-macos.py` wrapping `notarytool submit/log` and
   `stapler`, enforcing 8.2 and writing the manifest fragment.
8. **Provenance**: `scripts/release-provenance.py` (manifest, SBOM, `SHA256SUMS`).
9. **Workflow**: `.github/workflows/release-macos.yml` per section 7, and the documented
   one-time repository settings (environments, reviewers, tag ruleset, CODEOWNERS).
10. **Fail-closed rehearsal before any credential exists**: push a pre-release tag to a fork or a
    throwaway repository with no secrets. Prove that the sign job fails at the secret-presence
    check and that nothing is uploaded or published.
11. **First real run**, only on Nima's explicit go-ahead with credentials provisioned: an
    `rc` tag, a draft release, then the full clean-machine matrix
    ([validation plan](../validation/M7.2-macos-release-validation-plan.md)).
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
- GitHub, *Deployments and environments* (reference)
