# M2 macOS native authentication validation

Issue: #11. Branch: `feature/m2-production-auth`.
Starting main/head: `aeba71a548ca2b935aa2eb53a740f3ea0879d6f2`.
Validation date: 2026-10-03 (operator Europe/Stockholm context).
Implementation commit: the commit containing this report; exact final SHA is recorded in the PR.

Evidence labels: [SOURCE] inspected implementation/previous reviewed API contract; [TEST]
deterministic checks; [MACOS] locally observed platform behavior; [HARDWARE] physical-key
observations; [INFERENCE] conclusion from those sources; [UNRESOLVED] evidence still required.

## Production path

[SOURCE] `AuthenticationAuthority` reserves the existing global `SensitiveWorkflowGate` and
`PromptController`, minting workflow, prompt and acquisition identities. The canonical discovery
supervisor supplies the generation-bound device target. A native menu lists each discovered key
using backend-owned opaque handles and product/manufacturer/transport labels. The selected handle
must survive a fresh registry refresh before preparation; stale selections are rejected, never rebound.
The PIN sheet identifies that selected key. The transaction exclusively borrows the supervisor
for its entire lifetime; background refresh cannot interleave. Multiple connected keys are
supported as separate sequential workflows, with no shared or cached authority.

[SOURCE] The worker opens a fresh native device, gets capabilities and PIN retries, and chooses
`CredManReadOnly` only with permission tokens plus advertised `perCredMgmtRO`; ordinary supported
credential management selects `CredMan`. Only explicit CTAP 2.0 preview evidence without scoped
tokens selects `LegacyUnscoped`. Duplicate/contradictory/unsupported evidence fails closed. Native
permission support is cross-checked before acquisition. There is no caller-selected scope.

[SOURCE] A real main-window AppKit asynchronous sheet contains `NSSecureTextField`, fixed backend
text, reported retries, a low-retry warning and an additional native checkbox on the last retry.
Cancel is default. The controller rejects stale/double completions and retains admission until
the sheet is detached, ordered out, its timer invalidated and observer removed. Failure to prove
teardown retains the gate. No debug/modality-spike API is used by the production entry.

[SOURCE] A dedicated Unix socket at fixed child fd 3 transports exactly one frame: magic/version,
worker generation, device generation, workflow, prompt, acquisition, request ID, bounded length,
then PIN. The maximum payload is 63 UTF-8 bytes; embedded NUL, invalid UTF-8, short/oversized
frames, mismatched binding, EOF truncation and trailing/replayed payload fail closed. No normal
JSON request contains PIN bytes. Both ends close after use; sender storage is consumed and
worker storage is consumed after native use.

[SOURCE] PIN storage is a fixed 64-byte `Zeroizing<Box<[u8]>>` allocation with no Clone, Debug, Display, or serde.
NSString writes directly into that Rust buffer without an intermediate Rust String/CString.
Ownership moves a pointer, not PIN bytes, through the Rust completion channel. The guarantee covers Rust-owned buffers on normal drop/error paths. It does not cover AppKit/input
method copies, libfido2 internals, kernel socket buffers, paging, hibernation, crash dumps,
forced process death, or authenticator-side token state. No PIN/token persistence or logging is
implemented. `FIDO_DEBUG` presence is refused before native initialization; child environment is
cleared.

[SOURCE] PUAT bytes remain inside libfido2. An owned, non-clone, non-serde `AuthorizationGrant`
binds exact acquisition, actual kind and both generations. Grant validation consumes that grant;
the transaction allows one acquisition attempt. M2 validates only attached authority/correlation.
It executes no credential metadata, RP or credential enumeration and no mutation. M3 can replace
that named bounded validation slot with a named inspection operation inside the same acquisition,
before cleanup; no generic authenticated CTAP interface or token cache exists.

[SOURCE] `fido_dev_set_puat(NULL, 0)` must succeed and both native length/pointer must show absence.
Cleanup failure overrides success as `CleanupFailed`; the native session is consumed/dropped and
the worker is retired on every outcome. Successful evidence is returned only after native device
drop. Failed/uncertain cleanup never permits reuse. Only proven kill/reap permits a replacement;
the existing supervisor then advances worker generation and invalidates old handles. No old
grant survives.

## Timing and revocation

[SOURCE] Production constants: prompt 30 s from reservation; native request 5 s shared among all
subcalls; exchange margin 100 ms; reap 2 s; independent worker transaction expiry 40 s; minimum
post-retirement settle 1 s. Admission policy: three cancellations/timeouts/rejections within
60 s cause a 30 s cooldown. All are backend owned, finite and independent of renderer input.

[SOURCE] App shutdown and main-window loss revoke the authority epoch. Whole-app-lifetime observers
revoke on NSWorkspace sleep/session resignation and the macOS distributed screen-lock signal.
Prompt polling and endpoint exchange polling check that epoch; the latter contains/reaps on
revocation. Revocation after possible submission returns conservative uncertainty. A live native
device handle fails closed on removal/I/O failure and is never reopened/rebound for another key.
Worker restart invalidates registry handles and authorization bindings.

[SOURCE] Host timeout is not evidence of CTAPHID_CANCEL. Kill/reap establishes host execution
quiescence, not immediate authenticator cancellation or known retry state. No error, wrong PIN,
blocked PIN, transport uncertainty or worker restart auto-retries authentication. Fresh authority
requires a new workflow after settle/cooldown. Unproven prompt teardown or process reap keeps
admission held; it does not fabricate successful recovery.

## Platform/build boundary

[MACOS] macOS 26.5.2, build 25F84; Rust 1.98.1. pkg-config reports libfido2 1.17.0; `otool -L`
confirms the worker links `/opt/homebrew/opt/libfido2/lib/libfido2.1.dylib`, current version 1.17.0.
The macOS build requires exactly the reviewed 1.17.0 pkg-config baseline and rejects an unverified
library-directory override. Production required PUAT symbols also prevent binding an older ABI.

[SOURCE] The Tauri command/permission/event allowlist is unchanged: only foundation status
and discovery. Foundation status now uses framework-injected backend State to return fixed
nonsecret text and a presentation-only revision for the last authentication attempt. The renderer
polls it and shows a dismissible toast for 10 seconds, without occupying a permanent page section;
that history is never consulted for approval/admission and is not a reusable authenticated
session. Its timer/dismissal cannot change admission or native security deadlines. The revision
distinguishes repeated identical outcomes only; it is not an acquisition/approval identity.
No PIN, grant, acquisition ID or native path is in this DTO. The new native menu has no renderer-callable command and no credential DTO. The
modality spike remains a separate debug feature; enabling it suppresses the production menu.

[SOURCE] The per-key `PIN check passed` tag is historical display only. It is added only after
`Validated` plus proven attached-PUAT cleanup, worker quiescence and prompt teardown. A fresh
attempt removes the prior result when it finishes; only another fully proven success restores
it. The tag is never consulted for admission, native selection, capability selection or grant
validation. Immediate cleanup means there is no active reusable authentication to suppress;
the existing global gate still rejects concurrent attempts.

[SOURCE] History remains in app memory. A fresh OS-random app scope hashes the reviewed macOS
`ioreg://` connection entry identifier with a domain separator. The same connected entry can
retain display history across worker retirement while all old authorization handles become
invalid. Distinct entries do not share tags even with identical product names/AAGUIDs. Only
canonical nonzero IORegistry paths qualify; missing randomness or other path formats disable
history. Raw registry identifiers, paths, hashes and the app scope never enter renderer DTOs;
discovery exposes only a historical boolean. Discovery prunes absent or duplicate correlations,
and restarting the app clears all history. Reconnecting through a new registry entry yields
fresh history. This is connection correlation, not cryptographic per-unit identity.

[SOURCE] The connection format is established by the reviewed
[libfido2 1.17.0 macOS HID implementation](https://github.com/Yubico/libfido2/blob/1.17.0/src/hid_osx.c).
Apple documents the registry identifier's system-wide lifetime in
[IORegistryEntryGetRegistryEntryID](https://developer.apple.com/documentation/iokit/1514719-ioregistryentrygetregistryentryi).

[SOURCE] Windows auth remains unavailable and #19/PR #20 remain separate. Linux production auth
is unavailable: its native adapter has no PUAT implementation or linkage. Ubuntu 24.04's 1.14
can cover discovery plus deterministic contracts only. Linux enablement requires packaging a
reviewed >=1.17 release, matching runtime loading policy, and CI that compiles/executes that native
path. A separate macOS CI job requires reviewed 1.17.0 and compiles the default native path;
CI has no hardware claim. Signing/notarization/bundled library packaging remain later work.

## Deterministic validation

[TEST] Full Rust workspace/all-targets suite: 227 passing tests, including production
debug-environment refusal and malformed/ambient native-authority rejection. Exact-acquisition/kind/generation rejection, capability choice, bounds/
framing/replay, cleanup/poisoning, wrong-PIN typed semantics, prompt binding/teardown, real child
retirement/restart, stale handles, kill/reap ordering and zero queue/cooldown are covered. New
descriptor tests prove intended fd retention and no unrelated-child inheritance. A real-child
two-key fixture selects different native sessions/grant kinds and invalidates both old handles
after retirement while distinct display correlations remain stable. Hash tests distinguish
connections/app scopes and refuse malformed/non-macOS paths. Authentication schemas reject
injected history identifiers. Process tests
require permission to inspect their own children; the sandbox-only process-counter run failed
because process inventory was denied, and the permitted full run passed.

[TEST] Rust formatting, workspace/all-targets locked clippy with warnings denied, renderer boundary,
Svelte check, frontend tests/build, Prettier and whitespace checks passed. pnpm's test command
reports no frontend test files (allowed by the existing script), not frontend test coverage.
Final frontend verification used Node 24.19.0 with repository-pinned pnpm 10.17.1.

## Native/hardware evidence

[HARDWARE] The attached reference model was confirmed from the USB registry: manufacturer Thetis,
product Security Key(F829), VID:PID `1ea8:f829`, matching M1.5. No serial number was recorded.
Three initial explicit native workflows returned `Validated`, actual `CredMan`, retry count
8 before submission, attached-PUAT-cleared=true, worker-quiescent=true, prompt-torn-down=true.
Acquisition/worker/device generation tuples were `(1, 1, 1)`, `(2, 2, 1)` and `(3, 3, 1)`.
The second and third demonstrate fresh acquisitions following retirement/restart; device slot
generation is scoped by the strictly advancing worker generation. Exact binding is checked
by the worker transaction and parent response validator before reporting success. No enumeration
or mutation ran, and no automatic retry exists.

[HARDWARE] The operator independently submitted two wrong PINs after those initial successes;
the agent neither requested nor initiated them. They returned `WrongPin` with proven attached
PUAT cleanup/quiescence/teardown. Pre-submission retries advanced 8 -> 7 -> 6. The next correct
submission (acquisition 6 / worker generation 6) returned `Validated`; subsequent prompts
reported retries 8. Two subsequent operator cancellations (acquisitions 7 and 8) returned
`Cancelled` with quiescence/teardown, and no PIN submission. Their cleanup flag is false because
no native acquisition/explicit attached-token clear was performed; their unopened-to-authority
sessions and workers were discarded. This matches the reviewed Thetis behavior. No further
wrong-PIN testing is needed.

[MACOS] Each prompt logged main-thread presentation, secure control, window-modal association,
Cancel as default, and detached teardown. The operator entered the PIN through the native UI.
Only nonsecret binding IDs, retry counts, categories and booleans appeared in captured output;
no PIN or PUAT bytes were exposed. Computer-use capture was denied by macOS TCC; no capture
permission was changed. The operator's initial report of no dialog was subsequently resolved
by the successful native workflows.

[MACOS] Real workstation lock/sleep delivery was subsequently observed in the separate active-workflow
runs recorded under "Final empirical macOS lifecycle evidence" below; this evidence is distinct from
deterministic epoch revocation. The distributed screen-lock notification is platform-specific and
is not a portable or cryptographic session-attestation API.

[UNRESOLVED] PerCredMgmtRO/legacy hardware and built-in UV remain outside this single-key evidence.

[INFERENCE] The required macOS M2 hardware gate passed. This foundation is ready for independent
review; it is not a merge approval. Native per-key selection and transient result presentation
were compiled/checked after the initial hardware observations; secret transport, native
acquisition/cleanup and exact-grant validation retain the same bounded transaction design.

[MACOS] The operator reported visible cancellation feedback; a supplied screenshot independently
showed successful validation feedback on the reference Thetis (AAGUID matching M1.5). The
captured feedback build also returned `Validated` with cleanup/quiescence/teardown. After the
multi-key/toast changes, the operator confirmed both keys were listed, selected-target
presentation worked, and toast dismissal/expiry worked. Only cancellation was requested for
this final display check; no further PIN attempt was requested. A second supplied screenshot
showed two Thetis keys with distinct AAGUIDs. Product/VID:PID and AAGUID are not per-unit identity;
generation-bound opaque handles route the native selection. The original build showed temporary
session tags on cards and the native menu. The focused follow-up below removes that presentation;
those values remain internal ephemeral routing identity and may change after restart/replug.

[HARDWARE] With the per-key native menu active, two further explicit submissions returned
`Validated`, `CredMan`, retries 8, attached-PUAT cleanup, worker quiescence and prompt teardown.
Acquisition/worker/device generation tuples were `(1, 1, 1)` and `(2, 2, 1)` in the relaunched
application. This repeats successful fresh acquisition after restart through the final
multi-key entry path. Native authority was cleared/discarded after those results. The subsequent
historical-tag addition retains no authenticated session.

[HARDWARE] The final historical-tag build completed two more native workflows with
`Validated`, `CredMan`, pre-submission retries 8, attached-PUAT-cleared=true,
worker-quiescent=true and prompt-torn-down=true. Their acquisition/worker/device tuples
were `(1, 1, 1)` and `(2, 2, 1)`. The operator confirmed that `PIN check passed` appeared
only on the selected key. Disconnect/reconnect tag clearing follows the inspected registry
correlation/pruning design and deterministic tests; it was not separately observed on hardware.

[UNRESOLVED] Independent security/architecture review is required before merge.

## Focused M2 presentation and identity follow-up

Starting branch HEAD: `8557a41c5513be45de60a4c887b05390d60d77c1` (fetched and pulled before edits).
The follow-up commit and validation results are recorded in PR #21, which remains Draft.

[SOURCE] Cards now show product above manufacturer and a supported-transport summary. The native
menu and PIN sheet use the same backend-formatted metadata. Transport ordering is USB, NFC,
Bluetooth LE, Internal, Hybrid, then other names alphabetically; empty metadata has generic
fallbacks. No vendor-specific product parsing exists. Normal presentation removes the session
badge, raw-handle footer and generation field. AAGUID remains in technical details with its
model/variant meaning; it cannot uniquely identify a physical unit. Supported transports may
help distinguish variants; they do not assert the current connection or unique physical identity.

[SOURCE] Labels that collide after product/manufacturer/transports are formatted receive `Key 1`,
`Key 2`, etc. in snapshot enumeration order. These are explicitly temporary presentation numbers;
they can change with discovery order or membership. They are neither persisted nor read for
routing, authorization or history correlation. The exact backend-owned `NativeTarget` handle
and event ID remain unchanged. Refresh before prompting still rejects stale handles, and worker
retirement still invalidates them. The renderer gains only display strings through the existing
read-only discovery DTO; the command and permission allowlists remain unchanged.

### macOS stable-identifier investigation

[SOURCE] Our native discovery adapter copies libfido2's path, VID/PID, manufacturer and product;
there is no serial field. In the reviewed
[libfido2 1.17.0 HID source](https://github.com/Yubico/libfido2/blob/1.17.0/src/hid_osx.c),
`get_path` builds `ioreg://<entry ID>` from `IORegistryEntryGetRegistryEntryID` and `get_str`
reads manufacturer/product only. That path identifies an IORegistry connection, not a persistent
physical unit. The existing app-scoped history hash does not improve its persistence semantics.

[SOURCE] Apple's
[IOHIDDeviceKeys.h](https://github.com/apple-oss-distributions/IOHIDFamily/blob/main/IOHIDFamily/IOHIDDeviceKeys.h)
defines `kIOHIDSerialNumberKey` as the string property `SerialNumber`. A future worker-side
macOS lookup can resolve the current entry with `IORegistryEntryIDMatching`, create an
`IOHIDDeviceRef`, and read `IOHIDDeviceGetProperty(..., CFSTR(kIOHIDSerialNumberKey))` without
opening/authenticating or modifying the key. The corresponding USB device property is
`USB Serial Number`; `iSerialNumber` is a descriptor index, not the serial itself. Availability
of these APIs does not guarantee that a device supplies a nonempty, unique, stable serial.

[MACOS] Read-only IOKit inventory found the two attached Thetis `Security Key(F829)` devices
(`1ea8:f829`). Both HID entries lacked `SerialNumber`, `PhysicalDeviceUniqueID` and `UniqueID`.
Both corresponding `IOUSBHostDevice` entries reported `iSerialNumber = 0` and no `USB Serial Number`.
Only presence/types/zero-index results were reported; no raw serial was displayed or saved.
No reconnect/reboot stability experiment or authenticator mutation was performed.

[INFERENCE] No suitable stable per-unit identifier was established for these keys. Persistent
aliases are intentionally deferred to M3. DeviceHandle, session/worker/device generation, AAGUID,
VID/PID, manufacturer/product, transports, port/location and the temporary registry identifier
are not alias keys. Other hardware may expose a serial, but its vendor semantics and uniqueness
need verification across reconnect, port changes and restart before supporting persistence.
If a proven serial is available, keep the bounded raw value backend-only and propose a versioned,
length-delimited vendor/product/serial namespace hashed with HMAC under an installation-local
persistent secret. The resulting opaque app-local alias key must never authorize a workflow;
missing, ambiguous or duplicate serials must disable automatic alias association. This derivation
is a future proposal, not implemented identity or an authenticity guarantee.

[TEST] Follow-up coverage checks metadata-only labels, deterministic transports and temporary
duplicate numbering. Native-target tests prove identical visible labels still select distinct
handles and old event IDs fail closed after replacement. The real-child two-key test retains
exact selection/grant-kind and retirement assertions with the new presentation, then rejects a
retired handle as `StaleAcquisition` before PIN presentation despite identical rediscovered labels.
The renderer boundary now denies direct `fido-auth` alongside the existing lower-level crates. Its regression
script injects all eight denied dependencies and unexpected commands/permissions into isolated
fixtures; the unchanged approved allowlists pass.

[TEST] Follow-up validation passed: `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets --locked -- -D warnings`, and
`cargo test --workspace --all-targets --locked` (232 tests). Renderer-boundary checks, including
resolved generated ACL output and the negative fixtures, passed. Frontend Prettier, Svelte
typecheck (zero errors/warnings) and production build passed using Node 24.19.0 / pnpm 10.17.1.
The existing frontend test command passed with **no test files**; no frontend test coverage is
claimed. `git diff --check` passed. These checks establish deterministic/source evidence for the
label follow-up; no new native UI observation or hardware authentication workflow is claimed.
At this presentation follow-up, independent review and real lock/sleep delivery remained unresolved.
The later empirical evidence below satisfies the lifecycle delivery gate for the tested macOS path.

## Final empirical macOS lifecycle evidence

[MACOS] [HARDWARE] Follow-up observations on 2026-10-03–04 (Europe/Stockholm) tested production
head `6c0a9e837ec5ae2d1b159c33fc98de4841ac8de0` on the macOS workstation and reference Thetis
path described above. These observations came from separate runs, including a later focused
post-lock admission reproduction; they are not one continuous successful test sequence.
No PIN was submitted in these lifecycle tests. Temporary local diagnostics recorded nonsecret
event/stage categories, epoch-advancement and cleanup booleans, and relative timing. All temporary
diagnostics/helpers were removed and the original executable rebuilt after testing. Each run
ended with runtime source restored exactly to the tested HEAD and a clean checkout.

### A — active-app screen lock: PASSED

[MACOS] [HARDWARE] The production native PIN sheet was active when the Mac locked.
`screen_lock` reached the production callback while the workflow was active, before unlock or
the prompt timeout, and advanced the authority epoch. The workflow returned `Revoked`, never
`Validated`; prompt teardown and worker quiescence/reap were proven. A fresh workflow opened
afterward. No PIN was submitted.

Representative timing from one run, relative to sheet opening:

`+2.48s lock → +2.59s lifecycle callback / epoch advancement → +2.88s teardown + Revoked → +6.10s unlock`

### B — inactive-app screen lock: PASSED for lifecycle delivery/revocation

[MACOS] [HARDWARE] A fresh application process opened an active native PIN sheet, then
FidoManager became inactive before lock. The production `screen_lock` callback arrived while
the app remained inactive and the workflow was active, before unlock or reactivation. Distributed
notification delivery was **not deferred until app reactivation in this observed run**.
The epoch advanced, the workflow returned `Revoked`, and prompt teardown and worker quiescence
were proven. No PIN was submitted.

Representative timing from this active-workflow run, relative to sheet opening:

`+6.52s app inactive → +9.98s lifecycle callback → +10.25s Revoked/cleanup → +14.74s unlock → +38.35s app reactivation`

[MACOS] The first post-lock fresh-sheet attempt in that run was reported not to open, but no
backend workflow or admission-error log was captured. Its cause was unconfirmed; no specific
admission failure or cooldown explanation was established from that capture.

[MACOS] **Supplemental post-lock admission/recovery evidence, from a later separate fresh-process
reproduction:** temporary stage diagnostics traced native menu click → `authentication::start()`
→ target resolution → `AuthenticationAuthority::reserve()` → discovery refresh → presenter.
The menu click reached the backend; `start()` entered; target resolution and `reserve()` succeeded;
discovery refresh succeeded with the selected target still valid; the presenter was reached;
and a fresh native sheet opened approximately 0.39 s after the click, visually confirmed by the
operator. No failing stage, separate menu/UI defect, or SensitiveWorkflowGate recovery defect
reproduced. This proves successful post-lock admission in that reproduction; it does not identify
the cause of the earlier reported failure.

The focused reproduction's initial workflow had already returned `TimedOut` before lock.
It is supplemental evidence for **post-lock admission/recovery only**, and is **not additional
active-workflow revocation evidence**. B's active revocation evidence comes from the earlier
inactive-app run above.

### C — system sleep/wake: PASSED

[MACOS] [HARDWARE] Another fresh application process had an active production native PIN sheet
when the operator put the Mac to sleep. The production NSWorkspace sleep lifecycle callback
(`NSWorkspaceWillSleepNotification`) was delivered before wake while the workflow was active
and advanced the epoch; `screen_lock` also arrived during the transition. The workflow returned
`Revoked`, never `Validated`, with prompt teardown and worker quiescence/reap proven.
A separate read-only observer supplied the wake marker. A fresh workflow opened after wake,
confirmed by both native presentation diagnostics and the operator. No PIN was submitted.

Representative timing from this run, relative to sheet opening:

`+4.27s sleep callback → +4.46s Revoked/cleanup → +11.32s wake marker`

### Lifecycle merge-gate conclusion

[INFERENCE] The real macOS lifecycle delivery merge gate is satisfied for the tested M2 macOS
reference path: active-app lock, inactive-app lock, and system sleep/wake. The separate runs
prove observed production callback delivery and fail-closed active-workflow revocation,
prompt teardown, and worker quiescence on this tested workstation. Supplemental post-lock
admission succeeded without a reproduced menu/UI or gate recovery defect.

This conclusion does not generalize to all macOS versions, Linux, Windows, other grant kinds,
or built-in UV. The earlier unexplained fresh-sheet report is not retroactively assigned a
cause, and the supplemental `TimedOut` reproduction is not counted as active revocation.
Satisfying this lifecycle gate is not merge approval; PR #21 remains Draft.

## Exact changed files

- `.github/workflows/ci.yml`
- `Cargo.lock`
- `Cargo.toml`
- `crates/fido-auth/Cargo.toml`
- `crates/fido-auth/src/lib.rs`
- `crates/fido-core/src/lib.rs`
- `crates/fido-libfido2/Cargo.toml`
- `crates/fido-libfido2/build.rs`
- `crates/fido-libfido2/src/lib.rs`
- `crates/fido-libfido2/src/native/authentication.rs`
- `crates/fido-native-ui/Cargo.toml`
- `crates/fido-native-ui/src/lib.rs`
- `crates/fido-native-ui/src/macos_pin.rs`
- `crates/fido-platform/Cargo.toml`
- `crates/fido-platform/src/process.rs`
- `crates/fido-service/Cargo.toml`
- `crates/fido-service/src/authentication.rs`
- `crates/fido-service/src/discovery.rs`
- `crates/fido-service/src/lib.rs`
- `crates/fido-service/src/presentation.rs`
- `crates/fido-service/src/process_worker.rs`
- `crates/fido-service/src/supervisor.rs`
- `crates/fido-worker-fixture/Cargo.toml`
- `crates/fido-worker-fixture/src/bin/fido-worker-fixture.rs`
- `crates/fido-worker-fixture/tests/authentication.rs`
- `crates/fido-worker-fixture/tests/descriptor_hygiene.rs`
- `crates/fido-worker-protocol/Cargo.toml`
- `crates/fido-worker-protocol/src/handshake.rs`
- `crates/fido-worker-protocol/src/lib.rs`
- `crates/fido-worker/Cargo.toml`
- `crates/fido-worker/src/engine.rs`
- `crates/fido-worker/src/main.rs`
- `crates/fido-worker/src/runtime.rs`
- `crates/fido-worker/tests/production_binary.rs`
- `docs/SECURITY_MODEL.md`
- `docs/adr/ADR-009-WORKER-BOUNDARY.md`
- `docs/validation/M2-macos-native-auth.md`
- `package.json`
- `scripts/check-renderer-boundary.mjs`
- `scripts/test-renderer-boundary.mjs`
- `src-tauri/Cargo.toml`
- `src-tauri/src/authentication.rs`
- `src-tauri/src/commands/mod.rs`
- `src-tauri/src/lib.rs`
- `src/App.svelte`
- `src/styles.css`
