# M4 production macOS PIN mutation validation

Date: 2026-10-04 (Europe/Stockholm).
Branch: `feature/m4-pin-mutation`.
Base: `96b7ebc1482c457b725a134601e9002f320c4493`, merged
[PR #26](https://github.com/mbzbugsy/fidomanager/pull/26).
Implementation SHA: the exact head recorded in the Draft PR containing this report.

## Baseline and scope

The existing checkout was clean before implementation and was switched to the
requested branch from the required merge commit. Fetching latest main confirmed
that base. The baseline [CI run](https://github.com/mbzbugsy/fidomanager/actions/runs/37211455170)
completed successfully for that exact commit.

This change installs production native Set PIN, Change PIN and deliberate recovery
acknowledgement on macOS. Linux and Windows retain read-only discovery/native
unsupported behavior. macOS foundation phase reporting is now M4. This is not a
packaging, notarization or public-release readiness claim. Credential deletion,
reset, Windows PR #20 and BooGooCypher behavior are unchanged. The existing opt-in
manual deletion probe remains frozen and outside production dependencies.

## Operation and native UI

Only trusted Security key menu routing can start mutation. Valid current backend
GetInfo explicitly selects Set PIN for `clientPin=false`, Change PIN for
`clientPin=true`, and neither for missing, duplicate/contradictory, malformed or
unsupported capability evidence. The menu route binds operation and live opaque
target; refreshed eligibility is checked before reserving an immutable intent.
The worker independently verifies the approved operation on its exact native
object. All sensitive menu items are disabled during a workflow; the single
service gate remains authoritative with no queue and the existing shared cooldown.

The native Security key menu groups each connected authenticator into its own
submenu, for example `Security Key (F829) · Thetis · USB`, with short
`Inspect credentials…` and capability-selected `Set PIN…` or `Change PIN…` items.
Device metadata/transport appears only in the submenu title. Grouping uses the
exact backend handle, so identical labels never merge devices or route actions.
Action IDs, full native-sheet target labels and workflow authority remain unchanged.
Busy-state disabling reaches the submenu and every nested action. Recovery stays
at the top level because its incident record identifies no reconnected physical
key; the existing barrier still removes ordinary actions.

AppKit sheets run on the main thread and display the exact trusted label, operation
and persistent physical-key effect. Set collects new/confirmation; Change collects
current/new/confirmation and shows remaining retries before submission. Exactly
one retry requires acknowledgement. The rows read top-to-bottom as current/new/
confirmation for Change and new/confirmation for Set, with equal field widths.
Input focus starts on current PIN for Change or new PIN for Set; recovery starts
on Cancel. Cancel remains the default Return action, and the actual attached
sheet/default cell is checked at presentation.
Mutation/recovery action is initially disabled for 500 ms. Confirmation must match;
a new PIN must have at least four Unicode scalar values within the existing
4–63-byte valid NUL-free UTF-8 bounds. Authenticator policy may impose a supported
minimum; no invented complexity rule is added. No automatic retry occurs.

All NSSecureTextField values are cleared before teardown acknowledgement. Rust
buffers use fixed 64-byte allocations and zeroize on every exit, including transport
and callback failures. AppKit/NSString internal copies cannot be guaranteed
zeroized. Secrets have no Clone, Copy, Debug, Display or serde implementation.
The confirmation allocation is discarded in native UI; the worker receives only
new PIN for Set or current/new for Change.

## Dispatch, protocol and native source evidence

The production order is shared gate reservation → exact intent → non-mutating
preparation → exact native sheet/secrets → native teardown → one-use permit →
durable Pending → final exact target/generation/epoch/expiry validation and permit
consumption → durable DispatchCapable → private consumed dispatch permit → bound
secret and execution request → one native high-level call. The original public
foundation transition still returns no executable authority. The private handoff
cannot be serialized, cloned, persisted or used for another intent. A lifecycle
change during marker sync or any later host failure retains the marker/barrier.

Worker protocol **4** adds only PreparePinMutation (SensitiveRead) and
ExecutePinMutation (Mutation), plus typed prepared/completed responses. Each carries
exact operation, worker/device generation, workflow, prompt, acquisition session
and approved intent digest. Execution is bound to its exact request ID. Unknown
fields, generic mutation requests and secret JSON fields fail closed. Preparation
and execution are one-use, share the existing secret descriptor rather than PUAT
authority, and cannot coexist with another sensitive session. The worker exits
after an execution response; the service independently retires and reaps it.

**FMPIN003** is a new fixed binary frame, separate from inspection's FMPIN002.
Its 107-byte header includes every binding above plus exact request and current/new
lengths. Set and Change are structurally distinct. Fixed bounded Rust buffers are
zeroized on both ends. Wrong bindings, truncated/oversized/NUL/invalid UTF-8 fields,
trailing bytes and a second frame are rejected; EOF seals one frame. No PIN goes
through normal worker JSON, renderer DTOs, logs, intent digest or journal.

The checksum-verified, patched libfido2 **1.17.0** source was prepared through the
repository builder before writing FFI. Revision:
`b974e7cf2ee7392134cc12c08b76a068cf250dd8`; source archive SHA-256:
`a7c340900cb58b6905e12855944069024f39707f9573d52d4830a4561a50819a`.
The patch affects credential parsing bounds and does not change PIN semantics.

Reviewed source includes `pin.c` 64–122, 385–578, `ecdh.c` 166–208,
`authkey.c` 26–106, `io.c` status handling, `fido/err.h` and `dev.c` 97–245,
527–588. Fresh open performs HID INIT/GetInfo. Preparation re-reads bounded GetInfo
and Change queries ClientPIN getPinRetries (subcommand 1), supplying no PIN,
consuming no retry and acquiring no PUAT. PIN support and protocol 1 or 2 are
required. The unique prepared native object is held until consumed execution;
there is no close/reopen or persistent reconnect identity claim.

Execution revalidates eligibility and, for Change, requires retry state to equal
what the sheet displayed. Passive revalidation and the high-level PIN call share
the normal five-second NativeDeadline. `fido_dev_set_pin` occurs exactly once:
NULL old PIN selects Set; a borrowed current PIN selects Change. Pinned source
shows ECDH/getKeyAgreement, encryption, ClientPIN transmit and final status receive
inside this multi-exchange function. No generic pointer/raw-CTAP escape is added.

The [ADR-010](../adr/ADR-010-MUTATION-OUTCOME-RECOVERY.md) classifier is unchanged:
pre-entry failure is NotDispatched; FIDO_OK is ConfirmedSuccessful; only the exact
parameter/PIN rejection allowlist is Rejected. TX/RX, INTERNAL, parse, timeout,
transport, lost response and unknown post-entry statuses remain OutcomeUnknown.
After the durable dispatch marker, the service also conservatively retains unknown
outcome for a later pre-entry host/native abort. Rejection does not imply unchanged
retry counters. Native cleanup status never rewrites the authenticator outcome.

## Journal, retirement and recovery

The existing NoRecord → Pending → DispatchCapable → Resolved state machine and
concrete owner-only, no-follow, atomic/full-sync storage contract are preserved.
A valid Pending-only restart proves no dispatch claim; it is durably resolved as
NotDispatched before a new incident replaces it. Failed writes/sync poison admission.
ConfirmedSuccessful/Rejected resolve durably only after prompt teardown and worker
quiescence. Failed resolution retains the definitive outcome independently while
admission remains blocked. Unknown outcome leaves DispatchCapable unresolved.
Every workflow path retires the child and kill/reaps as needed before gate release;
kill/reap is not described as cancellation of authenticator state.

A valid unresolved PIN incident replaces ordinary inspect/set/change menu entries
with native Review uncertain PIN operation. Recovery first establishes worker
quiescence, then requires the bound native acknowledgement checkbox and action,
with Cancel default. It collects no PIN and durably writes AcknowledgedUnknown;
it does not convert the historical result to success or failure. Ordinary sensitive
work remains blocked until that acknowledgement is durably resolved.

The record intentionally contains no device identity, so recovery does not infer
which reconnected physical key was involved. No optional passive Set reconciliation
is implemented: the sheet says configuration of the previous key cannot be
established and never claims an exact value. Change explicitly states that old/new
validity cannot be determined without an authentication attempt; neither is probed.
Corrupt, unreadable or poisoned storage offers informational failure without a
native acknowledgement bypass. No renderer recovery clearance exists.

Results use plain language attached to the selected key or a success notice naming
its trusted label. Unrelated connected device cards/issues are retained.

## Deterministic and boundary coverage

The full macOS Rust suite passes **335 tests**, with zero failures or ignored tests,
plus **3 compile-fail permit doctests**. This adds 16 tests over the 319-test merged
foundation baseline; many new tests iterate both operations and multiple faults.

| Area | Evidence |
| --- | --- |
| Authority/intent | Existing foundation tests retain all workflow pairings, zero queue, shared cooldown, immutable operation/target/generation binding, stale prompt/workflow, TTL, revocation, one-shot use and replay checks. |
| Secrets | Set/Change round trips; every binding/header dimension; wrong request; truncation at every offset; oversize, NUL, UTF-8, trailing/second frame; trait and explicit zeroization contracts. |
| Protocol/worker | Strict non-secret typed JSON and exact classes; native call counter stays zero for unprepared, incompatible, stale/bad operation/generation/session/request and late requests; valid execution occurs once and replay never executes again. |
| Adapter/outcomes | Pre-entry incompatibility/expired deadline gives zero calls; both operations exhaust known negative and byte-valued status codes plus unknown extremes; cleanup failure preserves outcome. Foundation tests independently assert the ADR-010 allowlist. Contradictory result reasons are rejected. |
| Durable dispatch | Real process fixtures exercise successful/rejected/unknown results, preparation failure, post-marker pre-entry failure, lost/crashed/hung workers and cleanup failure for both operations. Trace asserts Pending then DispatchCapable before definitive resolution. Failed Pending/Dispatch durability gives zero completed mutation; resolution failure retains confirmed success and blocks admission. |
| Lifecycle/crash | Foundation Pending/DispatchCapable restart tests; actual process revocation during DispatchCapable sync sends no execution and retains Barrier. Synthetic crash/timeout/lost response after execution entry stays unknown. No live hardware fault injection. |
| Quiescence/recovery | Child retirement and handle invalidation on every tested path; ordinary work blocked before acknowledgement; restart barrier; durable AcknowledgedUnknown with no secret/probes; corrupt storage never presents acknowledgement. Existing reap-before-replacement tests remain intact. |
| Native UI/presentation | Exact target/operation/persistent text, confirmation equality and current-PIN structural policy, four-scalar minimum, last-retry acknowledgement, teardown-bound approval and stale callbacks; static hostile controls reject unsafe Cancel default. Other-key issue/card preservation is retained. |

The real renderer checker runs **73 times**: 70 hostile fixtures and 3 valid/restored
baselines. It freezes the three parameterless renderer commands and their resolved
ACL, denies direct native/worker/secret dependencies in Tauri, freezes the manual
spike, forbids unreviewed mutation/reset/deletion routes and permits only the one
reviewed native PIN call site. Additional hostile controls cover secret/permit
serde/Clone/Debug traits (including manual serialization), public dispatch authority,
marker bypass, renderer secret/permit fields and unsafe native sheet default.
Static guards are regression evidence, not a formal proof of arbitrary source edits.

## Commands and local results

Environment: macOS 26.5.2 (25F84), arm64, Rust 1.98.1 (Homebrew), Node 22.19.0,
pnpm 11.25.0. CI retains pinned Node 24.21.0/pnpm 10.17.1. No frontend dependency
or lockfile changed. The sandbox initially blocked a pre-existing loopback test;
the authorized full suite passed outside the sandbox without changing that test.

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | PASS |
| `cargo test --workspace --all-targets --locked` | PASS: 335 tests |
| `cargo test -p fido-service --doc --locked` | PASS: 3 compile-fail tests |
| `node scripts/check-renderer-boundary.mjs` | PASS |
| `node scripts/test-renderer-boundary.mjs` | PASS: 73 executions |
| `pnpm check` | PASS: zero errors/warnings |
| `pnpm test` | PASS: 74 tests, 2 files |
| `pnpm build` | PASS |
| `pnpm exec prettier --check .` | PASS |
| `git diff --check` | PASS |
| `cargo build -p fidomanager-app --locked` | PASS: production macOS AppKit application |
| `cargo build -p fido-worker --locked` | PASS: production worker |
| `python3 scripts/test-libfido2.py --rebuild` | PASS: exact source/patch, native bounds, negative linkage/NDEBUG controls and byte-identical private archive builds in separate paths |
| `python3 scripts/test-credman-linkage.py` | PASS: existing credential controls plus PIN unresolved/wrong-object/wrong-archive/dead-stripped controls |
| `python3 scripts/verify-libfido2-linkage.py target/debug/fido-worker` | PASS: all 16 credential symbols and live `fido_dev_set_pin` from the same exact pinned/private archive; identity/hash match; no libfido2 dylib or unresolved FIDO symbol |

The final-link check is performed on a standalone production worker build after
`cargo clean -p fido-worker`, because test binaries can overwrite a shared Cargo
link-map output and a cached build may not relink it. CI forces that fresh link.
A mismatched map fails closed; it is not accepted as attribution evidence.
Remote feature-branch CI is evaluated after upload; its exact head/run/result is
recorded in the Draft PR. This committed report does not claim an unobserved run.

## Hardware evidence and operator gate

**Set PIN hardware validation: NOT PERFORMED.**
**Change PIN hardware validation: NOT PERFORMED.**
**Recovery hardware fault scenarios: NOT PERFORMED.**

Native menu follow-up: all four macOS app menu tests pass, covering duplicate
labels/interleaved device actions, exact handle routing and stale IDs, Set/Change/
unavailable capability cases and top-level recovery. Workspace clippy, Rust
formatting, all 73 boundary-check executions, Prettier and diff checks pass. These
are affected checks for this presentation change; the full-suite counts above
describe the preceding runtime validation. This follow-up adds only a test-time
serde_json dependency and changes no worker protocol, PIN transport or mutation
authority. Normal Tauri development visual confirmation of the grouped menu is
pending; hardware mutation remains on hold.

Operator preparation at `5df83d5fbaaac29ed3e5b242a7c1c97b9fbd9940`:

- The operator selected the connected small Thetis key and explicitly authorized
  one persistent Change PIN. Read-only discovery reported Security Key(F829),
  Thetis, USB, vendor/product `0x1ea8`/`0xf829`, and `clientPin=true`.
- The operator first pressed Authenticate for credential inspection. That result
  was not independently observed; this was not a Change PIN submission.
- An operator-supplied screenshot of the empty Change PIN sheet confirmed the
  exact trusted key, operation, persistent-change text and normal retry category
  (8 remaining). It exposed reversed field order, unequal widths and initial
  focus on confirmation. These layout issues were corrected before submission.
- The operator reported that the untouched sheet closed itself, consistent with
  expiry. No mutation submission was reported, no saved mutation record was
  present, and no native mutation outcome or journal transition is claimed.
- Computer Use was denied Terminal access and macOS screen capture permission;
  live prompt teardown/quiescence and the inspection result were not independently
  observed. The screenshot establishes only the visible pre-submission UI.
- The operator also reported the generic Dock icon. The icon assets/configuration
  are unchanged; the test executable used `tauri/custom-protocol` without an app
  bundle. Tauri 2.12.0 installs its embedded Dock icon only in development mode.
  No icon asset or packaging change is needed.

Normal Tauri development validation at
`568c79627a71f966829ebcce4d6794b80cee1225`, following green
[CI run 37221765175](https://github.com/mbzbugsy/fidomanager/actions/runs/37221765175):

- `pnpm tauri dev --no-watch` started the local Vite server and the ordinary
  `native-pin` application, without `custom-protocol` or `native-ui-spike`.
  The operator confirmed the correct Dock icon and the corrected top-to-bottom
  Change PIN field order. Initial input focus was not separately confirmed.
- The operator kept the fields empty and reported the sheet closed. Native
  runtime logs independently confirmed main-thread secure controls, window
  modality, Cancel default, detached teardown, `NotDispatched`, worker quiescence,
  prompt teardown and `recovery_required=false`. Both recorded empty-sheet
  workflows had these categories. No saved mutation incident record was present.
- No PIN mutation was submitted or entered; no Pending/DispatchCapable transition
  or authenticator mutation outcome is claimed. The operator explicitly placed
  mutation on hold. The earlier authorization is not being exercised.

The Tauri CLI rewrote the `tauri-build` dependency into equivalent explicit empty
features syntax during launch; that generated manifest edit was reverted. The
application source, icon assets, packaging settings and dependency versions did
not change during this visual validation.

No real mutation success/rejection/uncertainty is claimed. Native runtime
compilation, exact-symbol attribution and synthetic fixtures are software evidence
only. No dedicated unconfigured key has been selected; Set PIN must remain NOT
PERFORMED unless one is already available and explicitly authorized.

After deterministic tests/builds/available CI are green and the Draft PR exists,
work must stop in interactive operator mode. Give one simple human action at a
time and wait for the reply. Before the first real mutation, name the selected
physical key and intended operation, state its persistent effect and evidence to
observe, exclude wrong-PIN/retry depletion/reset/deletion/unplug/crash/corruption
experiments, then obtain explicit authorization. A PIN is entered only in the
native secure sheet. One success suffices; no automatic retry or change-back occurs.
Restoring a PIN is a separately authorized second mutation. A subsequent normal
inspection using the new PIN also requires separate operator agreement. Record
only permitted non-secret facts here if hardware validation is later performed.

## Review inventory

Changed files cover `fido-auth` mutation ownership/framing; `fido-native-ui` AppKit
sheets and bound completion; `fido-service` private dispatch, outcomes, journal
resolution and activity presentation; `fido-worker-protocol` version 4;
`fido-worker` consumed native session/runtime; `fido-libfido2` exact private adapter;
synthetic worker fixture tests; native Tauri menu/routing; hostile boundary/linkage
checks and macOS CI step labels; architecture/security/ADR-010 and this evidence
report. Cargo.lock changes only for the fixture's serde_json test dependency.
The exact changed-file list, base/head SHA, CI outcome and working-tree state are
reported in the Draft PR review handoff. The PR stays Draft and must not be merged.
