# ADR-010: PIN mutation outcome evidence and persistent recovery

Status: Proposed for independent review (M4 foundation, no mutation dispatch).
Baseline: main `7422a04010793fe095f0a0fc8c1c99c530f5cd52`, merged PR #25.

## Scope and evidence labels

[SOURCE] means inspected, checksum-verified pinned source, not a hardware observation.
[SPEC] means the linked CTAP algorithm. [POLICY] means an application decision.
This foundation adds no PIN mutation FFI, worker request, native mutation dialog,
verification/probing, reset or credential deletion. The existing opt-in, non-shipping
M1.5 manual deletion probe is unchanged and excluded from production dependencies.

The architecture's sections 17–20, 23 and Milestone 4, the security model, ADR-009,
and merged [M2](../validation/M2-macos-native-auth.md),
[M3 inspection](../validation/M3-credential-inspection.md) and
[M3 native bounds](../validation/M3-bounded-libfido2.md) remain the governing contracts.

## Exact source reviewed before choosing the table

[SOURCE] The production macOS adapter uses libfido2 **1.17.0**, revision
`b974e7cf2ee7392134cc12c08b76a068cf250dd8`, not a floating 1.17.x installation.
[`source.lock.json`](../../native/libfido2/source.lock.json) pins the source archive
SHA-256 `a7c340900cb58b6905e12855944069024f39707f9573d52d4830a4561a50819a`.
The cached archive was verified and extracted through `scripts/build-libfido2.py`
`prepare`, including exact patch application and patched-file digest validation.
The project patch changes credential-management allocation bounds only; it does not
change `pin.c`, `ecdh.c`, `authkey.c`, `io.c` or `fido/err.h`.

Reviewed upstream files at that exact revision:

- [pin.c, lines 64–122 and 385–546](https://github.com/Yubico/libfido2/blob/b974e7cf2ee7392134cc12c08b76a068cf250dd8/src/pin.c#L385)
- [ecdh.c, lines 166–208](https://github.com/Yubico/libfido2/blob/b974e7cf2ee7392134cc12c08b76a068cf250dd8/src/ecdh.c#L166)
- [authkey.c, lines 26–106](https://github.com/Yubico/libfido2/blob/b974e7cf2ee7392134cc12c08b76a068cf250dd8/src/authkey.c#L26)
- [io.c, especially lines 333–356](https://github.com/Yubico/libfido2/blob/b974e7cf2ee7392134cc12c08b76a068cf250dd8/src/io.c#L333)
- [fido/err.h](https://github.com/Yubico/libfido2/blob/b974e7cf2ee7392134cc12c08b76a068cf250dd8/src/fido/err.h)
- [fido_dev_set_pin manual](https://github.com/Yubico/libfido2/blob/b974e7cf2ee7392134cc12c08b76a068cf250dd8/man/fido_dev_set_pin.3)

[SOURCE] `oldpin == NULL` selects set PIN; otherwise the same high-level API selects
change PIN. Both paths call `fido_do_ecdh`, whose `fido_dev_authkey` sends/receives
ClientPIN getKeyAgreement (subcommand 2). They then pad/encrypt the new PIN; change
also hashes/encrypts the old PIN. They build/transmit ClientPIN subcommand 3 or 4,
then `fido_dev_set_pin_wait` receives the final status. One local timeout budget is
passed through these exchanges. This is a **multi-exchange** high-level call.

[SOURCE] `fido_do_ecdh` collapses authkey failures to `FIDO_ERR_INTERNAL`; the
high-level caller cannot recover their phase or original CTAP rejection code.
`fido_rx_cbor_status` returns the first byte of a received CBOR-command payload,
or RX on failed/empty receive. It can also return INTERNAL from a response-buffer
allocation failure **after mutation transmit**. Both mutation transmit helpers
combine frame-construction failure and `fido_tx` failure under TX. HID transmit
can fail after partial output. These return codes do not themselves prove that
nothing reached the authenticator.

## PIN operation evidence table

[POLICY] The table assumes the pinned API, an exclusively held current worker/device
incarnation, valid application approval, correlated responses and the normal CTAP
contract. A malformed, uncorrelated or unsupported execution context overrides a
narrow status classification to `OutcomeUnknown`. No hardware result is claimed.

| Evidence | Set PIN | Change PIN | Justification |
| --- | --- | --- | --- |
| Application proves the high-level mutating function was never entered: invalid/stale permit or target, cancelled/expired prompt, lifecycle revocation, preparation/open failure, failed journal write/sync | `NotDispatched` | `NotDispatched` | [POLICY] Proven service/worker phase boundary, independently of authentication side effects. |
| High-level `FIDO_OK` (0) | `ConfirmedSuccessful` | `ConfirmedSuccessful` | [SOURCE] Success follows final status receive; no later refresh result rewrites this outcome. |
| `FIDO_ERR_INVALID_PARAMETER` (0x02), `FIDO_ERR_MISSING_PARAMETER` (0x14) | `Rejected` | `Rejected` | [SOURCE/SPEC] Definitive parameter rejection before storing the new PIN. |
| `FIDO_ERR_PIN_AUTH_INVALID` (0x33) | `Rejected` | `Rejected` | [SPEC] Validation rejection precedes PIN storage. |
| `FIDO_ERR_PIN_POLICY_VIOLATION` (0x37) | `Rejected` | `Rejected` | [SOURCE/SPEC] Includes local `pad64` length rejection before mutation transmit and authenticator policy rejection before PIN storage. |
| `FIDO_ERR_PIN_INVALID` (0x31), `FIDO_ERR_PIN_BLOCKED` (0x32), `FIDO_ERR_PIN_AUTH_BLOCKED` (0x34) | `OutcomeUnknown` | `Rejected` | [SPEC/POLICY] Change-PIN rejection; do not assume undocumented set-PIN behavior for these statuses. |
| `FIDO_ERR_TX` (-1), `FIDO_ERR_RX` (-2), timeout, transport failure, lost/empty response, parse errors, worker death, cancellation without phase proof after entry | `OutcomeUnknown` | `OutcomeUnknown` | [SOURCE/POLICY] Possible mutation transmit with no definitive completion evidence. |
| `FIDO_ERR_INTERNAL` (-9), other negative codes after entry | `OutcomeUnknown` | `OutcomeUnknown` | [SOURCE/POLICY] Phase information is unavailable; INTERNAL includes a post-transmit allocation failure. Even a usually pre-transmit error is not generalized to NotDispatched. |
| All other positive/unknown/vendor statuses, including timeout/action-timeout/cancel/processing statuses, PIN_NOT_SET (0x35), NOT_ALLOWED (0x30), and ERR_OTHER (0x7f) | `OutcomeUnknown` | `OutcomeUnknown` | [POLICY] No blanket “positive means rejected” rule; narrower classification needs separately verified operation evidence. |

[SPEC] The rejection allowlist uses CTAP 2.1 sections
[6.5.5.5 and 6.5.5.6](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#settingNewPin).
Those algorithms reject invalid parameters, missing parameters, authentication
validation and PIN policy before storing the new PIN. Change PIN also rejects
wrong/blocked PINs before replacement. It may decrement retries before returning
an error, and a later rejection may follow retry-counter changes.

[POLICY] `pin_call_outcome` encodes this conservative table without calling any
native API. Authentication retry state is a separate dimension: `Rejected` says
no requested PIN replacement, not “no authenticator side effects.” A separate
preparation/authentication failure can be NotDispatched for the mutation while
still leaving authentication retries uncertain. Change PIN checks the old PIN
inside the multi-exchange call; attached M2 PUAT presence does not replace that
check or constitute application approval. **No automatic mutation retry follows
OutcomeUnknown**, nor does any error reuse the permit.

## Shared authority and immutable approval

[POLICY] `AuthenticationAuthority` retains one private `SensitiveWorkflowGate`
and one private `PromptController`. Inspection, SetPin, ChangePin and Recovery
use the same `reserve_sensitive` path, workflow identity sequence, prompt identity
sequence, zero queue and existing three-interruption/60-second/30-second cooldown.
No second mutation gate or renderer-callable command is introduced. Native dialog
teardown and native execution quiescence remain prerequisites for release.

`OperationIntent` is backend-constructed with private immutable fields: operation,
backend-selected opaque target handle, exact worker-local target, DeviceGeneration,
WorkerGeneration, workflow/prompt identities, a fresh random intent nonce,
authority identity, cancellation epoch and trusted creation/expiry bounds.
The opaque handle and worker generation identify a live registry incarnation;
there is no claim of persistent physical-device identity. Canonical version 1 is
fixed-width big-endian, domain-separated and hashed with SHA-256. PIN values and
PUATs are absent, including from the canonical form. No intent is persisted.

The existing 30-second prompt limit also bounds intent lifetime. An owned
`OperationPermit` has a **10-second TTL**, capped by intent expiry. It binds the
canonical digest, is non-serde/non-Clone/non-Copy with private construction, and
is minted only after an exact Approved outcome arrives on the authority's native
teardown channel. There is no mutation presenter installed in this PR.

Consumption checks active workflow, exact digest, live authority identity/epoch,
prompt binding, expiration, registered target/generations and durable Pending
state under the one gate lock and an exclusive canonical-supervisor borrow.
Every attempt consumes the owned permit, including failure; reservation state
rejects replay. Epoch changes during sync and expiry before acknowledgement fail
closed with the durable marker retained. Lock/sleep/session-switch/shutdown use
the existing M2 epoch; disconnect/worker replacement invalidate exact targets.

`mark_dispatch_capable` returns only a policy result, never a dispatch token,
request or callback. A future mutation implementation must separately review the
actual worker handoff, preserving generation/epoch validation through that
handoff. This foundation cannot be mistaken for an already reviewed native
mutation implementation.

## Durable journal and startup admission

[POLICY] `JournalStorage` is a bounded, platform-neutral read/atomic durable replace
interface. `RecoveryJournal` privately enforces:

`NoRecord → Pending → DispatchCapable → Resolved`.

Pending is written only for a ready approved intent/permit. DispatchCapable requires
an explicit separate durable acknowledgement after final validation/consumption.
A failed write, flush or sync returns no successful transition and poisons runtime
journal admission. If bytes were published before sync failed, startup reads them
conservatively; dispatch was never authorized by the failed acknowledgement.

NoRecord, valid Pending and valid Resolved start Open. Pending means no claimed
mutation dispatch and may be deliberately resolved as NotDispatched. Unresolved
DispatchCapable, malformed/unsupported/oversized bytes, unsafe storage or read
failure start Barrier. No ordinary inspection, SetPin or ChangePin bypasses it.
A persistent latch prevents ordinary completion evidence, reconnect, worker
replacement, page reload or epoch revocation from clearing it. Initialization is
one-shot; a live authority cannot reload an empty journal to erase an incident.
All authority constructors start blocked until storage is evaluated.

A resolved record is an atomic tombstone rather than unlink: it preserves the
opaque incident and, for deliberate continuation, `acknowledged_unknown` history.
Future adapter evidence may record definitive Rejected/ConfirmedSuccessful.
This foundation's trusted Recovery primitive only accepts exact native approval,
proven teardown/quiescence and either Pending/NotDispatched or
DispatchCapable/AcknowledgedUnknown. It implements no success verification and
cannot clear corrupt state. Failed resolution sync retains Barrier. A final native
Recovery UI and a reviewed procedure for storage corruption remain future work.

Persisted fields are exactly schema, application-format identifier, opaque random
incident ID, operation class, timestamp, phase and optional resolution. No PIN,
PUAT, credential secret, RP/account text, intent digest, workflow identity or raw
device path appears. Schema rejects unknown fields and malformed identifiers.
The barrier is global; the record does not try to recognize a reconnected key.

### Concrete macOS durability contract

[POLICY/SOURCE] Tauri supplies `app_data_dir()` to the native authority in setup,
after singleton registration and before inspection menu admission. Storage stays
in `fido-platform`, outside renderer and service policy. The fixed subdirectory
`fido-authority-recovery-v1` is owner-only 0700, and records/temp files are 0600.
The application data root must belong to the authority user and must not be
writable by other users. Existing unsafe permissions fail closed, rather than
silently “repairing” untrusted contents.

The implementation opens/pins a no-follow directory descriptor and uses relative
`openat`/`renameat`. Reads reject symlinks, hardlinks, special files, foreign ownership,
insecure permissions and oversized input. Replacements exclusively create a fresh
private temporary file, write/flush and sync (macOS **F_FULLFSYNC**), then
atomically rename and explicitly fsync the containing directory. A final macOS
F_FULLFSYNC on the renamed record flushes drive caches after the directory entry
is synced, as required by the ordering rationale in Apple’s
[fsync manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html). Newly created ancestor and
namespace directory entries are synced into their parents. A failed sync, including
unsupported full-sync semantics, fails closed; there is no silent durability fallback.
A failed post-rename sync may leave a new marker on disk, so runtime admission is
poisoned and never treats that error as authorization.

This is the OS/storage durability contract, not a guarantee against defective
storage hardware or deliberate same-user/admin deletion. No signature/encryption
claims tamper-proof same-user storage. Windows broker namespace/ACL decisions are
still ADR-013/#20 work; this PR does not implement them.

## Recovery by PIN operation

[POLICY] After quiescence, SetPin may permit passive `clientPin` reconciliation:
configured state is evidence that a PIN exists, not evidence of the exact value
or actor responsible. This does not automatically resolve a historical incident.
ChangePin has no non-destructive read-back proving old/new validity; automatic
old/new probing and ordinary retry-consuming inspection remain prohibited while
unresolved. Any future verification requires an explicit Recovery workflow with
remaining retries visible. There is no probing or verification implementation here.

## Native deadline ceiling and validation

[POLICY] `NativeDeadline::MAX_BUDGET` is 60 seconds for one request. Zero, oversized
or unrepresentable budgets become immediately expired; there is no one-year
fallback. Existing production 1–5-second native budgets and remaining-time sharing
are unchanged. Tests cover zero, exact maximum, maximum plus one nanosecond and
Duration::MAX, along with the existing timeout shrink/rounding tests.

Deterministic coverage and exact command results are recorded in
[M4 foundation validation](../validation/M4-mutation-foundation.md).
