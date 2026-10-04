# M3 production macOS credential inspection

Starting main: `b2ca1efce5edccb12a4b320ba248a4cbdca0e752` (PR #24 / #22).
Branch: `feature/m3-credential-inspection`, freshly created from fetched main.
The pre-#22 branch with that name was preserved as
`feature/m3-credential-inspection-pre22-backup`; its contents were not reused.
Issue #14 is referenced for review, not automatically closed. PR #25 now also implements the
minimum M3 requirement of issue #23 (BooGooCypher readiness status only; see
[M3-boogoocypher-readiness.md](M3-boogoocypher-readiness.md)). Issue #23 is referenced, not closed.
Credential inspection never touches BooGooCypher.

## Trusted operation and native lifetime

A native Security key menu item, “Inspect credentials on …”, selects an exact
backend-owned DeviceHandle. Labels never route targets. The canonical supervisor
refreshes and checks that handle without rebinding stale selections. The existing
global CredentialInspection gate reserves one workflow without a queue. Existing
AcquisitionBinding, prompt teardown, revocation epoch and secret fd rules apply.

Worker protocol changes from 2 to 3. `InspectCredentials { binding }` is a named
SensitiveRead requiring device_generation, the exact pending binding, and a request
ID strictly later than PrepareAuthentication. It consumes the pending session and
secret channel before validating/reading, so replay, wrong binding, out-of-order
requests, malformed secret framing and inspection without preparation fail closed.
An unrelated request while authentication is pending destroys that authority.
There is no generic CTAP/CBOR command or reusable authorization object.

The macOS adapter opens once, reads GetInfo, selects/cross-checks GrantKind and
reads PIN retries as in M2. The trusted AppKit secure sheet collects one normal PIN;
WebView never sees it. One inspection NativeDeadline (5,000 ms) covers PUAT acquisition,
metadata, RP enumeration and every credential enumeration. Each native call receives
only the remaining budget. It acquires and checks attached PUAT on the same owned
device, drops PIN storage, and passes NULL PIN to all credman reads.

Only these CTAP read APIs are called: `fido_credman_get_dev_metadata`,
`fido_credman_get_dev_rp`, `fido_credman_get_dev_rk`. The FFI signatures were checked
against checksum-pinned 1.17.0 `src/fido/credman.h`, `src/fido.h` and `src/credman.c`.
Thetis supports pinUvAuthToken and credMgmt but not perCredMgmtRO, so selection is
CredMan (0x04). Its authenticator capability can authorize mutation; the application
exposes only named reads. CredManReadOnly (0x40) remains preferred where supported;
M2's explicitly restricted legacy selection remains intact.

Every native container has a matching free guard. Hashes, IDs and text are copied
before native free. PUAT clear is checked through both return status and attached
state; explicit close must also succeed. Failure of either discards inventory and
returns CleanupFailed. Device free completes before the adapter returns. Every
service path retires/kills/reaps the worker; unproven prompt teardown or quiescence
keeps the recovery barrier. Revocation discards inventory. Host kill means execution
quiescence, not authenticator cancellation/revocation. mutation_outcome is always None.
No PIN retry, PIN persistence, PUAT cache, device reopen, delete/update/reset/PIN-change
request or mutation UI is added.

## Resource bounds

| Resource | Bound | Rationale |
| --- | ---: | --- |
| Native RP or RK allocation | 256 | Unchanged reviewed #22 private parser ceiling |
| Owned RP groups | 64 | Conservative desktop inventory scope |
| Aggregate credentials across all RPs | 128 | Caps copying, handle mapping and renderer entries |
| RP text | 254 UTF-8 bytes | Conservative domain-sized display; exact bytes retained |
| RP C-string scan | 255 bytes including NUL | No probe beyond this explicit application scan bound |
| Aggregate copied RP text | 16,256 bytes | 64 × 254 |
| Credential ID | 512 bytes | Conservative identifier support; reject before copy |
| Aggregate copied IDs | 65,536 bytes | 128 × 512 |
| User name / display name | 256 UTF-8 bytes each | Bounded display only; no user ID read or exported |
| User/display C-string scan | 257 bytes including NUL | Same narrow scanner; invalid/oversized data fails |
| Aggregate user/display text | 65,536 bytes | 128 × 2 × 256 |
| Renderer groups / credential entries | 64 / 128 | Same structural bounds; never truncate silently |
| Selected authenticator label | 1,024 bytes | Validated backend presentation text |
| Worker response frame | 1,048,576 bytes | Existing frame ceiling unchanged |
| Worker request frame | 16,384 bytes | Existing ceiling unchanged |

The aggregate byte ceilings follow directly from the enforced item and per-field
ceilings; no unbounded string or byte buffer enters the owned inventory. A deterministic
worst-case JSON test fills every group, every ID with 255 bytes, and every display
field with escaping characters. Even that inventory uses less than half the existing
response frame allowance, leaving ample space for the bounded envelope/evidence.
Exceeding an application bound produces BoundExceeded, not a truncated successful list.

## RP trust and completeness

The native pointer+length hash must be exactly 32 bytes. That hash is authoritative;
it is not inferred from text. A single narrow Rust C-string scanner reads at most
the explicit scan bound, requires NUL, copies bytes before free, checks UTF-8 and
rejects controls/bidi direction controls. SHA-256 hashes the exact copied RP text
bytes without normalization. Display/continuation uses text only when the digest
matches the authoritative hash exactly. Absent, empty, malformed, invalid UTF-8,
unsafe-control, over-bound, unterminated or mismatching RP text retains its hash
internally and becomes an explicit incomplete group. No guessed domain or empty
string is substituted. Public libfido2 1.17.0 has no hash-only RK continuation API;
these groups cannot be enumerated through this baseline.

Complete yields Exact(n). Noncontradictory Incomplete yields AtLeast(n). Inconsistent
yields Unknown. Duplicate RP hashes are preserved and flagged, never deduplicated;
duplicate credential IDs also invalidate a numeric total. Metadata mismatch after
complete enumeration, enumerated count above metadata, or an enumerated RP with an
explicitly empty successful RK result is contradictory. Explicit CTAP NO_CREDENTIALS
is distinguished from native failure; inconsistent metadata is retained rather than
replaced with zero. Partial native RK failures never copy partially populated arrays:
the RP is marked EnumerationFailed, or a typed fatal error is returned. Empty success
is never substituted for a native error. Scalar count equality has no authority;
the spike diagnostic is renamed `raw_count_equals_metadata`, and renderer state uses
only the typed assessment.

## Snapshot and identity boundary

The worker returns bounded owned inventory to the trusted service only. The service
independently validates bounds, text and RP digest consistency. InspectionStore now
holds separate snapshots and private raw identity mappings for every currently
connected inspected key. Labels never identify entries. Starting a fresh inspection
invalidates only the selected key's snapshot before PIN acquisition; success replaces
only that entry, while failure/cancellation leaves other keys intact.

Each entry binds its display DeviceHandle, exact connected DeviceGeneration and a
fresh random 128-bit EnumerationEpoch. CredentialHandles are independently random
128-bit values, with collisions rejected within an inventory. Neither encodes raw
identity. Backend lookup requires all four matching dimensions: current display
DeviceHandle, exact DeviceGeneration, EnumerationEpoch and CredentialHandle. Exact
credential ID and RP hash remain private; stale or cross-key lookup fails closed.
Mutation remains deferred and this mapping grants no operation authority.

### Worker retirement and connection continuity

M2 deliberately invalidates **all native operation DeviceHandles** on every worker
retirement, including a successful inspection. Those handles still route the native
menu and AuthenticationAuthority, and none is reused or rebound. To retain another
key's inventory without changing that invariant, the backend has a separate typed
DisplayDeviceHandle registry. The renderer receives only this nonauthorizing display
handle and its connected generation. DisplayDeviceHandle is never accepted by the
native operation resolver or an AcquisitionBinding.

The registry reconciles against every trusted discovery manifest. Within a worker,
changed native handle/generation or vendor/product advances the display generation
and purges that key's inventory and raw mapping. An incomplete/unreadable discovery view purges the affected inventory. Disconnect removes both; replug
creates a new connection/handle and starts Not inspected. No label-based correlation
is allowed. Across worker generations, continuity is allowed only after explicitly
proven orderly retirement/reap and a subsequent fresh manifest with a uniquely
matching existing app-scoped macOS IORegistry connection marker. That backend-only
marker changes on replug and never grants authentication approval. Missing or
ambiguous markers cannot preserve inventories across retirement. Unexpected worker
replacement, discovery failure or unproven quiescence clears the store.

During the orderly retirement/refresh gap, publication and identity resolution are
suspended. Normal restart backoff keeps dormant entries, with no DTO returned until
fresh discovery verifies them. A retired or older worker cannot republish them.
Lock order is discovery then inspection throughout. Device cards and inspections
are returned together in one coherent list_authenticators response; foundation_status
retains only nonsensitive service status/notice fields.

Renderer DTO:

```text
AuthenticatorList {
  enumerationEpoch,
  devices [{ existing safe device fields, handle, generation,
    inspection: { state: "not_inspected" }
      | { state: "inspected", snapshot: {
          deviceHandle, deviceGeneration, epoch, authenticator,
          assessment { completeness, total { kind, value? },
                       duplicate_rps, duplicate_credentials, count_contradiction },
          rps [{ verifiedText?, issue?,
                 credentials [{ handle, userName?, displayName? }] }]
      }}
  }]
}
```

All connected keys appear in their existing cards. Each card shows Not inspected or
its own RP groups, entries, completeness and Exact/At least/Unknown total. An
uninspected key never claims zero credentials. Identical labels are disambiguated
by the existing presentation details; opaque handles are never displayed as text.
There is no renderer Inspect action, new command or ACL permission. Each key still
requires its own explicit native menu selection and native PIN/PUAT workflow.
Both tagged states and all inventory DTO layers reject unknown fields. Raw hashes,
IDs, user IDs, auth bindings, native worker/workflow/acquisition/prompt identities,
paths, pointers, permissions, PIN and PUAT never enter these DTOs. Hardware logs
contain fixed categories and booleans, never account text, counts or raw identities.

The existing discovery ceiling limits the collection to 64 connected devices; each
inventory retains the reviewed 64 RP / 128 credential / per-field byte bounds above.
Thus the aggregate private ID budget is at most 4 MiB, copied user/display text
4 MiB and RP text 1,040,384 bytes. A deterministic 64-device maximum-escaping DTO
fixture is under 16 MiB. Over-limit discovery purges the store rather than silently
truncating it. Native allocation, single-key worker frames and deadlines are unchanged.

## Credential inventory presentation

Presentation only. The backend Complete / Incomplete / Inconsistent assessment and its
Exact / AtLeast / Unknown total are unchanged, and no enum word is shown to the user.
Credentials is a native section of the authenticator card (same surfaces, separators,
tokens and type hierarchy as AAGUID/Capabilities), not a standalone outlined box.

| Backend state | Total shown | Extra text |
| --- | --- | --- |
| Complete + Exact(1) | `1 credential` | “Inventory complete” (secondary) |
| Complete + Exact(n) | `n credentials` | “Inventory complete” (secondary) |
| Complete + Exact(0) | `0 credentials` | “No resident credentials were reported.” (the only state that may show zero) |
| Incomplete + AtLeast(n) | `At least n credentials` | “Some credentials could not be read. The actual total may be higher.” |
| Inconsistent + Unknown | `Credential count unavailable` | “The authenticator returned conflicting inventory information.” |
| Not inspected | `Not inspected` | Inspection is started from the native Security key menu; never implies zero |

Each verified RP group shows its RP text and the number of credentials listed for it;
an unverified or unreadable RP shows “RP identity unavailable” with “Incomplete” and no
invented domain. Warnings use text plus an icon, never color alone, and the section keeps
semantic headings (`h4` Credentials, `h5` per RP) and nested lists.

Credential names: identical displayName/userName is shown once; differing values show
displayName primary and userName subdued; a single available value is shown alone; neither
yields “Passkey”. Credential IDs and opaque CredentialHandles are never rendered (the
handle remains only the internal list key).

## Inspection start suppression and activity presentation

**Why the “cannot start” message appeared.** That text was emitted only when
`AuthenticationAuthority::reserve()` refused a native-menu start. From the code, the cause is
established as follows: the “Inspect credentials on …” items were always enabled and nothing
suppressed them while an inspection ran. A window-modal AppKit sheet does not disable the application
menu bar, so any second selection or duplicate menu event while the first start was still
active (PIN sheet, credential reads, cleanup) reached `reserve()` and was refused with
`OperationInProgress`. The refusal also set a 10-second toast, so a toast produced at the moment of a
duplicate event could still be on screen when the PIN sheet closed, which reads as “after PIN
submission”. Whether the platform ever delivers two events for one physical click cannot be proven
without hardware; the stderr line `[authentication] admission=…` (refusal) versus the new
`[authentication] duplicate start suppressed` (presentation guard) now distinguishes them. The gate,
cooldown and recovery barrier behavior is unchanged and remains authoritative.

**Presentation-layer suppression.** `fido_service::activity::ActivityTracker` holds one start slot.
The native start claims it before calling `reserve()`; a start that cannot claim it is dropped
silently. The claim is an RAII guard released on every return path. It authorizes nothing: every
claimed start still needs gate admission, the tracker is never read by the gate, prompt
controller, supervisor or worker, and it cannot extend or release any of them. The native inspect
items are also greyed for the lifetime of the claim (and rebuilt items inherit that state);
an event that still arrives is suppressed by the claim or refused by the gate. A boundary check
enforces that the claim precedes `reserve()` and that `reserve()` remains.

**Per-key state, no replacement view.** The authenticator cards stay visible throughout. The
`inspectionActivity` field of the parameter-free, non-blocking `foundation_status` DTO carries only
display-handle/phase/message values, because `list_authenticators` intentionally holds the discovery
lock for the entire inspection:

| Moment | Card of the inspected key |
| --- | --- |
| PIN sheet shown | “Waiting for PIN…” with native-sheet hint |
| PIN submitted, reads and cleanup | “Reading credentials…” |
| Success | inventory updates in place; small transient “Credentials refreshed” |
| Cancelled | quiet: no toast, no alert; card returns to its normal state |
| Failure | one plain-language message inside that key's card until the next attempt or disconnect |
| No key resolved yet (e.g. key vanished) | transient notice |
| Genuine concurrent refusal | “Security key operation still finishing. Try again in a moment.” |

Phases come from a data-free `Progress` callback (`PinRequested`, `PinSubmitted`) on the new
`inspect_with_progress`; `inspect` and `validate` are unchanged. All user-visible wording is fixed
backend text and a test asserts it never contains internal terms (workflow, admission, cooldown,
recovery, barrier, acquisition, binding, PUAT, worker, authentication, snapshot). The generic
“Authentication result” toast and its `authenticationNotice` DTO fields were removed.

Deterministic tests: duplicate/reentrant start suppression, slot release on drop, phase
transitions and per-key attribution, success transition, quiet cancellation, per-key problem
lifetime, wording, the exact serialized renderer shape, and SSR rendering of each state in the real
`App.svelte` with several keys. Because the native glue is macOS-only, it was type-checked and linted for
`aarch64-apple-darwin` from Linux (`cargo clippy -p fidomanager-app -p fido-service --all-targets`
with a stub C compiler for objc build scripts); it could not be run here and needs a macOS hardware
confirmation (menu greying while the sheet is open, and one click producing one sheet).

## Private-library linkage

The existing pinned private build, digest/identity probe and allocation patch are
unchanged. The production verifier matches the exact worker binary digest to its Cargo
link map and attributes all 16 used fido_credman_* symbols to the same credman.c object
in libfidomanager_fido2_bounded.a. It checks the live Symbols table (not dead stripped
entries), private build identity, archive digest, no libfido2 dylib, and no unresolved
FIDO symbols. Deterministic negative controls reject missing, unresolved, other-object
and dead-stripped attribution. macOS CI runs these controls and production verification.

## Validation evidence

Multi-device correction validation passed on the production macOS workstation:

- cargo fmt --all --check: passed.
- cargo clippy --workspace --all-targets --locked -- -D warnings: passed.
- cargo test --workspace --all-targets --locked: 255 passed, 0 failed, 0 ignored
  outside the sandbox, including unchanged process visibility/containment tests.
- node scripts/check-renderer-boundary.mjs and test-renderer-boundary.mjs: passed.
- pnpm check: 0 errors / 0 warnings; pnpm test: 5 passed, 0 failed (1 file).
- pnpm build and pnpm exec prettier --check .: passed.
- git diff --check: passed.
- Previous M3 python3 scripts/test-libfido2.py --rebuild: passed patched allocation
  tests, negative controls and byte-identical archive rebuilds. The correction changes
  no native library, FFI or linkage code, so this rebuild was not repeated.
- python3 scripts/test-credman-linkage.py: passed all positive/negative controls.
- cargo build -p fidomanager-app --features tauri/custom-protocol --locked: passed;
  production worker binary remains validated by the full workspace build/tests.
- python3 scripts/verify-libfido2-linkage.py target/debug/fido-worker: passed all
  16 production credman symbols, private archive identity/digest, no dylib or unresolved FIDO symbols.

The full Rust suite passed outside the sandbox after the unchanged process-visibility
negative control failed inside it. No containment test was weakened. New coverage
includes protocol framing/hostile fields, generation/class, binding/order/replay,
one-shot secret use, unrelated pending request, cleanup/close poisoning, owned native
copies, invalid/unterminated RP text, text/hash mismatch, hash-only records, duplicates,
contradictory totals, aggregate/ID/text bounds, snapshot stale handles, DTO unknown fields,
renderer command/permission allowlists and private-library symbol attribution.
Multi-device coverage adds identical labels, two independent snapshots, per-key epoch
replacement, cross-key/generation rejection, disconnect/replug, failed refresh,
ambiguous connection correlation, stale retired worker, bounded collection and hostile
fields in both display states. A real-process fixture runs A, B, reinspection of A and
cancellation of A across worker retirement, preserving B and rejecting all old native
operation handles. Five rendering tests compile the actual App and inventory component for SSR and cover zero connected, all uninspected,
mixed and multiple inspected keys, complete zero and incomplete/unknown totals.

## Final presentation and readiness validation (Linux, deterministic)

Run on a Linux workstation after the presentation and BooGooCypher changes; no hardware was
touched and no wrong-PIN, mutation or reset operation was performed:

- cargo fmt --all --check: passed.
- cargo clippy --workspace --all-targets --locked -- -D warnings: passed.
- cargo test --workspace --all-targets --locked: 280 passed, 0 failed, 0 ignored on Linux
  (15 `boogoocypher-status` and 11 inspection-activity tests; macOS-only native tests are not compiled here).
- cargo clippy for `aarch64-apple-darwin` on `fidomanager-app` and `fido-service` (type-checks the
  macOS-only native menu/start code from Linux; not executed).
- node scripts/check-renderer-boundary.mjs (including the resolved generated ACL after a build)
  and test-renderer-boundary.mjs: passed, with new BooGooCypher separation controls.
- pnpm check: 0 errors / 0 warnings; pnpm test: 26 passed (was 5); pnpm build and
  pnpm exec prettier --check .: passed; git diff --check: passed.
- python3 scripts/test-credman-linkage.py: passed. No native library, FFI or linkage code changed, so
  the private libfido2 rebuild and the macOS binary linkage verifier were not re-run.

## Real Thetis read-only evidence (2026-10-04, Europe/Stockholm)

Observed from the production native menu and AppKit sheet:

- Operator confirmed Thetis connected and the Authenticators screen visible.
- Native selection prepared CredMan; sheet ran on main thread with secure control,
  window modality and default Cancel.
- One guided normal PIN submission acquired attached PUAT for the requested Thetis
  inspection; no wrong-PIN, automatic PIN retry or mutation experiment ran.
- Metadata, RP enumeration and credential enumeration all returned successfully.
- Typed snapshot: Complete; total kind: Exact. No account identifiers/counts are recorded.
- Native PUAT cleared, device closed/freed, prompt detached/torn down, and worker quiescent
  after retirement/reap; no surviving native authorization was returned or retained.
- Backend stored sanitized snapshot. Operator confirmed Complete and Exact displayed in the renderer.
- A prior cancelled prompt and an expired prompt were both torn down and reaped before
  acquisition. These were not additional credential inspections.
- No mutation command issued (read-only FFI surface and sanitized lifecycle evidence).

After the guided run, the operator reported independently inspecting a second connected
key. Sanitized logs show a second CredMan acquisition and successful metadata/RP/credential
reads, Complete/Exact snapshot, clear/close/free, prompt teardown and worker retirement/reap.
No extra hardware operation was requested by Codex at that point. The earlier
single-slot implementation displayed only the most recently inspected key; this
product correction replaces that behavior with per-connected-key snapshots. The
original read-only native cleanup evidence remains applicable.

Initial direct debug launch showed a blank window because its configured development
URL had no frontend server. The hardware app was rebuilt using
`cargo build -p fidomanager-app --features tauri/custom-protocol --locked`, embedding
the validated dist assets. The blank instance was stopped and the embedded-frontend
instance was launched. The operator confirmed the rendered Authenticators screen.
This launch correction changed no source, ACL, worker, native budget or authentication logic.

## Multi-key UI confirmation (2026-10-04, Europe/Stockholm)

After all deterministic tests were green, the final embedded-frontend build was
launched for the two already available USB keys. Interactive operator mode used
one action per prompt and waited for each confirmation:

- Operator confirmed both connected cards initially showed Not inspected.
- Key 1: native menu selection, native secure PIN sheet, one normal PIN submission.
  Sanitized lifecycle: CredMan, attached PUAT, successful metadata/RP/credential
  reads, Complete/Exact, PUAT cleared, device closed/freed, prompt torn down and
  worker quiescent after retirement. No mutation issued.
- Operator confirmed Key 1 Complete/Exact and Key 2 still Not inspected.
- Key 2: independent native menu selection, native secure PIN sheet, one normal
  PIN submission. The same successful read-only and cleanup lifecycle was logged.
- Operator confirmed **both credential inventories simultaneously visible**, each
  Complete/Exact. No account text, credential details or counts were collected.

No additional wrong-PIN, mutation or automatic inspection was performed. Hardware
check covered simultaneous display; deterministic tests cover disconnect/replug,
reinspection, cancellation and stale/cross-key resolution.

## Files changed by the multi-device correction

- `crates/fido-service/src/authentication.rs`
- `crates/fido-service/src/inspection.rs`
- `crates/fido-worker-fixture/tests/authentication.rs`
- `docs/validation/M3-credential-inspection.md`
- `scripts/check-renderer-boundary.mjs`
- `scripts/test-renderer-boundary.mjs`
- `src-tauri/src/authentication.rs`
- `src-tauri/src/commands/mod.rs`
- `src-tauri/src/lib.rs`
- `src/App.svelte`
- `src/CredentialInventory.svelte`
- `src/inspection.ts`
- `tests/CredentialInventory.test.ts`

## All M3 PR changed files

- `.github/workflows/ci.yml`
- `Cargo.lock`
- `crates/fido-core/src/inventory.rs`
- `crates/fido-core/src/lib.rs`
- `crates/fido-libfido2/Cargo.toml`
- `crates/fido-libfido2/src/inspection.rs`
- `crates/fido-libfido2/src/lib.rs`
- `crates/fido-libfido2/src/native/authentication.rs`
- `crates/fido-libfido2/src/native/inspection.rs`
- `crates/fido-native-ui/src/macos_pin.rs`
- `crates/fido-puat-spike/src/bin/fido-puat-spike.rs`
- `crates/fido-service/Cargo.toml`
- `crates/fido-service/src/authentication.rs`
- `crates/fido-service/src/inspection.rs`
- `crates/fido-service/src/lib.rs`
- `crates/fido-worker-fixture/src/bin/fido-worker-fixture.rs`
- `crates/fido-worker-fixture/tests/authentication.rs`
- `crates/fido-worker-protocol/src/lib.rs`
- `crates/fido-worker/src/engine.rs`
- `docs/validation/M3-credential-inspection.md`
- `scripts/check-renderer-boundary.mjs`
- `scripts/test-credman-linkage.py`
- `scripts/test-renderer-boundary.mjs`
- `scripts/verify-libfido2-linkage.py`
- `src-tauri/src/authentication.rs`
- `src-tauri/src/commands/mod.rs`
- `src-tauri/src/lib.rs`
- `src/App.svelte`
- `src/CredentialInventory.svelte`
- `src/inspection.ts`
- `tests/CredentialInventory.test.ts`
- `src/styles.css`
- `crates/fido-service/src/activity.rs` (new), `crates/fido-service/src/authentication.rs`, `crates/fido-service/src/lib.rs`
- `crates/boogoocypher-status/` (new: Cargo.toml, src/lib.rs, src/http.rs, src/tests.rs)
- `docs/validation/M3-boogoocypher-readiness.md`
- `src-tauri/build.rs`
- `src-tauri/capabilities/main.json`
- `src-tauri/permissions/autogenerated/boogoocypher_status.toml`
- `src-tauri/Cargo.toml`
- `Cargo.toml`
