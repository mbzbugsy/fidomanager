# M3 production macOS credential inspection

Starting main: `b2ca1efce5edccb12a4b320ba248a4cbdca0e752` (PR #24 / #22).
Branch: `feature/m3-credential-inspection`, freshly created from fetched main.
The pre-#22 branch with that name was preserved as
`feature/m3-credential-inspection-pre22-backup`; its contents were not reused.
Issue #14 is referenced for review, not automatically closed. Issue #23 remains
an immediate, separate M3 follow-up; no readiness endpoint/network/status work is included.

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
independently validates bounds, text and RP digest consistency, assesses completeness,
and replaces its InspectionStore. Fresh snapshots get independently random 128-bit
EnumerationEpoch and random CredentialHandles, with collisions rejected. Neither is
an encoding/digest of raw identity. Exact ID and RP hash remain in a private mapping.
Lookup requires matching epoch, handle and originating DeviceHandle; stale epochs,
handles and device selections fail closed. Replacing/clearing the snapshot retires old
mappings. The mapping grants no authorization: future mutation needs fresh trusted
approval, exact live device generation and the ID enumerated in that same epoch.
Mutation remains deferred.

Renderer DTO:

```text
InspectionSnapshot {
  epoch, authenticator,
  assessment { completeness, total { kind, value? },
               duplicate_rps, duplicate_credentials, count_contradiction },
  rps [{ verifiedText?, issue?,
         credentials [{ handle, userName?, displayName? }] }]
}
```

Only the existing parameter-free foundation_status retrieves this sanitized
snapshot. No renderer inspection command or added ACL permission exists. Renderer
shows selected authenticator, RP groups, credential/passkey entries, typed completeness,
Exact/At least/Unknown totals and explicit unread/unsupported messages. All DTOs reject
unknown fields. Raw hashes, IDs, user IDs, auth bindings, worker/workflow/acquisition/
prompt identities, paths, pointers, permissions, PIN and PUAT never enter this DTO.
Raw inventory Debug is redacted; hardware logs contain fixed categories and booleans,
not account text, counts or identifier material.

## Private-library linkage

The existing pinned private build, digest/identity probe and allocation patch are
unchanged. The production verifier matches the exact worker binary digest to its Cargo
link map and attributes all 16 used fido_credman_* symbols to the same credman.c object
in libfidomanager_fido2_bounded.a. It checks the live Symbols table (not dead stripped
entries), private build identity, archive digest, no libfido2 dylib, and no unresolved
FIDO symbols. Deterministic negative controls reject missing, unresolved, other-object
and dead-stripped attribution. macOS CI runs these controls and production verification.

## Validation evidence

Final deterministic validation passed on the production macOS workstation:

- cargo fmt --all --check: passed.
- cargo clippy --workspace --all-targets --locked -- -D warnings: passed.
- cargo test --workspace --all-targets --locked: 248 passed, 0 failed, 0 ignored
  outside the sandbox, including unchanged process visibility/containment tests.
- node scripts/check-renderer-boundary.mjs and test-renderer-boundary.mjs: passed.
- pnpm check: 0 errors / 0 warnings; pnpm test: passed (no frontend test files).
- pnpm build and pnpm exec prettier --check .: passed.
- git diff --check: passed.
- python3 scripts/test-libfido2.py --rebuild: passed patched allocation tests,
  unpatched/override/corrupt input negative controls and byte-identical archive rebuilds.
- python3 scripts/test-credman-linkage.py: passed all positive/negative controls.
- cargo build -p fido-worker -p fidomanager-app --locked: passed.
- python3 scripts/verify-libfido2-linkage.py target/debug/fido-worker: passed all
  16 production credman symbols, private archive identity/digest, no dylib or unresolved FIDO symbols.

The full Rust suite passed outside the sandbox after the unchanged process-visibility
negative control failed inside it. No containment test was weakened. New coverage
includes protocol framing/hostile fields, generation/class, binding/order/replay,
one-shot secret use, unrelated pending request, cleanup/close poisoning, owned native
copies, invalid/unterminated RP text, text/hash mismatch, hash-only records, duplicates,
contradictory totals, aggregate/ID/text bounds, snapshot stale handles, DTO unknown fields,
renderer command/permission allowlists and private-library symbol attribution.

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
No extra hardware operation was requested by Codex. Both keys' display-history PIN-check
markers may remain, but InspectionStore keeps one latest selected-authenticator snapshot:
a second inspection replaces the first; identical RP/app text never merges credential
sets across keys. The operator's report that only the latest key inventory appears is
expected for this snapshot scope. No mutation was issued in either observed inspection.


Initial direct debug launch showed a blank window because its configured development
URL had no frontend server. The hardware app was rebuilt using
`cargo build -p fidomanager-app --features tauri/custom-protocol --locked`, embedding
the validated dist assets. The blank instance was stopped and the embedded-frontend
instance was launched. The operator confirmed the rendered Authenticators screen.
This launch correction changed no source, ACL, worker, native budget or authentication logic.

## Changed files

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
- `src/styles.css`
