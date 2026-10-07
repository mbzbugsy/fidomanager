# M5 credential deletion fix validation

Date: 2026-10-07 (Europe/Stockholm).
Branch: `feature/m5-credential-deletion`.
Reviewed baseline: `7c1358b466bf1bca90397eefe7e69de738bb6e5a`.
Implementation SHA: the commit containing this report, recorded in Draft
[PR #29](https://github.com/mbzbugsy/fidomanager/pull/29).

This records implementation and deterministic validation against the supplied
brief. The original independent review texts are not repository artifacts.
The existing checkout and branch were used; the remote was fetched and pulled
before editing. No new branch or PR, merge, or physical hardware mutation was
performed.

## Inspection selection and current native proof (H1)

Inspection evidence now identifies what was selected. It does not retain the
inspection worker as deletion authority. `StoredInspection.authority` was removed.
An accepted inspection result carries explicit `inspection_worker` provenance;
publication checks that generation instead of capturing whichever worker happens
to be current when publication occurs. A late result cannot publish against a
newer worker's manifest. The legacy weaker identity resolver is test-private.

An exact target owns the verified RP text and hash, credential ID, optional
user.id, names, authenticator label, display generation, enumeration epoch and
opaque credential handle. It can remain a selection after orderly inspection
worker retirement and discovery reconciliation. It grants no native authority.

The high-level deletion orchestrator acquires the shared sensitive gate before
resolving the current worker/device candidate. The immutable intent binds this
candidate together with the exact selection. Before dispatch it rechecks the
current supervisor, native device generation, worker generation, inspection epoch,
approval, lifecycle and durable receipt. Protocol version 7 carries the complete
backend identity to the current worker; raw identity never enters renderer DTOs.

The current prepared native session revalidates capabilities and retry context,
enumerates only the intended verified RP, and requires one exact credential-ID
match and matching user.id when the selection supplied one. Absence, duplicate
IDs, changed user identity, malformed rows and inconsistent enumeration reject
the proof. The proof and deletion use the same open `Device`. The RP credential
copying function is shared with bounded M3 inspection, including count checks
before allocation, bounded IDs/text, and aggregate limits. Only a successful proof
can reach the one native delete call.

The process regression executes the production order: worker N inspects, is
retired and reaped, retirement is recorded, inventory is published using N's
provenance, worker N+1 discovers, and the real service deletion workflow prepares
N+1 and proves the credential before entering deletion. N's old native handle no
longer resolves. A separate publication test rejects a late N result after N+1
has already reconciled.

## Typed deletion recovery (H2)

`RecoverableOperation` selects SetPin, ChangePin or DeleteCredential while
preserving the existing journal schema, application identifier and serialized
operation names. PIN recovery rejects deletion incidents. Generic recovery
reservation/resolution helpers are crate-private.

Deletion recovery has its own presentation, completion type, AppKit purpose,
native menu action, title and acknowledgement checkbox. Its completion cannot
carry PIN secrets. Trusted text explains that the credential may or may not have
been deleted, the incident cannot identify a reconnected key, acknowledgement
preserves uncertainty, and no deletion is retried. The backend presentation also
provides the incident timestamp; the journal stores no credential identity.

The service retires/reaps worker execution before presenting recovery. Resolution
requires a bound native controller approval receipt, completed sheet teardown,
live lifecycle/deadline, matching recovery admission and independent quiescence.
It durably resolves as `AcknowledgedUnknown`. Poisoned/corrupt storage has no
acknowledgeable operation. Cached inspection is cleared before the ceremony, so a
subsequent credential mutation requires fresh inspection.

## Permit, presentation and boundary hardening

- The compile-fail doctest uses `(*p).clone()` to test the owned permit rather
  than cloning a reference. CI explicitly runs service doctests on Linux and macOS.
- The named one-second `DELETE_PERSISTENCE_LIFETIME_MARGIN` is checked before
  persistence. Inclusive boundary and adjacent nanosecond tests cover it. Expiry
  or revocation during fsync still fails closed after the write; the margin does
  not assume a maximum fsync duration.
- Deletion reservations and approve/Pending/dispatch/finish helpers are private.
  No successful reservation escapes the high-level workflow. Setup and ordinary
  cancellation paths tear down and release the gate after proven quiescence.
- The future deletion sheet model preserves full verified RP text, both account
  names, authenticator label, stable fingerprint, incomplete-inventory warning
  and explicit irreversible-deletion consequence. The same truncated SHA-256
  fingerprint appears on inspection cards. No renderer deletion control was added.
- `WorkerRequest` Debug redacts all request contents by default, with regression
  coverage. Backend raw identity also has redacted Debug.
- Scoped deletion requires genuine `credMgmt`; preview plus scoped-token support
  without `credMgmt` is refused. Explicit legacy FIDO 2.0 unscoped preview remains
  supported. Read-only credential-management permission is never deletion authority.
- Confirmed success and unknown deletion invalidate inspection. A durable
  DispatchCapable record dominates a later worker-reported pre-delete failure;
  it conservatively retains an unknown outcome and recovery barrier.
- Renderer hostile mutations cover Clone/Debug/Serialize denial for deletion
  permits/receipts, private dispatch authority, consumption by value, durable
  ordering, backend-only identity types, and exact renderer DTO field allowlists.

## Deterministic coverage and limitations

Nine new process test functions exercise the real
`AuthenticationAuthority::delete_credential` and recovery orchestration with
synthetic native I/O, rather than constructing permits. They cover successful and
explicitly rejected deletion, cancellation, preparation failure, production
inspection retirement, proof-negative identities, every journal transition's
storage failure before and after publication, lifecycle revocation during Pending
and DispatchCapable writes, expiry during fsync, stale/replaced epochs, cleanup
failure, lost response, crash, hang, unknown result, restart, typed recovery, and
literal M4 SetPin/ChangePin serialized journal compatibility. Native entry events
are durably recorded by the fixture so crash/lost-response cases prove one entry
and no retry. Success and Rejected durably resolve without a barrier; uncertain
entry remains DispatchCapable across restart.

Layered service guard tests additionally reject wrong worker, native device ID,
device generation, replaced selection and insufficient lifetime at dispatch
transition. Worker-engine tests reject wrong worker immediately at execute and
cover Prepare twice, absent device, mismatched generation/binding, Execute without
Prepare, wrong digest/workflow/prompt/acquisition, malformed/truncated/trailing
secret, replay, second execute and an unrelated intervening request. Shared native
policy tests prove zero delete calls on failed pre-entry guards and exactly one
call on accepted execution, including conservative result classification.

The software tests compile production AppKit/native code but do not exercise a
human interacting with an AppKit sheet or a real authenticator. No physical
credential deletion, reset, wrong-PIN attempt, retry exhaustion, live unplug or
real-journal corruption was performed. No supplied finding was intentionally
left unfixed. The renderer deletion UI and future deletion sheet are outside this
pass as requested; only the deletion presentation model and typed recovery sheet
were added.

## Native linkage provenance

The verifier requires a live `T _fido_credman_del_dev_rk` definition attributed to
`credman.c.o` in the exact private pinned archive used by the worker. Negative
controls reject unresolved, wrong-object, wrong-archive, unrelated-object and
dead-stripped symbols. Final verification uses a freshly linked production worker
after tests, because test harnesses can overwrite the shared link-map output.

The existing pinned libfido2 1.17.0 native checks also verify bounded RP/RK parser
allocation, unpatched negative controls, source/patch integrity, build environment
sanitization, refusal of system-library substitution and byte-identical archives
built in separate paths.

## Validation commands

Local environment: macOS 26.5.2 (25F84), Rust/Cargo 1.98.1, Node 22.19.0 and
pnpm 11.25.0. CI retains its pinned Node 24.21.0/pnpm 10.17.1 environment. No
dependency or lockfile was changed.

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test --workspace --all-targets --locked` | 371 passed, 0 failed, 0 ignored |
| `cargo test -p fido-service --doc --locked` | 8 compile-fail doctests passed |
| `pnpm install --frozen-lockfile` | Passed |
| `pnpm security:renderer-boundary` | Passed; 112 checker executions |
| `pnpm lint` | Passed |
| `pnpm typecheck` | Passed; 0 errors, 0 warnings |
| `pnpm test` | 74 passed |
| `pnpm build` | Passed |
| `python3 scripts/build-libfido2.py fetch` | Passed; pinned source verified |
| `python3 scripts/test-libfido2.py --rebuild` | Passed; bounds, negative controls, reproducibility |
| `cargo clean -p fido-worker` | Passed; fresh production link follows |
| `cargo build -p fido-worker --locked` | Passed |
| `python3 scripts/test-credman-linkage.py` | Passed; all symbol attribution controls |
| `python3 scripts/verify-libfido2-linkage.py target/debug/fido-worker` | Passed; exact private archive, live deletion symbol, no libfido2 dylib |
| `git diff --check` | Passed |

The initial sandboxed workspace run failed at the unchanged BooGooCypher loopback
socket test because local binding was denied. The complete suite passed outside
the sandbox. Initial frontend verification caught fingerprint markup sharing an
account-label CSS class; a distinct class fixed it, and the full frontend suite
passed. The originally broken owned-clone doctest was reproduced before its fix.
No assertion was removed or weakened to accommodate these failures.

## Files changed

- `.github/workflows/ci.yml`
- `crates/fido-auth/src/deletion.rs`
- `crates/fido-core/src/inventory.rs`
- `crates/fido-libfido2/src/deletion.rs`
- `crates/fido-libfido2/src/lib.rs`
- `crates/fido-libfido2/src/native/deletion.rs`
- `crates/fido-libfido2/src/native/inspection.rs`
- `crates/fido-native-ui/src/lib.rs`
- `crates/fido-native-ui/src/macos_pin.rs`
- `crates/fido-service/src/activity.rs`
- `crates/fido-service/src/authentication.rs`
- `crates/fido-service/src/deletion.rs`
- `crates/fido-service/src/inspection.rs`
- `crates/fido-service/src/mutation.rs`
- `crates/fido-service/src/recovery.rs`
- `crates/fido-worker-fixture/src/bin/fido-worker-fixture.rs`
- `crates/fido-worker-fixture/src/lib.rs`
- `crates/fido-worker-fixture/tests/authentication.rs`
- `crates/fido-worker-fixture/tests/credential_deletion.rs`
- `crates/fido-worker-protocol/src/lib.rs`
- `crates/fido-worker/src/engine.rs`
- `crates/fido-worker/src/runtime.rs`
- `docs/validation/M5-credential-deletion-fixes.md`
- `scripts/check-renderer-boundary.mjs`
- `scripts/test-credman-linkage.py`
- `scripts/test-renderer-boundary.mjs`
- `scripts/verify-libfido2-linkage.py`
- `src-tauri/src/authentication.rs`
- `src-tauri/src/pin_mutation.rs`
- `src/CredentialInventory.svelte`
- `src/inspection.ts`
- `src/styles.css`
- `tests/CredentialInventory.test.ts`
