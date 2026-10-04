# M4 non-dispatching mutation foundation validation

Date: 2026-10-04 (Europe/Stockholm).
Branch: `feature/m4-mutation-foundation`.
Baseline: `7422a04010793fe095f0a0fc8c1c99c530f5cd52`, merged
[PR #25](https://github.com/mbzbugsy/fidomanager/pull/25).
Implementation SHA: the final commit recorded in the Draft PR; this report is part of it.

## Baseline and scope

The existing checkout was clean before switching branches. `git fetch origin main`
confirmed that origin/main was exactly PR #25's merge commit. The normal baseline
[CI run](https://github.com/mbzbugsy/fidomanager/actions/runs/37193095080) completed
successfully for that commit before implementation began.

No hardware mutation or verification was run. The application and worker have no
reachable PIN set/change, deletion or reset request/call. The pre-existing opt-in
M1.5 manual harness contains a deletion probe; its source is frozen byte-for-byte
by the static check and remains outside production dependencies. No harness,
BooGooCypher, Windows broker, packaging or release implementation was changed.
The PR remains Draft for independent review and is not merged.

## Authority, intent and recovery contract

`AuthenticationAuthority` retains one private service gate and prompt controller.
All four workflow classes share `reserve_sensitive`, the existing zero queue,
workflow/prompt sequences, cooldown and teardown/quiescence rules. Constructors
start with a recovery barrier until the one-shot journal load determines admission.
An authority-owned persistent latch cannot be cleared by ordinary completion,
worker replacement, reconnect, UI reload or lifecycle epoch changes.

The immutable exact-target intent and non-clone/non-serde one-use permit bind
operation, workflow/prompt, target handle/device incarnation, worker generation,
authority identity, cancellation epoch, canonical version/digest and trusted times.
Intent lifetime is bounded by the existing 30-second prompt policy. Permit TTL is
10 seconds, capped by intent expiry. Only bound trusted-native approval after
teardown can mint a permit; there is no installed mutation presenter or command.
Final consumption and generation validation are under the one gate lock and an
exclusive canonical-supervisor borrow. The durable transition returns no
executable request or dispatch capability.

Journal transitions are NoRecord → Pending → DispatchCapable → Resolved. Pending
alone does not imply dispatch. DispatchCapable survives restart as Barrier.
Malformed/unreadable/unsupported records and failed durability acknowledgements
fail closed. Resolved is an atomic tombstone; deliberate acknowledgement retains
historical uncertainty as `acknowledged_unknown`. No secret, raw path, account/RP
text, workflow/prompt identity or intent digest is persisted.

Concrete storage uses the framework-derived app data root, a 0700 authority
namespace, 0600 records, anchored no-follow descriptors, exclusive temporary
creation, atomic rename and explicit directory fsync. macOS F_FULLFSYNC occurs
before publication and again after directory-entry sync; required sync failures
never authorize a transition. Newly created ancestor entries are synced as well.
Durability is the OS/storage contract, with no same-user tamper-proof claim.

[ADR-010](../adr/ADR-010-MUTATION-OUTCOME-RECOVERY.md) records the checksum-verified
libfido2 1.17.0 source evidence and operation-specific status allowlist. The
high-level PIN API is multi-exchange. FIDO_OK confirms success; selected definitive
parameter/PIN rejections establish Rejected. TX/RX/timeout/parse/transport/lost-response
ambiguity after entry remains OutcomeUnknown. INTERNAL can occur after mutation
transmit and is also unknown. Authentication retry side effects remain separate;
no automatic retry or old/new PIN probing is implemented.

## Deterministic coverage

31 Rust tests were added relative to the 288-test macOS baseline:

- Service: 18 intent/permit/shared-authority tests and 6 journal/recovery-policy
  tests. Cases cover all workflow pairings, shared cooldown, exact canonical
  fields, actual reservation workflow/prompt changes, wrong/absent device and
  worker generations, teardown-bound approval, expiry, one-shot/replay rejection,
  lifecycle epochs, successor/other-authority rejection, Pending restart,
  DispatchCapable restart, deliberate resolution, resolution rejection/failure with quiescent release and fresh Recovery admission,
  unreadable/corrupt/unsupported records, Pending/write/sync failures, revocation
  during sync and an ordinary finish attempting to clear the persistent latch.
- Platform: 3 concrete durable-storage tests for replacement/reopen, bounded
  reads, 0600/0700 permissions and rejected symlink/hardlink/unsafe storage.
- Adapter: 1 additional deadline test; the former overflow test now rejects zero,
  oversized and Duration::MAX, while the new test accepts the exact maximum.
- Protocol: 1 test rejects forged set/change/reset/delete messages and checks that
  every admitted request has a non-mutation operation class.
- Process fixture: 2 tests preserve admission through real worker crash/reap,
  replacement and authority restart, and admit inspection for Pending-only startup.

Three additional compile-fail doctests reject permit construction, cloning and
serialization. Static checks freeze the worker request variants, forbid production
mutation FFI/calls, prevent importing the opt-in spike into production, and prevent
new renderer authority/secret/journal fields or commands. The regression script
runs 53 checker executions (50 hostile fixtures and 3 valid/restored baselines),
including 10 new M4 negative controls. No existing M2/M3 assertion was weakened;
inspection fixtures now explicitly initialize an empty read-only journal.

## Commands and final results

Local environment: macOS 26.5.2 (25F84), Rust 1.98.1 (Homebrew), Node 22.19.0,
pnpm 11.25.0. These are the installed local frontend tools; repository CI still
pins Node 24.21.0 and pnpm 10.17.1. No frontend dependency/lockfile was changed.

| Command | Final result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test --workspace --all-targets --locked` | 319 passed, 0 failed, 0 ignored |
| `cargo test -p fido-service --doc --locked` | 3 compile-fail tests passed |
| `node scripts/check-renderer-boundary.mjs` | Passed, including generated ACL checks |
| `node scripts/test-renderer-boundary.mjs` | Passed, 53 checker executions |
| `pnpm check` | Passed, 0 errors / 0 warnings |
| `pnpm test` | Passed, 74 tests in 2 files |
| `pnpm build` | Passed |
| `pnpm exec prettier --check .` | Passed |
| `git diff --check` | Passed |

The initial sandboxed full-suite attempt stopped at an unchanged BooGooCypher
localhost redirect test because loopback binding was denied. The complete suite
passed outside the sandbox, including existing process-visibility/containment
checks. No test was skipped or weakened and no external service was contacted
by that loopback fixture. The final suite was rerun after storage-ordering and recovery-clearance ownership changes.

Final Rust breakdown:

| Target | Passed |
| --- | ---: |
| boogoocypher-status | 15 |
| fido-auth | 8 |
| fido-core | 7 |
| fido-libfido2 | 10 |
| fido-native-ui | 9 |
| fido-platform | 3 |
| fido-puat-spike (non-native unit contracts) | 62 |
| fido-service | 117 |
| fido-worker unit tests / production-binary tests | 8 / 4 |
| fixture authentication | 7 |
| fixture descriptor hygiene | 3 |
| fixture handshake/framing | 20 |
| fixture mutation foundation | 2 |
| fixture orphan cleanup | 4 |
| fixture process lifecycle | 9 |
| fixture supervisor recovery | 6 |
| fido-worker-protocol | 24 |
| fidomanager app | 1 |
| **Total** | **319** |

## Exact changed files and types

New files:

- `crates/fido-platform/src/recovery_file.rs`: `DurableRecoveryFile`.
- `crates/fido-service/src/mutation.rs`: `OperationIntent`, `OperationPermit`,
  `MutationReservation`, `RecoveryReservation`, `MutationError`; intent version
  and trusted permit TTL constants.
- `crates/fido-service/src/recovery.rs`: `JournalStorage`, `JournalError`,
  `PinOperation`, `JournalPhase`, `Resolution`, `RecoveryJournal`, `PinRecoveryPolicy`,
  private `Record`, journal bound and conservative `pin_call_outcome` classifier.
- `crates/fido-worker-fixture/tests/mutation_foundation.rs`: real-process recovery
  admission fixtures.
- `docs/adr/ADR-010-MUTATION-OUTCOME-RECOVERY.md`.
- `docs/validation/M4-mutation-foundation.md`.

Modified files:

- `crates/fido-libfido2/src/lib.rs`: fail-closed NativeDeadline ceiling and tests.
- `crates/fido-platform/src/lib.rs`: Unix storage module export.
- `crates/fido-service/Cargo.toml`: serde_json available to journal policy in production.
- `crates/fido-service/src/authentication.rs`: shared reservation path, fail-closed
  startup/journal ownership and initialized inspection fixtures.
- `crates/fido-service/src/lib.rs`: mutation/recovery modules and persistent gate latch.
- `crates/fido-worker-fixture/tests/authentication.rs`: empty read-only startup journal.
- `crates/fido-worker-protocol/src/lib.rs`: non-mutation request regression test only;
  executable protocol and version remain unchanged.
- `scripts/check-renderer-boundary.mjs`: foundation static guards.
- `scripts/test-renderer-boundary.mjs`: hostile foundation fixtures and execution count.
- `src-tauri/src/lib.rs`: authority startup load before sensitive native admission.
- `docs/ARCHITECTURE_AND_RELEASE_PLAN.md`: link to implemented foundation scope.
- `docs/SECURITY_MODEL.md`: link to pinned-source ADR-010 evidence.

Native PIN mutation execution, mutation presenter, deliberate verification and final
recovery/corrupt-storage UI are future work. No hardware behavior or physical
power-loss experiment is claimed; source, deterministic faults and concrete local
filesystem replacement/reopen tests are the evidence for this foundation.
