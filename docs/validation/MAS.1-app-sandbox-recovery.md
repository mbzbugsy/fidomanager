# MAS.1 — macOS App Sandbox recovery and persistence validation

Status: **PASS locally** for synthetic journal writes, exact-byte process-restart persistence,
authority admission and single-instance compatibility under a kernel-enforced App Sandbox.
This is a credential-free compatibility test, not a Mac App Store submission or a power-loss test.
G5 recovery continuity between installation channels remains **OPEN**.
The committed runtime evidence was freshly rerun after the Opus E1/E2 changes on
2026-10-10 at 20:09 UTC; it is not a relabeling of the original reviewed run.

Base: `main` at `2e80fe74031cca13199bb39a391b4bf37a2aa8c7` (merged PR #37).
Host: macOS 26.5.2 (25F84), arm64, SIP enabled; Rust 1.98.1; Python 3.9.6;
Node 22.19.0 and local pnpm 11.25.0. The frontend dependencies match the checked-in manifest/lock;
CI retains its pinned Node/pnpm configuration.

## Scope and safety

The Rust fixture is an ignored macOS libtest module behind `cfg(all(test, target_os = "macos"))`.
It reaches the existing private `RecoveryJournal` transitions and
`AuthenticationAuthority::initialize_recovery_at`, and uses the unchanged
`DurableRecoveryFile` and `InstanceLock`. There is no production feature, IPC command, authority
constructor, worker launch, PIN/PUAT, device identity or FIDO execution path added by MAS.1.
All operation labels and journal outcomes in this report are **synthetic**; no credential was deleted.

The runner builds that test executable locally and signs a disposable bundle ad hoc, with Hardened
Runtime and exactly MAS.0's existing app entitlements. An embedded copy of the fixture carries
exactly the existing worker inheritance entitlements. It is a test child, not a FIDO worker.
The existing USB/network grants are unused; no entitlement file or release signer is changed.

Every storage access by the fixture follows successful self-checks for `sandbox_check(pid)=1`,
valid code-signing status and Hardened Runtime, a HOME ending in the dedicated container, and a
32-character hexadecimal run identifier. Paths cannot be supplied as arbitrary journal locations.
The unsandboxed control fails at the first guard, before resolving or inspecting application data.
The only external read attempt is the G5 probe of a runner-created temporary synthetic marker,
with its disposable path checked separately. The real channel journals are never named by the
fixture or accessed by the runner. In particular, **the existing user `incident.json` was never
read, hashed, modified or deleted**. No real-channel comparison was used as a safety check.

Identity: `eu.fidomanager.desktop.mas1recoverytest`. Storage:

```text
~/Library/Containers/eu.fidomanager.desktop.mas1recoverytest/Data/
  Library/Application Support/eu.fidomanager.desktop.mas1recoverytest/
    runs/<fresh-uuid>/<case>/fido-authority-recovery-v1/incident.json
```

Run artifacts stay in that disposable namespace for inspection. Reproduction uses a new namespace
without replacing existing test records. The runner terminates its holding processes and inherit
child; waits are bounded if the runner fails. No production signing credentials, TCC grants, SIP
changes, publication, PR #35/#36 changes or release-signer repository access occurred.

## Reproduce

From the local MAS.1 checkout on a SIP-enabled Mac, without signing variables:

```sh
python3 scripts/test-macos-sandbox-recovery-runner.py
python3 scripts/test-macos-sandbox-recovery.py --report target/mas1-recovery/local-run.json
```

The second command must run outside an enclosing command sandbox: otherwise its unsigned control
is already sandboxed by the caller and correctly refuses to produce a passing report. It compiles
with `cargo test -p fido-service --lib --locked --no-run`, signs ad hoc only, verifies the bundle
and exact entitlement sets, and runs exactly the one ignored test per step. It requires successful
libtest completion as well as kernel and structured assertion evidence. A live PID or an empty
test filter cannot count as protocol/persistence success.

For CI packaging coverage only:

```sh
python3 scripts/test-macos-sandbox-recovery.py --build-only
```

That does not launch the fixture or establish runtime enforcement. Hosted runners are not used as
the SIP-enabled runtime gate. The local evidence includes binary and production-source SHA-256s;
it records process IDs, kernel flags, synthetic contents, record hashes and admission outcomes.
See [runtime-report.json](data/mas.1-recovery/runtime-report.json). Random incident/run identifiers
and PIDs naturally differ between runs. The script redacts the operator's home/worktree paths.

## Locally established results

| Case | Observation and assertions | Result |
| --- | --- | --- |
| Enforcement | Each sandboxed process reports `sandbox_check=1`, successful `csops`, valid signature and runtime flags (`0x22011311` locally); unsigned control reports 0 and fails before storage | PASS |
| Real journal transitions | Production Pending → DispatchCapable → Resolved, using the real durable storage; no physical mutation or dispatch occurs | PASS |
| Metadata and contents | Root/namespace 0700; lock and record 0600; current UID 501; regular single-link record; exact schema/application/operation/phase/resolution; no leftover temporary record | PASS |
| Unresolved DispatchCapable restart | After acknowledgement, writer stays alive, is killed with SIGKILL and reaped; a different process reacquires the lock and reloads identical bytes/SHA-256/incident with Barrier | PASS |
| Pending-only restart | Same forced termination; identical record reloads Pending with Open admission, correctly indicating no successful dispatch-capable acknowledgement | PASS |
| Resolved restart | Separate normal-exit writer and reader for each of NotDispatched, Rejected, ConfirmedSuccessful and AcknowledgedUnknown; exact history preserved and Open admission | PASS |
| Authority initialization | Starts blocked; each case requires exact `Ok(())` with a journal or `Err(Unavailable)` with no journal, plus exact phase/poison/admission. Every successful initialization refuses a second load before opening fresh storage | PASS |
| Blocked workflows | For untrustworthy/unresolved records, inspection, SetPin, ChangePin, deletion, Reset and sensitive export all return RecoveryBarrier before prompts/workers | PASS |
| Singleton | A second signed process completes successfully at AlreadyHeld, before journal loading; holder killed/reaped; replacement acquires and initializes recovery | PASS |
| Lock CLOEXEC/inheritance | Inherit-only signed child is sandboxed and remains executing (not a zombie) before/after parent termination and replacement acquisition; it cannot retain the lock. Parser requires distinct PID-matched kernel sandbox/signature/runtime evidence for parent and child | PASS |
| G5 separate-storage probe | External synthetic DispatchCapable marker denied with EPERM; empty independent container journal starts Open; external synthetic bytes unchanged | PASS (hazard reproduced; migration not tested) |

### Exact initialization outcomes (E1/E2 delta)

The fixture asserts initialization results independently of admission, then emits `authority`
evidence. The runner validates every expected case's initialization, journal presence, phase,
poison state and admission; seed/reload record admissions must also match. A Barrier caused by
storage-open failure cannot substitute for a successfully initialized unresolved journal.

| Scenario | Exact initialization / journal state | Admission |
| --- | --- | --- |
| DispatchCapable seed/reload; post-publication failure reload | `Ok(())`; journal present, DispatchCapable, not poisoned | Barrier |
| Pending seed/reload; restored write-denied Pending; four resolved cases | `Ok(())`; journal present, expected Pending/Resolved phase, not poisoned | Open |
| 11 invalid-record cases and 5 unsafe/inaccessible record cases | `Ok(())`; poisoned journal present, no accepted phase | Barrier |
| Permissive namespace, namespace symlink, permissive app-data root | `Err(Unavailable)`; no journal, no phase or poison state | Barrier |
| Empty singleton and G5 disposable roots | `Ok(())`; journal present, no phase, not poisoned | Open |

Completed fixtures require valid kernel evidence and successful libtest completion. Holding
fixtures are terminated intentionally after their asserted evidence, so the parser instead checks
the same kernel fields against the actual holding PID, and both parent/child PIDs for the lock
case. Missing, duplicate, wrong-PID, unsandboxed, invalid-signature or missing-runtime evidence
fails the run. The inherited child's readiness event alone is insufficient.

### Synchronization evidence and its limits

[SOURCE + LOCAL] Every successful journal transition uses production
`DurableRecoveryFile::replace`: exclusive 0600 temporary creation, write/flush, macOS
`fcntl(F_FULLFSYNC)`, `renameat`, `fsync` of the containing directory, and a second
`fcntl(F_FULLFSYNC)` on the renamed record. The function propagates errors from these mandatory
calls without a weaker fallback. Newly created directories use the existing ancestor/directory
sync path. That production file is unchanged from the base and its hash is recorded in the report.
Successful transition acknowledgements therefore establish that this path returned success under
the sandbox on this host. **No syscall trace was collected**; there is no claim of independently
measured call counts or individual syscall timing.

[APPLE] Apple's [fsync manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
distinguishes host-to-drive synchronization from the stronger full-sync request. [LIMIT]
Successful calls plus SIGKILL/restart persistence do **not** prove survival of power loss, an OS
crash, faulty storage firmware or defective hardware. No power cut, reboot, device failure or
actual kernel synchronization-failure injection was performed. A real write denial and a separately
labeled injected acknowledgement failure are exercised below.

## Negative matrix

All **21 distinct cases pass** in the sandboxed fixture. These test denial behavior, not successful
hardware failure recovery. The production barriers and receipt construction remain unchanged.

| Cases | Count | Required outcome |
| --- | --- | --- |
| Malformed JSON, invalid UTF-8, empty, oversized, unknown field, unsupported schema, inconsistent resolution, invalid incident, unknown operation, wrong application, Resolved without resolution | 11 | Startup Barrier; six ordinary workflows refused; original bad bytes unchanged; no acknowledgement bypass |
| Mode-000 record, permissive record, record symlink, record hardlink, record directory, permissive namespace, namespace symlink, permissive app-data root | 8 | Startup remains blocked; six ordinary workflows refused. Unsafe root also rejects another lock acquisition |
| Injected failed acknowledgement after real successful DispatchCapable replacement | 1 | No receipt returned; live journal poisoned and cannot resolve; on-disk DispatchCapable reloads Barrier |
| Actual owner-write denial after successful Pending | 1 | Production temporary-file creation fails; no DispatchCapable receipt; runtime Barrier; previous bytes unchanged. After permissions are restored, Pending-only reload correctly starts Open |

The injected case calls the real production replacement first, then returns an I/O error from a
test-only storage wrapper. It models ambiguous publication before failed acknowledgement; it is
**not** evidence of an actual kernel `F_FULLFSYNC` error. In the write-denial case the owner-only
namespace is made 0500 temporarily, so the real filesystem denies creation. Both modifications
are confined to fresh disposable records. Foreign-UID ownership rejection remains source/unit
policy; MAS.1 does not change ownership to another user or require root.

The Python evidence parser's 14 regression tests reject empty filters, live-but-incomplete
process output, failing exits, missing/ambiguous record evidence, unsandboxed or invalid runtime
status, wrong authority/record admission, substituted initialization outcomes, missing or invalid
holding/child kernel evidence, and signing-variable injection. The boundary mutation check rejects removing the fixture's
test-only compilation guard; fixture selectors/evidence strings are forbidden in production Rust.

## G5 recommendation and blockers

See [ADR-018 §5.1](../adr/ADR-018-MACOS-APP-SANDBOX.md#51-g5-investigation-and-recommendation-mas1).
MAS.1 demonstrates why a separate empty container cannot account for another channel's unresolved
history. It implements no cross-channel read, import, migration manifest, shared container or
authority bypass.

The preferred first-public-release design in [Issue #38](https://github.com/mbzbugsy/fidomanager/issues/38)
is **one Team-ID-prefixed App Group container, one shared existing schema-1 recovery journal,
and one shared flock-based single-instance authority** across both production channels. Shared
journal visibility and exclusion must both hold; independent storage can miss unresolved history
and independent locks permit concurrent authority. Group-root resolution/open/validation must
fail closed on missing, denied or unsafe access, without an independent-storage fallback.

No general legacy migration engine, downgrade sentinel, schema 2 or multi-incident UI is proposed.
The maintainer's existing pre-release recovery state requires a **separately reviewed,
human-controlled transition** that preserves recovery admission; block that transition if this
cannot be established. MAS.1 never accesses that state and implements no G5 changes.

G5 remains **OPEN** until implementation and signed validation are complete. Apple-dependent
gates include genuine Apple Development/Developer ID group access, shared journal and flock
validation, notarization/Gatekeeper, store provisioning, and TestFlight cross-channel group sharing
and reinstall/concurrent-launch behavior. Ad-hoc probes and plausible OS-returned group URLs do
not prove actual App Group access. A one-channel instruction or first-launch file copy alone is
not authority continuity. Current disposable test identities remain isolated.

## Local regression validation

The following commands were rerun locally in the existing MAS.1 worktree for the Opus delta.
Initial implementation validation also ran in that isolated worktree. Initial command-sandbox failures for loopback
binding and `hdiutil` were environment restrictions; rerunning those checks outside that sandbox
passed. No product fix or weakened test assertion was used for those failures.

| Validation | Result |
| --- | --- |
| `cargo fmt --all --check` | PASS |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | PASS |
| `cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings` | PASS |
| `cargo test --workspace --all-targets --locked --offline` | 498 passed, 0 failed, 2 ignored (MAS.1 and packaged-worker fixtures run separately) |
| `cargo test -p fido-service --doc --locked --offline` | 8 passed |
| `pnpm lint`, `pnpm typecheck`, `pnpm test` | PASS; 0 type errors; 45 tests |
| `pnpm security:renderer-boundary` | PASS; 161 checker executions, including the MAS.1 compilation-guard mutation |
| `python3 scripts/test-macos-sandbox-recovery-runner.py` | 14 passed |
| `python3 scripts/test-native-deps.py` | PASS |
| `python3 scripts/package-macos.py --dmg` | PASS; unchanged credential-free Developer ID path |
| `python3 scripts/test-macos-bundle-check.py <Developer-ID-path app>` | PASS; 33 mutated bundles rejected |
| `packaged_worker -- --ignored` against that app | 1 passed |
| `python3 scripts/package-macos-sandbox.py` | PASS; existing MAS.0 signature/entitlement/inheritance checks |
| Production bundle fixture-marker absence | PASS; both app and worker executables in both build flavors (4 executables) |
| MAS.1 local sandbox runner | PASS; six restart cases, 21 negatives, singleton/CLOEXEC, unsigned control and G5 probe |

Non-blocking review items E3–E5 and cosmetic naming item D3 are deferred. Production recovery
algorithms, entitlements, signing architecture and distribution identities are unchanged.

CI builds/signs/verifies the MAS.1 fixture in `--build-only` mode and runs the parser regressions.
The local runtime report supplies enforcement/persistence evidence; CI is not claimed to replace it.
