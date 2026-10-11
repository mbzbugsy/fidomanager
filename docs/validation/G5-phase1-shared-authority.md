# G5 Phase 1 — shared macOS recovery authority

Status: implemented for independent review; **G5 remains OPEN** for signed validation. This
supersedes the earlier [decision-boundary snapshot](G5-phase1-decision-boundary.md). Base is
`a661d4c7b055f5c2e88adb2dbeb9ca2c7c4e5b57` (merged MAS.0/MAS.1). PR #40 remains draft.

## Approved architecture and implementation

[Issue #38](https://github.com/mbzbugsy/fidomanager/issues/38) and the
[maintainer decision](https://github.com/mbzbugsy/fidomanager/pull/40#issuecomment-6102688283)
approve exactly:

| Purpose | Value |
| --- | --- |
| Existing sole release Team ID | `7VGK9SN42B` |
| Shared App Group | `7VGK9SN42B.eu.fidomanager.authority` |
| Developer ID main | `eu.fidomanager.desktop` |
| Store main | `eu.fidomanager.desktop.mas` |
| Developer ID worker (unchanged) | `eu.fidomanager.desktop.fido-worker` |

Approval establishes source configuration, not Apple registration, provisioning or signed access.
The store worker signing/per-release identity is a separate MAS.2/G4 gate; it is not inferred
from the store app ID.

Both production channel selections use one Foundation-resolved group root, one existing
`fido-authority-recovery-v1/incident.json` schema-1 journal and one `single-instance.lock` flock.
The Developer ID service uses the existing shared
`worker_authenticity::developer_id_requirement(APP_IDENTIFIER, team)` APP_REQ builder: Apple
generic anchor, fixed main ID/Team, Developer ID CA OID `1.2.840.113635.100.6.2.6` and Developer ID
Application leaf OID `1.2.840.113635.100.6.1.13`. It validates this strict requirement, Hardened
Runtime, dynamic valid/kill status and strictly typed exact main grants before requesting the
group URL, acquiring the flock or accessing recovery. Apple Development feasibility must not
weaken this production requirement.
The store selection also requires actual kernel sandbox state. Root paths are never constructed
from HOME, an environment variable, arguments or an inferred bundle ID.

The current **store-main predicate is a temporary fail-closed placeholder**. Its Developer
ID-style leaf `subject.OU` Team rule cannot accept Apple-re-signed App Store/TestFlight code;
its exact four-grant parser also rejects additional profile-derived entitlements. A real
store-signed build is rejected **before shared App Group resolution, flock acquisition or
recovery loading**. G1/G5 must implement and validate the correct store-main signing requirement,
Team ID binding and exact profile-derived entitlements. MAS.2/G4 separately owns worker
authenticity. No TestFlight or store-signed success is claimed, including by mocked checker
tests. This delta does not implement the final store-main predicate.

`AuthorityRoot` opens the existing root with `O_NOFOLLOW_ANY | O_DIRECTORY | O_CLOEXEC` on Darwin,
requires ownership by the effective user, mode `0700`, and no extended ACL. Query errors fail
closed. There is no root creation, canonicalization, alternate-root selection or permission
repair. Lock and journal namespace opens use the same pinned descriptor. The flock precedes
recovery, plugins, UI, IPC, discovery and worker initialization. A contender exits before journal
access. It remains held through cleanup until actual process termination; descriptors are not
inherited across exec. Replacement/synchronization in `DurableRecoveryFile::replace`, the entire
`RecoveryJournal` algorithm and schema are unchanged. Initialization now has a descriptor-based
entrypoint; the existing development entrypoint reuses it.

The production overlays pin channel IDs, features and main grants. `macos-release-signing` implies
shared authority, and shared authority alone is an app compilation error. The store overlay
selects sandbox plus shared authority, but additionally refuses worker/UI initialization if the
temporary main predicate is satisfied, until G4 establishes store worker authenticity. Real
store-signed builds are refused earlier as described above. This prevents an unsigned-development verifier
from becoming production store authority. Developer ID publisher/per-release checks and zero
worker grants remain intact. Workers never depend on the new Foundation resolver; the platform
crate's dependency set remains unchanged. Windows behavior is unchanged.

Default unsigned development retains its original plugin/storage. Ad-hoc packaging selects no
shared production authority, and both sandbox fixtures retain dedicated identities/containers.
No signing credential/profile/secret, real incident journal or physical FIDO/PIN operation was
accessed; no production app was launched. No migration engine, downgrade sentinel, schema 2 or
multi-incident UI was added.

## B1/B2 review delta — locally verified on 2026-10-11

Baseline: reviewed HEAD `54ea7af6501d6989e1aaacae7e9c3474ffee8710`. B1 replaces the independent
Developer ID publisher text with the shared APP_REQ builder at the early authority check. Two
focused Rust tests pin both Developer ID OIDs, the fixed app ID/Team and invalid-input rejection.
Four new boundary mutations reject a Team-ID-only replacement, a disconnected builder, missing
signature validation and group resolution before validation. B2 changes documentation only:
the store signing/entitlement predicate remains the same temporary fail-closed placeholder.

All checks below were genuinely rerun locally in the existing worktree. Final frontend checks
used bundled Node 24.19.0 and pnpm 11.25.0 with existing dependencies. The ad-hoc packaging
scripts used the default Node 22.19.0; their generated frontend asset names/content match the
subsequent Node 24 build. No production-channel app, signing identity or profile was used.

| Delta check | Result |
| --- | --- |
| Focused Developer ID authority regressions | PASS: 2 tests |
| Rust formatting; all-feature workspace Clippy with warnings denied | PASS |
| Workspace/all-target Rust tests, final full rerun | PASS: 508 passed, 0 failed, 3 ignored |
| Shared-authority service feature; service doctests | PASS: 185 passed, 2 ignored; 8 doctests |
| Both production app flavors, compile only; shared-only negative | PASS; shared-only selection rejected with the expected compilation error |
| Frontend lint, typecheck, tests, build | PASS: 0 type errors/warnings, 45 tests |
| Renderer boundary and mutation suite | PASS: 171 checker executions |
| Exact authority policy/main-checker/signing-command controls | PASS: 4 test methods; signing calls mocked |
| MAS.1 evidence parser | PASS: 14 tests |
| Both macOS ad-hoc packaging paths | PASS: Developer ID-path app/DMG and isolated sandbox app |
| Bundle negatives; packaged worker health | PASS: 33 mutations rejected; 1 synthetic handshake/health test |

The first full Rust run failed the existing
`process_worker::tests::worker_identity::path_checks_run_again_on_every_launch` assertion:
`HandshakeTimeout` instead of `SpawnFailed` for a child exiting without a handshake. That test
passed in isolation and the subsequent entire suite passed. No worker code or timing was changed.
This transient failure is recorded rather than counted as an initial pass.

The runtime fixture, persistence algorithms and source files hashed by the committed sandbox
report are unchanged by B1/B2. The SIP-enabled fixture and native archive rebuilds were **not**
rerun for this delta; the original report below retains its original run ID/date and is not
relabeled as new runtime evidence. Apple-signed and TestFlight gates remain blocked. New-head
CI status is reported on PR #40 after push; local passes do not establish a CI result.

Reproduce the focused regression separately with:

```sh
cargo test -p fido-service --features macos-shared-authority --locked --offline \
  shared_authority::tests::developer_id_authority
pnpm security:renderer-boundary
```

## Initial Phase 1 locally verified results

Validation ran locally in `/private/tmp/fidomanager-g5` on arm64 macOS 26.5.2, SIP enabled. Final
frontend checks used Node 24.19.0; the available pnpm 11.25.0 ran existing installed dependencies
without installation/lockfile changes. CI retains its pinned Node 24.21.0/pnpm 10.17.1. Native
source caches were reused; separate-path private archive rebuilds were rerun. This is not a
fresh-machine or Windows runtime claim.

| Check | Result |
| --- | --- |
| Rust formatting; all-feature workspace Clippy with warnings denied | PASS |
| Workspace/all-target Rust tests | PASS: 506 passed, 0 failed, 3 ignored |
| Service with shared-authority feature; service doctests | PASS: 183 passed, 2 ignored; 8 doctests |
| Both production app flavors, compile only | PASS; neither was signed or launched |
| Shared-only app feature negative control | PASS: rejected with exact production-channel compilation error |
| Frontend lint, typecheck, tests, build | PASS: 0 type errors/warnings, 45 tests |
| Renderer boundary checks | PASS: 167 checker executions, including G5 selection/resolver/lifetime negatives |
| Exact entitlement/main-checker/signing-command controls | PASS: 4 test methods; malformed/extra/missing grants, wrong Team/ID/certificate/runtime, Apple publisher requirement failures and channel mismatch rejected; signing calls mocked |
| MAS.1 evidence parser | PASS: 14 tests; fail-closed kernel/signature/admission/holding-child evidence controls retained |
| SIP-enabled disposable recovery fixture, descriptor-based root/lock/storage | PASS: 6 persistence/restart cases, 21 negatives, unsigned rejection, singleton/crash/CLOEXEC with inherited child |
| MAS.1 fixture build-only packaging | PASS; packaging coverage only |
| Native source/parser/linkage/reproducibility suites | PASS: patched/unpatched controls, native environment/parser bounds, system-library rejection, byte-identical separate-path private archive rebuilds |
| Both macOS ad-hoc packaging paths | PASS: Developer ID-path app/DMG and isolated sandbox app; exact grants/feature/linkage checks |
| Bundle negative controls; packaged worker health fixture | PASS: 33 bundle mutations rejected; 1 handshake/health test, no device access |
| Fresh debug worker link-map/credential/PIN symbol checks | PASS: wrong object/archive, dead-strip and hostile-link inputs rejected; only private static archives/system linkage |

New synthetic shared-authority tests exercise the same acquisition/storage path from two logical
channel holders against a disposable ordinary directory: unresolved DispatchCapable reloads
with exact loaded phase and Barrier admission, resolved records reopen admission, malformed
records remain blocked, unsafe namespaces/lock symlinks refuse acquisition before journal
creation, contention excludes a second process, and SIGKILL/restart preserves the barrier.
Platform tests also reject absent/relative roots, permissive modes, root and ancestor symlinks
(with an existing valid nested target as positive control), and extended ACLs despite mode 0700.
A path-replacement test proves lock and storage remain anchored to the same already opened root.
Unsigned production acquisition is rejected before the real group resolver is reached.

These tests **do not** establish real Developer ID/store group visibility: logical holders use a
synthetic root, and the kernel-enforced fixture uses its disposable ordinary sandbox container,
not a production App Group. Only signed validation can join those facts.

## Reproducible kernel sandbox evidence

The fresh committed report is
[`data/g5-phase1/sandbox-recovery-runtime.json`](data/g5-phase1/sandbox-recovery-runtime.json),
started **2026-10-10 22:50:53 UTC**, run **`25e5d84d869f4bea8eebcf42c9c58a51`**. It hashes the
root, lock, storage, journal, authority and fixture source; records exact ad-hoc grants/signature
shape, kernel sandbox/signature/runtime events from writers, reloaded processes, holding
fixtures and the inherit-only child; and validates emitted initialization/admission outcomes.
The parent dies while the inherited child remains alive, yet a new holder reacquires the lock.

Successful production calls establish that this filesystem accepted the mandatory write/flush,
`F_FULLFSYNC`, `renameat`, directory `fsync`, directory `F_FULLFSYNC` path. No syscall trace or
power-loss experiment was collected. Process-restart persistence is proved; physical power-loss
durability is **not**. Old MAS.1 evidence was not overwritten or relabeled.

One genuine failed intermediate run exposed sandbox denial when the first root-opener design
read ancestor directories. The final Darwin opener uses all-component `O_NOFOLLOW_ANY` without
ancestor directory reads or new entitlements. Local negative controls establish this behavior;
Apple's [macOS 11-era XNU header](https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.81.3/bsd/sys/fcntl.h)
and [open implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.81.3/bsd/vfs/vfs_vnops.c)
also specify the flag and rejection path. Real supported-OS signed validation remains required.

Reproduce without signing variables or credentials (the runtime negative control, loopback tests
and DMG tooling require execution outside an enclosing command sandbox):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-targets --locked --offline
cargo test -p fido-service --features macos-shared-authority --locked --offline
cargo test -p fido-service --doc --locked --offline
cargo check -p fidomanager-app --features macos-release-signing --locked --offline
cargo check -p fidomanager-app --features macos-app-sandbox,macos-shared-authority --locked --offline
# Must fail: "shared authority requires a production channel feature"
cargo check -p fidomanager-app --features macos-shared-authority --locked --offline
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm security:renderer-boundary
python3 scripts/test-macos-authority-policy.py
python3 scripts/test-macos-sandbox-recovery-runner.py
python3 scripts/test-native-deps.py
python3 scripts/test-libfido2.py --rebuild
python3 scripts/test-macos-sandbox-recovery.py --build-only
python3 scripts/test-macos-sandbox-recovery.py --report target/mas1-recovery/g5-regression-run.json
python3 scripts/package-macos.py --dmg
python3 scripts/test-macos-bundle-check.py 'target/macos-package/Fido Manager.app'
python3 scripts/package-macos-sandbox.py
FIDOMANAGER_PACKAGED_WORKER="$PWD/target/macos-package/Fido Manager.app/Contents/MacOS/fido-worker" \
  cargo test -p fido-worker --test packaged_worker --locked --offline -- --ignored
cargo clean -p fido-worker
cargo build -p fido-worker --locked --offline
python3 scripts/test-credman-linkage.py
python3 scripts/verify-libfido2-linkage.py target/debug/fido-worker
```

## Remaining gates and independent review

- **Apple-signed — BLOCKED, not passed:** registration/entitlement access with the approved
  identities, first-launch group-root availability, actual root permissions/ACLs, behavior on
  supported macOS versions, journal sharing, cross-channel contention/restart/denials,
  Apple Development feasibility without relaxing production APP_REQ, Developer ID
  notarization/Gatekeeper and the protected signing driver's exact main-only grant policy.
- **TestFlight/App Store Connect — BLOCKED, not passed:** correct store-main signing requirement,
  Team ID binding and exact profile-derived entitlements (G1/G5), coinstallation/reinstallation,
  store/Developer ID sharing and MAS.2/G4 store worker
  authenticity. The current production store executable intentionally cannot start UI/workers.
- **Maintainer state — separately reviewed human transition required:** independent journals can
  hide unresolved incidents and separate locks permit concurrency. The real pre-release journal
  was never read/hashed/modified/migrated or bypassed by launching a new production channel.
  This PR gives no permission to switch that installation's authority or clear its barrier.
- **Review focus:** exact main-entitlement exception to ADR-017, CF object/type/ownership parsing,
  trusted resolver, root ACL/no-follow policy, descriptor races, process-exit lock lifetime,
  compile-time channel separation and fail-closed MAS.2 gate. Same-user/privileged deliberate
  container or lock replacement remains outside the cooperating-instance security boundary.

Read-only inventories of #35 (`cf00a31`) and #36 (`3229912`) identified overlapping checker/ADR/
preflight policies. Their branches, PRs #20/#35/#36 and the release-signer repository are untouched.
Their eventual integration must reconcile the exact main grant while preserving all worker,
publisher and per-release binding checks. No Apple-dependent gate is marked complete by local
synthetic tests. PR #40 stays draft for independent Opus review and is not merged.
