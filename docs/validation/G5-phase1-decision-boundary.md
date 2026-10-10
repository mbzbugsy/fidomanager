> Historical decision-boundary snapshot. The maintainer approved the identities in PR #40;
> current implementation and genuinely rerun results are in [Phase 1 evidence](G5-phase1-shared-authority.md).
> Results below describe the earlier documentation-only HEAD, not the implemented shared authority.

# G5 Phase 1 — shared authority decision boundary

Status: **BLOCKED BY MISSING IDENTITY / ENTITLEMENT DECISIONS**. This is a documentation-only
draft for independent review, not an implementation of shared production recovery authority.
Base: latest main `a661d4c7b055f5c2e88adb2dbeb9ca2c7c4e5b57` (MAS.0 and MAS.1 merged).
Host: macOS 26.5.2 arm64, SIP enabled.

## Verified repository facts

- `crates/fido-service/src/worker_authenticity.rs` pins the sole reviewed
  `MACOS_RELEASE_TEAM_ID: Option<&str> = None`. The optimized release flavor has a compile-time
  assertion requiring a provisioned value; debug release startup rejects an unprovisioned ID.
- Developer ID's current app identifier is `eu.fidomanager.desktop`; its worker identifier is
  `eu.fidomanager.desktop.fido-worker`. These are source facts, not a decision to use the same
  app identity for a future store build.
- MAS.0 packaging defines a disposable `.sandboxtest` identity, and MAS.1 defines another test
  identity. Neither is a production Mac App Store identifier or real App Group-access proof.
- Current checks pin Developer ID zero entitlements and the sandbox app/worker grant sets.
  No production group grant or trusted-API shared-root startup path exists on this base.

## Decisions required before safe implementation

1. Provision/review the existing Team ID constant using the identity decision required by
   ADR-017. Do not invent a second constant, derive it from running code, or accept it from
   environment/renderer input. No signing credentials are requested or used by this draft.
2. Approve the exact Team-ID-prefixed App Group identifier, including its suffix. Without a
   real reviewed prefix an exact production entitlement cannot be pinned safely.
3. Decide and pin the production Mac App Store bundle identifier and whether the two channels
   share it. This affects installation/signing policy; the test identity cannot substitute.

The user explicitly required stopping at an unresolved bundle-ID or entitlement decision.
Consequently this draft does not modify runtime code, production algorithms, entitlements,
signing architecture, workers, distribution identities or Windows behavior. It does not claim
Phase 1 complete and adds no placeholder production grant, fallback or test-only authority.

## Architecture after the decision

The preferred first-release design remains [Issue #38](https://github.com/mbzbugsy/fidomanager/issues/38):
one Team-ID-prefixed App Group container, one existing schema-1 recovery journal, and one shared
flock authority. Resolve the root with the trusted macOS API, validate actual open/access plus
ownership/mode/no-follow policy, and acquire the process-lifetime lock before recovery/UI/IPC/
worker initialization. A plausible OS-returned URL is insufficient. Missing or denied access must
fail closed without creating or choosing another root. Reuse DurableRecoveryFile/RecoveryJournal
unchanged. Both production app grant sets need the same exact group ID; workers retain their
current contracts. Unsigned development and ad-hoc fixtures remain isolated and credential-free.

Independent journals can hide unresolved incidents; independent channel locks allow concurrent
authority. The maintainer's real unresolved pre-release journal was never read, hashed, modified,
deleted, migrated, overwritten or bypassed. No production channel was launched. A separately
reviewed human-controlled transition must preserve recovery admission or remain blocked. No
general migration engine, downgrade sentinel, schema 2 or multi-incident UI is implemented.

## Coordination

Read-only PR metadata/file inventories were inspected for drafts #35 and #36. #35 modifies
`scripts/check-macos-bundle.py`, provenance and CI; #36 modifies ADR-017 and adds preflight policy.
This draft touches the ADR and this evidence document only. Their branches and PRs, PR #20, and
the release-signer repository are untouched. Once the identity decision is resolved, reconcile
the exact app-entitlement policy with their reviewed changes; retain strict worker entitlement,
publisher and exact-release checks.

## Validation status

Existing credential-free regression checks were run locally in `/private/tmp/fidomanager-g5`. They exercise the current
development/test flavors, **not an implemented G5 path**. No shared production App Group success,
shared root resolution, cross-channel journal visibility or production lock contention is claimed.

| Check | Result |
| --- | --- |
| Rust formatting; all-feature workspace Clippy with warnings denied; workspace tests; service doctests | PASS; 498 passed, 0 failed, 2 ignored; 8 doctests |
| Frontend lint/typecheck/tests/build and renderer boundary checks | PASS; 0 type errors/warnings, 45 tests, 161 boundary checker executions |
| Existing MAS.1 parser, build-only and SIP-enabled synthetic sandbox runtime | PASS; 14 parser tests, six restart cases, 21 negatives, singleton/CLOEXEC and separate-storage probe |
| Native source tests; both ad-hoc macOS packaging paths; bundle negative controls; packaged-worker health fixture | PASS; Developer ID-path app/DMG, sandbox test bundle, 33 negative bundle mutations, 1 packaged-worker test |
| Native parser/linkage/reproducibility suite (`test-libfido2.py --rebuild`) | PASS; patched/unpatched controls, system-linkage rejection and byte-identical separate-path private archive rebuilds |
| Fresh debug worker link-map and credential/PIN symbol checks | PASS; wrong-object/archive/dead-strip and hostile-link-input controls rejected; no authenticator access |

The existing MAS.1 regression report is `target/mas1-recovery/g5-regression-run.json`, from
2026-10-10 21:27 UTC, run `7bd4396f0d1f4e509a212c087403e3e0`. It is a fresh run of the unchanged
fixture in a new disposable namespace, not new G5 shared-container evidence. Production app
executables were never launched; packaged worker health checks access no authenticators.

Reproduce the current-flavor regressions without signing variables:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-targets --locked --offline
cargo test -p fido-service --doc --locked --offline
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm security:renderer-boundary
python3 scripts/test-native-deps.py
python3 scripts/test-libfido2.py --rebuild
python3 scripts/test-macos-sandbox-recovery-runner.py
python3 scripts/test-macos-sandbox-recovery.py --build-only
python3 scripts/test-macos-sandbox-recovery.py --report target/mas1-recovery/g5-regression-run.json
python3 scripts/package-macos.py --dmg
python3 scripts/test-macos-bundle-check.py 'target/macos-package/Fido Manager.app'
python3 scripts/package-macos-sandbox.py
cargo clean -p fido-worker
cargo build -p fido-worker --locked --offline
python3 scripts/test-credman-linkage.py
python3 scripts/verify-libfido2-linkage.py target/debug/fido-worker
```

As in MAS.1, the runtime negative control requires execution outside an enclosing command sandbox.
The Rust loopback tests and DMG checks also ran outside that command sandbox. Dependency caches
were reused locally; this does not claim a fresh-machine build or power-loss durability.

## Signed gates — blocked, not passed

- **Implementation:** blocked until the reviewed Team ID, exact group grant and production
  channel identity decisions above are available. Synthetic shared-root G5 tests are not added
  for an absent implementation; existing MAS.1 journal/lock tests do not substitute for them.
- **Apple-signed feasibility/distribution:** no certificate/profile/secret access. Real Apple
  Development and Developer ID group access, journal durability/visibility, cross-channel lock
  contention/restart/denials, Hardened Runtime, notarization and Gatekeeper remain unvalidated.
- **TestFlight/App Store Connect:** provisioning/entitlement acceptance, store/Developer ID
  sharing, reinstall and concurrent launches remain unvalidated. MAS.2/G4 worker authenticity
  remains an independent gate.

G5 stays OPEN. This draft is not permission to switch the maintainer's storage or publish either
production channel.
