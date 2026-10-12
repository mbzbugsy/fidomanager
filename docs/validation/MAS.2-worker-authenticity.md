# MAS.2 — release-specific worker authenticity

Status: credential-free implementation for independent review. **M1–M6, G1/G5 and G8 remain
BLOCKED** for Apple-signed/TestFlight evidence. This does not establish App Store compatibility.
Base: main `e8f4280b066c60d2fbbc580e837828317f78952c`.
[Issue #41](https://github.com/mbzbugsy/fidomanager/issues/41) is the approved architecture.

## Architecture and trust boundaries

The production worker signing identifier is
`eu.fidomanager.desktop.mas.fido-worker.<version>.<40-lower-hex-source-commit>.mas`. The sole
reviewed Team is `7VGK9SN42B`. Expected identity comes from compiled metadata and reviewed
protected-signing assignment, never a candidate worker, renderer, runtime environment or
configuration. The identifier is meaningful only when authenticated against the Apple MAS
publisher/leaf requirement and CodeDirectory Team binding. A byte marker is consistency only.

`macos-mas-signing` is a separate app/service/platform/worker feature; the app feature implies
sandbox/shared authority. The production overlay selects it. Ordinary development and both
existing ad-hoc packaging paths keep their current features, identities, grants and storage.
Cargo feature unification is checked against platform compiled flags; conflicting or mismatched
flavors reject startup, and optimized conflicting production builds cannot compile.
The public development-tool launcher constructor also refuses in production MAS builds; only
cfg(test) fixtures may deliberately use a development verifier in that flavor. Developer ID's
existing development-tool API is unchanged.

Each spawn repeats path/layout/permission checks, thin-arm64 validation, exact release/publisher
validation, CodeDirectory Team, flags and exactly `{app-sandbox:true, inherit:true}`. Static C_s
is read only after the code object passes authenticated validation and all fact checks. A private,
immutable, non-cloneable token binds C_s and the dynamic requirement to that spawn and verifier
policy. Concurrent tokens cannot overwrite one another. Dynamic verification uses the owned,
unreaped child PID and requires the same release requirement AND C_s, matching running cdhash,
grants/Team/flags and valid/kill status before ParentHello or any secret. Identity failure latches
permanently and contains the child; no retry or unsigned fallback is possible. ChildHello.build_id
is the compiled `<version>+<commit>.mas` consistency check after authentication.

The conservative initial publisher policy uses Apple's documented Mac App Store leaf OID
`1.2.840.113635.100.6.1.9` under the Apple generic anchor; Team comes from CodeDirectory rather
than Developer ID subject.OU. This is an implementation policy awaiting M1/M3 signed validation,
including a separate TestFlight acceptance decision. The conservative signature flag mask permits
runtime plus optional kill; unreviewed flags are refused until M5. No broad certificate alternative
or entitlement exception is added.

Developer ID keeps its fixed worker identifier, CA/Application OIDs, APP_REQ, authenticated sealed
release record, file digest, per-release cdhash and existing build-ID format. Its verification
algorithms are unchanged; the shared launcher API now transports a token. Windows defaults are
unchanged. The existing G5 App Group, production main IDs, schema-1 recovery and flock algorithms
are unchanged. The store-main predicate remains the G1/G5 fail-closed placeholder. The explicit
production store startup gate now stops **before App Group resolution, flock or recovery access**,
even if that placeholder unexpectedly matches. No production-channel app was launched.

## Disposable runtime evidence

The runner `scripts/test-macos-mas-worker.py` builds an ignored service libtest parent and a
health-only protocol peer. Parent identity: `eu.fidomanager.desktop.mas2authtest`, with only the
existing three MAS.0 app grants. Workers have only sandbox/inherit. No certificate, key, profile,
App Group grant, recovery API or native FIDO linkage is present. Each run creates a fresh UUID
under that dedicated sandbox container, after kernel/signature/identity/container guards.

The synthetic compile-time source label is `0123456789abcdef0123456789abcdef01234567`, clearly
not release provenance. Only libtest compiles the private ad-hoc policy (exact identifier, Team
absent, runtime/kill/adhoc flags); production retains the Apple requirement and reviewed Team.
The same immutable-token, fact-checking and production endpoint/containment code runs in the
fixture. The health-only peer handles no discovery, device, PIN or recovery operations.

The 22 scenarios cover:

- Correct release identifier accepted through dynamic verification, ParentHello and health.
- Older release, wrong flavor/commit, extra/missing/false/integer grants, missing runtime,
  unreviewed flags and a real fat arm64/x86_64 binary rejected before ParentHello.
- The production publisher policy rejecting the ad-hoc worker without fallback.
- World/group writable, symlink, directory and missing paths permanently rejected.
- Authenticated A substituted with differently signed bytes B before spawn, dynamically rejected
  before ParentHello and contained; terminal latch remains set.
- Removal after authenticated static validation causing exec refusal, also permanently latched
  before any ParentHello. This conservative MAS rule does not alter Developer ID spawn errors.
- Correctly authenticated code reporting the wrong build ID rejected after hello and contained.
- Unsigned-token substitution refused; two concurrent valid tokens accepting their own children,
  rejecting crossed hashes and a foreign verifier token, without ParentHello.

The parser requires the exact scenario set, actual admission/hello/latch/containment outcomes,
distinct authenticated C_s values, completion, and kernel sandbox/runtime/kill evidence from
both the parent and verified inherited children. It refuses missing, duplicate, mistyped or
contradictory evidence and empty/multiple-test filter results. The external runner's preparation
protocol is bounded to reviewed fixture operations and UUID paths; it is not a production API.

Initial fixture attempts genuinely failed with EPERM: sandbox-created executable copies acquired
quarantine without user consent. Fixture-filtered kernel logs identified that refusal. Preparation
and deliberate substitution now occur in the external credential-free runner, modeling external
replacement with already signed test files. No quarantine is stripped or entitlement expanded.
A subsequent run completed assertions but failed evidence parsing because manually verified
children exited before their kernel messages were captured. The test now waits for their fixture
kernel readiness while retaining owned/unreaped Child handles. These failures are not counted
as passes.

The genuinely executed report is
[`data/mas2/sandbox-worker-runtime.json`](data/mas2/sandbox-worker-runtime.json), started
**2026-10-12 22:04:32 UTC**, run **`0a1f819464874f59bd94187702f010c3`**, on arm64 macOS 26.5.2
with SIP enabled. All eight reported Rust source hashes match the committed source. Its 22
scenarios pass, including the real post-static removal/exec refusal. It records parent and
inherited-child kernel evidence, two distinct authenticated static hashes, per-case outcomes,
the unsandboxed refusal and the synthetic build label. This is ad-hoc mechanics, not Apple proof.

## Checks actually executed

Validation ran locally in `/private/tmp/fidomanager-mas2`. Frontend checks and final packaging
used Node 24.19.0 and pnpm 11.25.0 with existing installed dependencies. Native source archives
were freshly downloaded and checked against repository pins; no signing environment was used.

| Check | Result |
| --- | --- |
| Rust formatting; all-target/all-feature workspace Clippy with warnings denied | PASS |
| Workspace/all-target tests | PASS: 514 passed, 0 failed, 4 intentionally ignored |
| MAS-only service; mixed Developer ID/MAS service | PASS: 189 unit tests and 8 doctests each; 1 production-library development-constructor integration refusal per flavor |
| Service doctests separately | PASS: 8 |
| Platform-only feature unification mismatch | PASS: 1 focused test; startup rejected without resolving a worker |
| Synthetic MAS compiled build-ID controls | PASS: 2 focused platform tests |
| Typed CF inherited-worker grant parser | PASS: 1 test with exact/missing/extra/false/integer/non-dictionary controls |
| Optimized MAS without source metadata; mixed flavors with valid synthetic metadata | PASS: both compile-time refusals with expected diagnostic |
| Both production app flavors | PASS: compile only; neither signed nor launched |
| Developer ID/G5 isolation comparison against base | PASS: exact requirement-builder and macOS verifier/startup bodies unchanged; release record, recovery/lock algorithms, approved identities/grants and Developer ID overlay byte-identical |
| Frontend lint/typecheck/build/tests | PASS: 0 type errors/warnings, 45 tests |
| Renderer boundary/mutation checks | PASS: 179 checker executions |
| MAS contract/checker/evidence controls | PASS: 4 test methods; publisher/Team checker calls mocked, parser negatives fail closed |
| G5 exact policy; MAS.1 evidence parser | PASS: 4 and 14 test methods respectively |
| Both existing macOS ad-hoc packaging paths | PASS: Developer ID-path app/DMG and isolated sandbox app |
| Bundle negatives; packaged worker health | PASS: 33 mutated bundles rejected; 1 synthetic handshake/health test |
| MAS.1 fixture build-only | PASS: packaging only; recovery runtime not rerun or relabeled |
| Native input/extraction/environment/parser/linkage/reproducibility checks | PASS: patched/unpatched negative controls and byte-identical separate-path private archive rebuilds |
| Debug worker credential/PIN/deletion link-map controls | PASS: unresolved/wrong object/archive/dead-strip/hostile-link negatives rejected |
| Actual native MAS worker flavor with synthetic metadata | PASS: optimized compile and static/link-map checks, compiled `.mas` build ID found; not signed or executed |
| SIP-enabled MAS.2 sandbox runtime | PASS: 22 scenarios; original failed attempts retained in the account above |

One early standalone platform parser invocation matched zero tests because it omitted
`macos-code-signing`; it is **not counted as a pass**. The corrected feature-enabled invocation
ran the parser test. All-feature Clippy initially found legacy-only dead-code annotations and a
test-module placement issue; both were corrected and the full check passed. No blocked check is
marked PASS. `--build-only` and mocked signing/checker tests prove packaging/parser coverage only.
New-head CI status is reported on the draft PR after push, separately from these local results.

## Reproduce without credentials

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-targets --locked --offline
cargo test -p fido-service --features macos-mas-signing --locked --offline
cargo test -p fido-service --features macos-release-signing,macos-mas-signing --locked --offline
cargo test -p fido-service --doc --locked --offline
cargo test -p fido-platform --features macos-code-signing --locked --offline inherited_worker_grants
cargo check -p fidomanager-app --features macos-release-signing --locked --offline
cargo check -p fidomanager-app --features macos-mas-signing --locked --offline
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm security:renderer-boundary
python3 scripts/test-mas-worker-policy.py
python3 scripts/test-macos-authority-policy.py
python3 scripts/test-macos-sandbox-recovery-runner.py
python3 scripts/test-macos-mas-worker.py --build-only
python3 scripts/test-macos-mas-worker.py --report target/mas2-authenticity/local-run.json
python3 scripts/package-macos.py --dmg
python3 scripts/package-macos-sandbox.py
```

Process/loopback tests, DMG tooling and the unsandboxed runtime negative control need execution
outside an enclosing command sandbox. The runner itself requires arm64 macOS with SIP enabled,
refuses signing environment variables and creates only a dedicated disposable identity/container.
The release contract/checker consumes trusted version/commit inputs and never executes workers:

```sh
python3 scripts/mas-worker-policy.py --version 0.1.0 --source-commit <reviewed-full-source-commit>
# Future signed gate only; NOT executed in this credential-free implementation:
python3 scripts/check-macos-mas-worker.py <signed-app>/Contents/MacOS/fido-worker \
  --version <reviewed-version> --source-commit <reviewed-full-source-commit>
```

## Apple-dependent gates and independent review

| Gate | Status and required evidence |
| --- | --- |
| M1 | **BLOCKED:** actual Apple re-signing preserves identifier, Team, exact grants and relevant flags; inspect actual cdhash |
| M2 | **BLOCKED:** App Store Connect accepts changing per-release helper identifiers and upgrades; protected pipeline assignment/integration |
| M3 | **BLOCKED:** genuine MAS/TestFlight leaf OID(s), CodeDirectory Team semantics and explicit TestFlight acceptance decision |
| M4 | **BLOCKED:** static/dynamic Security.framework and owned-PID verification inside genuine sandbox, offline with bounded latency on supported macOS versions |
| M5 | **BLOCKED:** runtime/kill and allowed signature-flag semantics after Apple re-signing |
| M6 | **BLOCKED:** genuine signed older/wrong-team/publisher/identifier/Developer ID/ad-hoc/swap negatives before ParentHello with terminal containment |
| G1/G5 | **BLOCKED:** correct store-main predicate, exact profile-derived grants, first-launch App Group availability, real permissions/ACLs, supported OS behavior, shared journal/lock validation |
| G8 | **BLOCKED:** full TestFlight/App Store Connect runtime path |

The maintainer's existing unresolved pre-release journal was never read, hashed, modified,
migrated, cleared or bypassed by launching a new production app. Its transition remains a
separately reviewed human-controlled decision. No migration engine or new journal schema exists.
PRs #20/#35/#36 and the release-signer repository are untouched.

Independent Opus review should focus on immutable per-spawn C_s/policy provenance and concurrent
spawns; child ownership/unreaped PID and containment ordering; static-to-spawn races and thin-arm64
checks; exact CF grant types/ownership; publisher versus CodeDirectory Team binding; compile-time
feature unification and early store refusal; protected identifier assignment assumptions; and
whether fixture/checker results support precisely the claims made. Keep the PR draft; do not merge.
