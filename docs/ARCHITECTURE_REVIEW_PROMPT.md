# Independent Architecture and Security Review Prompt

Use this prompt for independent reviewers of FidoManager revision 3.

The purpose is not to obtain agreement. Reviewers should actively attempt to invalidate the security contracts before implementation of sensitive workflows.

---

You are acting as an independent architecture and security reviewer.

Project:
FidoManager
https://github.com/mbzbugsy/fidomanager

Purpose:
A vendor-neutral desktop application for inspecting and managing FIDO2 / CTAP authenticators such as Thetis, YubiKey, Feitian and similar security keys.

## Source-control requirements

Prefer reviewing the current local checkout of `mbzbugsy/fidomanager` if you have access to it.

Before review:

1. fetch the latest remote state;
2. switch to `main`;
3. pull `origin/main` with fast-forward only;
4. verify the working tree is clean;
5. record the exact commit SHA reviewed.

Read these current files directly from the repository:

- `docs/ARCHITECTURE_AND_RELEASE_PLAN.md`
- `docs/SECURITY_MODEL.md`
- `docs/ARCHITECTURE_REVIEW_PROMPT.md`

If local repository access is unavailable, fetch the exact current `main` versions and report the commit SHA used.

Do not modify files, create branches, commits, or pull requests. This is a read-only review.

## Revision-3 architecture summary

The proposed architecture now uses:

- Tauri 2 for desktop shell/presentation;
- Svelte/TypeScript WebView frontend treated as untrusted for secrets and sensitive consent;
- Rust trusted FIDO authority;
- Tauri-independent `fido-service` as offline policy/workflow owner;
- native PIN/UV collection and native operation-specific authorization;
- one canonical per-device worker owning one live native handle;
- complete serialized transactions;
- zero queue for authorization-gated workflows;
- immutable backend-owned `OperationIntent` / single-use `OperationPermit`;
- application-managed PIN/UV authorization where supported by the selected libfido2 API;
- a formal libfido2 fit spike before credential inspection;
- authoritative RP-hash preservation and enumeration-completeness tracking;
- separate mutation outcome, native-call quiescence, and view-freshness state;
- explicit `NotDispatched`, `Rejected`, `ConfirmedSuccessful`, and `OutcomeUnknown` semantics backed by adapter-level evidence;
- a minimal crash-safe recovery journal/barrier for unresolved mutations;
- single-instance management authority per interactive user session;
- a reset ceremony with high-friction approval before the timed reconnect stage and a hard single-device invariant;
- an early Windows access/elevation spike;
- if elevation is required, authoritative FIDO policy/native approval/device execution move into the elevated broker;
- `fido-service` remains network-free;
- optional export/provider functionality lives outside core FIDO authority and is excluded from MVP builds;
- BooGooCypher remains post-MVP and its plaintext/encryption/key-wrapping trust model is intentionally unresolved pending a dedicated ADR.

## Prior review findings already addressed or reframed

Earlier reviews identified:

- renderer-controlled PIN/consent;
- credential inspection sequenced before authentication design;
- reset/reconnect identity ambiguity;
- binary success/failure semantics for uncertain mutations;
- possible Windows elevation requirements;
- native prompt flooding;
- session-scoped uncertainty disappearing on disconnect;
- unclear adapter evidence for mutation outcomes;
- network/export code sharing the FIDO policy process;
- incomplete RP-hash/libfido2 assumptions.

Revision 3 attempts to address these structurally.

Do not merely repeat the earlier findings. Determine whether the new contracts actually solve them and whether the fixes introduce new failure modes.

## Review perspectives

Review from at least these perspectives:

1. security architecture and trust boundaries;
2. threat model completeness;
3. CTAP/FIDO2 correctness;
4. current libfido2 API fit;
5. Rust/FFI safety and ownership;
6. Tauri/WebView attack surface;
7. native UI threading/modality/input-injection risks;
8. PIN/UV/token lifecycle;
9. immutable operation intent/permit design;
10. renderer prompt-flood/consent-fatigue resistance;
11. device/session identity and reconnect safety;
12. per-device worker and external contention;
13. mutation evidence and `OutcomeUnknown` correctness;
14. crash-recovery journal/barrier;
15. PIN set/change safety and retry exhaustion;
16. credential enumeration/RP-hash completeness;
17. credential deletion safety;
18. reset timing and single-device ceremony;
19. Windows broker authority and IPC;
20. macOS/Linux process and UI behaviour;
21. native-call timeout/cancellation/hung-call containment;
22. single-instance policy;
23. parser/resource-exhaustion resistance against malicious authenticators;
24. optional export/provider isolation;
25. BooGooCypher trust-model questions;
26. updater/release/supply-chain security;
27. testing strategy and missing fault-injection scenarios;
28. long-term maintainability for a small project;
29. vendor-neutral extensibility;
30. architectural choices that would be expensive to reverse later.

## Specific contracts to challenge

### A. Renderer authority

Can a compromised renderer still:

- obtain secret input;
- trick native code into authorizing a different target;
- flood/fatigue the user into approval;
- abuse navigation/custom protocols/download/network paths;
- exploit a renderer-callable DTO to smuggle sensitive material?

Is the proposed no-secret-in-command-schema invariant sufficient and testable?

### B. Native authorization

Is the `OperationIntent` / `OperationPermit` model sufficiently bound to:

- operation kind;
- device generation;
- exact credential/target;
- RP hash;
- enumeration epoch;
- expiry;
- cancellation generation;
- worker restart/disconnect/session lock?

Can a late native callback authorize stale/replaced state?

### C. Sensitive workflow concurrency

Is a global zero-queue/one-sensitive-prompt policy sufficient?

Can read-only work, cancellation, device-removal events, or external clients still produce unsafe interleavings?

### D. libfido2 fit

The design uses libfido2 1.17.0 as the reviewed API baseline, not necessarily the final production pin.

Verify whether the selected/current release actually supports the required semantics for:

- application-managed PIN/UV auth tokens;
- credential-management permissions;
- read-only credential-management authorization;
- UV-only management;
- token invalidation/expiry;
- RP-hash enumeration;
- reset;
- timeout/cancellation;
- mutation-stage evidence.

Identify where public high-level APIs collapse multiple protocol exchanges in ways that prevent safe classification.

### E. Mutation evidence

Challenge the evidence contract:

- Is `NotDispatched` defined narrowly enough?
- When can `Rejected` be asserted safely?
- Can success be distinguished from post-refresh failure?
- Are authentication side effects separate from mutation outcome?
- Are there libfido2 retry/internal behaviours that could invalidate the model?

### F. Native-call quiescence

Can a blocked/hung native call still execute after state reconciliation or cancellation?

Is in-process containment sufficient, or should mutation-capable builds require a separate worker process on all platforms?

### G. Recovery journal

Does the minimal crash-safe marker actually survive the dangerous windows without becoming a persistent device-tracking mechanism?

Can the journal itself be corrupted, rolled back, or cleared in a way that removes a needed recovery barrier?

Is a global conservative barrier preferable to weak device matching after restart?

### H. Reset ceremony

Verify the reset timing model against the current FIDO/CTAP specification and libfido2/reference hardware.

Challenge:

- confirmation before the timed reconnect stage;
- exact-one-device invariant;
- candidate safety snapshot;
- handle/generation binding;
- physical user-presence timing;
- identical-device substitution;
- expiry/retry behaviour;
- reset response loss;
- devices/versions with different reset behaviour.

Do not treat AAGUID/VID/PID/path matching as cryptographic continuity.

### I. Windows broker

If elevation is required, does placing the authoritative service/native UI/device worker in the broker close the confused-deputy problem?

Review:

- active-user vs alternate-credential elevation;
- pipe ACL/peer verification;
- per-launch binding/replay;
- client death;
- broker lifetime;
- per-machine installation;
- DLL loading;
- UAC vs operation-specific consent;
- browser/Windows WebAuthn contention;
- protocol/version skew.

### J. RP hash and completeness

Is the rule `SHA-256(returned exact RP text) == authoritative RP hash` sufficient to call text verified?

Can current libfido2 enumerate credentials when only a hash/truncated RP text is available?

Can count/completeness checks produce false confidence?

### K. Optional export / BooGooCypher

The core now passes only an immutable minimized snapshot to a separate post-MVP export helper, and provider code is excluded from MVP builds.

Challenge whether that is sufficient isolation.

Also review the still-open questions:

- where encryption occurs;
- whether a remote provider ever receives plaintext;
- provider-independent authenticated envelope;
- key wrapping vs data encryption;
- recovery if provider disappears;
- OS secret-store limitations;
- TLS/custom-CA/pinning policy;
- `hmac-secret` data-loss/provisioning coupling.

Do not assume a separate same-user process is equivalent to a security sandbox.

## Output format

Use this structure:

### Executive assessment

State whether each implementation gate can proceed:

- Milestone 1 read-only discovery
- Milestone 1.5 feasibility spikes
- Milestone 2 native authentication
- Milestone 3 credential inspection
- Milestones 4–6 mutations
- Windows implementation
- post-MVP export/provider work

### Former blocker status

For each relevant prior blocker, classify:

- Resolved
- Partially resolved
- Unresolved
- Regressed

Explain the exact remaining gap and any new risk introduced by the fix.

### New critical issues

For each:

- issue;
- why it matters;
- realistic failure/attack scenario;
- recommended architectural change.

### High-priority improvements

Issues to resolve before the affected feature or public alpha.

### Medium/low-priority improvements

Hardening and maintainability improvements.

### Cross-document contradictions

Identify inconsistent requirements between the architecture plan and security model.

### CTAP/libfido2 review

Be specific about APIs/protocol semantics that support or contradict the design.

### Operation lifecycle review

Review intent → approval → auth → dispatch → response → refresh/reconciliation → recovery.

### Platform-specific review

Separate:

- macOS
- Windows
- Linux

### Release/supply-chain review

Review native dependencies, CI, signing, provenance, SBOM, updater, and urgent patch delivery.

### Optional export/BooGoo review

Assess whether the proposed boundary is genuinely outside core FIDO authority and list unresolved trust decisions.

### Missing threat/acceptance scenarios

List concrete tests or failure cases not yet covered.

### Suggested revised architecture

Only if material changes are still required. Do not redesign the whole project merely for stylistic preference.

### Questions for the project owner

Ask only questions whose answers materially affect implementation/security contracts.

Be specific, skeptical, and technically concrete.

Treat this review as a security design gate for software that may eventually manage production authenticators.
