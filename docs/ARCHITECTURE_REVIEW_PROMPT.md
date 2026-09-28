# Independent Architecture and Security Review Prompt

Use this prompt unchanged for independent reviewers so their conclusions can be compared without cross-contamination.

---

You are acting as an independent architecture and security reviewer.

Project:
FidoManager
https://github.com/mbzbugsy/fidomanager

Purpose:
A vendor-neutral desktop application for inspecting and managing FIDO2 / CTAP authenticators such as Thetis, YubiKey, Feitian and similar security keys.

The current proposed architecture uses:

- Tauri 2 for desktop shell/presentation;
- Svelte/TypeScript WebView frontend;
- Rust native backend;
- a Tauri-independent `fido-service` layer that owns sessions, workflow policy and operation outcomes;
- native PIN/UV collection and native final authorization for sensitive operations;
- one per-device worker owning the live authenticator handle and executing complete serialized transactions;
- a narrow safe Rust adapter over libfido2;
- an explicit `OutcomeUnknown` state for mutations whose completion cannot be established;
- a dedicated reset reconnect state machine;
- no backend/cloud account;
- no telemetry;
- capability/state-driven vendor-neutral behaviour;
- signed native desktop releases;
- optional future security-provider integration such as BooGooCypher, outside the core FIDO trust path.

Please review the current versions of:

- `docs/ARCHITECTURE_AND_RELEASE_PLAN.md`
- `docs/SECURITY_MODEL.md`

Do NOT simply confirm that the design is reasonable.

Act as if this application will eventually be trusted to manage real security keys containing production credentials.

The first review already identified weaknesses around renderer trust, credential-inspection authentication, uncertain mutation outcomes, reset reconnect identity, and possible Windows elevation. The documents have been revised. Your task is to determine whether those revisions are actually sufficient and to identify new or remaining weaknesses.

Review the proposal from the following perspectives:

1. Security architecture and trust boundaries
2. Threat model
3. CTAP/FIDO2 correctness
4. libfido2 API fit and known abstraction gaps
5. Rust/FFI safety
6. Tauri/WebView command attack surface
7. Native PIN/UV and consent boundary
8. PIN/UV token and secret lifetime
9. Device identification and reconnect ambiguity
10. Complete-transaction serialization and cancellation
11. Mutation `OutcomeUnknown` semantics and reconciliation
12. Credential deletion safety
13. Reset state-machine safety
14. Cross-platform USB/HID behaviour
15. macOS deployment/signing/notarization
16. Windows privilege/elevation/broker architecture
17. Linux permissions/udev/package behaviour
18. CI/CD and supply-chain security
19. Dependency and native-library management
20. Updater architecture and rollback prevention
21. Testing strategy, especially hostile-renderer and packaged-app tests
22. Long-term maintainability
23. Vendor-neutral capability/state modelling
24. Optional BooGooCypher/security-provider boundary
25. Architectural decisions that would be expensive to change later

Pay particular attention to these decisions and open questions:

A. Is keeping Tauri for presentation while moving PIN entry and final sensitive authorization to native UI a sufficiently strong boundary against a compromised renderer?

B. Does the proposed Tauri command adapter expose too much authority even with opaque handles and explicit permissions?

C. Is `fido-service` the correct owner of sessions, authorization, policy, operation reservations, reset workflow and mutation outcomes?

D. Is serializing complete transactions through a single per-device worker correct, including cancellation and external contention?

E. Is the four-state mutation model (`NotDispatched`, `Rejected`, `ConfirmedSuccessful`, `OutcomeUnknown`) sufficient? What additional recovery states or invariants are required?

F. Is the reset reconnect state machine safe when two or more identical authenticators are present and physical continuity cannot be proven cryptographically?

G. Does the domain model preserve enough RP identity information, especially RP ID hashes, to avoid libfido2 credential-management abstraction problems?

H. Should the libfido2 boundary use generated low-level bindings / a reviewed `-sys` crate plus a project-owned safe adapter, or another design?

I. Is the preliminary linking policy sound:
- bundled/static libfido2 on macOS/Windows where practical;
- system shared libraries for distro Linux packages;
- controlled bundled dependencies for portable Linux artifacts?

J. What exactly must the early Windows 11 feasibility spike establish before the process/elevation architecture is frozen?

K. Are capability support, current configuration, adapter support, OS availability, authorization requirements and application policy separated correctly?

L. Are the revised public-alpha security gates early enough, especially for credential inspection, PIN mutation, deletion and reset?

M. Is the updater design sufficient against authentic rollback, key compromise and renderer-controlled update configuration?

N. Is the optional security-provider boundary sufficient to ensure BooGooCypher cannot become part of the FIDO trust path or gain CTAP mutation authority?

O. If BooGooCypher is later used for encrypted exports, should FidoManager define a provider-independent encrypted envelope before provider-specific encryption?

P. Are OS secret stores sufficient for persistent provider API credentials, and what additional threat assumptions must be documented?

Q. Is a future `hmac-secret`-based hardware-bound export design compatible with vendor neutrality, multi-key recovery and acceptable data-loss semantics?

R. What assumptions in the revised plan remain incorrect, incomplete or insufficiently justified?

Output your review using this structure:

## Executive assessment

Give a concise assessment of the revised architecture.

State clearly whether you think read-only discovery can proceed and which later milestones, if any, should remain blocked.

## Critical issues

Problems that should block implementation of the affected workflows until resolved.

For each:
- issue
- why it matters
- realistic failure/attack scenario
- recommended change

## High-priority improvements

Important issues that should be addressed before public alpha.

## Medium/low-priority improvements

Useful hardening or maintainability improvements.

## Architecture decisions you agree with

Only include these when you can explain WHY they are sound.

## Architecture decisions you disagree with

Explain the alternative you recommend.

## CTAP/libfido2 review

Review protocol modelling, authorization, credential management, RP identity/hash handling, reset semantics and future extensibility.

## Frontend/native trust-boundary review

Review Tauri commands, native PIN/confirmation, hostile-renderer assumptions and IPC authority.

## Operation-lifecycle review

Review transaction serialization, cancellation, reconnect, uncertainty and reconciliation.

## Platform-specific concerns

Separate:
- macOS
- Windows
- Linux

## Release and supply-chain review

Review signing, packaging, native dependency pinning, CI, SBOM, provenance and updater strategy.

## Optional BooGooCypher/security-provider review

Review:
- isolation from CTAP/FIDO authority;
- provider API credential handling;
- TLS/endpoint configuration;
- data minimization and export privacy;
- offline degradation;
- provider-independent envelope design;
- future `hmac-secret` hardware-bound export risks.

Do not assume BooGooCypher is required; its optionality is an architectural requirement.

## Missing threat scenarios

Identify realistic threats or misuse cases still not addressed by the documents.

## Suggested revised architecture

If you recommend architectural changes, describe the smallest viable change to component boundaries.

## Questions for the project owner

List questions that must be answered before implementation or public mutation-capable releases.

Be specific.
Prefer concrete technical criticism over generic best practices.
Do not redesign the entire project unless there is a material security or maintainability reason to do so.
