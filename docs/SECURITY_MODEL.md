# FidoManager Security Model

Status: Proposed, revision 3

This document aligns with revision 3 of `ARCHITECTURE_AND_RELEASE_PLAN.md`.

Revision 3 keeps the WebView outside the trusted path for authenticator PINs and security-sensitive consent, and adds explicit contracts for immutable operation intent, sensitive-workflow concurrency, mutation evidence, crash recovery, reset timing, Windows broker authority, and export/provider separation.

## 1. Security objectives

FidoManager is intended to inspect and manage real FIDO2/CTAP authenticators without introducing unnecessary trust, persistence, privilege, or network dependencies.

The application should reduce management friction without weakening authenticator security or becoming a high-value long-lived secret store.

Primary objectives:

- keep authenticator PINs and PIN/UV authorization material out of the WebView;
- prevent renderer-controlled data from being treated as proof of human consent;
- bind sensitive approval to one immutable operation and target;
- make destructive and PIN mutations conservative under timeout/disconnect/crash;
- avoid persistent device tracking unless separately justified;
- preserve offline core operation;
- contain privileged Windows authority if elevation is required;
- prevent optional export/network features from gaining CTAP authority.

## 2. Trust boundaries

Primary trust boundaries are:

1. User ↔ native sensitive interaction
2. User ↔ WebView presentation
3. WebView ↔ Tauri command adapter
4. Tauri command adapter ↔ trusted FIDO authority
5. `fido-service` ↔ native UI controller
6. `fido-service` ↔ per-device worker
7. per-device worker ↔ `fido-libfido2`
8. libfido2 ↔ OS HID/platform transport
9. operating system ↔ physical authenticator
10. recovery journal ↔ trusted FIDO authority
11. optional Windows elevated broker ↔ unelevated client
12. trusted FIDO authority ↔ post-MVP export handoff
13. export helper ↔ optional provider endpoint
14. updater/release pipeline ↔ installed application

The desktop application must not be treated as one uniformly trusted blob.

## 3. Assets to protect

Security-sensitive assets include:

- authenticator PINs;
- PIN/UV authorization tokens;
- PIN-derived/intermediate protocol secrets;
- exact user intent for sensitive operations;
- immutable operation permits;
- credential/RP/user metadata;
- authoritative RP hashes and credential identifiers;
- session/handle generation integrity;
- mutation outcome evidence;
- recovery journal integrity;
- provider credentials/export keys when optional export exists;
- signing/release/update keys and release provenance.

Authenticator private credential keys are not expected to be exportable. FidoManager must never imply otherwise.

## 4. Threat actors and assumptions

### Compromised renderer

A compromised WebView/JavaScript environment is in scope.

It may:

- call renderer-exposed commands directly;
- reorder/duplicate requests;
- provide deceptive labels/metadata;
- flood workflow-start requests;
- attempt to navigate/open external resources;
- inspect all data deliberately rendered in JavaScript.

It must not be able to obtain PINs from the legitimate workflow or provide the application with PIN/token material through command schemas.

### Local unprivileged process

Same-user local software is in scope as a distinct actor.

Depending on OS/display system it may be able to:

- race for device access;
- synthesize input into native windows;
- attempt local IPC connections;
- inspect same-user files/secrets subject to platform controls.

Native prompts primarily remove renderer authority; they are not a universal defense against every same-user process.

### Malicious/buggy authenticator

A connected authenticator is untrusted input.

It may return malformed, deceptive, oversized, inconsistent, or unsupported protocol data.

### Compromised native dependency

libfido2 or transitive native dependencies are part of the trusted computing base and may contain memory-safety or logic vulnerabilities.

### Compromised remote provider/updater endpoint

Optional provider and update endpoints are untrusted remote peers whose compromise must not create direct CTAP authority.

### Fully compromised OS/kernel

A fully compromised OS with arbitrary process-memory/kernel control is outside FidoManager's protection goals.

## 5. Renderer authority restrictions

Renderer-callable commands must never accept fields intended for:

- PIN text;
- PIN/UV tokens;
- ECDH/shared secrets;
- provider API credentials;
- export/data keys;
- raw CTAP payloads;
- arbitrary device/library/file/executable paths.

The renderer may request high-level workflows through opaque typed handles.

Examples:

- allowed: `begin_credential_inspection(device_handle)`
- allowed: `begin_delete_credential(credential_handle)`
- prohibited: `delete_credential(device_path, credential_id, approved=true)`
- prohibited: `execute_ctap(raw_bytes)`

CI should mechanically inspect renderer-callable DTO schemas for prohibited secret-bearing fields.

## 6. Sensitive native interaction

PIN entry and security-sensitive authorization occur outside the WebView.

Native interaction must:

- derive operation descriptions from trusted backend records;
- sanitize untrusted device/RP/user strings at the native display boundary;
- attach/modally parent dialogs correctly where supported;
- run on the platform-required UI thread/event loop;
- make cancel/safe action the default;
- avoid destructive action as initial focus/default;
- enforce a brief anti-accidental-click delay for destructive approval;
- timeout and release reservations safely;
- use a single global sensitive-prompt controller.

Only one sensitive authorization workflow may be active at once.

A compromised renderer can request a workflow but cannot provide the final approval result.

## 7. Prompt flooding / consent fatigue

Prompt flooding is a renderer-level denial-of-service and consent-fatigue threat.

Mitigations:

- zero queue for authorization-gated workflows;
- one global sensitive prompt/controller;
- immediate `OperationInProgress` rejection for concurrent sensitive requests;
- cooldown/rate limits after cancellation where appropriate;
- no endless queued dialogs;
- destructive actions are not default/focused and may require stronger gestures for reset.

## 8. Immutable operation intent and approval

Human approval authorizes exactly one immutable backend-owned operation intent.

The intent binds at least:

- operation kind;
- workflow ID;
- exact device session/generation;
- exact target/credential where applicable;
- authoritative RP hash for credential deletion;
- enumeration epoch where relevant;
- exact parameters;
- expiry;
- cancellation generation;
- backend-derived human-readable description.

Approval creates a single-use `OperationPermit`.

The permit is revoked by:

- disconnect;
- generation change;
- target replacement;
- cancellation;
- expiry;
- workstation lock/session change where policy requires;
- worker restart;
- owner loss;
- relevant authorization-state change.

Permit consumption and final pre-dispatch validation are atomic from the service perspective.

A renderer-provided boolean or callback result is never accepted as proof of consent.

## 9. Authentication/PIN/UV threats

Authentication can consume retry counters even when the requested operation is read-only in intent.

Mitigations:

- query remaining PIN retry state before submission where available;
- show retry state in native UI;
- warn prominently at low remaining retry counts;
- require additional acknowledgement when only one reported retry remains;
- no automatic wrong-PIN retry;
- distinguish temporary PIN-auth blocking, permanent PIN blocking, UV blocking, and policy violations;
- do not silently set a PIN to unlock management functionality;
- inspection authorization cannot authorize a mutation at the application-policy layer.

## 10. PIN/UV token lifecycle

PIN/UV authorization is native-only.

For supported authenticators/library paths:

- acquire the minimum operation-appropriate authorization;
- prefer read-only credential-management authorization where available;
- keep authorization transaction-bounded;
- erase application-held token buffers after use;
- invalidate logically on cancel/disconnect/lock/worker restart/expiry/security-state changes;
- never persist PIN/UV tokens to disk.

If the authenticator/library lacks permission scoping, the broader fallback must be documented and must not silently grant additional application authority.

The libfido2 fit spike determines what can be enforced by the pinned release.

## 11. Secret-memory limitations

Rust zeroizing types reduce avoidable retention but do not create an absolute guarantee.

Remaining limitations include:

- native-library copies;
- OS paging;
- hibernation;
- crash dumps;
- allocator/runtime behaviour;
- unavoidable platform UI/input-method buffers.

The supported guarantee is that FidoManager does not intentionally persist or log PIN/token material and minimizes its lifetime/copies.

## 12. Device identity and continuity

Normal device sessions are anchored to one live native/OS handle owned by one worker.

AAGUID, VID/PID, product text, serial text, firmware values, and USB paths are metadata, not universal proof of physical identity.

A disconnect invalidates the normal session generation.

Persistent user-facing physical-device fingerprints are not part of MVP.

Safety/recovery comparisons may use coarse metadata but must never be presented as cryptographic identity proof.

## 13. Opaque handle safety

Renderer-visible handles must be:

- opaque;
- strongly typed;
- non-reusable;
- bound to a specific session/generation;
- bound to an enumeration epoch where applicable;
- revoked when backing state is no longer valid.

A credential handle cannot be used where a device/session handle is expected.

Execution resolves handles back to authoritative backend records immediately before sensitive intent creation/dispatch.

## 14. Single-instance ownership

MVP permits one FidoManager management instance per interactive user session.

This reduces internal races between independently owned device handles/workers.

A second application launch must not create a second management authority.

This does not prevent Chrome, browsers, vendor tools, or OS services from competing for the same authenticator.

## 15. External contention

Other FIDO clients are external actors that FidoManager cannot fully serialize.

Consequences:

- channel/device busy conditions are expected;
- enumeration can become stale/inconsistent;
- authorization state can change externally;
- external actions may explain read-back state.

The UI must distinguish complete/fresh vs incomplete/stale state and must not infer that FidoManager caused every observed state transition.

## 16. Mutation outcome evidence

The service-level outcome must be justified by adapter-level evidence.

### `NotDispatched`

Use only when the adapter can establish the mutating command could not have reached the authenticator.

### `Rejected`

Use only after a definitive rejection attributable to the mutating command.

### `ConfirmedSuccessful`

Use only after a definitive success attributable to the mutating command.

### `OutcomeUnknown`

Use whenever dispatch may have occurred but success/rejection cannot be established safely.

Transport receive failure after possible dispatch is not automatically `Rejected`.

A confirmed mutation followed by failed refresh remains `ConfirmedSuccessful` with stale/incomplete view state.

Authentication side effects such as retry-counter changes are tracked independently from mutation outcome.

## 17. Native-call quiescence

Mutation outcome and native execution state are separate.

A worker cannot be reused while a native call may still execute.

Reconciliation of visible authenticator state does not prove a blocked call has terminated.

Each native call must have an explicit deadline policy.

If safe in-process cancellation/quiescence cannot be demonstrated, mutation-capable releases require worker-process containment so a hung native call can be terminated without reusing the affected process/handle.

Terminating a worker after dispatch-capable execution produces conservative uncertainty unless stronger evidence exists.

## 18. Crash/reconnect uncertainty

A disconnect is a common cause of `OutcomeUnknown`, so session-scoped quarantine is insufficient.

Before a mutation becomes dispatch-capable, write a minimal crash-safe recovery marker.

The recovery marker intentionally does **not** become a persistent device identity database.

It contains only what is needed to establish that unresolved mutation risk exists.

On crash/restart or unresolved disconnect:

- ordinary mutations remain blocked by a recovery barrier;
- a native recovery workflow explains the uncertainty;
- reconnect/restart alone is not considered recovery;
- if physical identity cannot be established, recovery remains conservative rather than pretending a match.

## 19. Recovery journal confidentiality/integrity

The journal must not contain:

- PINs;
- tokens;
- credential secrets;
- encryption keys;
- unnecessary RP/account metadata;
- persistent identity claims.

Journal writes/removal must be atomic enough that a crash cannot silently erase a dispatch-capable marker.

A false-positive recovery barrier is preferable to a false-negative that allows an unsafe follow-up mutation.

## 20. Operation-specific reconciliation

### Delete

Re-enumeration can show that a credential is absent, but absence does not prove which actor removed it.

### Set PIN

`clientPin` metadata can support reconciliation of whether a PIN became configured, but cannot identify the value.

### Change PIN

There is no safe automatic read-back of which PIN is active. Do not test old/new values automatically.

### Reset

Post-reset state may support reconciliation, but an empty key does not prove that the intended physical authenticator was the one reset.

## 21. Reset-specific threats

Reset carries unique identity and timing hazards.

Threats:

- wrong identical key inserted after disconnect;
- second key appears during ceremony;
- approval reused for a replacement device;
- timing pressure encourages early dispatch;
- reset response lost after actual mutation;
- reset warning incorrectly implies only listed credentials are affected.

Mitigations:

- exactly one manageable FIDO key during timed reset stage;
- high-friction impact approval before disconnect/reconnect timing begins;
- candidate safety snapshot and newly opened handle/generation binding;
- no automatic same-model authorization transfer;
- no long post-reconnect confirmation dialog inside the short CTAP acceptance window;
- physical authenticator user-presence remains part of the timed ceremony;
- ambiguity/disconnect/timeout/generation change aborts the attempt;
- reset warning covers discoverable, non-discoverable, and CTAP1/U2F credentials as applicable.

The reviewed specification baseline uses a short reset acceptance window after power-up; implementation must verify the exact pinned behaviour and maintain sufficient timing margin.

## 22. RP identity / incomplete enumeration

Returned RP text is untrusted and may be absent/truncated/inconsistent.

The authoritative binary RP hash is preserved separately.

RP text is marked verified only when the exact text hashes to the authoritative hash.

If the adapter cannot enumerate credentials for a hash-only/truncated RP:

- report unsupported/incomplete enumeration;
- never show an empty list as though enumeration succeeded;
- never reconstruct a guessed RP ID.

Native deletion UI also sanitizes account/RP strings and exposes verification state where relevant.

## 23. Malicious device metadata / parser exhaustion

Threats include:

- oversized counts;
- malformed UTF-8/text;
- Unicode bidirectional/control characters;
- deceptive whitespace/confusables;
- large allocations inside native code;
- inconsistent credential counts.

Mitigations:

- native/adapter-level resource bounds where possible;
- transaction deadlines;
- output limits;
- sanitizer/normalizer for display text;
- preserve raw protocol identity separately from sanitized display text;
- malformed-count/fault-injection tests against the real adapter;
- consider worker-process containment when native allocations cannot be safely bounded.

## 24. Native UI spoofing limitations

Moving sensitive UI out of the WebView prevents JavaScript from legitimately collecting PINs or directly asserting consent.

It does not guarantee:

- protection against a compromised OS;
- protection against all accessibility/input-injection tools;
- that a malicious renderer cannot draw a visual imitation of a native dialog.

Therefore:

- no renderer command accepts PIN material;
- renderer network exfiltration is restricted;
- operation-specific native UI is consistent and clearly tied to backend state;
- native prompts use proper window modality/parenting.

## 25. Workstation lock / suspend / session switch

Lock, suspend, resume, and user-session changes may invalidate assumptions about:

- authorization lifetime;
- device handle continuity;
- native dialog ownership;
- displayed credential metadata.

Policy should clear/hide credential views and revoke active operation permits/authorization contexts on relevant lock/session events.

An active native call still must reach quiescence before its worker is reused.

## 26. Windows elevated broker

If Windows feasibility testing shows direct management requires elevation, the broker becomes the trusted authority for brokered operations.

It must own or enforce:

- FIDO session state;
- immutable operation intent;
- native operation-specific consent;
- native PIN/UV collection;
- token state;
- device worker/handle;
- permit consumption;
- mutation outcome/recovery state.

The unelevated client is a viewer/workflow starter only.

UAC approval is not FIDO-operation approval.

## 27. Broker IPC threats

Threats include:

- same-user process connects to pipe;
- replay from earlier broker launch;
- protocol downgrade/version skew;
- client dies while broker retains authority;
- alternate-user over-the-shoulder elevation;
- writable install/DLL path;
- renderer-controlled inputs proxied through valid client.

Mitigations:

- strict ACL/security descriptor;
- explicit peer/server authentication suitable for the chosen model;
- per-launch/session nonce/binding;
- replay rejection;
- typed bounded messages;
- no raw CTAP/path/library/executable commands;
- short, explicit broker lifecycle policy;
- protected signed install location;
- authoritative approval occurs in broker-owned trusted path.

## 28. macOS/Linux native process threats

On macOS/Linux, trusted FIDO policy may initially live in the native application process while the WebView remains untrusted.

This increases the importance of:

- strict Tauri command schemas;
- no remote content/arbitrary network in the renderer;
- native UI thread correctness;
- libfido2 containment/timeout behaviour;
- packaged application testing.

If hung native code or parsing risk cannot be bounded acceptably, a separate worker process becomes a release requirement.

## 29. Network posture

Core `fido-service` is network-free.

The WebView has no general-purpose HTTP authority.

Network-capable functionality is purpose-separated:

- updater;
- optional post-MVP export/provider helper.

Neither receives live CTAP handles, PIN/UV authorization, or permission to initiate authenticator mutation.

## 30. Optional export/provider threat boundary

Provider isolation is not established merely by a Rust trait or crate.

A post-MVP export helper should receive only:

- an immutable minimized export snapshot;
- approved destination/provider parameters;
- no live service reference;
- no device handle;
- no PIN/token;
- no CTAP authority.

Export approval must be bound to the exact payload/destination/provider if sensitive data leaves the machine.

The provider must not be able to return instructions that trigger FIDO workflows.

## 31. BooGooCypher-specific unresolved trust decisions

BooGooCypher remains optional and excluded from MVP builds.

Before implementation decide explicitly:

- whether BooGoo receives plaintext;
- where encryption occurs;
- whether BooGoo performs key wrapping rather than data encryption;
- provider-independent authenticated envelope format;
- recovery/provider-disappearance model;
- credential storage/scoping;
- endpoint/TLS/redirect/proxy limits;
- LAN custom CA/certificate/SPKI pinning policy;
- response/resource limits.

No invalid-certificate bypass is acceptable as a normal configuration path.

Remote plaintext encryption is a materially different privacy boundary from local encryption or remote key wrapping and must be disclosed as such.

## 32. OS secret-store limitations

OS secret stores are preferred for provider credentials but are not equivalent to a hardware security boundary.

Their protection differs by platform and login/session state.

If the platform keyring is unavailable or locked, FidoManager must not fall back to plaintext credential storage.

## 33. Updater threat model

The updater can replace the security-critical executable and is therefore part of the transitive trust chain even though it has no live CTAP authority.

Mitigations required before updater release:

- authenticated update metadata/artifacts;
- downgrade/security-floor enforcement;
- freshness/freeze strategy;
- key-rotation/compromise recovery;
- atomic install/recovery;
- no renderer-controlled update URL/key/version policy;
- no update during sensitive prompt, reset ceremony, active native execution, or unresolved recovery barrier;
- no authenticator metadata in update requests.

## 34. Supply-chain threats

Threats include:

- malicious package/build script;
- mutable GitHub Action;
- compromised native source archive;
- malicious artifact substituted between build/sign steps;
- valid signing of malicious output;
- vulnerable bundled native dependency.

Mitigations:

- lockfiles;
- pinned actions by full commit SHA;
- dependency/advisory policy for Rust/frontend/native libraries;
- source authenticity/checksum verification;
- isolated signing jobs;
- protected release environments;
- digest-bound artifact handoff;
- artifact-specific SBOM/provenance;
- native dependency patch/CVE cadence.

## 35. Logging/crash diagnostics

Release logs must not contain:

- PINs;
- tokens;
- provider credentials;
- encryption keys;
- raw secret-bearing protocol data;
- full credential IDs unless explicitly needed in controlled diagnostics;
- unnecessary account/device identifiers.

Crash/diagnostic tooling must be reviewed for sensitive-memory/data exposure before enabling collection.

## 36. Security acceptance scenarios

Before the relevant features ship, test at least:

- renderer invokes every sensitive workflow without intended UI;
- renderer floods prompt requests;
- stale/wrong-kind handle substitution;
- target changes while native PIN/approval is pending;
- disconnect after permit approval before dispatch;
- crash after dispatch before response recording;
- receive failure after possible successful mutation;
- confirmed mutation followed by failed refresh;
- reconnect with unresolved mutation uncertainty;
- application restart with recovery marker;
- cancellation followed by late native completion;
- reconciliation while native call remains blocked;
- workstation lock/suspend during PIN or approval;
- two identical keys during reset;
- second key appears during timed reset stage;
- reset candidate replacement;
- two application launches;
- external browser/vendor contention;
- malformed counts/deceptive Unicode reaching native UI;
- invalid cached authorization token;
- Windows broker replay/client death/alternate-user elevation;
- export payload or destination changes after approval.

## 37. Security claims explicitly not made

FidoManager does not claim:

- protection against a fully compromised kernel/administrator environment;
- cryptographic proof that a reconnected key is the same physical key on all authenticators;
- perfect zeroization of every copy created by OS/native dependencies;
- complete serialization against browsers/vendor tools;
- that native dialogs are universally unspoofable;
- that signed binaries are automatically trustworthy without a trustworthy build pipeline.

## 38. Open security questions

1. Which exact current libfido2 release becomes the production pin after the fit spike?
2. Is upstream RP-hash enumeration sufficient, or is an upstream contribution/product limitation needed?
3. Which native UI mechanism is used on each platform?
4. Is worker-process containment mandatory on macOS/Linux before mutation support?
5. Which Windows elevation/user models are supported?
6. What is the minimum privacy-preserving recovery-journal schema?
7. What exact reset safety snapshot can be used without implying persistent identity?
8. What BooGoo encryption/key-wrapping trust model is acceptable post-MVP?
9. What updater/signing key-recovery process can maintainers realistically support?

These questions must be resolved through spikes/ADRs before the affected capability is considered production-ready.
