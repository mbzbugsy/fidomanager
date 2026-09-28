# FidoManager Security Model

Status: Proposed, revision 2

This document aligns with the revised architecture in `ARCHITECTURE_AND_RELEASE_PLAN.md`. The most important trust decision is that the WebView is considered potentially compromised and is not trusted to handle authenticator PINs or prove user consent for sensitive operations.

## 1. Security objective

FidoManager is intended to inspect and manage real FIDO2/CTAP authenticators without introducing unnecessary trust, persistence, privilege or network dependencies.

The application should reduce management friction without weakening the security properties of the authenticator or creating a new high-value secret store.

## 2. Trust boundaries

Primary trust boundaries are:

1. User ↔ native sensitive interaction
2. User ↔ WebView presentation
3. WebView ↔ Tauri command adapter
4. Tauri command adapter ↔ `fido-service`
5. `fido-service` ↔ per-device worker
6. per-device worker ↔ `fido-libfido2`
7. libfido2 ↔ OS HID/platform transport
8. operating system ↔ physical authenticator
9. optional security-provider client ↔ provider endpoint
10. updater/release pipeline ↔ distributed application binary
11. optional Windows elevated broker ↔ unelevated application

The desktop process must not be treated as one uniformly trusted blob.

## 3. Assets to protect

FidoManager must protect:

- authenticator PINs;
- PIN/UV authorization tokens and derived values;
- exact user intent for sensitive operations;
- credential/RP/user metadata;
- authenticator identifiers where exposed;
- integrity of session/credential handles;
- integrity of mutation outcome state;
- optional provider API credentials and encryption keys;
- updater trust roots;
- application signing keys and release credentials.

FidoManager must not claim access to authenticator private credential keys. Standard FIDO private keys are expected to remain non-exportable inside authenticators.

## 4. Attacker classes

### Compromised renderer

Renderer code may invoke available Tauri commands directly, forge UI state, lie about what was displayed, replay requests and attempt target substitution.

Security requirement:

- legitimate workflows do not reveal PINs or PIN/UV tokens to JavaScript;
- JavaScript is not accepted as proof of final approval for credential deletion, PIN mutation or reset;
- renderer-supplied labels/paths are not authoritative targets;
- renderer cannot issue raw CTAP commands or choose native-library paths.

### Local unprivileged process

A separate local process may race device access, attempt broker IPC, inspect non-protected files, or manipulate environment/process state.

Mitigations include strict broker peer/session validation if a broker is introduced, trusted library locations, OS-protected secret storage and minimal local IPC surfaces.

### Malicious or malformed authenticator

A connected device may return malformed, oversized, unexpected or deceptive metadata.

Treat all device-provided strings and structures as untrusted input. Bound lengths/counts, sanitize display text, handle Unicode/control characters, and parse defensively.

### Supply-chain attacker

Dependencies, build scripts, CI actions, caches or release workflows may be compromised without directly stealing signing keys.

A correctly signed malicious build is still malicious. Release provenance and build-input trust therefore matter independently of signing.

### Compromised provider/update endpoint

Optional network-backed features introduce endpoint substitution, replay, credential theft, rollback and availability threats.

These trust paths must remain isolated from core FIDO operation authority.

## 5. Threats explicitly out of scope

FidoManager cannot protect secrets from a fully compromised OS/kernel with arbitrary process-memory access and UI control.

This exclusion does not mean all local attackers are out of scope. Unprivileged processes, compromised renderer code, malformed devices and supply-chain threats remain relevant.

Native UI is not claimed to defeat a hostile OS or universal prompt spoofing. Its purpose is to remove JavaScript from the legitimate secret/consent path.

## 6. Sensitive interaction policy

Native interaction is required for:

- PIN entry;
- PIN set/change values;
- final approval of credential deletion;
- final approval of authenticator reset;
- any future operation whose safety depends on proving deliberate user intent.

The native prompt must use backend-owned device/credential state to describe the operation.

There must be no renderer-callable equivalent of `confirm(id, true)` that constitutes authorization.

## 7. IPC and command misuse

Threats:

- forged requests;
- replay;
- stale handles;
- target substitution;
- oversized payloads;
- request flooding;
- calling sensitive commands outside intended UI flow.

Mitigations:

- explicit Tauri application-command permissions;
- framework-derived caller checks;
- opaque backend-issued handles;
- strict DTO validation;
- bounded payloads/rates;
- short-lived workflow/session state;
- one-shot backend authorization consumption;
- hostile-renderer tests for every sensitive command;
- no generic raw-command escape hatch.

## 8. PIN/UV and secret lifetime

Protected material includes PIN text, PIN/UV tokens, derived values, provider API credentials, encryption keys and any secret-bearing extension output.

Rules:

- never persist PINs or PIN/UV tokens;
- never expose them to WebView state;
- minimize native/Rust copies;
- use zeroizing owned buffers where practical;
- never log or format them into diagnostics/panics;
- reject invalid C-string input such as embedded NULs;
- explicitly expire authorization contexts;
- never automatically retry an incorrect PIN;
- do not claim a universal guarantee that sensitive bytes never reach disk because paging/hibernation/crash collection are OS-controlled.

## 9. Device identity and reconnect confusion

AAGUID, product strings, VID/PID and USB paths are not proof of physical continuity.

Normal session state is invalidated when device continuity is lost.

Reset is the exception in the sense that it may intentionally enter a reconnect ceremony, but authorization must never be transferred automatically to a same-model replacement.

If multiple candidate devices are present and continuity is ambiguous, stop and require explicit fresh selection/confirmation.

## 10. Complete transaction ownership

One per-device worker owns the live native handle and authorization context.

Authentication plus multi-step management operations form one serialized transaction.

Background polling must not interleave with stateful enumeration or mutation.

Cancellation of the caller must not silently free the worker while a native blocking call is still active.

Competing browsers/vendor tools are external actors and may still change device state; FidoManager must detect/reconcile rather than assume exclusive ownership.

## 11. Mutation outcomes

Mutation results are not binary success/failure.

At minimum:

- `NotDispatched`
- `Rejected`
- `ConfirmedSuccessful`
- `OutcomeUnknown`

`OutcomeUnknown` means the request may have reached the authenticator but completion cannot be established.

For an uncertain mutation:

- never retry automatically;
- block further mutation until reconciliation/deliberate recovery;
- communicate uncertainty clearly;
- avoid unsafe probing, especially after PIN changes.

## 12. Credential deletion

The trusted workflow must verify:

- opaque target resolves to current backend-owned state;
- the device transaction is reserved;
- native final confirmation references the correct RP/account;
- required authentication is fresh and scoped appropriately;
- approval is consumed exactly once;
- session continuity still holds immediately before dispatch.

After confirmed success, refresh state.

Users must be told that deleting a credential from the authenticator does not remove its server-side registration.

## 13. Reset

Reset is a dedicated state machine.

Security requirements:

- dedicated Danger Zone;
- native impact confirmation;
- warnings include credentials that FidoManager may not be able to enumerate;
- explicit expected disconnect/reconnect states where needed;
- fresh confirmation of the candidate reconnected device;
- stop on ambiguous multiple candidates;
- no authorization carry-over to a same-model replacement;
- explicit `OutcomeUnknown` handling;
- do not imply unrelated PIV/OTP/OpenPGP applications are reset unless separately verified.

## 14. Metadata privacy

Credential/RP/user metadata can disclose account relationships even without credential private keys.

Mitigations:

- ephemeral views by default;
- clear sensitive views on disconnect and consider clearing on workstation lock/inactivity;
- no favicon/logo fetching for RPs;
- no default logging of RP/user metadata;
- diagnostics are previewable/redacted;
- persistent device inventory requires separate privacy review.

## 15. Native library / FFI threats

Risks include pointer lifetime bugs, null/length misuse, incorrect ownership, unsafe threading assumptions and library-search hijacking.

Mitigations:

- narrow safe Rust adapter;
- opaque native types;
- RAII ownership;
- checked sizes/conversions;
- no implicit `Send`/`Sync` assumptions;
- pinned reviewed libfido2/native dependency versions;
- trusted library locations;
- no runtime native-library downloads;
- per-platform loading audit.

## 16. Windows privilege boundary

Windows direct-management requirements must be established with an early feasibility spike.

If elevation is required, the WebView/Tauri process remains unelevated.

A privileged broker, if needed, must:

- expose only fixed typed operations;
- authenticate local peer/session;
- reject arbitrary paths/raw CTAP/library requests;
- keep native authorization in the trusted path;
- run only for the minimum required lifetime/privilege.

## 17. Optional BooGooCypher/provider threat boundary

BooGooCypher is optional and outside the core FIDO trust path.

Threats include:

- provider API credential theft;
- malicious/compromised provider endpoint;
- TLS or endpoint substitution;
- redirect/proxy surprises;
- accidental export of account/device metadata;
- replay;
- availability failure;
- dependency creep that makes FIDO operations rely on the provider.

Mitigations:

- backend-only provider client;
- no provider secret in WebView;
- OS-protected secret storage;
- explicit constrained endpoint configuration;
- provider disabled by default;
- exact export payload preview/documentation;
- provider failure isolated from FIDO management;
- updater and provider trust roots kept separate.

Future hardware-bound export using `hmac-secret` requires a separate threat model covering recovery, rotation, multi-key enrollment and unrecoverability.

## 18. Network posture

Core authenticator management works offline.

The renderer has no general-purpose network capability.

Approved backend-only network uses are limited to separately reviewed modules such as:

- signed update checks;
- explicitly enabled security providers.

No authenticator metadata is sent unless the user explicitly selected it for export.

## 19. Updater threats

Risks include malicious update source, rollback to vulnerable signed versions, key compromise and renderer-controlled update configuration.

Before updater release require:

- bundled trust root;
- signed artifact/version/platform/channel binding;
- downgrade policy in Rust;
- rotation/compromise recovery;
- atomic install/interruption recovery;
- no update during active authenticator operations;
- renderer cannot control update URL/key/comparator;
- updater key separate from OS signing identities/provider credentials.

## 20. Supply-chain and release threats

Mitigations:

- lockfiles and pinned toolchains/dependencies;
- release-sensitive GitHub Actions pinned by commit SHA;
- protected release environment;
- minimal CI token permissions;
- no privileged untrusted PR workflow;
- artifact-digest verification between build/sign/publish stages;
- SBOM for actual shipped artifacts;
- provenance linking release artifacts to approved source commit;
- final checksums after artifact-changing signing/notarization steps.

## 21. Logging and diagnostics

Release logging is minimal.

Never log:

- PIN/PIN-UV tokens;
- provider API credentials;
- encryption keys;
- raw secret-bearing CTAP payloads;
- full credential IDs by default;
- authenticator serial numbers by default;
- RP/user metadata by default.

Diagnostic exports are explicit, previewable and redacted by default.

## 22. Security gates

### Before credential inspection

- native secret-input path reviewed;
- authorization lifetime/scope defined;
- transaction serialization defined;
- credential-management/RP-hash semantics verified.

### Before any public mutation

- native final authorization;
- hostile-renderer direct-command tests;
- uncertain-outcome handling;
- cancellation semantics;
- packaged-app trust-boundary tests;
- two independent authenticator implementations tested;
- platform privilege model established.

### Before reset

- reconnect ambiguity/state machine reviewed;
- sacrificial hardware tests;
- complete warnings for invisible credentials.

### Before optional provider support

- API credential storage;
- endpoint/TLS/proxy/redirect policy;
- data-minimization/export preview;
- offline degradation;
- provider cannot issue CTAP mutations.

## 23. Remaining open questions

1. Which exact native UI toolkit/pattern should implement PIN and confirmation on each OS?
2. What is the best low-level Rust binding strategy for the pinned libfido2 release?
3. Does the selected libfido2 API preserve all RP hash semantics required for complete credential enumeration?
4. What exact Windows operations require elevation, if any?
5. Is a separate worker process desirable on macOS/Linux for containment/hung-call recovery?
6. How should duplicate FidoManager instances coordinate access?
7. What supported-version/security-patch SLA can the project realistically maintain?
8. What updater trust-root and key-rotation process should be adopted?
9. If BooGooCypher ships, should FidoManager define a provider-independent encrypted export envelope?

Resolve durable decisions through ADRs rather than informal implementation choices.
