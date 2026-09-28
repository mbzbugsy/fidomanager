# FidoManager Architecture and Release Plan

Status: Proposed, revision 3  
Target: Pre-implementation architecture and security gate  
Repository: `mbzbugsy/fidomanager`

Revision 3 incorporates the converging findings from three independent reviews of revision 2. The core stack remains Tauri + Rust + libfido2, but the security contracts are now more explicit around consent, authorization, device ownership, mutation evidence, crash recovery, reset timing, Windows privilege separation, and optional export/network code.

The principal revision-3 decisions are:

- the WebView remains untrusted for PINs and security-sensitive consent;
- sensitive workflows use immutable backend-owned operation intents/permits;
- authorization-gated workflows are never queued behind one another;
- only one FidoManager instance may own device-management state per user session;
- mutation outcome, native-call quiescence, and view freshness are separate concepts;
- uncertain mutations survive disconnect and process restart through a minimal crash-safe recovery journal;
- adapter-level evidence rules determine `NotDispatched`, `Rejected`, `ConfirmedSuccessful`, and `OutcomeUnknown`;
- reset confirmation occurs before the timed reconnect stage, with a hard single-device invariant during the reset ceremony;
- libfido2 capability/fit verification is a formal gate before credential inspection;
- if Windows requires elevation, the elevated broker owns authoritative FIDO policy, native authorization, device handles, tokens, and outcomes;
- export/provider code is moved out of `fido-service` and out of the core FIDO process where practical;
- BooGooCypher remains optional, post-MVP, and excluded from MVP builds.

## 1. Purpose

FidoManager is a local, vendor-neutral desktop application for inspecting and managing FIDO2 / CTAP authenticators such as Thetis, YubiKey, Feitian and similar security keys.

The application addresses a practical gap between vendor-specific management tools, limited browser management UIs, and powerful but low-level CLI tooling.

The application must not infer support from vendor identity. Behaviour should be driven by:

1. authenticator-advertised capabilities;
2. current authenticator configuration;
3. selected libfido2/adapter support;
4. OS/transport availability;
5. current authentication/authorization requirements;
6. application policy.

## 2. Core principles

### Local first

Core authenticator management must work offline and must not require an account, cloud service, telemetry, analytics, or remote configuration.

Authenticator information may leave the machine only when the user explicitly selects data for a documented export or other separately reviewed network-backed feature.

### Vendor neutrality

Core logic depends on CTAP/FIDO semantics, not manufacturer checks.

Evidence-backed compatibility workarounds may exist behind a narrow compatibility layer, but vendor identity must not become the normal dispatch mechanism.

### Capability-driven, state-aware behaviour

A single `supportsX` boolean is not sufficient for security-sensitive features.

The UI and service layer must distinguish:

- advertised support;
- current configuration;
- adapter/library support;
- platform availability;
- authorization requirements;
- application policy;
- known/unknown completeness of the current view.

Unknown CTAP versions and option strings are preserved for diagnostics but do not automatically enable operations.

### Explicit trust boundaries

The Svelte/WebView renderer is presentation-only for sensitive workflows.

A compromised renderer is in scope. It must not be able to:

- obtain authenticator PINs through the legitimate workflow;
- provide the application with PIN text through any Tauri command schema;
- manufacture proof of user consent for deletion, PIN mutation, reset, or sensitive export;
- submit arbitrary device paths or raw CTAP commands;
- choose native library paths;
- gain general shell, filesystem, HID/USB, or network authority.

### Safe failure and explicit uncertainty

A timeout, cancellation request, process interruption, or disconnect after a mutation may have been dispatched is not equivalent to failure.

The application prefers conservative uncertainty over false certainty.

### Minimal privilege

The WebView never receives direct HID/USB access.

Privileged access, if required by a platform, must live behind the smallest practical trusted native boundary. The Tauri/WebView process must not be elevated merely to gain authenticator access.

### Transparent security

Security-sensitive contracts, release provenance, secret handling, mutation semantics, and platform-specific privilege boundaries are documented for independent review.

## 3. Proposed technology stack

### Desktop shell

- Tauri 2
- Svelte
- TypeScript
- pnpm

Tauri is retained for packaging and presentation. It is not the security policy layer.

### Native implementation

- Rust stable
- libfido2 through a narrow project-owned safe adapter over reviewed low-level bindings

Rust owns the trusted policy and device-management path.

### libfido2 policy

Do not reimplement CTAP framing, HID transport, or CBOR without a compelling reason.

The adapter must preserve:

- opaque native types;
- RAII ownership;
- checked lengths/counts/nullability;
- native error context needed for conservative outcome classification;
- explicit timeout/cancellation semantics;
- a pinned and documented ABI/version policy.

A libfido2 fit spike is mandatory before credential-management implementation. Revision 3 uses libfido2 1.17.0 as the reviewed baseline because its application-managed PIN/UV-token APIs are relevant to the design; the production pin may be a later reviewed release.

## 4. Proposed repository structure

```text
fidomanager/
├── src/                              # Svelte/WebView presentation
│   ├── components/
│   ├── pages/
│   ├── stores/
│   └── lib/
├── src-tauri/
│   ├── src/
│   │   ├── main.rs
│   │   ├── commands/                 # narrow workflow-start adapter
│   │   └── state.rs
│   ├── capabilities/
│   └── tauri.conf.json
├── crates/
│   ├── fido-core/                    # platform-independent model/contracts
│   ├── fido-service/                 # offline policy/workflows/sessions/outcomes
│   ├── fido-native-ui/               # native PIN + operation-specific consent
│   ├── fido-libfido2/                # safe adapter + low-level bindings
│   ├── fido-platform/                # platform integration / broker protocol
│   └── fido-export/                  # post-MVP export helper contracts
├── helpers/
│   └── fido-export-helper/           # optional separate process, post-MVP
├── tests/
├── docs/
│   ├── ARCHITECTURE_AND_RELEASE_PLAN.md
│   ├── SECURITY_MODEL.md
│   ├── ARCHITECTURE_REVIEW_PROMPT.md
│   ├── DEVICE_COMPATIBILITY.md
│   └── adr/
├── .github/workflows/
├── README.md
├── LICENSE
└── THIRD_PARTY_NOTICES.md
```

The exact crate split may change after prototypes. The trust boundaries must not silently collapse when code is reorganized.

## 5. Logical architecture

```text
Svelte / WebView
      │
      │ typed workflow requests + sanitized DTOs
      ▼
Tauri command adapter
      │
      │ caller checks, schema validation, size/rate limits
      ▼
Trusted FIDO authority
      │
      ├── fido-service
      │     ├── session/handle registry
      │     ├── policy engine
      │     ├── operation reservations
      │     ├── immutable operation intents/permits
      │     ├── mutation outcome + recovery state
      │     └── reset state machine
      │
      ├── fido-native-ui
      │     ├── native PIN/UV interaction
      │     └── operation-specific authorization
      │
      └── per-device worker
            │
            ▼
        fido-libfido2
            │
            ▼
      OS HID / platform transport
            │
            ▼
       Authenticator
```

The **Trusted FIDO authority** is a logical boundary.

Initial process placement:

- macOS/Linux: it may live in the application's native Rust process, subject to the worker-containment gate below;
- Windows: if direct management requires elevation, the trusted authority moves into the elevated broker rather than leaving policy/consent in the unelevated Tauri process.

Optional export/provider code sits outside this authority.

## 6. Domain model: `fido-core`

`fido-core` must not depend on Tauri, libfido2, USB/HID, network clients, or BooGooCypher.

Expected concepts include:

- `DeviceSessionId`
- `DeviceGeneration`
- `DeviceSnapshot`
- `DeviceHandle`
- `CredentialHandle`
- `EnumerationEpoch`
- `RelyingPartyHash`
- `CredentialMetadata`
- `CapabilityState`
- `AuthorizationRequirement`
- `AuthorizationContext`
- `OperationIntent`
- `OperationPermit`
- `MutationOutcome`
- `ExecutionQuiescence`
- `ViewFreshness`
- structured recovery actions
- stable application error types

Opaque handles must be typed, non-reusable, session/generation-bound, and invalidated when their owning state becomes stale.

## 7. `fido-service`: offline policy owner

`fido-service` owns security-relevant FIDO workflows independently of Tauri.

Responsibilities:

- device-session lifecycle;
- canonical per-device worker registry;
- opaque handle issuance/resolution;
- per-device operation reservation;
- authorization lifetime/scope policy;
- native interaction requests;
- immutable operation intents/permits;
- complete transaction boundaries;
- cancellation and timeout semantics;
- mutation outcome classification;
- recovery barriers/journal interpretation;
- reset reconnect ceremony;
- platform-independent policy decisions.

`fido-service` must remain network-free.

It must not own:

- BooGooCypher HTTP/TLS;
- updater HTTP/TLS;
- generic export transport;
- arbitrary filesystem/network clients.

## 8. Tauri command boundary

Tauri commands are workflow starters and DTO translators, not security authority.

Rules:

- explicit application-command permission manifest;
- explicitly selected production capability files;
- framework-derived caller context checks;
- opaque typed handles only;
- bounded request sizes and rates;
- no generic `execute_ctap`, `open_device(path)`, `load_library`, shell, arbitrary filesystem, or arbitrary HTTP commands;
- no PIN/UV-token/encryption-key fields in any renderer-callable command schema;
- stale/wrong-kind handles rejected before workflow creation;
- hostile-renderer tests call every sensitive command directly without its intended UI.

A build-time/CI schema check should fail if a renderer-callable DTO introduces fields intended for PINs, PIN/UV tokens, provider credentials, private key material, or other secrets.

## 9. Native sensitive interaction

Sensitive interaction occurs outside the WebView.

Native UI is required for:

- authenticator PIN entry;
- PIN set/change input;
- credential-deletion authorization;
- reset impact authorization;
- any future sensitive export whose security property depends on deliberate user selection/consent.

The native layer must:

- render text from backend-owned state;
- sanitize untrusted authenticator/RP/user text itself;
- be parented/modally associated with the application window where the platform supports it;
- run on the platform's required UI thread/event-loop mechanism;
- use Cancel as the safe/default action;
- avoid destructive actions as the initially focused/default button;
- enforce a brief anti-accidental-click activation delay for destructive actions;
- timeout rather than reserve a worker indefinitely;
- be controlled by one global sensitive-prompt controller.

The renderer may request a sensitive workflow. It cannot create unlimited simultaneous prompts.

At most one authorization-gated native workflow may be active globally in the application authority at a time. Additional requests fail immediately with `OperationInProgress`.

Where practical, combine the exact operation description and required PIN/authentication into one native interaction rather than separate generic prompts.

The security claim remains narrow:

> The legitimate sensitive workflow does not expose PINs to JavaScript and does not treat JavaScript as evidence of user consent.

This does not claim protection against a fully compromised OS or all same-user input-injection mechanisms.

## 10. Single-instance and ownership policy

For MVP, exactly one FidoManager management instance may own device-management state per interactive user session.

A second launch should focus/activate the first instance or exit cleanly.

Any arguments/URLs delivered by a second-launch mechanism are untrusted input.

Single-instance enforcement does not serialize browsers, vendor tools, or other external FIDO clients; those remain external actors.

## 11. Authentication and authorization model

Separate:

1. user authentication to the authenticator (PIN or built-in UV);
2. authenticator-issued PIN/UV authorization token state;
3. application-level user consent for a specific operation;
4. PIN set/change as a mutation.

A credential-management authorization token is **not** consent to delete a credential.

Rules:

- never automatically retry a wrong PIN;
- query PIN retry state before PIN submission where available;
- display remaining retries in the native prompt;
- show a prominent low-retry warning when the reported count is low;
- when only one reported retry remains, require an additional explicit acknowledgement before submission;
- distinguish temporary auth blocking from permanent PIN blocking and from UV blocking;
- do not silently set a PIN to make management features available;
- fresh application-level approval is required for each mutation;
- authorization collected for inspection cannot authorize deletion or PIN mutation.

## 12. libfido2 fit spike — gate before credential inspection

Before Milestone 2 completes, run an empirical fit spike against the selected libfido2 baseline and representative hardware.

The spike must determine:

- application-managed PIN/UV-token behaviour;
- permission-scoped credential-management authorization;
- read-only credential-management authorization where supported;
- UV-only credential-management behaviour;
- token lifetime/expiry/invalidation semantics;
- what happens when an invalid cached token remains attached to a device object;
- CTAP 2.0 fallback behaviour where permission scoping is unavailable;
- RP-hash vs RP-text enumeration support;
- timeout/cancellation behaviour;
- reset behaviour/timing on reference devices;
- error information sufficient for mutation evidence classification.

The reviewed 1.17.0 API baseline includes application-managed PIN/UV-token support and credential-management token categories. The spike must validate how those APIs behave in the exact workflows FidoManager needs rather than assuming the abstraction is sufficient from signatures alone.

For each required behaviour, record one of:

- supported by pinned upstream API;
- supported only through a reviewed lower-level path;
- requires upstream work;
- unsupported product limitation.

Do not silently replace scoped authorization with a broader long-lived PIN buffer.

## 13. Secret handling

Protected material includes more than PIN text:

- PIN input;
- PIN/UV tokens;
- PIN-derived values;
- ECDH/intermediate protocol secrets;
- provider API credentials;
- export/data keys;
- secret-bearing CTAP extension output.

Rules:

- secrets never cross into renderer DTOs;
- PINs and PIN/UV tokens are never persisted;
- use owned zeroizing buffers where practical;
- minimize copies and conversions;
- reject embedded NULs before C-string boundaries;
- erase authorization buffers as soon as native code no longer borrows them;
- never include secrets in logs, traces, panic text, crash annotations, or diagnostics;
- document that paging, hibernation, crash dumps, and native-library internals prevent an absolute guarantee that bytes never reach storage.

## 14. Device identity and session continuity

Default device identity remains ephemeral.

AAGUID, product strings, VID/PID, serial text, firmware metadata, and USB location/path may aid safety checks but are not universal cryptographic proof that a reconnected authenticator is the same physical object.

Normal session continuity is anchored to one live OS/native device handle owned by one worker.

A device removal/handle failure invalidates that session generation.

Persistent user-facing device fingerprints are not introduced for MVP.

Safety/recovery metadata must not be presented as proof of identity.

## 15. Canonical per-device worker model

One worker owns one live native handle and the associated authorization context.

Complete transactions are serialized, not individual libfido2 calls.

Example:

```text
credential inspection
  reserve worker
  → collect PIN/UV natively
  → acquire minimum supported authorization
  → enumerate RPs/credentials
  → release/erase authorization
  → publish sanitized snapshot
```

Rules:

- no background polling inside a stateful transaction;
- every native call has an explicit deadline/timeout policy;
- cancellation of an async caller does not imply cancellation of native execution;
- worker reuse requires proven native-call quiescence;
- reconciliation of device state does not by itself prove a blocked native call has stopped;
- external client contention maps to a structured `DeviceBusy`/contention condition where possible;
- interrupted enumeration is marked incomplete rather than silently reused.

If in-process timeout/cancellation cannot provide safe hung-call recovery, a separate killable worker process becomes mandatory before mutation-capable public builds.

## 16. Sensitive workflow concurrency: zero queue

Authorization-gated or mutation workflows are **not queued**.

If any sensitive prompt, sensitive operation reservation, or mutation transaction is active, another sensitive workflow request fails immediately with `OperationInProgress`.

This applies to:

- credential deletion;
- PIN set/change;
- reset;
- sensitive export approval;
- future security-critical management operations.

Read-only background refresh must not interleave with a stateful/sensitive transaction.

## 17. Immutable operation intent and permit

Every security-sensitive operation is represented by an immutable backend-owned `OperationIntent`.

At minimum it binds:

- operation kind;
- workflow ID;
- device session/generation;
- worker/handle generation;
- exact target object;
- enumeration epoch where applicable;
- exact credential ID for deletion;
- authoritative RP hash where applicable;
- operation parameters;
- creation/expiry time;
- cancellation generation;
- human-readable description derived from the same backend record.

Native approval produces an `OperationPermit` bound to that exact intent.

A permit:

- is single-use;
- is short-lived;
- cannot be retargeted;
- is consumed atomically with final pre-dispatch validation;
- is revoked by disconnect, target replacement, cancellation, lock/suspend, expiry, owner loss, relevant authorization-state change, or worker restart.

A changed target or changed device generation requires a new native prompt.

## 18. Mutation execution evidence contract

The service-level mutation outcome must be justified by adapter-level evidence.

### Mutation outcomes

| Outcome | Required meaning |
| --- | --- |
| `NotDispatched` | The adapter can establish that the mutating command could not have reached the authenticator. |
| `Rejected` | A definitive rejection attributable to the mutating command was received. |
| `ConfirmedSuccessful` | A definitive success response attributable to the mutating command was received. |
| `OutcomeUnknown` | Dispatch may have occurred but the result cannot be established safely. |

Rules:

- entering a high-level mutating libfido2 call is **not** automatically evidence of dispatch or rejection;
- if the library cannot expose enough phase information, classify conservatively;
- a receive/transport failure after dispatch may be `OutcomeUnknown`;
- a confirmed mutation stays `ConfirmedSuccessful` even if post-operation refresh fails;
- authentication side effects such as retry-counter changes are tracked separately from mutation outcome;
- no mutation is automatically retried after `OutcomeUnknown`.

### Separate lifecycle dimensions

Do not overload mutation outcome with other state.

Track independently:

- `ExecutionQuiescence`: active vs definitively stopped;
- `ViewFreshness`: fresh vs stale/incomplete;
- cancellation request/acknowledgement state.

A worker is reusable only after native execution is quiescent, even if device-state reconciliation has already occurred.

## 19. Crash-safe uncertainty and recovery journal

`OutcomeUnknown` must survive disconnect and process restart.

Before a mutation can enter the dispatch-capable phase, FidoManager writes a minimal crash-safe recovery marker.

The marker must not contain:

- PINs;
- PIN/UV tokens;
- credential secrets;
- export keys;
- unnecessary account metadata;
- a claim of persistent physical-device identity.

Minimum persisted recovery information may include:

- operation class;
- timestamp;
- application version/schema version;
- opaque incident ID;
- whether dispatch-capable execution had begun;
- privacy-minimized/coarse device context only if required for safe recovery.

On clean definitive `Rejected` or `ConfirmedSuccessful`, the marker is resolved/removed atomically.

If the process crashes or loses the device while the marker remains, the next launch enters a **recovery barrier** before further mutations.

Default recovery is conservative and may be global rather than pretending to identify a physical key after restart.

A deliberate native recovery workflow explains the uncertainty and the safe next actions. Restarting the application, reconnecting a key, or reopening a page is not itself recovery.

## 20. Reconciliation policy by mutation

Reconciliation differs by operation and must be documented/tested.

### Credential deletion

- re-enumerate if supported;
- absence may indicate deletion succeeded, but does not prove which actor changed state;
- confirmed deletion plus failed refresh remains confirmed with stale view.

### Set PIN

- `clientPin` state may provide strong evidence that a PIN is now configured;
- do not infer the exact PIN value from metadata.

### Change PIN

- no non-destructive read-back proves whether old or new PIN is active;
- never automatically test both values;
- show remaining retries before any deliberate verification attempt.

### Reset

- post-reset metadata/credential state may support reconciliation;
- an apparently empty key is not proof that the intended physical key was reset;
- lost response after possible dispatch remains uncertain unless stronger evidence exists.

## 21. Credential-management data and RP identity

Preserve at least:

- authoritative RP ID hash;
- optional returned RP ID text;
- optional display name;
- validation/completeness status;
- exact credential identifier for internal execution;
- sanitized display form separately from raw protocol identity.

If RP text is present, mark it verified only when hashing the exact text produces the authoritative RP hash.

If text is absent, truncated, invalid, or does not match the hash:

- do not reconstruct a guessed RP ID;
- label the text as unavailable/unverified;
- display the hash where needed for safe native confirmation;
- do not report an empty credential set merely because text-based enumeration cannot continue.

Where available, compare authenticator-reported resident-credential metadata/counts with enumerated results. Any shortfall is visibly incomplete.

Before choosing a project patch/fork, prefer a current upstream hash-based API if available or pursue an upstream addition.

## 22. Credential inspection workflow

Credential inspection is read-only in intent but security-sensitive because it may require PIN/UV authorization and reveal account metadata.

Workflow:

1. reserve the worker;
2. query/display relevant PIN/UV retry state where available;
3. collect authentication natively;
4. acquire the minimum supported credential-management authorization;
5. enumerate within a bounded transaction/deadline;
6. detect incomplete enumeration;
7. erase/revoke application-held authorization state;
8. publish only sanitized metadata to the renderer;
9. clear/lock sensitive views on disconnect, workstation lock, session switch, or other policy event.

The libfido2 fit spike determines exact token/UV behaviour.

## 23. PIN set/change workflow

PIN mutation is a sensitive mutation.

Requirements:

- native UI only;
- backend-built operation intent;
- exact device/session binding;
- retry count shown before submission when available;
- no automatic retry;
- fresh approval for every mutation;
- single-use permit;
- crash-safe pre-dispatch recovery marker;
- conservative `OutcomeUnknown` handling;
- no automatic old/new PIN probing after uncertainty.

Native PIN dialogs themselves can serve as final authorization when they display the exact target device and operation and require an explicit action button; avoid redundant generic confirmation dialogs.

## 24. Credential deletion workflow

Deletion uses an immutable operation intent bound to:

- exact device generation;
- exact credential ID;
- authoritative RP hash;
- backend-owned account/RP display data;
- enumeration epoch/current target validation.

Native confirmation explains:

- the credential on the authenticator will be deleted;
- deletion does not remove the registration from the remote website/service;
- account enumeration may be incomplete;
- no automatic retry follows uncertainty.

The permit is consumed only after final target/session validation.

## 25. Reset ceremony

Reset is a dedicated high-risk state machine.

The reviewed CTAP reset baseline imposes a short power-up acceptance window (10 seconds in the reviewed specification baseline for the timed reset ceremony). The implementation must verify the selected spec/library/device behaviour and budget the ceremony accordingly.

### Reset invariants

- exactly one manageable FIDO authenticator may be connected during the timed disconnect/reconnect/reset phase;
- any second candidate appearing aborts the ceremony;
- all high-friction impact confirmation occurs **before** the timed reconnect stage;
- no authorization/approval is silently transferred to a same-model replacement;
- FidoManager never claims cryptographic continuity unless a protocol feature actually provides it;
- a candidate metadata match is a safety check, not proof of identity;
- the user is warned that reset destroys FIDO credentials including credentials the app cannot enumerate;
- the operation is described as a FIDO reset and does not imply PIV/OTP/OpenPGP reset.

### Proposed reset state machine

```text
Idle
→ PreparingReset
→ AwaitingImpactConfirmation
→ AwaitingExpectedDisconnect
→ AwaitingSingleCandidateReconnect
→ CandidateVerifiedForTimedAttempt
→ ExecutingReset
→ ConfirmedSuccessful / Rejected / OutcomeUnknown
```

`AwaitingImpactConfirmation` is a native high-friction step; for example, typing a reset phrase is acceptable.

Before disconnect, record a non-authoritative safety snapshot of available device/topology metadata and, where supported, use a physical-identification cue such as wink/touch-to-select.

After reconnect:

- require exactly one candidate;
- compare the candidate with the safety snapshot as far as supported;
- bind the timed attempt to the newly opened candidate handle/generation;
- do not present a long human-reading dialog that consumes the reset window;
- dispatch only within the verified timed attempt;
- rely on the authenticator's required physical user-presence gesture as the final real-time hardware interaction;
- another disconnect, ambiguity, timeout, cancellation, or generation change aborts the attempt.

If the timing window expires, return a definitive `Rejected`/restart-required result when the protocol provides such evidence; the user must repeat the timed stage under the same pre-approved impact intent only if policy explicitly allows that intent to remain valid and no device/target state changed. Otherwise require new approval.

## 26. Platform process placement

### macOS

Initial development target:

- Apple Silicon macOS;
- roaming USB FIDO authenticator;
- trusted Rust authority in the native app process unless worker-containment testing requires a helper process.

Native sensitive UI must use AppKit-compatible main-thread/event-loop dispatch and proper window modality.

### Linux

Initial targets:

- Ubuntu LTS;
- Fedora;
- X11 and Wayland behaviour explicitly tested.

Do not run the GUI as root. Distinguish `AccessDenied` from `DeviceAbsent` and document safe udev/active-session access rules.

### Windows

Windows is a separate process-boundary gate because direct FIDO management may require elevation.

The Windows feasibility spike must cover:

- enumeration vs open/getInfo when unelevated;
- credential management;
- PIN set/change;
- reset;
- standard-user + alternate-credential/UAC elevation;
- browser/Windows WebAuthn contention;
- broker lifetime;
- protected install location;
- x64 and any intended ARM64 support;
- SmartScreen/Smart App Control/WDAC behaviour;
- clean broker/client failure recovery.

## 27. Windows elevated broker contract

If elevation is required, the unelevated Tauri/WebView process is not the authoritative FIDO security process.

The elevated broker must own or independently enforce:

- device session/handle ownership;
- `fido-service` policy state for brokered operations;
- immutable operation intent;
- native PIN entry;
- native final authorization;
- PIN/UV authorization context;
- worker/device execution;
- permit consumption;
- mutation outcome and uncertainty state.

The broker must not accept client assertions such as `approved=true`.

IPC must use:

- a fixed typed protocol;
- protocol/version negotiation;
- per-launch/session binding;
- replay protection;
- strict Windows security descriptors/peer validation;
- client-death handling;
- bounded payloads/timeouts;
- no raw CTAP, device paths, library paths, executable paths, or arbitrary filesystem/network instructions.

The broker runs in the active interactive context required for native operation-specific UI. UAC consent is not consent to a particular FIDO mutation.

The broker executable and private libraries must be installed in administrator-protected locations and signed.

## 28. libfido2 and native supply chain

Do not download native libraries at application runtime.

Requirements:

- pin an approved libfido2 release;
- verify source authenticity/checksums/provenance as available;
- record exact build configuration;
- track libcbor/OpenSSL/zlib/udev and other bundled native dependencies;
- audit build scripts/compiler flags/features;
- disable unneeded transports/features where practical;
- document static vs dynamic linking per artifact;
- preserve third-party notices;
- maintain a patch/CVE policy for bundled native dependencies.

Users should not need Homebrew or a separate system package on macOS/Windows releases.

Linux distro packages may use controlled system dependencies with explicit minimum versions where that is the safer maintenance trade-off.

## 29. Testing strategy

### Domain/service tests

Test:

- handle typing/generation/epoch invalidation;
- immutable intent/permit binding;
- permit expiry/revocation/one-shot consumption;
- sensitive zero-queue behaviour;
- capability/configuration/availability separation;
- recovery barriers/journal state;
- reset transition guards;
- operation-specific reconciliation.

### Adapter/FFI tests

Test:

- ownership/free ordering;
- nullability;
- counts/lengths/conversions;
- malformed strings/control characters;
- embedded NUL rejection;
- token attachment/invalidation;
- timeout/cancellation;
- fault injection before/around/after mutating calls;
- outcome evidence mapping;
- native resource exhaustion/malformed-count handling where possible.

### Hostile renderer tests

Test direct invocation of sensitive commands for:

- prompt flooding;
- stale/wrong-kind handles;
- duplicated/reordered requests;
- attempting to supply target metadata;
- attempts to supply secret-looking fields;
- navigation/subframe/custom-protocol/external-URL paths;
- download/network escape paths.

### Packaged application tests

Browser-only Playwright tests are insufficient.

Test final packaged binaries for:

- real IPC permissions;
- native prompt modality/threading;
- sleep/wake/lock/session switch;
- rapid replug;
- hubs;
- two identical keys;
- competing browser/vendor clients;
- clean machine launch;
- library loading paths;
- signing/notarization/quarantine behaviour.

### Mutation failure scenarios

Mandatory scenarios include:

- crash after dispatch before response recording;
- disconnect followed by a fresh session while uncertainty exists;
- cancellation followed by a late success response;
- reconciliation while the original native call is still blocked;
- two application instances racing;
- two simultaneous native workflow requests;
- reset candidate replacement;
- failed post-refresh after confirmed mutation;
- invalid cached authorization token on reused native handle.

Use sacrificial test authenticators only for destructive automated/manual testing.

## 30. Compatibility matrix

Maintain `docs/DEVICE_COMPATIBILITY.md`.

Track at least:

- exact device/model/firmware;
- OS/version/architecture;
- discovery/GetInfo;
- PIN/UV mode;
- credential management;
- RP enumeration completeness;
- deletion;
- reset ceremony/timing;
- known limitations/workarounds.

Before a mutation-capable public alpha, validate at least two independent authenticator implementations.

## 31. Optional export architecture

Export is separate from the FIDO policy engine.

`fido-service` may produce a sanitized immutable `ExportSnapshot` only after the relevant device transaction has ended.

A post-MVP export flow is:

```text
Trusted FIDO authority
      │
      │ immutable minimized ExportSnapshot
      │ no PIN / PUAT / live handle / service reference
      ▼
Trusted export approval
      │ exact payload summary + destination/provider binding
      ▼
fido-export helper process
      │
      ├── local export implementation
      └── optional provider transport
            └── BooGooCypher
```

The export helper:

- has no CTAP authority;
- has no device handle;
- has no PIN/PUAT;
- cannot call back into FIDO workflows;
- receives only the approved snapshot and export parameters;
- returns status/result references, not executable instructions.

Provider support is excluded from MVP builds at build time, not merely disabled with a runtime flag.

## 32. BooGooCypher status

BooGooCypher remains a possible post-MVP provider for protected exports.

It is not required for ordinary FIDO management.

Before any BooGoo support ships, a dedicated ADR must define:

- whether provider code ever receives plaintext;
- whether encryption is local, remote, or a hybrid key-wrapping model;
- provider-independent versioned authenticated export envelope semantics;
- payload/destination approval binding;
- API credential scope/storage;
- endpoint allowlisting;
- redirect/proxy/TLS/certificate policy;
- LAN/custom-CA or certificate/SPKI-pin policy without an `accept invalid certs` bypass;
- failure/timeout/response-size limits;
- provider disappearance/recovery/migration behaviour;
- whether an offline recovery recipient/key is required.

A remote service that performs encryption over plaintext is a materially different trust model from local encryption or remote key wrapping. The UI/documentation must not hide that distinction.

The deferred `hmac-secret` research path remains outside MVP and requires separate review of credential provisioning, RP binding, multi-key recovery, reset/deletion coupling, rotation, and permanent data-loss risk.

## 33. Network policy

Core FIDO management has no network dependency.

The WebView has no general-purpose network authority.

Network-capable components are isolated by purpose:

- updater;
- post-MVP export/provider helper.

Neither may receive live CTAP handles, PIN/UV authorization state, or authority to initiate authenticator mutations.

## 34. Logging and diagnostics

Release logging is minimal.

Never log:

- PINs;
- PIN/UV tokens;
- export/provider credentials;
- encryption keys;
- raw secret-bearing CTAP data;
- full credential IDs by default;
- unnecessary serial/account metadata.

Diagnostic export must be explicit, previewable/minimized, and independently approved if it leaves the machine.

## 35. CI pipeline

Every pull request should run at least:

### Frontend

```text
pnpm install --frozen-lockfile
lint
typecheck
tests
```

### Rust

```text
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
```

### Security/dependency checks

- Cargo dependency/advisory policy;
- frontend dependency policy;
- native dependency/version verification;
- lockfile verification;
- Tauri build smoke test;
- schema checks for forbidden secret-bearing renderer command fields;
- action pinning verification.

PR/untrusted jobs receive no production signing or provider credentials.

## 36. Release pipeline

Use semantic versioning.

Example flow:

```text
main
  ↓
reviewed release candidate
  ↓
tag vX.Y.Z
  ↓
native build per target
  ↓
record artifact digest
  ↓
isolated signing/notarization
  ↓
final checksums + artifact-specific SBOM
  ↓
provenance metadata
  ↓
publish GitHub Release
```

Use protected release environments, minimal token permissions, digest-bound handoff between build/sign/publish, and reviewed workflow changes.

Never allow privileged workflows to execute untrusted PR code.

## 37. Signing and packaging

### macOS

- Developer ID signing;
- Hardened Runtime with minimal entitlements;
- notarization and stapling;
- sign nested helpers/libraries correctly;
- no debug entitlements in release;
- clean/quarantined/offline launch test.

### Windows

- Authenticode sign app, installer, and broker/helper binaries;
- timestamp signatures;
- protected per-machine location for elevated helper if required;
- test install/upgrade/repair/uninstall and alternate-user elevation scenarios.

### Linux

- explicit package/runtime dependency policy;
- checksums and signed metadata where practical;
- safe udev/active-session access instructions;
- never recommend root GUI execution or world-writable hidraw rules.

## 38. Updater policy

No silent automatic updater in the initial alpha.

Before an updater ships:

- trusted update public key is bundled;
- artifacts/metadata are cryptographically authenticated;
- version/platform/architecture/channel are bound to metadata/signatures;
- downgrade/security-floor policy is enforced outside renderer control;
- key rotation/compromise recovery is documented;
- installation is atomic/recoverable;
- no renderer-controlled URL/key/version comparator;
- no authenticator metadata in update requests;
- update installation is prohibited during sensitive prompts, reset ceremonies, active native execution, or unresolved mutation recovery barriers.

Updater code has no live CTAP authority.

## 39. Build provenance and SBOM

Record for each artifact:

- source commit;
- version tag;
- target triple;
- Rust toolchain;
- Node/pnpm/Tauri versions;
- libfido2 and bundled native dependency versions;
- compiler/SDK/build options;
- artifact digest;
- signing/notarization status.

Generate an SBOM for the actual shipped artifact, including bundled native libraries/helpers.

Distinguish traceable, repeatable, and bit-reproducible builds; do not claim bit reproducibility merely because versions are pinned.

## 40. Implementation milestones

### Milestone 0 — repository foundation

- documentation/ADRs;
- Tauri/Rust/Svelte skeleton;
- CI/dependency policy;
- single-instance foundation;
- no mutation.

### Milestone 1 — read-only discovery

macOS/Linux first:

- enumerate roaming keys;
- GetInfo;
- insertion/removal;
- capabilities/configuration/options;
- AAGUID/transport;
- no PIN;
- no credential enumeration.

Windows M1 waits for the access feasibility spike if required by platform access rules.

### Milestone 1.5 — native/platform feasibility spikes

- libfido2 fit spike;
- native UI threading/modality spike on each platform;
- Windows direct-access/broker spike;
- worker timeout/cancellation/hung-call spike;
- RP-hash enumeration spike.

### Milestone 2 — native authentication foundation

- native PIN/UV interaction;
- retry-state UX;
- authorization token scope/lifetime;
- sensitive-prompt controller;
- zero-queue policy;
- secret lifecycle tests;
- no credential enumeration until the fit spike contracts are resolved.

### Milestone 3 — credential inspection

- bounded authenticated transaction;
- RP hash preservation/validation;
- completeness tracking;
- sanitized metadata publication;
- lock/disconnect clearing policy.

### Milestone 4 — PIN set/change

- immutable operation intent;
- native authorization;
- recovery journal;
- adapter evidence contract;
- uncertainty handling.

### Milestone 5 — credential deletion

- exact credential/RP binding;
- native authorization;
- no sensitive queue;
- sacrificial-hardware validation;
- uncertainty reconciliation.

### Milestone 6 — reset

- hard single-device ceremony;
- pre-reconnect impact confirmation;
- timed reconnect attempt;
- candidate-handle binding;
- reset-specific reconciliation;
- multi-vendor hardware validation.

### Milestone 7 — mutation-capable public alpha

Only after all applicable security gates pass:

- signed/notarized macOS build;
- limited documented compatibility claim;
- second independent authenticator implementation validated;
- SBOM/provenance/release workflow;
- security policy and vulnerability intake.

### Post-MVP — optional export/provider

- provider-independent export contract;
- separate export helper;
- build-time feature separation;
- BooGoo-specific ADR and threat review;
- no FIDO-authority regression.

## 41. Security gates before sensitive implementation

Sensitive workflows must not proceed until the relevant gate is explicitly resolved:

1. native UI threading/modality and prompt-controller design;
2. no-secret renderer command invariant;
3. libfido2 token/UV/credential-management fit;
4. RP-hash enumeration strategy;
5. PIN retry-state handling;
6. canonical per-device ownership + single-instance enforcement;
7. immutable operation intent/permit contract;
8. zero-queue sensitive workflow policy;
9. adapter-level mutation evidence contract;
10. explicit call deadlines/cancellation/quiescence policy;
11. crash-safe recovery journal/barrier;
12. per-operation reconciliation rules;
13. reset transition table and timing budget;
14. Windows broker authority/IPC model if applicable;
15. multi-vendor hardware validation before public mutation support.

## 42. Pre-1.0 release gates

Before 1.0 additionally review:

- CSP/navigation/custom-protocol/external-URL policy;
- packaged WebView attack surface;
- native library loading/search paths;
- dependency supply chain and native CVE cadence;
- signing/notarization/installer trust;
- updater trust root/downgrade/freeze recovery;
- logging/redaction/crash diagnostics;
- privacy model and persistent aliases if introduced;
- OS lock/suspend/session-switch behaviour;
- platform compatibility and accessibility implications;
- trademark/public branding requirements.

If provider support exists before 1.0, also review the complete export/provider threat model separately.

## 43. ADRs to create/update

- ADR-001: Desktop application rather than web/mobile
- ADR-002: Tauri 2 + Rust with untrusted WebView for sensitive workflows
- ADR-003: libfido2 as CTAP implementation and adapter policy
- ADR-004: vendor-neutral capability/state-driven core
- ADR-005: no cloud account and no telemetry
- ADR-006: no automatic updater during initial alpha
- ADR-007: native PIN/UV and operation-specific authorization
- ADR-008: optional security-provider/export architecture outside core FIDO authority
- ADR-009: complete-transaction per-device worker ownership
- ADR-010: mutation outcome/evidence/recovery model
- ADR-011: reset ceremony and single-device invariant
- ADR-012: single-instance management policy
- ADR-013: Windows broker authority/process placement
- ADR-014: RP-hash completeness and enumeration limitation strategy
- ADR-015: separate export helper and BooGoo integration trust model

## 44. Remaining open questions

The following remain deliberately open and must be resolved by spikes/ADRs rather than informal implementation:

1. Does the chosen current libfido2 release expose all required RP-hash enumeration semantics, or is upstream work required?
2. What exact native UI implementation is used on macOS, Windows, and Linux?
3. Is a separate worker process required on macOS/Linux for hung-call containment before mutation support?
4. What Windows user/elevation configurations are officially supported?
5. What exact platform/device metadata is safe/useful in the reset safety snapshot without implying identity?
6. Should low-retry submission policy use one universal threshold or device/policy-specific wording?
7. What minimum recovery-journal metadata is necessary without creating persistent device tracking?
8. Which packaged Linux formats are supported initially?
9. For BooGooCypher, where does encryption/key wrapping occur and what plaintext, if any, may cross the provider boundary?
10. What long-term updater/signing key-recovery policy is supportable by the maintainers?
