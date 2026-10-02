# FidoManager Architecture and Release Plan

Status: Proposed, revision 3 (focused-gate patch)  
Target: Implementation baseline for Milestones 0, 1 and 1.5  
Repository: `mbzbugsy/fidomanager`

Revision 3 incorporates the converging findings from three independent reviews of revision 2. The focused-gate patch incorporates the subsequent independent gate reviews of revision 3. All three focused reviewers returned a conditional pass for repository foundation, macOS/Linux read-only discovery, and feasibility spikes; none required a wholesale architectural redesign.

The core stack remains Tauri + Rust + libfido2. Sensitive functionality remains gated until the contracts and empirical questions relevant to that milestone are resolved.

The principal revision-3 decisions are:

- the WebView remains untrusted for PINs and security-sensitive consent;
- sensitive workflows use immutable backend-owned operation intents/permits;
- every native prompt has its own prompt-instance identity and is bound to one workflow generation;
- authorization-gated workflows are never queued behind one another and are subject to authority-wide admission/cooldown policy;
- only one FidoManager instance may own device-management state per user session;
- the service-to-worker boundary is expressed as an owned, serializable request/response protocol so worker deployment can move from thread to process without rewriting service semantics;
- mutation outcome, native-call quiescence, view freshness, and recovery admission are separate state dimensions;
- uncertain mutations survive disconnect and process restart through a minimal fail-closed crash-safe recovery journal;
- adapter-level evidence rules determine `NotDispatched`, `Rejected`, `ConfirmedSuccessful`, and `OutcomeUnknown`;
- reset uses a `ResetCeremonyGrant` plus a generation-bound `ResetDispatchPermit` rather than allowing a normal permit to survive reconnect;
- libfido2 capability/fit verification is a formal gate before credential inspection;
- application-managed PIN/UV tokens are treated as ambient native authority that must be explicitly attached, bounded, and cleared by the adapter;
- if Windows requires elevation, the elevated broker owns authoritative FIDO policy, native authorization, device handles, tokens, outcomes, and recovery state;
- export/provider code is moved out of `fido-service` and out of the core FIDO process where practical;
- BooGooCypher remains optional, post-MVP, and excluded from MVP builds;
- updater network/process placement must be reviewed before updater implementation rather than silently reintroducing network code into the PIN-holding authority.

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
- provide the application with PIN text through any Tauri command or event schema;
- manufacture proof of user consent for deletion, PIN mutation, reset, recovery clearance, or sensitive export;
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

The reviewed API baseline is libfido2 1.17.0. Production must pin a tagged reviewed release at or above that baseline unless an ADR records why a different version is required.

A libfido2 fit spike is mandatory before credential-management implementation. The spike validates real hardware behaviour rather than assuming that API signatures imply authenticator support.

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

The service-to-worker protocol types may live in `fido-core` or a later dedicated protocol crate, but they must remain independent of Tauri and libfido2 native pointers.

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
      │     ├── mutation outcome + recovery admission
      │     └── reset state machine
      │
      ├── fido-native-ui
      │     ├── native PIN/UV interaction
      │     └── operation-specific authorization
      │
      └── process-transparent worker endpoint
            │ owned serializable requests/responses
            ▼
        per-device worker
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

- macOS/Linux: the authority lives in the application's native Rust process; native FIDO work runs in a killable child worker process (`fido-worker`, decided by the M1.5 containment work, ADR-009), and the authority itself does not link libfido2;
- Windows: if direct management requires elevation, the trusted authority moves into the elevated broker rather than leaving policy/consent in the unelevated Tauri process.

Optional export/provider code sits outside this authority.

The M1.5 hung-call/containment work decided that macOS/Linux workers are killable child processes, including for read-only discovery (ADR-009). This deployment decision did not change the service-visible protocol.

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
- `PromptInstanceId`
- `OperationIntent`
- `OperationPermit`
- `ResetCeremonyGrant`
- `ResetDispatchPermit`
- `MutationOutcome`
- `ExecutionQuiescence`
- `ViewFreshness`
- `RecoveryAdmission`
- structured recovery actions
- stable application error types.

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

## 8. Tauri command and event boundary

Tauri commands are workflow starters and DTO translators, not security authority.

Rules:

- explicit application-command permission manifest;
- explicitly selected production capability files; do not grant broad default capability sets without review;
- framework-derived caller context checks;
- opaque typed handles only;
- bounded request sizes and rates;
- no generic `execute_ctap`, `open_device(path)`, `load_library`, shell, arbitrary filesystem, or arbitrary HTTP commands;
- stale/wrong-kind handles rejected before workflow creation;
- hostile-renderer tests call every sensitive command directly without its intended UI;
- Tauri events/channels, navigation, custom protocols, plugin permissions, and external URL paths are part of the same renderer-to-host attack surface and must be tested explicitly.

Renderer-callable DTOs must be safe **by construction**, not by field-name heuristics. The default allowed field shapes are:

- opaque typed handles;
- bounded integers;
- booleans/enums whose meaning does not assert approval;
- narrowly reviewed fixed-format values.

Free-form strings/byte arrays require an explicit schema allowlist entry and security review. The initial allowlist for secret-bearing or authority-bearing free-form data is empty.

No renderer-callable schema may accept PIN/UV-token/provider-secret/private-key/raw-CTAP/approval material.

## 9. Native sensitive interaction

Sensitive interaction occurs outside the WebView.

A **sensitive workflow** is any workflow that:

- opens a native security-sensitive prompt;
- acquires an authenticator PIN/UV authorization token;
- performs recovery of an uncertain sensitive operation;
- dispatches an authenticator mutation; or
- approves sensitive export.

This includes credential inspection, PIN set/change, deletion, reset, recovery, and sensitive export approval.

Native UI is required for:

- authenticator PIN entry;
- PIN set/change input;
- credential-deletion authorization;
- reset impact authorization;
- deliberate recovery acknowledgement where required;
- any future sensitive export whose security property depends on deliberate user selection/consent.

The native layer must:

- render text from backend-owned state;
- sanitize untrusted authenticator/RP/user text itself;
- bind each dialog to a unique `PromptInstanceId` and one workflow generation;
- be parented/modally associated with the application window where the platform supports it;
- run on the platform's required UI thread/event-loop mechanism;
- use Cancel as the safe/default action;
- avoid destructive actions as the initially focused/default button;
- enforce a brief anti-accidental-click activation delay for destructive actions;
- timeout rather than reserve a worker indefinitely;
- be controlled by one global sensitive-prompt controller.

At most one sensitive workflow may be active globally in the authority at a time. Additional requests fail immediately with `OperationInProgress`.

Zero queue is not sufficient by itself. The authority must enforce a renderer-independent admission budget across workflow types and windows. Repeated cancellation, timeout, or rejection must trigger a bounded cooldown/suppression period before renderer-triggered sensitive prompts can resume. Threshold, observation window, cooldown duration, and trusted-native override semantics are explicit non-renderer-controlled policy constants that must be fixed before Milestone 2 ships.

Renderer-triggered sensitive prompts are admitted only while the application is in an appropriate foreground/visible state where the platform can establish that state reliably.

The sensitive-workflow lock is released only when:

1. all native dialogs for the workflow are closed;
2. the associated worker/native call is quiescent where one was started; and
3. the recovery-admission state has been evaluated.

Where practical, combine the exact operation description and required PIN/authentication into one native interaction rather than separate generic prompts.

Platform constraints for the M1.5 native-UI spike:

- **macOS:** AppKit interaction runs on the main thread. Production sensitive prompts should use window-modal sheets/asynchronous completion rather than a blocking `runModal` design that depends on a nested event loop.
- **Linux:** supported X11/Wayland configurations must demonstrate true transient/modal association using the GTK main context. If reliable parenting/modality cannot be achieved for a compositor/toolkit combination, that combination is not silently treated as supported.
- **Windows with elevated broker:** the broker owns the sensitive prompt. Cross-integrity parenting to the unelevated Tauri window must not be assumed; the spike must validate the supported association model. UIPI/input-integrity properties must not be described as protecting PIN confidentiality from same-user malware.

The security claim remains narrow:

> The legitimate sensitive workflow does not expose PINs to JavaScript and does not treat JavaScript as evidence of user consent.

This does not claim protection against a fully compromised OS or all same-user input observation/injection mechanisms.

## 10. Single-instance and ownership policy

For MVP, exactly one FidoManager management instance may own device-management state per interactive user session.

A second launch should focus/activate the first instance or exit cleanly.

Any arguments/URLs delivered by a second-launch mechanism are untrusted input.

Single-instance enforcement is primarily coordination/DoS resistance, not proof of trusted caller identity.

Multiple frontend windows, if ever supported, resolve to the same authoritative service/worker registry. Prefer one primary application window for MVP and deny uncontrolled `window.open` paths.

Single-instance enforcement does not serialize browsers, vendor tools, or other external FIDO clients; those remain external actors.

On Windows with a broker, the broker's authority singleton may need a stronger machine/session scope than the UI singleton; ADR-013 decides this after the Windows spike.

## 11. Authentication and authorization model

Separate:

1. user authentication to the authenticator (PIN or built-in UV);
2. authenticator-issued PIN/UV authorization token state;
3. application-level user consent for a specific operation;
4. PIN set/change as a mutation.

A credential-management authorization token is **not** consent to delete a credential.

Rules:

- never automatically retry a wrong PIN;
- query PIN retry count before PIN submission where the selected libfido2 path exposes it;
- display remaining retries in the native prompt;
- show a prominent low-retry warning when the reported count is low;
- when only one reported retry remains, require an additional explicit acknowledgement before submission;
- do not claim to know `powerCycleState` or temporary/permanent blocking before submission if the selected API does not expose it; map `PIN_AUTH_BLOCKED`, `PIN_BLOCKED`, UV-blocked and related returned states explicitly after an attempt;
- do not silently set a PIN to make management features available;
- fresh application-level approval is required for each mutation;
- authorization collected for inspection cannot authorize deletion or PIN mutation at the application-policy layer.

## 12. libfido2 1.17.x fit and token contract

Before Milestone 2 completes, run an empirical fit spike against the pinned libfido2 baseline and representative hardware.

The reviewed 1.17.0 source establishes several baseline facts that the design must accommodate:

- `fido_dev_get_puat()` supports application-managed PIN/UV authorization tokens and permission categories including `FIDO_PUAT_CREDMAN` and `FIDO_PUAT_CREDMAN_RO`;
- an attached PUAT is stored on the `fido_dev_t` and may take precedence over PIN-based authentication in token-aware operations;
- read-only credential-management authorization requires the application-managed PUAT path; the legacy per-call credential-management path is not assumed read-only;
- built-in UV can be requested through the application-managed path on supporting authenticators;
- libfido2 does not by itself prove that an authenticator enforces every requested permission; application policy must combine `getInfo` capability evidence with empirical device testing;
- legacy CTAP 2.0 token fallback is unscoped/PIN-only and must be represented as a distinct authorization mode;
- native call timeouts are not assumed finite by default;
- attached token state is not assumed to be cleared merely by closing/reopening transport state.

Adapter requirements derived from those facts:

- token acquisition is an explicit transaction step;
- mutating adapter methods accept an explicit typed application authorization argument and never rely on ambient token presence as application consent;
- a token guard clears the application-attached PUAT on **every** transaction exit path before the worker is released;
- tests assert no PUAT remains attached after a transaction completes/fails/cancels;
- disconnect/reconnect frees the old native device object and creates a new `fido_dev_t`; do not reuse a native object across device generations;
- authorization buffers are erased when native code no longer borrows them;
- every native call has a finite explicit timeout, and the worker also enforces a transaction-level deadline across multi-call operations;
- permission-scoped/read-only capability is represented separately from unscoped legacy fallback;
- Windows FidoManager builds should disable libfido2's Windows Hello pseudo-device (`USE_WINHELLO=OFF`) unless an ADR later establishes a specific need for it.

The fit spike must still determine empirically:

- which target authenticators honor `CREDMAN_RO` and relevant permission/RP scoping;
- UV-only credential-management behaviour;
- token lifetime/expiry/invalidation semantics;
- behavior of stale/invalid token state;
- CTAP 2.0 fallback on supported legacy hardware;
- RP-hash vs RP-text enumeration support;
- timeout/cancellation/thread-safety behavior;
- reset behavior/timing on reference devices;
- error information sufficient for operation-specific mutation evidence classification.

For each required behaviour, record one of:

- supported by pinned upstream API;
- supported only through a reviewed lower-level path;
- requires upstream work;
- unsupported product limitation.

Do not silently replace scoped authorization with a broader long-lived PIN buffer.

The M1.5 fit spike (`docs/spikes/M1.5-libfido2-puat-fit.md`) confirmed from 1.17.0 source, and adds as adapter requirements:

- `fido_dev_get_puat()` silently falls back to unscoped CTAP 2.0 `getPinToken` and returns `FIDO_OK` when `pinUvAuthToken` is not advertised, so the adapter decides scoped versus legacy from GetInfo before calling it; read-only additionally requires `perCredMgmtRO`;
- token-aware calls are never made with a PIN argument (the per-call path always requests full `cm`) or without an attached token (on a UV-capable authenticator that starts built-in UV);
- `fido_dev_close()` does not clear an attached token; only `fido_dev_set_puat(dev, NULL, 0)`, a new acquisition, or `fido_dev_free()` does;
- `fido_init()` enables libfido2 protocol logging whenever the `FIDO_DEBUG` environment variable is present, whatever flags are passed, so a native process that handles a PIN or token must refuse to start (before `fido_init` and before spawning threads) if it is set;
- a token cleanup that cannot be proven (clear error, or token still attached) makes the native object unusable: it is discarded, or contained and replaced per ADR-009, never reused for another transaction;
- the PUAT APIs first appear in 1.17.0, so every build that links the token path, including Linux CI and distro packages, needs at least that version.

Thetis hardware validation (firmware 0x100, which does not advertise `perCredMgmtRO` or `uv`) confirmed that closing and reopening an object keeps its token, that a newer or power-cycled-out token fails with `PIN_AUTH_INVALID` without consuming a PIN retry, and that a fresh object starts without a token. On such a key credential inspection needs ordinary `cm` authorization with read-only behaviour enforced by FidoManager policy, not by the authenticator. These results are single-device evidence, recorded in the same report.

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

- secrets never cross into renderer DTOs/events;
- PINs and PIN/UV tokens are never persisted;
- use owned zeroizing buffers where practical;
- minimize copies and conversions;
- reject embedded NULs before C-string boundaries;
- erase authorization buffers as soon as native code no longer borrows them;
- never include secrets in logs, traces, panic text, crash annotations, or diagnostics;
- document that paging, hibernation, crash dumps, native-library internals, and platform input methods prevent an absolute guarantee that bytes never reach storage.

A persistent-at-authenticator read-only token must not be described as being revoked merely because FidoManager erased its host copy. The application guarantee is that FidoManager does not persist or intentionally retain its bearer token bytes after the authorized transaction.

## 14. Device identity and session continuity

Default device identity remains ephemeral.

AAGUID, product strings, VID/PID, serial text, firmware metadata, and USB location/path may aid safety checks but are not universal cryptographic proof that a reconnected authenticator is the same physical object.

Normal session continuity is anchored to one live OS/native device handle owned by one worker.

A device removal/handle failure invalidates that session generation and requires a new native device object.

Persistent user-facing device fingerprints are not introduced for MVP.

Safety/recovery metadata must not be presented as proof of identity.

## 15. Canonical per-device worker and process-transparent protocol

One worker owns one live native device object/handle and the associated authorization context.

Complete transactions are serialized, not individual libfido2 calls.

The `fido-service` ↔ worker interface is an owned, serializable request/response message protocol from the first implementation commit.

Protocol rules:

- no borrowed Rust references across the boundary;
- no closures/function pointers/native pointers in requests or responses;
- explicit request IDs, deadlines, cancellation IDs, operation class, and bounded payloads;
- stable typed error/result envelopes;
- explicit evidence fields needed by mutation-outcome classification;
- no assumption that service and worker share an address space.

The production endpoint is a child-process worker. The M1 in-process thread endpoint proved the protocol was process-transparent (the child endpoint reused it without semantic change) and was then removed from the production path because it cannot prove quiescence (ADR-009).

Example:

```text
credential inspection
  reserve worker
  → collect PIN/UV natively
  → acquire minimum supported authorization
  → worker request: bounded inspection transaction
  → enumerate RPs/credentials
  → clear attached authorization
  → report result + completeness/evidence
  → publish sanitized snapshot
```

Rules:

- no background polling inside a stateful transaction;
- every native call has an explicit deadline/timeout policy;
- each transaction also has a wall-clock deadline;
- cancellation of an async caller does not imply cancellation of native execution;
- worker reuse requires proven native-call quiescence;
- reconciliation of device state does not by itself prove a blocked native call has stopped;
- external client contention maps to a structured `DeviceBusy`/contention condition where possible;
- interrupted enumeration is marked incomplete rather than silently reused;
- device-provided counts/lengths are validated/capped before Rust allocation where possible; native-library allocation behavior is part of containment testing.

The M1.5 hung-call/containment spike was the single decision point for deployment containment before sensitive public functionality, and it found that in-process behavior cannot stop, join, or prove quiescence of a hung native call. Therefore macOS/Linux use a killable worker process behind the same protocol. Containment rules that now hold in code:

- the endpoint terminates and **reaps** a worker before it reports any timeout, crash, or protocol violation, and only a successful reap is reported as `Quiescent`;
- `contain()` is idempotent and reports `Active` when quiescence cannot be proven; a worker is never replaced while its predecessor is `Active`;
- every worker start is a handshake (protocol version, worker generation, worker pid) followed by a health check; replacement workers receive a strictly higher `WorkerGeneration`;
- deadlines nest strictly (transaction, then exchange, then native); later exchanges receive the *remaining* transaction time and each native sub-call the remaining request time;
- frames are bounded before allocation in both directions, and malformed, truncated, empty, oversized, or unsolicited frames are protocol violations that terminate the worker;
- restarts back off exponentially and a sliding-window circuit breaker pauses respawning of a crash-looping worker;
- a worker cannot outlive its service: it exits on stdin EOF, on parent-pid change, and on any panic.

## 16. Sensitive workflow concurrency and admission: zero queue

Sensitive workflows are **not queued**.

If any sensitive prompt, sensitive operation reservation, token-acquiring transaction, recovery workflow, or mutation transaction is active, another sensitive workflow request fails immediately with `OperationInProgress`.

This applies to:

- credential inspection;
- recovery workflows;
- credential deletion;
- PIN set/change;
- reset;
- sensitive export approval;
- future security-critical management operations.

Read-only background refresh must not interleave with a stateful/sensitive transaction.

The authority-wide admission/cooldown policy in section 9 applies even after the active workflow is cancelled or times out, preventing sequential prompt flooding.

## 17. Immutable operation intent, prompt binding, and permit

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
- canonical backend-owned intent representation used to derive what is displayed.

Before showing a sensitive native prompt, the authority creates a unique `PromptInstanceId`/nonce bound to that workflow generation and intent.

The prompt callback carries that prompt-instance identity. A callback is accepted only if it matches the currently registered prompt for the same workflow generation. Late/stale callbacks are discarded and cannot approve a later workflow.

The user-visible operation description is derived from the same canonical intent representation. The permit binds a digest/version of that canonical representation so code cannot silently retarget an approval after the user saw it.

Native approval produces an `OperationPermit` bound to that exact intent.

A normal permit:

- is single-use;
- has an explicit finite TTL set by trusted policy;
- cannot be retargeted;
- is consumed atomically with final pre-dispatch validation;
- is always revoked by disconnect, target replacement, cancellation, workstation lock/suspend/session switch, expiry, owner loss, relevant authorization-state change, or worker restart.

Production prompt lifetime, permit TTL, and any UV/touch-wait extension are explicit policy constants fixed and tested before Milestone 2 is allowed to ship; they are never renderer-controlled or unbounded.

A changed target or changed device generation requires a new normal permit. Reset is the sole special ceremony and uses the distinct grant/permit objects defined in section 25 rather than weakening this rule.

Application permits are distinct from libfido2's attached PUAT state. The adapter never treats ambient token presence as proof of an application permit.

## 18. Mutation execution evidence and lifecycle dimensions

The service-level mutation outcome must be justified by adapter-level evidence.

### Mutation outcomes

| Outcome | Required meaning |
| --- | --- |
| `NotDispatched` | The application has evidence that the mutating function was not entered / the mutation could not have reached the authenticator. |
| `Rejected` | A definitive rejection attributable to the requested mutation or a pre-mutation protocol step was received and no requested state change occurred. |
| `ConfirmedSuccessful` | A definitive success response attributable to the mutation was received. |
| `OutcomeUnknown` | Dispatch may have occurred but the result cannot be established safely. |

Baseline evidence rules for libfido2 1.17.x:

- acquire required PUAT/authentication in a separate earlier step where the operation allows it;
- failures before the mutating libfido2 call is entered are `NotDispatched` for that mutation;
- once a mutating high-level call is entered, `NotDispatched` is not inferred from a generic transport return code;
- `FIDO_OK` from the mutating call is `ConfirmedSuccessful`;
- a definitive positive CTAP status attributable to the mutation/pre-mutation exchange is `Rejected` when it establishes that the requested state change did not occur;
- `FIDO_ERR_TX`, `FIDO_ERR_RX`, timeout, parse/transport ambiguity, or lost response after possible mutation dispatch is `OutcomeUnknown` unless operation-specific evidence proves a narrower result;
- `FIDO_ERR_TX` may be annotated internally as likely-not-dispatched where useful, but that annotation does not weaken the user-visible conservative outcome;
- `fido_dev_set_pin`/PIN-change is multi-exchange and requires an operation-specific evidence table in ADR-010;
- reset response loss remains `OutcomeUnknown` even if the device immediately re-enumerates; reconciliation is separate evidence;
- a confirmed mutation stays `ConfirmedSuccessful` even if post-operation refresh fails;
- authentication side effects such as retry-counter changes are tracked separately;
- no mutation is automatically retried after `OutcomeUnknown`.

Cancellation request/acknowledgement is not a fifth mutation outcome. A cancel signal does not prove an already-dispatched mutation was undone. Definitive cancellation-before-execution may be represented in workflow state only when the protocol/library provides evidence for that wait/phase.

### Independent runtime dimensions

Do not overload mutation outcome with other state.

Track independently:

1. `MutationOutcome` — what is known about the requested mutation;
2. `ExecutionQuiescence` — whether native execution is definitely stopped;
3. `ViewFreshness` — whether currently displayed/read-back state is fresh, stale, or incomplete;
4. `RecoveryAdmission` — whether ordinary sensitive/mutation work is allowed or blocked by an unresolved incident;
5. cancellation request/acknowledgement state where relevant.

A worker is reusable only after native execution is quiescent, even if device-state reconciliation has already occurred.

## 19. Fail-closed crash recovery journal and admission barrier

`OutcomeUnknown`/dispatch risk must survive disconnect and process restart.

The recovery journal uses an explicit two-phase per-incident protocol:

```text
NoRecord
  → Pending
  → DispatchCapable
  → Resolved
```

1. `Pending` is written after a mutation intent/permit is ready but before the operation can enter the dispatch-capable phase.
2. `DispatchCapable` is durably written and flushed **before** calling the mutating libfido2 function.
3. Definitive `Rejected` or `ConfirmedSuccessful` resolves/removes the incident atomically after required bookkeeping.

A crash while only `Pending` is durably recorded is not treated as evidence that the mutation was dispatched. A crash with `DispatchCapable` unresolved activates a recovery barrier.

Journal failure is fail-closed: if the required state cannot be written and durably acknowledged, mutation dispatch does not occur.

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
- application/schema version;
- opaque incident ID;
- journal phase (`Pending`/`DispatchCapable`);
- privacy-minimized context only where required for safe recovery.

The default post-restart barrier is authority-wide/global rather than pretending to identify a physical key after restart.

While a barrier is active:

- ordinary mutations are blocked;
- retry-consuming authentication is allowed only through the deliberate recovery workflow where the per-operation recovery policy permits it;
- passive read-only reconciliation is permitted only after execution is quiescent and only where the operation-specific policy says it is safe;
- reconnect/restart/page navigation never clears the barrier.

A deliberate native recovery workflow must provide a defined exit. Where protocol evidence can reconcile the state, show that evidence. Where exact historical outcome cannot be proven but safe continuation is possible, a high-friction acknowledgement may clear the admission barrier while preserving the historical incident outcome as unknown in the local recovery record/log metadata allowed by policy.

The journal uses restrictive platform-appropriate permissions and an authority-specific namespace. Same-user software that can deliberately delete/alter the user's application data remains a limitation of the supported threat boundary; do not add ad-hoc signing that pretends to solve a compromised same-user/administrator environment.

On Windows, recovery-state placement is part of ADR-013. If alternate-credential elevation is supported, the journal/singleton cannot accidentally follow whichever administrator profile performed the elevation; use an authority namespace/location whose ACL and ownership model survives the supported elevation flow.

## 20. Recovery/reconciliation policy by mutation

Each mutation must have an explicit recovery table before implementation.

The table states:

- passive queries allowed after quiescence;
- whether any retry-consuming authentication is allowed and only through recovery UI;
- evidence that may narrow the current state;
- conditions for clearing `RecoveryAdmission::Barrier`;
- historical outcome retained when continuation is allowed without proof of original completion.

### Credential deletion

- re-enumerate if supported and quiescent;
- absence may indicate deletion succeeded, but does not prove which actor changed state;
- confirmed deletion plus failed refresh remains confirmed with stale view.

### Set PIN

- `clientPin` state may provide strong evidence that a PIN is now configured;
- do not infer the exact PIN value from metadata.

### Change PIN

- no non-destructive read-back proves whether old or new PIN is active;
- never automatically test both values;
- ordinary credential inspection must not consume PIN retries while an unresolved PIN-change incident exists;
- any deliberate PIN verification attempt occurs through recovery UI with remaining retries shown.

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

Validate RP hash length; an RP hash not exactly 32 bytes is malformed for the supported CTAP model and results in incomplete/error state rather than guessed identity.

If RP text is present, mark it verified only when hashing the exact text produces the authoritative RP hash.

If text is absent, truncated, invalid, or does not match the hash:

- do not reconstruct a guessed RP ID;
- label the text as unavailable/unverified;
- display the hash where needed for safe native confirmation;
- do not report an empty credential set merely because text-based enumeration cannot continue.

For MVP, if the pinned upstream libfido2 path cannot enumerate credentials using only the authoritative RP hash, hash-only/truncated/mismatching RPs are an explicit `Incomplete/Unsupported` product limitation. Do not add an ad-hoc raw-CBOR path merely to avoid that limitation during MVP. Upstream support may be pursued separately.

M1.5 outcome (`docs/spikes/M1.5-rp-hash-enumeration.md`, libfido2 1.17.0): the public API exposes the authoritative hash (`fido_credman_rp_id_hash_ptr/len`) but `fido_credman_get_dev_rk` takes RP ID text and hashes it itself, so hash-only enumeration is an unsupported product limitation until upstream adds a hash-taking entry point. Credential enumeration continues only for an RP whose text verified against the hash; every other RP is `Incomplete/Unsupported` and its credentials are never listed or individually deletable. CTAP permits authenticators to truncate or omit RP ID text (CTAP 2.2 section 6.8.7), so this is an expected case, not an edge case.

When authenticator metadata exposes resident-credential totals, completeness checking against successfully enumerated credentials is mandatory. Duplicate authoritative RP hashes or inconsistent counts produce incomplete/inconsistent state, never silent deduplication or a false empty result.

Deletion is available only for credential records that were actually listed with an exact credential ID and remain valid in the current enumeration epoch.

## 22. Credential inspection workflow

Credential inspection is read-only in intent but security-sensitive because it may require PIN/UV authorization and reveal account metadata.

Workflow:

1. reserve the sensitive-workflow/worker slot;
2. query/display relevant PIN/UV retry state where available;
3. collect authentication natively;
4. acquire the minimum supported application-managed credential-management authorization;
5. enumerate within bounded per-call and transaction deadlines;
6. detect incomplete enumeration;
7. clear attached PUAT and erase application-held authorization state;
8. publish only sanitized metadata to the renderer;
9. clear/lock sensitive views on disconnect, workstation lock, session switch, suspend, or other relevant security event.

On lock/suspend/session switch, active application permits and authorization contexts are always logically revoked. This revocation does not imply that an in-flight native call has stopped; worker reuse still requires quiescence.

The libfido2 fit spike determines the supported authorization modes per device.

## 23. PIN set/change workflow

PIN mutation is a sensitive mutation.

Requirements:

- native UI only;
- backend-built operation intent;
- prompt-instance binding;
- exact device/session binding;
- retry count shown before submission when available;
- no automatic retry;
- fresh approval for every mutation;
- single-use permit;
- fail-closed recovery journal before dispatch;
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

The reviewed CTAP baseline requires the reset request for a displayless authenticator to reach the authenticator within a short post-power-up acceptance window (10 seconds in the reviewed specification baseline). The user-presence/touch completion is a separate protocol interaction; do not describe the entire touch ceremony as necessarily completing within that same ten seconds. Device/transport behavior must be verified empirically and recorded in the compatibility matrix.

### Reset authorization objects

Reset does **not** exempt a normal `OperationPermit` from disconnect revocation.

Instead it uses two distinct objects:

1. `ResetCeremonyGrant`
   - created by the high-friction native impact acknowledgement while the original device generation is still connected;
   - bound to the reset workflow, pre-disconnect safety snapshot, operation description/digest, cancellation generation, and a finite wall-clock ceremony expiry;
   - may survive exactly the expected reset disconnect/reconnect transition;
   - cannot authorize or dispatch `fido_dev_reset()` by itself.

2. `ResetDispatchPermit`
   - created by trusted service policy only after the timed reconnect candidate satisfies the ceremony guards;
   - bound to the newly opened candidate native handle/device generation;
   - single-use and valid only for a very short timed attempt;
   - is the only permit that can authorize reset dispatch;
   - may be minted without repeating the full human impact warning because the `ResetCeremonyGrant` already captured that acknowledgement and the authenticator's own touch/user-presence is the final physical gesture.

No ordinary permit survives reconnect. No candidate receives a dispatch permit merely because model/AAGUID/path metadata matches.

### Reset eligibility and invariants

For the MVP reset ceremony, an **eligible candidate** is a supported physical roaming FIDO authenticator exposed through the selected direct-management transport. Software/pseudo authenticators such as Windows Hello are excluded from candidate counts, and composite interfaces must be normalized so one physical authenticator is not double-counted.

Invariants:

- before the intentional disconnect, exactly one eligible target authenticator is selected and all high-friction impact confirmation is completed;
- zero eligible devices are expected while waiting for reinsertion;
- at most one eligible candidate may appear during the timed ceremony;
- exactly one validated candidate/handle exists at reset dispatch;
- any second eligible candidate or topology ambiguity aborts the ceremony;
- no authorization/approval is silently transferred to a same-model replacement;
- FidoManager never claims cryptographic continuity unless a protocol feature actually provides it;
- candidate metadata is safety evidence, not proof of identity;
- serial text may be compared when the authenticator exposes it, but absence is not an error and a match is not universal cryptographic proof;
- protocol continuity evidence such as an encrypted identifier may be evaluated by the spike where available, but is not assumed usable until verified;
- the user is warned that reset destroys FIDO credentials including credentials the app cannot enumerate;
- the operation is described as a FIDO reset and does not imply PIV/OTP/OpenPGP reset.

### Reset state machine

```text
Idle
→ PreparingReset
→ AwaitingImpactConfirmation
→ GrantIssued
→ AwaitingExpectedDisconnect
→ AwaitingSingleCandidateReconnect
→ CandidateValidated
→ DispatchPermitIssued
→ ExecutingReset
→ ConfirmedSuccessful / Rejected / OutcomeUnknown
```

`AwaitingImpactConfirmation` is a native high-friction step; for example, typing a reset phrase is acceptable.

Before disconnect:

- ensure the candidate set is unambiguous;
- record a non-authoritative safety snapshot of available device/topology/serial/capability metadata;
- prepare the crash-recovery incident record so only the minimal durable `DispatchCapable` transition remains on the timed path;
- where supported, use a physical-identification cue such as wink/touch-to-select;
- issue a finite `ResetCeremonyGrant` only after native impact acknowledgement.

After reconnect, keep the timed path minimal:

1. confirm at most one eligible candidate;
2. open a fresh native device object/handle;
3. compare only the safety evidence required by the reset policy/device profile;
4. durably transition the recovery journal to `DispatchCapable`;
5. mint the generation-bound `ResetDispatchPermit`;
6. dispatch reset;
7. rely on the authenticator's required physical user-presence/touch as the final real-time hardware interaction.

Do not put a long human-reading dialog, broad capability refresh, retry query, network operation, or nonessential disk logging on the timed reconnect path.

The reset spike must measure insertion-to-dispatch latency on reference hardware/OS combinations. An OS insertion notification is not treated as the physical power-up instant. The app's UI timing budget is derived from verified spec/device behavior and measured margin; it must not invent a universal shorter device deadline.

A maximum disconnect/reconnect duration is an explicit reset-policy/device-profile constant. Grant expiry, another disconnect, ambiguity, cancellation, lock/suspend, topology change, candidate-generation change, or unsupported timing aborts the attempt.

At most one timed retry may reuse the same `ResetCeremonyGrant`, and only if the grant has not expired and no candidate/topology/safety evidence changed. Otherwise the ceremony returns to `Idle` and requires new impact acknowledgement.

Whether a particular device can/should first attempt reset on the still-open pre-disconnect handle is a compatibility-spike decision. Such an attempt, if supported, is itself a real mutation and must follow the same journal/evidence rules; a definitive `NOT_ALLOWED` may transition to the replug ceremony.

Reset behavior that varies by authenticator/CTAP revision — long-touch requirement, permitted reset transports, re-enumeration/reboot behavior, biometric-reset semantics, timing quirks — belongs in `DEVICE_COMPATIBILITY.md` and the operation capability model.

## 26. Platform process placement

### macOS

Initial development target:

- Apple Silicon macOS;
- roaming USB FIDO authenticator;
- trusted Rust authority in the native app process; native FIDO work in the killable `fido-worker` child process (M1.5).

Native sensitive UI must use AppKit main-thread dispatch and window-modal asynchronous presentation. Blocking modal-loop designs are not the default production pattern.

### Linux

Initial targets:

- Ubuntu LTS;
- Fedora;
- X11 and Wayland behavior explicitly tested.

Do not run the GUI as root. Distinguish `AccessDenied` from `DeviceAbsent` and document safe udev/active-session access rules.

Native sensitive UI must demonstrate reliable GTK transient/modal association on each supported display environment. Wayland/compositor combinations for which that relationship cannot be established are unsupported until a reviewed mechanism exists; do not substitute an unparented floating dialog silently.

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
- initiating-user vs elevating-user identity;
- recovery journal/singleton namespace;
- protected install location;
- x64 and any intended ARM64 support;
- SmartScreen/Smart App Control/WDAC behavior;
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
- mutation outcome, quiescence, and recovery admission state.

The broker treats the unelevated/same-user client as a workflow requester, not a proof-of-trust source. It must remain safe if that client is malicious but cannot bypass broker-owned native authorization.

The broker must not accept client assertions such as `approved=true`.

IPC must use:

- a fixed typed protocol;
- protocol/version negotiation;
- launch/session binding established by a reviewed bootstrap mechanism;
- replay protection;
- strict Windows security descriptors and peer/server validation suitable for the supported initiating/elevating user model;
- client-death handling;
- bounded payloads/timeouts;
- no raw CTAP, device paths, library paths, executable paths, or arbitrary filesystem/network instructions.

Any bootstrap secret/capability used to bind the initiating client to the broker must not be passed through an exposed renderer field and must not rely on command-line secrecy. The Windows spike/ADR selects the final inherited-handle/object/other OS mechanism.

ADR-013 must explicitly decide:

- supported initiating-user/elevating-user combinations, including whether alternate-credential elevation is unsupported for MVP;
- broker singleton scope;
- pipe/server ownership and ACL principal;
- launch binding/server verification/replay model;
- broker lifetime (per operation vs per application session) and idle timeout;
- behavior when the client dies before/after possible dispatch;
- recovery journal namespace/location across supported elevation identities;
- termination rules while execution or recovery is unresolved.

The broker runs in the active interactive context required for broker-owned operation-specific UI. UAC consent is not consent to a particular FIDO mutation.

The broker executable and private libraries must be installed in administrator-protected locations and signed. Windows dynamic-library search policy must be hardened; static linking of the reviewed libfido2 stack is preferred where supportable.

## 28. libfido2 and native supply chain

Do not download native libraries at application runtime.

Requirements:

- pin an approved tagged libfido2 release;
- production version must be at least the reviewed security baseline unless an ADR explicitly justifies otherwise;
- verify source authenticity/checksums/provenance as available;
- record exact build configuration;
- track libcbor/OpenSSL/zlib/udev and other bundled native dependencies;
- audit build scripts/compiler flags/features;
- disable unneeded transports/features where practical;
- build Windows direct-management artifacts with `USE_WINHELLO=OFF` unless intentionally reviewed otherwise;
- document static vs dynamic linking per artifact;
- preserve third-party notices;
- maintain a patch/CVE policy for bundled native dependencies.

Users should not need Homebrew or a separate system package on macOS/Windows releases.

Linux distro packages may use controlled system dependencies with explicit minimum versions where that is the safer maintenance trade-off; the distro version must still satisfy the token/adapter contract actually used by the package.

## 29. Testing strategy

### Domain/service tests

Test:

- handle typing/generation/epoch invalidation;
- immutable intent/prompt/permit binding;
- stale prompt callback rejection;
- permit expiry/revocation/one-shot consumption;
- sensitive zero-queue behavior;
- sequential prompt admission/cooldown;
- capability/configuration/availability separation;
- four independent runtime dimensions (outcome/quiescence/freshness/admission);
- two-phase recovery journal/barrier state;
- reset grant/dispatch-permit transition guards;
- operation-specific reconciliation.

### Worker protocol tests

Test the same service-facing request/response contract against:

- fake/fault-injecting endpoint (deterministic coordinator and supervisor policy tests);
- the production child-process endpoint against real worker processes, including hang, crash, orphan, framing, handshake, and descriptor-hygiene fault injection (`crates/fido-worker-fixture`).

No service test may depend on borrowed/native pointers crossing the worker boundary.

### Adapter/FFI tests

Test:

- ownership/free ordering;
- fresh device-object creation after reconnect;
- nullability;
- counts/lengths/conversions;
- malformed strings/control characters;
- embedded NUL rejection;
- PUAT attachment/cleanup on every exit path;
- explicit per-call timeout and transaction deadline;
- cancellation behavior/thread-safety assumptions;
- fault injection before/around/after mutating calls;
- operation-specific outcome evidence mapping;
- native resource exhaustion/malformed-count handling where possible.

### Hostile renderer tests

Test direct invocation of sensitive commands/events for:

- concurrent prompt flooding;
- sequential prompt flooding/cooldown;
- stale/wrong-kind handles;
- duplicated/reordered requests;
- attempting to supply target metadata;
- schema attempts to carry secrets/approval/free-form payloads;
- navigation/subframe/custom-protocol/external-URL paths;
- Tauri event/plugin capability escape paths;
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
- signing/notarization/quarantine behavior.

### Mutation/recovery failure scenarios

Mandatory scenarios include:

- journal directory unwritable/full/durability failure;
- crash in `Pending` vs `DispatchCapable`;
- crash after dispatch before response recording;
- disconnect followed by a fresh session while uncertainty exists;
- cancellation followed by a late success response;
- reconciliation while the original native call is still blocked;
- two application instances racing;
- two simultaneous native workflow requests;
- sequential cancel/re-prompt attack;
- reset candidate replacement after impact acknowledgement;
- reset grant expiry/retry;
- failed post-refresh after confirmed mutation;
- invalid cached authorization token on reused native handle (must be impossible after reconnect by construction);
- worker process termination after possible dispatch.

Use sacrificial test authenticators only for destructive automated/manual testing.

## 30. Compatibility matrix

Maintain `docs/DEVICE_COMPATIBILITY.md`.

Track at least:

- exact device/model/firmware;
- OS/version/architecture;
- discovery/GetInfo;
- PIN/UV mode;
- scoped/read-only/unscoped authorization mode;
- credential management;
- RP enumeration completeness;
- deletion;
- reset ceremony/timing;
- reset transport/long-touch behavior where exposed;
- known limitations/workarounds.

Before a mutation-capable public alpha, validate at least two independent authenticator implementations.

## 31. Optional export architecture

Export is separate from the FIDO policy engine.

`fido-service` may produce a sanitized immutable `ExportSnapshot` only after the relevant device transaction and authorization context have ended.

The snapshot contains only data the user selected for the approved export purpose and has an explicit lifecycle/erasure policy.

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
- has no operation permit;
- cannot call back into FIDO workflows;
- receives only the approved snapshot and export parameters;
- returns typed status/result references, not executable instructions.

Provider support is excluded from MVP builds at build time, not merely disabled with a runtime flag.

Post-MVP defense in depth may additionally sandbox/restrict the helper using platform mechanisms where practical.

## 32. BooGooCypher status

BooGooCypher remains a possible post-MVP provider for protected exports.

It is not required for ordinary FIDO management.

Before **implementation** of BooGoo/provider support, a dedicated ADR must define:

- whether provider code ever receives plaintext;
- whether encryption is local, remote, or a hybrid key-wrapping model;
- provider-independent versioned authenticated export envelope semantics;
- payload/destination approval binding;
- API credential scope/storage;
- endpoint allowlisting;
- redirect/proxy/TLS/certificate policy;
- LAN/custom-CA or certificate/SPKI-pin policy without an `accept invalid certs` bypass;
- failure/timeout/response-size limits;
- provider disappearance/recovery/migration behavior;
- whether an offline recovery recipient/key is required.

A remote service that performs encryption over plaintext is a materially different trust model from local encryption or remote key wrapping. The UI/documentation must not hide that distinction.

The deferred `hmac-secret` research path remains outside MVP and requires separate review of credential provisioning, RP binding, multi-key recovery, reset/deletion coupling, rotation, and permanent data-loss risk.

## 33. Network and updater process policy

Core FIDO management has no network dependency.

The WebView has no general-purpose network authority.

Network-capable components are isolated by purpose:

- updater;
- post-MVP export/provider helper.

Neither may receive live CTAP handles, PIN/UV authorization state, or authority to initiate authenticator mutations.

Export/provider uses the separate helper boundary defined above.

Updater process placement is **not** assumed safe merely because it is an updater. Before updater implementation, ADR-006/ADR-016 must choose one of:

- a separate update-check/download helper/process with no live CTAP authority; or
- an explicitly justified in-process design with a documented analysis of why its HTTP/TLS/parser attack surface is acceptable in the native authority process on the affected platform.

No updater network stack is added to the sensitive authority by convenience without that decision.

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
- renderer DTO allowlist/schema verification;
- Tauri capability/event/plugin permission verification;
- action pinning verification;
- post-MVP build assertion that MVP artifacts do not accidentally include provider/network dependencies intended to be excluded.

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
- test install/upgrade/repair/uninstall and supported elevation scenarios.

### Linux

- explicit package/runtime dependency policy;
- checksums and signed metadata where practical;
- safe udev/active-session access instructions;
- never recommend root GUI execution or world-writable hidraw rules.

## 38. Updater policy

No silent automatic updater in the initial alpha.

Before updater **implementation**, process/network placement must be decided as required by section 33.

Before an updater ships:

- trusted update public key is bundled;
- artifacts/metadata are cryptographically authenticated;
- version/platform/architecture/channel are bound to metadata/signatures;
- downgrade/security-floor policy is enforced outside renderer control;
- key rotation/compromise recovery is documented;
- installation is atomic/recoverable;
- no renderer-controlled URL/key/version comparator;
- no authenticator metadata in update requests;
- update installation is prohibited during sensitive prompts, reset ceremonies, active native execution, or unresolved recovery barriers.

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
- process-transparent service↔worker protocol types;
- no device mutation.

### Milestone 1 — read-only discovery

macOS/Linux first:

- enumerate roaming keys;
- GetInfo;
- insertion/removal;
- capabilities/configuration/options;
- AAGUID/transport;
- explicit timeout on every native call;
- bounded/validated output handling;
- free/recreate native device object on removal/reconnect;
- no PIN;
- no credential enumeration.

Windows M1 waits for the access feasibility spike if required by platform access rules.

### Milestone 1.5 — native/platform feasibility spikes

- libfido2 fit spike, including PUAT cleanup/scoping/legacy fallback;
- native UI threading/modality spike on each platform;
- Windows direct-access/broker identity/lifecycle spike;
- worker timeout/cancellation/hung-call/native-allocation containment spike;
- RP-hash enumeration spike, with product limitation as MVP default if upstream cannot safely support hash-only enumeration.

### Milestone 2 — native authentication foundation

Before shipping/using production authentication:

- native PIN/UV interaction;
- retry-state UX consistent with exposed API evidence;
- authorization token scope/lifetime;
- attached-PUAT guard/cleanup;
- sensitive-prompt controller;
- prompt-instance nonce binding;
- zero-queue + sequential admission/cooldown policy;
- mandatory lock/suspend/session-switch revocation;
- schema/event/capability hostile-renderer tests;
- concrete finite prompt/permit timeout constants;
- no credential enumeration until the fit-spike contracts are resolved.

### Milestone 3 — credential inspection

- bounded authenticated transaction;
- RP hash preservation/validation;
- explicit hash-only product limitation where required;
- completeness tracking;
- sanitized metadata publication;
- lock/disconnect clearing policy.

### Milestone 4 — PIN set/change

- immutable operation intent;
- native authorization;
- two-phase fail-closed recovery journal;
- recovery admission/clear procedure;
- operation-specific adapter evidence table;
- uncertainty handling.

### Milestone 5 — credential deletion

- exact credential/RP binding;
- native authorization;
- no sensitive queue/admission bypass;
- sacrificial-hardware validation;
- uncertainty reconciliation.

### Milestone 6 — reset

- `ResetCeremonyGrant` and generation-bound `ResetDispatchPermit`;
- hard eligible-single-device ceremony;
- pre-reconnect impact confirmation;
- measured timed reconnect attempt;
- candidate-handle binding;
- reset-specific recovery/evidence rules;
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
- BooGoo-specific ADR and threat review **before implementation**;
- no FIDO-authority regression.

## 41. Security gates before sensitive implementation

Sensitive workflows must not proceed until the relevant gate is explicitly resolved:

1. process-transparent worker protocol exists before code depends on worker placement;
2. native UI threading/modality and prompt-controller design;
3. no-secret renderer schema/event/capability invariant;
4. sensitive workflow definition + zero queue + sequential admission/cooldown;
5. prompt-instance binding and finite permit lifetime;
6. libfido2 token/UV/credential-management fit and attached-token cleanup contract;
7. RP-hash enumeration strategy/product limitation;
8. PIN retry-state handling consistent with actual API evidence;
9. canonical per-device ownership + single-instance enforcement;
10. immutable operation intent/permit contract;
11. adapter-level mutation evidence tables;
12. explicit per-call + per-transaction deadlines/cancellation/quiescence policy;
13. four independent runtime state dimensions including recovery admission;
14. two-phase fail-closed recovery journal/barrier + explicit clear procedure;
15. per-operation reconciliation/recovery rules;
16. reset grant/permit transition table and measured timing budget;
17. Windows broker authority/identity/lifecycle/IPC model if applicable;
18. multi-vendor hardware validation before public mutation support.

## 42. Pre-1.0 release gates

Controls needed by an earlier sensitive/public milestone must be completed at that milestone; this list is not permission to defer them until 1.0.

Before 1.0 additionally review:

- CSP/navigation/custom-protocol/external-URL policy;
- packaged WebView attack surface;
- native library loading/search paths;
- dependency supply chain and native CVE cadence;
- signing/notarization/installer trust;
- updater trust root/process placement/downgrade/freeze recovery;
- logging/redaction/crash diagnostics;
- privacy model and persistent aliases if introduced;
- OS lock/suspend/session-switch behavior;
- platform compatibility and accessibility implications;
- trademark/public branding requirements.

If provider support exists before 1.0, also review the complete export/provider threat model separately.

## 43. ADRs to create/update

- ADR-001: Desktop application rather than web/mobile
- ADR-002: Tauri 2 + Rust with untrusted WebView for sensitive workflows
- ADR-003: libfido2 as CTAP implementation and adapter policy
- ADR-004: vendor-neutral capability/state-driven core
- ADR-005: no cloud account and no telemetry
- ADR-006: no automatic updater during initial alpha; updater trust/process-placement gate
- ADR-007: native PIN/UV and operation-specific authorization
- ADR-008: optional security-provider/export architecture outside core FIDO authority
- ADR-009: complete-transaction worker ownership + process-transparent protocol/containment decision
- ADR-010: mutation outcome/evidence/recovery-admission/journal model
- ADR-011: reset ceremony, `ResetCeremonyGrant`, `ResetDispatchPermit`, and eligible-single-device invariant
- ADR-012: single-instance management policy
- ADR-013: Windows broker authority/process/identity/lifecycle placement
- ADR-014: RP-hash completeness and enumeration product-limitation strategy
- ADR-015: separate export helper and BooGoo integration trust model
- ADR-016: updater network/process placement and trust boundary

## 44. Remaining open questions

The following remain deliberately open and must be resolved by spikes/ADRs rather than informal implementation:

1. Which target authenticators actually honor the required libfido2 1.17.x PUAT permissions/read-only behavior?
2. What exact native UI implementation details pass packaged macOS, Windows, X11 and Wayland modality tests?
3. Does the M1.5 hung-call/native-allocation spike require child-process workers on macOS/Linux before Milestone 2/3 or only before mutation support?
4. What Windows user/elevation configurations are officially supported, and what broker singleton/journal/bootstrap model follows from that decision?
5. What exact platform/device metadata is safe/useful in the reset safety snapshot without implying identity?
6. What measured reset timing/disconnect limits and transport-specific profiles are supportable on reference authenticators?
7. What concrete prompt/permit timeout and admission/cooldown policy constants should ship for Milestone 2?
8. Which packaged Linux formats/display environments are supported initially?
9. For BooGooCypher, where does encryption/key wrapping occur and what plaintext, if any, may cross the provider boundary?
10. Which updater process placement is selected before updater implementation, and what long-term signing/update-key recovery policy is supportable by the maintainers?
