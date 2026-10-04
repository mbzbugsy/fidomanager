# FidoManager Security Model

Status: Proposed, revision 3 (focused-gate patch)

This document aligns with revision 3 of `ARCHITECTURE_AND_RELEASE_PLAN.md` after the focused security-gate reviews.

Revision 3 keeps the WebView outside the trusted path for authenticator PINs and security-sensitive consent. The focused-gate patch further makes explicit the contracts for process-transparent worker boundaries, prompt-instance binding, sequential prompt admission limits, attached-PUAT cleanup, conservative libfido2 mutation evidence, four independent runtime state dimensions, fail-closed two-phase recovery journaling, reset ceremony grants/dispatch permits, Windows broker identity/lifecycle, and updater process placement.

The review consensus permits Milestones 0, 1 on macOS/Linux, and Milestone 1.5 feasibility work. Sensitive production workflows remain gated until their applicable contracts/spikes pass.

## 1. Security objectives

FidoManager is intended to inspect and manage real FIDO2/CTAP authenticators without introducing unnecessary trust, persistence, privilege, or network dependencies.

The application should reduce management friction without weakening authenticator security or becoming a high-value long-lived secret store.

Primary objectives:

- keep authenticator PINs and PIN/UV authorization material out of the WebView;
- prevent renderer-controlled data from being treated as proof of human consent;
- bind sensitive approval to one immutable operation, target, prompt instance, and workflow generation;
- make destructive and PIN mutations conservative under timeout/disconnect/crash;
- separate mutation outcome from execution quiescence, view freshness, and recovery admission;
- avoid persistent device tracking unless separately justified;
- preserve offline core operation;
- contain privileged Windows authority if elevation is required;
- prevent optional export/network/updater features from gaining live CTAP authority.

## 2. Trust boundaries

Primary trust boundaries are:

1. User ↔ native sensitive interaction
2. User ↔ WebView presentation
3. WebView ↔ Tauri command/event adapter
4. Tauri command adapter ↔ trusted FIDO authority
5. `fido-service` ↔ native UI controller
6. `fido-service` ↔ process-transparent per-device worker protocol
7. per-device worker ↔ `fido-libfido2`
8. libfido2 ↔ OS HID/platform transport
9. operating system ↔ physical authenticator
10. recovery journal ↔ trusted FIDO authority
11. optional Windows elevated broker ↔ unelevated client
12. trusted FIDO authority ↔ post-MVP export handoff
13. export helper ↔ optional provider endpoint
14. updater/release pipeline ↔ installed application

The desktop application must not be treated as one uniformly trusted blob.

On Windows with a required elevated broker, the logical trusted FIDO authority is hosted in the broker rather than the unelevated Tauri process.

## 3. Assets to protect

Security-sensitive assets include:

- authenticator PINs;
- PIN/UV authorization tokens;
- PIN-derived/intermediate protocol secrets;
- exact user intent for sensitive operations;
- prompt-instance identities/nonces;
- immutable operation permits;
- reset ceremony grants/dispatch permits;
- credential/RP/user metadata;
- authoritative RP hashes and credential identifiers;
- session/handle generation integrity;
- mutation outcome evidence;
- execution-quiescence state;
- recovery-admission state;
- recovery journal integrity;
- provider credentials/export keys when optional export exists;
- signing/release/update keys and release provenance.

Authenticator private credential keys are not expected to be exportable. FidoManager must never imply otherwise.

## 4. Threat actors and assumptions

### Compromised renderer

A compromised WebView/JavaScript environment is in scope.

It may:

- call renderer-exposed commands/events directly;
- reorder/duplicate requests;
- provide deceptive labels/metadata;
- flood workflow-start requests sequentially or concurrently;
- attempt to navigate/open external resources;
- inspect all data deliberately rendered in JavaScript.

It must not be able to obtain PINs from the legitimate workflow or provide the application with PIN/token/approval material through command/event schemas.

### Local unprivileged process

Same-user local software is in scope as a distinct actor.

Depending on OS/display system it may be able to:

- race for device access;
- synthesize or observe input to native windows;
- attempt local IPC connections;
- inspect same-user files/secrets subject to platform controls.

Native prompts primarily remove renderer authority; they are not a universal defense against every same-user process.

On Windows, the elevated broker must remain safe even if a same-user unelevated client is malicious and can request workflows. Broker-owned native approval remains the security boundary for mutation intent.

### Malicious/buggy authenticator

A connected authenticator is untrusted input.

It may return malformed, deceptive, oversized, inconsistent, unsupported, or intentionally resource-exhausting protocol data.

### Compromised native dependency

libfido2 or transitive native dependencies are part of the trusted computing base and may contain memory-safety or logic vulnerabilities.

### Compromised remote provider/updater endpoint

Optional provider and update endpoints are untrusted remote peers whose compromise must not create direct CTAP authority.

### Fully compromised OS/kernel

A fully compromised OS with arbitrary process-memory/kernel control is outside FidoManager's protection goals.

## 5. Renderer authority restrictions

Renderer-callable interfaces must be safe by construction.

The default allowed renderer-to-host field shapes are:

- opaque typed handles;
- bounded integers;
- booleans/enums that do not assert authorization/approval;
- narrowly reviewed fixed-format values.

Free-form strings/byte arrays require explicit schema allowlisting and security review. The initial allowlist for secret-bearing or authority-bearing free-form data is empty.

Renderer-callable commands/events must never accept fields for:

- PIN text;
- PIN/UV tokens;
- ECDH/shared secrets;
- provider API credentials;
- export/data keys;
- raw CTAP payloads;
- operation approval/permit material;
- arbitrary device/library/file/executable paths.

The renderer may request high-level workflows through opaque typed handles.

Examples:

- allowed: `begin_credential_inspection(device_handle)`
- allowed: `begin_delete_credential(credential_handle)`
- prohibited: `delete_credential(device_path, credential_id, approved=true)`
- prohibited: `execute_ctap(raw_bytes)`

CI must inspect the renderer-callable schema/capability surface rather than guessing based on field names. Tauri events/channels/plugin permissions are included in the hostile-renderer surface, not only command handlers.

## 6. Sensitive native interaction

A **sensitive workflow** is any workflow that:

- opens a native security-sensitive prompt;
- acquires authenticator PIN/UV authorization;
- performs deliberate recovery of an unresolved sensitive incident;
- dispatches an authenticator mutation; or
- approves sensitive export.

Sensitive workflows include credential inspection, PIN set/change, deletion, reset, recovery, and sensitive export approval.

PIN entry and security-sensitive authorization occur outside the WebView.

Native interaction must:

- derive operation descriptions from trusted backend records;
- sanitize untrusted device/RP/user strings at the native display boundary;
- allocate a unique prompt-instance ID/nonce per dialog and workflow generation;
- attach/modally parent dialogs correctly where supported;
- run on the platform-required UI thread/event loop;
- make cancel/safe action the default;
- avoid destructive action as initial focus/default;
- enforce a brief anti-accidental-click delay for destructive approval;
- timeout and release reservations safely only after quiescence/recovery policy allows release;
- use one global sensitive-prompt controller.

Only one sensitive workflow may be active at once in an authority.

A compromised renderer can request a workflow but cannot provide the final approval result.

### Platform UI constraints

- **macOS:** sensitive prompts run on the main AppKit thread and should use asynchronous window-modal sheets/completion handlers rather than a blocking nested modal loop as the production pattern.
- **Linux:** supported X11/Wayland configurations must demonstrate true GTK transient/modal association on the GTK main context. Unsupported compositor/toolkit combinations are marked unsupported rather than silently falling back to an unparented dialog.
- **Windows with elevated broker:** the broker owns the native prompt. Cross-integrity parenting to the unelevated Tauri window is not assumed. The Windows spike validates the supported association model. UIPI must not be presented as protection of PIN confidentiality from all same-user malware/keylogging.

## 7. Prompt flooding / consent fatigue

Prompt flooding is a renderer-level denial-of-service and consent-fatigue threat.

Mitigations:

- zero queue for sensitive workflows;
- one global sensitive-prompt controller;
- immediate `OperationInProgress` rejection for concurrent sensitive requests;
- authority-wide admission budget across workflow types/windows;
- mandatory cooldown/suppression after repeated cancellation, timeout, or rejection within a bounded interval;
- renderer cannot control threshold/window/cooldown values;
- renderer-triggered sensitive prompts require an appropriate foreground/visible application state where that can be established reliably;
- no endless queued or sequential dialogs;
- destructive actions are not default/focused and may require stronger gestures for reset.

The exact production threshold/window/cooldown constants must be fixed and tested before Milestone 2 ships.

The macOS M2 implementation accepts the existing backend policy as production constants: three
cancellations/timeouts/rejections in 60 seconds cause a 30-second cooldown; there is no queue or
override. PIN prompts expire after 30 seconds from reservation. Native auth exchanges have a
5-second shared native budget plus a 100-ms transport margin; kill/reap has a 2-second bound.
The child independently expires an authentication transaction after 40 seconds and a retired
auth worker has a minimum 1-second settle interval before replacement. These are conservative
initial production decisions, not measured authenticator cancellation guarantees. See
[M2 validation](validation/M2-macos-native-auth.md).

The sensitive-workflow exclusion lock is released only after native dialogs are closed, associated native execution is quiescent, and recovery admission has been evaluated.

## 8. Immutable operation intent, prompt binding, and approval

Human approval authorizes exactly one immutable backend-owned operation intent.

The intent binds at least:

- operation kind;
- workflow ID;
- exact device session/generation;
- exact worker/native-handle generation;
- exact target/credential where applicable;
- authoritative RP hash for credential deletion;
- enumeration epoch where relevant;
- exact parameters;
- expiry;
- cancellation generation;
- canonical backend-owned representation used to derive the human-readable description.

Each prompt is assigned a unique `PromptInstanceId`/nonce bound to the workflow generation and intent.

The native callback must return that prompt identity through the trusted native channel. It is accepted only if it matches the currently registered prompt for the same workflow generation. A stale callback is discarded and cannot approve a later workflow.

The permit binds a digest/version of the canonical intent representation that produced the displayed operation description.

Approval creates a single-use `OperationPermit`.

A normal permit is always revoked by:

- disconnect;
- generation change;
- target replacement;
- cancellation;
- expiry;
- workstation lock;
- suspend;
- user/session switch;
- worker restart;
- owner loss;
- relevant authorization-state change.

Permit consumption and final pre-dispatch validation are atomic from the service perspective.

A renderer-provided boolean/callback result is never accepted as proof of consent.

Prompt/permit lifetimes are finite trusted policy constants. They are not renderer-controlled or unbounded and must be fixed before Milestone 2 ships.

Application permits are independent from any libfido2 PUAT attached to a device object. Ambient PUAT presence is never proof of user approval.

Reset does not weaken the normal disconnect-revocation rule; it uses the distinct `ResetCeremonyGrant`/`ResetDispatchPermit` contract in section 21.

## 9. Authentication/PIN/UV threats

Authentication can consume retry counters even when the requested operation is read-only in intent.

Mitigations:

- query remaining PIN retry count before submission when the selected API exposes it;
- show retry count in native UI;
- warn prominently at low remaining retry counts;
- require additional acknowledgement when only one reported retry remains;
- no automatic wrong-PIN retry;
- do not claim pre-attempt knowledge of temporary-vs-permanent PIN blocking if the pinned API does not expose the relevant state;
- map returned `PIN_AUTH_BLOCKED`, `PIN_BLOCKED`, UV-blocked, and related errors explicitly after attempts;
- do not silently set a PIN to unlock management functionality;
- inspection authorization cannot authorize a mutation at the application-policy layer.

If an unresolved PIN-change incident exists, ordinary credential inspection/authentication must not consume retries. Retry-consuming verification occurs only through the deliberate recovery workflow.

## 10. PIN/UV token lifecycle and ambient authority

PIN/UV authorization is native-only.

For the reviewed libfido2 1.17.0 baseline:

- application-managed PUAT support exists, including `FIDO_PUAT_CREDMAN` and `FIDO_PUAT_CREDMAN_RO` categories;
- an attached PUAT is native object state and may take precedence over PIN-based authentication in token-aware calls;
- read-only credential-management authorization is available only through the application-managed path, not assumed from legacy per-call PIN paths;
- legacy CTAP 2.0 fallback is unscoped/PIN-only and must be represented distinctly;
- successful token acquisition does not prove every requested permission was actually enforced by every authenticator;
- an authenticator-side persistent/read-only token may outlive the host copy; host erasure is not protocol revocation.

Required adapter policy:

- acquire authorization as an explicit transaction step;
- use the minimum supported operation-appropriate authorization;
- prefer read-only credential-management authorization where empirically supported;
- mutating adapter calls require an explicit typed application authorization argument and never rely on ambient PUAT state as application consent;
- a guard clears any attached application PUAT on every transaction exit path before worker reuse;
- disconnect/reconnect frees the old native `fido_dev_t` and creates a new object; native device objects are not reused across generations;
- erase application-held token/PIN buffers after native borrowing ends;
- logically revoke contexts on cancel/disconnect/lock/suspend/session switch/worker restart/expiry/security-state changes;
- never persist PIN/UV tokens to disk;
- never silently extend authorization or fall back to broader permissions without the capability/policy model recording it.

Tests must verify that no application PUAT remains attached after success, failure, cancellation, or timeout.

The libfido2 fit spike validates real device support, token expiry/invalidation, UV-only behavior, legacy fallback, and cancellation/thread-safety assumptions.

## 11. Secret-memory limitations

Rust zeroizing types reduce avoidable retention but do not create an absolute guarantee.

Remaining limitations include:

- native-library copies;
- OS paging;
- hibernation;
- crash dumps;
- allocator/runtime behavior;
- unavoidable platform UI/input-method buffers.

The supported guarantee is that FidoManager does not intentionally persist or log PIN/token material and minimizes its lifetime/copies.

## 12. Device identity and continuity

Normal device sessions are anchored to one live native/OS handle owned by one worker.

AAGUID, VID/PID, product text, serial text, firmware values, and USB paths are metadata, not universal proof of physical identity.

A disconnect invalidates the normal session generation and the old native device object is freed rather than reopened for a replacement generation.

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

## 14. Single-instance and canonical ownership

MVP permits one FidoManager management instance per interactive user session.

This reduces internal races between independently owned device handles/workers.

A second application launch must not create a second management authority. Second-launch arguments are untrusted input.

This coordination mechanism is not itself a proof that the process is trusted; another process can still cause denial of service.

Multiple frontend windows, if supported, share the same canonical service/worker registry.

This does not prevent Chrome, browsers, vendor tools, OS services, another OS user session, or other native FIDO clients from competing for the same authenticator.

On Windows with an elevated broker, the broker's singleton/authority scope is separately decided by ADR-013.

## 15. Process-transparent per-device worker and external contention

One worker owns one live native device object/handle and one authorization context.

The service-to-worker interface is an owned, serializable request/response protocol from the first implementation commit.

It must not carry:

- borrowed references;
- closures/function pointers;
- native pointers/handles as service-visible Rust objects;
- assumptions that service and worker share an address space.

It must carry explicit:

- request ID;
- operation class;
- bounded owned payload;
- deadline;
- cancellation ID/state;
- typed result/error;
- evidence fields needed for outcome/quiescence classification.

The endpoint may initially run in-process. The same protocol must support a child-process worker without changing service semantics.

Other FIDO clients remain external actors that FidoManager cannot fully serialize.

Consequences:

- channel/device busy conditions are expected;
- enumeration can become stale/inconsistent;
- authorization state can change externally;
- external actions may explain read-back state.

The UI must distinguish complete/fresh vs incomplete/stale state and must not infer that FidoManager caused every observed state transition.

## 16. Mutation outcome evidence

The service-level outcome must be justified by adapter-level evidence.

### `NotDispatched`

Use only when the application can establish that the mutating call was not entered / the mutating command could not have reached the authenticator.

For the libfido2 1.17.x baseline, failures before entering the mutating call — such as invalid permit, cancelled prompt, failed authorization acquisition, failed durable journal transition — may be `NotDispatched`.

Do not infer `NotDispatched` from a generic `FIDO_ERR_TX` after entering a mutating high-level call.

### `Rejected`

Use only after a definitive rejection attributable to the requested mutation or a pre-mutation protocol step that establishes no requested state change occurred.

A definitive positive CTAP status can provide such evidence depending on the operation/phase.

### `ConfirmedSuccessful`

Use only after a definitive success attributable to the mutating command.

A subsequent failed refresh does not downgrade confirmed success.

### `OutcomeUnknown`

Use whenever dispatch may have occurred but success/rejection cannot be established safely.

After a mutating libfido2 call is entered, generic `FIDO_ERR_TX`, `FIDO_ERR_RX`, timeout, parse/transport ambiguity, or lost response defaults to `OutcomeUnknown` unless operation-specific evidence establishes a narrower result.

`FIDO_ERR_TX` may be recorded internally as likely-not-dispatched for diagnostic/reconciliation prioritization, but it does not weaken the conservative user-visible state.

### Operation-specific evidence

Acquire application-managed authorization in a separate earlier step where the workflow allows it. This removes authentication/token acquisition from the mutating call for operations such as token-backed credential deletion and makes evidence easier to classify.

`fido_dev_set_pin`/PIN change remains multi-exchange. The production macOS M4
adapter uses the exact pinned-source allowlist in
[ADR-010](adr/ADR-010-MUTATION-OUTCOME-RECOVERY.md). Passive preparation obtains
no PUAT and consumes no PIN attempt. The same unique native object is revalidated
immediately before one high-level call. A private consumed handoff exists only
after exact native approval, teardown, Pending, permit consumption and durable
DispatchCapable. Worker protocol 4 carries only typed non-secret bindings;
FMPIN003 carries fixed zeroizing PIN buffers outside JSON. Confirmation stays in
native UI. The renderer has no mutation or recovery-clear authority.

Every completion path retires and reaps the child independently of outcome.
Confirmed success/rejection is resolved durably after teardown and quiescence;
failed resolution preserves that native outcome while admission remains blocked.
After the durable marker, any later host abort retains uncertainty and the barrier.
Native sheet controls are cleared; AppKit/NSString internal copies are not promised
zeroized. Production evidence is recorded in
[M4 macOS validation](validation/M4-pin-mutation-macos.md).

Reset response loss remains uncertain even when the device re-enumerates quickly.

Cancellation request/acknowledgement is separate from mutation outcome. A cancellation signal does not un-run an already-executing mutation.

Authentication side effects such as retry-counter changes are tracked independently from mutation outcome.

## 17. Native-call quiescence and containment

Mutation outcome and native execution state are separate.

A worker cannot be reused while a native call may still execute.

Reconciliation of visible authenticator state does not prove a blocked call has terminated.

Each native call must have an explicit finite deadline policy. Transactions also have a wall-clock deadline across multiple calls.

libfido2/native parsing may allocate or block before Rust sees a bounded converted DTO. The malicious-authenticator threat therefore includes native-level resource exhaustion, not only Rust-side output size.

The M1.5 hung-call/native-allocation spike is the single containment decision point. If safe in-process quiescence/resource bounds cannot be demonstrated for later sensitive functionality, use a killable child-process worker behind the already process-transparent protocol.

Terminating a worker after dispatch-capable execution produces conservative uncertainty unless stronger evidence exists.

## 18. Runtime state dimensions and crash/reconnect uncertainty

A disconnect is a common cause of `OutcomeUnknown`, so session-scoped quarantine is insufficient.

Track at least four independent runtime dimensions:

1. `MutationOutcome` — what is known about the requested mutation;
2. `ExecutionQuiescence` — whether native execution is definitely stopped;
3. `ViewFreshness` — whether the currently displayed/read-back state is fresh, stale, or incomplete;
4. `RecoveryAdmission` — whether ordinary sensitive/mutation work is permitted or blocked by unresolved incident risk.

Cancellation request/acknowledgement may be tracked separately as workflow state.

A recovery barrier survives normal session invalidation/reconnect and process restart.

Reconciliation cannot release or reuse a worker while `ExecutionQuiescence` is not definitively quiescent.

## 19. Fail-closed two-phase recovery journal

Before a mutation becomes dispatch-capable, use a two-phase durable journal:

```text
NoRecord
  → Pending
  → DispatchCapable
  → Resolved
```

- `Pending` is durably written after the operation is ready but before mutating execution can begin.
- `DispatchCapable` is durably written/flushed immediately before the mutating libfido2 function is called.
- definitive `Rejected`/`ConfirmedSuccessful` resolves/removes the incident atomically after required bookkeeping.

If required journal state cannot be written and durably acknowledged, mutation dispatch is prohibited.

A crash in `Pending` does not imply the mutation was dispatched. A crash/restart with unresolved `DispatchCapable` activates `RecoveryAdmission::Barrier`.

The journal must not contain:

- PINs;
- tokens;
- credential secrets;
- encryption keys;
- unnecessary RP/account metadata;
- persistent physical-device identity claims.

Allowed minimum fields include:

- opaque incident ID;
- operation class;
- timestamp;
- app/schema version;
- journal phase;
- privacy-minimized context only when necessary for recovery safety.

Default recovery is authority-wide/global rather than pretending to identify a physical key after restart.

Journal files use restrictive platform-appropriate permissions/ACLs and a stable authority namespace.

Same-user software that can deliberately delete/modify the user's app data remains a limitation of the supported threat boundary. Do not add ad-hoc journal signatures and claim they solve a compromised same-user/administrator environment.

On Windows, if alternate-credential elevation is supported, journal/singleton placement must not accidentally depend on whichever administrator profile performed elevation; ADR-013 selects the authority namespace/location/ACL model.

## 20. Recovery admission and operation-specific reconciliation

While `RecoveryAdmission::Barrier` is active:

- ordinary mutations are blocked;
- retry-consuming authentication is blocked except through deliberate operation-specific recovery;
- passive reconciliation is allowed only after native execution is quiescent and the operation policy says the query is safe;
- reconnect/restart/reopening the UI never clears the barrier.

The deliberate native recovery workflow must have a defined exit.

For each mutation, the recovery table specifies:

- passive queries allowed after quiescence;
- whether retry-consuming authentication is allowed;
- evidence that may narrow current state;
- user information/warnings shown before risky verification;
- conditions for clearing the admission barrier;
- historical outcome retained when safe continuation is allowed without proof of original completion.

When exact historical outcome cannot be proven but safe continuation is possible, a high-friction native acknowledgement may clear the admission barrier while the original incident remains recorded as historically unknown using privacy-minimized metadata.

macOS M4 implements this acknowledgement for valid unresolved PIN incidents only.
The native sheet states the exact historical operation and uncertainty, defaults
to Cancel, requires an explicit checkbox/action and a brief action delay, and
collects no PIN. It retires the worker first and durably records
AcknowledgedUnknown only after bound native approval/teardown. Corrupt, unreadable
or runtime-poisoned storage has no acknowledgement bypass. The privacy-minimized
record does not identify a reconnected physical key. M4 therefore makes no passive
recovery read or old/new PIN verification; historical success is never inferred
from reconnect or acknowledgement.


### Delete

Re-enumeration can show that a credential is absent, but absence does not prove which actor removed it.

### Set PIN

`clientPin` metadata can support reconciliation of whether a PIN became configured, but cannot identify the value.

### Change PIN

There is no safe automatic read-back of which PIN is active. Do not test old/new values automatically.

Ordinary inspection cannot consume PIN retries while an unresolved PIN-change incident exists. Any deliberate verification attempt happens through recovery UI with remaining retries shown.

### Reset

Post-reset state may support reconciliation, but an empty key does not prove that the intended physical authenticator was the one reset.

## 21. Reset-specific threats and authorization model

Reset carries unique identity and timing hazards.

Threats:

- wrong identical key inserted after disconnect;
- second key appears during ceremony;
- old approval reused for a replacement device;
- timing pressure encourages unsafe early dispatch;
- reset response lost after actual mutation;
- reset warning incorrectly implies only listed credentials are affected.

A normal `OperationPermit` always dies on disconnect. Reset uses two distinct objects instead of making an exception:

### `ResetCeremonyGrant`

Created only after high-friction native impact acknowledgement while the original selected device generation is connected.

It binds:

- reset workflow identity;
- canonical operation description/digest;
- pre-disconnect non-authoritative safety snapshot;
- cancellation generation;
- finite wall-clock ceremony expiry.

It may survive exactly the expected reset disconnect/reconnect transition, but it **cannot** dispatch reset.

### `ResetDispatchPermit`

Created by trusted service policy only after the timed candidate satisfies the reset guards.

It binds:

- the newly opened native handle/device generation;
- the existing unexpired `ResetCeremonyGrant`;
- candidate-validation result;
- the current timed attempt;
- a very short single-use TTL.

It is the sole object that can authorize `fido_dev_reset()`.

This is the sole ceremony where a dispatch permit may be minted without repeating the full human impact warning, because the ceremony grant captured the impact acknowledgement and the authenticator's own required user-presence/touch is the final physical gesture.

### Reset candidate/timing mitigations

- before intentional disconnect, exactly one eligible target authenticator is selected;
- zero eligible devices are expected while waiting for reinsertion;
- at most one eligible candidate may exist in the timed reconnect stage;
- exactly one validated candidate generation exists at dispatch;
- a second candidate/topology ambiguity aborts;
- no automatic same-model authorization transfer;
- candidate safety snapshot and serial/topology/capability comparisons are safety evidence, not cryptographic identity proof;
- where an encrypted/protocol identifier is available, its usability as continuity evidence is verified before reliance;
- no long human-reading dialog occurs inside the short CTAP acceptance window;
- physical authenticator user-presence remains part of the timed ceremony;
- grant expiry, ambiguity, disconnect, cancellation, lock/suspend, generation change, or unsupported timing aborts;
- reset warning covers discoverable, non-discoverable, and CTAP1/U2F credentials as applicable.

The reviewed CTAP baseline requires the reset request for a displayless authenticator to reach the authenticator within a short post-power-up acceptance window (10 seconds in the reviewed baseline). This is not stated as a universal deadline for completion of the entire touch ceremony. Device/transport behavior must be measured and recorded in the compatibility matrix.

The timed path must account for USB enumeration/OS notification delay, open latency, required candidate validation, durable journal transition, and dispatch. Nonessential refresh/logging/network work is excluded.

The ceremony has an explicit maximum reconnect duration. At most one timed retry may reuse the same unexpired grant and only if no candidate/topology/safety evidence changed; otherwise fresh impact acknowledgement is required.

A compatibility spike may determine that some devices can attempt reset on the still-open current handle first. Such an attempt is itself a real mutation and follows the same permit/journal/evidence rules.

## 22. RP identity / incomplete enumeration

Returned RP text is untrusted and may be absent/truncated/inconsistent.

The authoritative binary RP hash is preserved separately and must have the expected length for the supported CTAP representation.

RP text is marked verified only when the exact text hashes to the authoritative hash.

If the adapter cannot enumerate credentials for a hash-only/truncated/mismatching RP:

- report unsupported/incomplete enumeration;
- never show an empty list as though enumeration succeeded;
- never reconstruct a guessed RP ID;
- do not offer deletion for a credential that was not actually enumerated with an exact credential ID.

For MVP, hash-only/truncated RP enumeration is a documented product limitation if the pinned upstream libfido2 API cannot support it safely. Do not add an ad-hoc raw-CBOR bypass solely to hide the limitation.

Where resident-credential total metadata is available, compare it against successfully enumerated credentials. Any shortfall, duplicate authoritative hash, or inconsistent count produces incomplete/inconsistent state.

Native deletion UI sanitizes account/RP strings and exposes verification state/hash context where relevant.

## 23. Malicious device metadata / parser exhaustion

Threats include:

- oversized counts;
- malformed UTF-8/text;
- Unicode bidirectional/control characters;
- deceptive whitespace/confusables;
- large allocations inside native code before Rust sees the data;
- inconsistent credential counts;
- stalled native reads/calls.

Mitigations:

- native/adapter-level resource bounds where possible;
- per-call and per-transaction deadlines;
- output limits;
- sanitizer/normalizer for display text;
- preserve raw protocol identity separately from sanitized display text;
- malformed-count/fault-injection tests against the real adapter;
- process-transparent worker interface from the beginning;
- worker-process containment if the M1.5 spike shows native allocation/hang risk cannot be bounded acceptably in-process.

## 24. Native UI spoofing limitations

Moving sensitive UI out of the WebView prevents JavaScript from legitimately collecting PINs or directly asserting consent.

It does not guarantee:

- protection against a compromised OS;
- protection against all accessibility/input-injection/keylogging tools;
- that a malicious renderer cannot draw a visual imitation of a native dialog.

Therefore:

- no renderer interface accepts PIN/approval material;
- renderer network exfiltration is restricted;
- operation-specific native UI is consistent and tied to immutable backend state/prompt identity;
- native prompts use proper window modality/association where the supported platform allows it;
- anti-spam/admission controls reduce prompt-fatigue attacks.

## 25. Workstation lock / suspend / session switch

Lock, suspend, resume, and user-session changes invalidate assumptions about authorization lifetime, prompt ownership, and normal session continuity.

Policy is mandatory:

- active operation permits are logically revoked on workstation lock, suspend, and user/session switch;
- active application authorization contexts/attached PUAT are logically revoked and cleared when safe to do so;
- credential views are hidden/cleared according to privacy policy;
- pending native prompt approval is invalidated;
- a resumed system does not revive a pre-lock permit.

This revocation does **not** imply that an already-running native call has stopped. Worker reuse still requires `ExecutionQuiescence::Quiescent`; unresolved dispatch risk activates recovery policy as applicable.

## 26. Windows elevated broker authority

If Windows feasibility testing shows direct management requires elevation, the broker becomes the trusted authority for brokered operations.

It must own or enforce:

- FIDO session state;
- canonical worker registry;
- immutable operation intent;
- broker-owned native operation-specific consent;
- native PIN/UV collection;
- token state;
- device worker/handle;
- permit consumption;
- mutation outcome/quiescence/recovery state;
- broker-side singleton/recovery namespace as defined by ADR-013.

The unelevated client is a viewer/workflow starter only and is treated as potentially malicious same-user input.

UAC approval is not FIDO-operation approval.

The broker must remain safe even when a valid client requests arbitrary allowed workflows repeatedly; broker-owned approval/admission policy is authoritative.

## 27. Broker IPC / identity / lifecycle threats

Threats include:

- same-user process connects to or launches the broker;
- replay from an earlier broker launch;
- protocol downgrade/version skew;
- pipe squatting/server spoofing;
- client dies while broker retains authority;
- alternate-user over-the-shoulder elevation;
- state/journal follows the wrong user profile;
- writable install/DLL path;
- renderer-controlled inputs proxied through a valid client.

Mitigations/requirements:

- fixed typed bounded protocol;
- protocol/version negotiation;
- broker is the authenticated/validated server according to the selected Windows design;
- launch/session bootstrap binding not based on command-line secrecy;
- replay rejection/per-connection nonce/counters as appropriate;
- strict ACL/security descriptors suitable for the supported initiating-user/elevating-user model;
- no raw CTAP/path/library/executable/general filesystem/network commands;
- protected signed per-machine helper install where elevation is used;
- explicit broker lifetime/idle policy;
- explicit client-death behavior before/after possible dispatch;
- broker termination forbidden while unresolved execution/recovery state would be lost;
- authority singleton and recovery-journal namespace survive every supported elevation flow;
- unsupported elevation configurations fail clearly rather than silently weakening the model.

ADR-013 must decide whether alternate-credential elevation is supported for MVP. It must also decide broker singleton scope, IPC ACL principal, launch-binding mechanism, server verification, lifetime, client-death rules, and recovery-state storage.

## 28. macOS/Linux native process threats

On macOS/Linux, trusted FIDO policy may initially live in the native application process while the WebView remains untrusted.

This increases the importance of:

- strict Tauri command/event schemas/capabilities;
- no remote content/arbitrary network in the renderer;
- native UI thread correctness;
- explicit libfido2 timeouts/token cleanup;
- process-transparent worker interface;
- packaged application testing.

If the M1.5 containment spike shows hung native code or native allocation risk cannot be bounded acceptably, a separate worker process becomes the required deployment behind the same protocol before the affected sensitive milestone.

## 29. Network posture and updater placement

Core `fido-service` is network-free.

The WebView has no general-purpose HTTP authority.

Network-capable functionality is purpose-separated:

- updater;
- optional post-MVP export/provider helper.

Neither receives live CTAP handles, PIN/UV authorization, operation permits, or permission to initiate authenticator mutation.

Export/provider runs behind the separate helper boundary described below.

Updater network/process placement must be decided **before updater implementation**. Do not assume an in-process Tauri updater is acceptable merely because it has no CTAP command API; an HTTP/TLS/remote-parser stack in the native PIN-holding authority reintroduces attack-surface coupling.

An updater ADR must either:

- place update check/download in a separate process/helper without live CTAP authority; or
- explicitly justify an in-process design and its transitive risk on the affected platform.

## 30. Optional export/provider threat boundary

Provider isolation is not established merely by a Rust trait or crate.

A post-MVP export helper receives only:

- an immutable minimized export snapshot created after the relevant FIDO transaction and authorization context ended;
- approved destination/provider parameters;
- no live service reference;
- no device handle;
- no PIN/token;
- no operation permit;
- no CTAP authority.

Export approval must be bound to the exact payload/destination/provider if sensitive data leaves the machine.

The snapshot contains only user-selected data and has a defined lifecycle/erasure policy.

The provider must not return instructions that trigger FIDO workflows; the return channel is typed status/result data only.

Post-MVP defense in depth may sandbox/restrict the helper with platform mechanisms where practical.

## 31. BooGooCypher-specific unresolved trust decisions

BooGooCypher remains optional and excluded from MVP builds.

Before **implementation** decide explicitly:

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

Provider code is excluded from MVP artifacts at build time, not only disabled at runtime.

## 32. OS secret-store limitations

OS secret stores are preferred for provider credentials but are not equivalent to a hardware security boundary.

Their protection differs by platform and login/session state.

If the platform keyring is unavailable or locked, FidoManager must not fall back to plaintext credential storage.

## 33. Updater threat model

The updater can replace the security-critical executable and is therefore part of the transitive trust chain even though it has no live CTAP authority.

Before updater implementation, decide its process/network placement under section 29.

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
- native dependency patch/CVE cadence;
- pinned tagged libfido2 production release;
- Windows direct-management builds disable unneeded Windows Hello integration unless deliberately reviewed.

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

Recovery records/log metadata may preserve an opaque incident and historical `OutcomeUnknown` acknowledgement, but must remain privacy-minimized and secret-free.

## 36. Security acceptance scenarios

Before the relevant features ship, test at least:

- renderer invokes every sensitive workflow without intended UI;
- renderer floods simultaneous prompt requests;
- renderer repeatedly cancels/timeouts and re-requests prompts until cooldown triggers;
- stale/wrong-kind handle substitution;
- stale prompt callback arrives after a new workflow started;
- target changes while native PIN/approval is pending;
- lock/suspend/session switch after approval but before dispatch;
- disconnect after permit approval before dispatch;
- PUAT remains attached after an error/cancel (must fail the test);
- reconnect reuses an old native device object (must be impossible by construction);
- crash in journal `Pending` state;
- crash in `DispatchCapable` state;
- journal directory unwritable/full/fsync failure and dispatch is blocked;
- crash after dispatch before response recording;
- receive failure after possible successful mutation;
- confirmed mutation followed by failed refresh;
- reconnect with unresolved mutation uncertainty;
- application restart with recovery barrier;
- ordinary inspection attempted while unresolved PIN-change incident exists;
- cancellation followed by late native completion;
- reconciliation while native call remains blocked (must remain blocked until quiescence);
- two identical keys during reset;
- second key appears during timed reset stage;
- reset candidate replacement after ceremony grant;
- reset grant expiry/timed retry;
- two application launches;
- external browser/vendor contention;
- malformed counts/deceptive Unicode reaching native UI/native allocation paths;
- Windows broker replay/client death/alternate-user elevation according to supported configuration;
- export payload or destination changes after approval.

## 37. Security claims explicitly not made

FidoManager does not claim:

- protection against a fully compromised kernel/administrator environment;
- cryptographic proof that a reconnected key is the same physical key on all authenticators;
- perfect zeroization of every copy created by OS/native dependencies;
- complete serialization against browsers/vendor tools/other OS users;
- that native dialogs are universally unspoofable;
- that UIPI or elevation universally prevents same-user PIN observation;
- that a same-user recovery journal is tamper-proof against malicious same-user software;
- that signed binaries are automatically trustworthy without a trustworthy build pipeline.

## 38. Open security questions

1. Which exact tagged libfido2 release becomes the production pin after the fit spike, and which reference authenticators honor the intended PUAT scopes?
2. Which native UI implementation details pass packaged tests on macOS, Windows, X11 and Wayland?
3. Does the M1.5 containment spike require child-process workers on macOS/Linux before Milestone 2/3 or only before mutation support?
4. Which Windows initiating-user/elevating-user configurations are supported, and what broker singleton/bootstrap/journal model follows?
5. What measured reset timing/disconnect limits and device profiles are supported without implying physical identity?
6. What finite prompt/permit timeout and sequential-admission/cooldown constants should ship for Milestone 2?
7. What exact operation-specific recovery tables and acknowledgement UX safely clear `RecoveryAdmission::Barrier`?
8. What BooGoo encryption/key-wrapping trust model is acceptable post-MVP?
9. Which updater process placement and signing/update-key recovery process can maintainers realistically support?

These questions must be resolved through spikes/ADRs before the affected capability is considered production-ready.
