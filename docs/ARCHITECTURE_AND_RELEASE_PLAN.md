# FidoManager Architecture and Release Plan

Status: Proposed, revision 2  
Target: Independent architecture and security review  
Repository: `mbzbugsy/fidomanager`

This revision incorporates the first independent security review. The principal architectural change is that the WebView is no longer trusted to collect authenticator PINs or to prove user consent for sensitive operations.

## 1. Purpose

FidoManager is a local, vendor-neutral desktop application for inspecting and managing FIDO2 / CTAP authenticators such as Thetis, YubiKey, Feitian and similar security keys.

The project addresses a practical gap between vendor-specific management tools, limited browser management UIs, and powerful but low-level CLI tooling.

The application must not infer support from vendor identity. Behaviour should be driven by authenticator capabilities, current device configuration, platform availability, adapter support, authorization requirements and application policy.

## 2. Core principles

### Local first

Core authenticator management must work offline and must not require an account, backend service, cloud storage, telemetry, analytics or remote configuration.

No authenticator information leaves the machine unless the user explicitly invokes a documented export or other optional network-backed feature.

### Vendor neutrality

Core logic depends on CTAP/FIDO semantics, not manufacturer checks.

Evidence-backed compatibility workarounds may exist behind a narrowly governed compatibility layer, but vendor identity must not become the core dispatch mechanism.

### Capability-driven, state-aware UI

The application must distinguish at least:

1. authenticator-advertised support;
2. current authenticator configuration;
3. adapter/library support;
4. OS/transport availability;
5. current authentication/authorization requirements;
6. application policy.

A single boolean such as `supportsCredentialManagement` is not sufficient to model all of those states.

Unknown CTAP versions/options must be preserved for diagnostics but must not automatically enable operations.

### Explicit trust boundaries

The Svelte/WebView renderer is presentation-only for sensitive workflows.

A compromised renderer is in scope. It must not be able to:

- obtain authenticator PINs through the legitimate workflow;
- manufacture proof of user consent for credential deletion, PIN mutation or reset;
- submit arbitrary device paths or raw CTAP commands;
- choose native library paths;
- gain generic network, filesystem, shell or process-spawn authority.

### Safe failure and explicit uncertainty

A timeout or disconnect after a mutation has been dispatched is not equivalent to failure.

FidoManager must model uncertain outcomes explicitly and must never automatically retry an operation whose completion is unknown.

### Minimal privilege

No renderer receives direct HID/USB access. Privileged platform access, if required, must be isolated behind the smallest practical native boundary.

### Transparent security

The project is open source. Security-sensitive architecture, secret handling, release provenance and destructive workflows must be documented for external review.

## 3. Proposed technology stack

### Desktop shell

Tauri 2.

Tauri is retained for cross-platform packaging and presentation, but it is not treated as the security policy layer.

### Native backend

Rust stable.

Rust owns:

- session and operation policy;
- authenticator discovery;
- libfido2 integration;
- capability/state mapping;
- native PIN/UV workflow orchestration;
- native final authorization for sensitive operations;
- per-device workers and complete transactions;
- reset state machines;
- explicit mutation outcomes;
- optional security-provider integrations;
- network access for approved backend-only features.

### FIDO implementation

libfido2 through a narrow project-owned safe Rust adapter over reviewed low-level bindings.

Do not reimplement CTAP framing, USB HID transport or CBOR handling without a compelling reason.

The selected binding strategy must preserve opaque native types, ownership rules, nullability, lengths, error mapping and the pinned native-library ABI/version policy.

### Frontend

- Svelte
- TypeScript
- pnpm

The frontend remains intentionally thin. It may display sanitized metadata and request workflows, but it does not own authenticator protocol logic, PINs, authorization tokens or destructive-operation approval.

## 4. Repository structure

```text
fidomanager/
├── src/                         # Svelte/WebView presentation
│   ├── components/
│   ├── pages/
│   ├── stores/
│   └── lib/
├── src-tauri/
│   ├── src/
│   │   ├── main.rs
│   │   ├── commands/            # narrow Tauri command adapter
│   │   └── state.rs
│   ├── capabilities/
│   └── tauri.conf.json
├── crates/
│   ├── fido-core/               # platform-independent domain model
│   ├── fido-service/            # workflows, policy, sessions, outcomes
│   ├── fido-native-ui/          # native PIN + sensitive confirmations
│   ├── fido-libfido2/           # safe adapter + low-level bindings
│   ├── fido-platform/           # platform-specific access/broker clients
│   └── security-providers/
│       └── boogoo/
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

The exact crate split may change after prototypes, but the trust boundaries should remain explicit.

## 5. Revised architecture

```text
Svelte / WebView
      │
      │ typed workflow requests + sanitized DTOs
      ▼
Tauri command adapter
      │
      │ caller/capability checks, payload validation,
      │ opaque handle resolution, rate/size limits
      ▼
fido-service
      │
      ├── session + policy state
      ├── operation reservation
      ├── mutation outcome tracking
      ├── native confirmation requests
      └── optional export orchestration
      │
      ├──────────────► Native interaction module
      │                 PIN/UV collection
      │                 final sensitive confirmation
      │
      ▼
Per-device worker
      │
      │ complete serialized transactions
      ▼
fido-libfido2
      │
      ▼
OS HID / platform transport
      │
      ▼
Authenticator
```

Optional network-backed security providers and the updater sit beside this path. Neither may issue CTAP mutations.

## 6. Domain layer: `fido-core`

`fido-core` contains platform-independent concepts and must not depend on Tauri, libfido2, USB/HID, BooGooCypher or networking.

Expected concepts include:

- `DeviceSessionId`
- `DeviceSnapshot`
- `AuthenticatorVersion`
- `CapabilityState`
- `RelyingParty`
- `RelyingPartyHash`
- `CredentialHandle`
- `CredentialMetadata`
- `AuthorizationRequirement`
- `OperationKind`
- `OperationOutcome`
- structured recovery actions
- stable application error types

Device/account strings are untrusted input and must retain enough structure to sanitize safely for display.

## 7. Application service layer: `fido-service`

`fido-service` owns the security-relevant workflows independently of Tauri.

Responsibilities:

- session creation/invalidation;
- opaque handle issuance/resolution;
- per-device operation reservation;
- authentication workflow orchestration;
- authorization scope/lifetime;
- native confirmation requests;
- complete transaction boundaries;
- cancellation and timeout semantics;
- outcome reconciliation;
- reset reconnect ceremony;
- policy decisions;
- export orchestration.

The service layer must be unit/integration testable without a WebView.

## 8. Tauri command boundary

Tauri commands are a narrow adapter, not business logic.

Rules:

- declare an explicit application-command permission manifest;
- explicitly select production capability files;
- validate caller context using framework-provided context rather than a caller-supplied label;
- use opaque session/credential handles instead of accepting authoritative device paths or credential metadata from the renderer;
- bound request size and request rate;
- reject stale handles;
- expose no `execute_ctap`, `open_device(path)`, `load_library`, generic HTTP, shell or arbitrary filesystem command;
- test direct hostile invocation of every sensitive command without the intended UI.

The renderer can request a workflow such as `begin_delete_credential(handle)` but cannot supply the final authorization decision.

## 9. Native interaction boundary

Sensitive user interaction must happen outside the WebView.

Native interaction is required for:

- authenticator PIN entry;
- PIN set/change input;
- final authorization of credential deletion;
- final authorization of authenticator reset;
- any future operation whose security property depends on proving deliberate user intent.

The operation description shown to the user must be constructed from backend-owned state, not renderer-provided labels.

Native UI does not claim universal protection from OS compromise, accessibility abuse or spoofing. The intended guarantee is narrower:

> The legitimate sensitive workflow neither exposes the PIN to JavaScript nor treats JavaScript as proof of user approval.

## 10. Authentication and authorization model

Separate these concepts explicitly:

1. PIN collection or built-in user verification;
2. PIN/UV authorization/token acquisition;
3. operation authorization scope;
4. PIN modification.

Credential inspection may require authentication even though it does not intentionally mutate credential state. Therefore secret-handling and authorization design must exist before credential enumeration is implemented.

Rules:

- reserve the device transaction before collecting sensitive authentication where practical;
- request the minimum appropriate authorization scope;
- keep PIN/UV tokens entirely native;
- expire/invalidate authorization contexts explicitly;
- never persist PIN/UV tokens to disk in the MVP;
- never automatically retry an incorrect PIN;
- do not silently set a PIN to unlock management features;
- distinguish PIN, UV and operation-specific authorization requirements.

## 11. Secret handling

Protected material includes more than PIN text:

- PIN input;
- PIN/UV tokens;
- PIN-derived values;
- provider API credentials;
- encryption/data keys;
- secret-bearing CTAP extension data such as keys returned for other protocol features.

Rules:

- do not expose secret values to the renderer;
- do not persist PINs or PIN/UV tokens;
- minimize copies;
- use owned zeroizing buffers in Rust where practical;
- audit native-library copies and cleanup;
- never include secrets in logs, tracing, panic formatting or diagnostic exports;
- reject embedded NULs before C-string boundaries;
- apply protocol-correct text/byte validation rather than JavaScript string-length assumptions;
- document that OS paging, hibernation and crash collection prevent a universal guarantee that sensitive bytes never reach storage.

## 12. Device identity and privacy

Default identity remains session-scoped and ephemeral.

AAGUID, product strings, VID/PID and USB paths are useful metadata but are not proof that a reconnected device is the same physical authenticator.

Persistent fingerprints are not introduced for MVP.

If persistent aliases or inventory are added later they require explicit privacy review and must never be confused with cryptographic proof of physical continuity.

## 13. Per-device worker and transaction model

One worker owns one live native device handle and its authorization context.

Serialize complete transactions, not individual library calls.

Example:

```text
Credential inspection transaction
  reserve worker
  → collect/authenticate natively
  → acquire scoped authorization
  → enumerate RPs
  → enumerate credentials
  → release/erase authorization
  → publish sanitized result
```

Rules:

- no background polling may interleave with stateful enumeration;
- queues are bounded;
- stale requests expire before execution;
- approved mutations may not sit indefinitely in a queue;
- cancellation must not simply drop an async future while the native call continues;
- the worker is not released to another operation until a blocking native call has actually completed or been reconciled;
- multiple FidoManager instances must be considered;
- browsers/vendor tools are external actors whose access cannot be fully serialized by FidoManager.

## 14. Mutation outcome model

Every mutation returns one of at least four semantic outcomes:

| Outcome | Meaning |
| --- | --- |
| `NotDispatched` | No mutation request reached the authenticator. |
| `Rejected` | A definitive rejection was received. |
| `ConfirmedSuccessful` | A success response was received. |
| `OutcomeUnknown` | Dispatch may have occurred but completion cannot be established. |

For `OutcomeUnknown`:

- never retry automatically;
- block further mutations for that session until reconciliation or deliberate recovery;
- communicate uncertainty explicitly;
- use read-back where meaningful without pretending it proves which actor caused state;
- after an uncertain PIN change, never automatically test both old and new PINs.

Error handling should use structured recovery actions such as:

- `AskForPin`
- `Reauthenticate`
- `PowerCycleRequired`
- `WaitForDevice`
- `ReconcileOutcome`
- `ManualRecoveryRequired`

A generic `retryable: true` is insufficient for sensitive operations.

## 15. Capability and availability model

Represent these dimensions separately:

```text
advertised_support
current_configuration
adapter_support
platform_availability
authorization_requirement
application_policy
```

Do not model CTAP evolution as a simple numeric version ladder. Preserve unknown version/option strings and negotiate explicit operation support.

Reserve architecture for:

- permission-scoped PIN/UV authorization;
- built-in UV independent of PIN text;
- credential-management variants;
- persistent or read-only authorization modes where supported;
- structured PIN policy/configuration;
- future reset/configuration requirements.

## 16. Credential-management data model

The domain model must retain both textual and binary RP identity material where available.

At minimum preserve:

- original RP ID hash;
- optional RP ID text;
- optional display name;
- completeness/validation status.

Do not assume a returned RP ID string is always complete enough to recompute the authoritative hash.

Before implementing credential enumeration, verify the selected libfido2 release exposes the required RP-hash semantics. If it does not, choose one of:

1. an upstream-supported API;
2. a narrowly reviewed project patch while pursuing upstream support;
3. an explicit product limitation.

Unsupported/incomplete enumeration must never be presented as an empty authenticator.

## 17. Destructive workflow authorization

Credential deletion and reset require native, operation-specific authorization.

A destructive workflow should:

1. resolve the renderer's opaque target to backend-owned state;
2. reserve the device operation slot;
3. construct the exact operation description from backend state;
4. present native operation-specific confirmation;
5. collect required authentication natively;
6. revalidate session continuity and authorization;
7. consume the approval exactly once;
8. execute the operation;
9. return a confirmed or explicitly uncertain outcome.

There must be no IPC equivalent to `confirm(id, true)` that can be invoked by renderer code to prove consent.

## 18. Credential deletion semantics

Deletion confirmation should display trustworthy backend-owned RP/account context and explain:

- the credential on the authenticator will be deleted;
- deleting it locally does not remove the registration from the website/service;
- enumeration may be incomplete on unsupported devices;
- no automatic retry occurs after an uncertain result.

After confirmed deletion, refresh device state.

## 19. Reset state machine

Reset is a separate workflow, not a normal mutation with generic reconnect handling.

Reset may require device-specific timing/power-cycle behaviour. The workflow must model explicit states such as:

```text
Idle
→ AwaitingNativeConfirmation
→ AwaitingExpectedDisconnect
→ AwaitingCandidateReconnect
→ AwaitingFreshCandidateConfirmation
→ ExecutingReset
→ Confirmed / OutcomeUnknown / Failed
```

Rules:

- never transfer authorization automatically to a same-model replacement;
- if multiple candidate devices make selection ambiguous, stop;
- prefer a single connected candidate during reset where practical;
- require fresh native confirmation of the reconnected candidate;
- state clearly that FidoManager cannot cryptographically prove physical continuity for every authenticator;
- reset warnings must cover credentials the application cannot enumerate;
- describe the operation as a FIDO reset and do not imply unrelated PIV/OTP/OpenPGP applications are reset unless separately verified.

## 20. MVP and implementation milestones

### Milestone 0 — Repository foundation

- architecture/security documentation;
- ADR skeleton;
- Tauri/Rust/Svelte bootstrap;
- CI/dependency policy;
- no device mutation.

### Milestone 1 — Read-only device discovery

- enumerate roaming authenticators;
- insertion/removal handling;
- `GetInfo`;
- AAGUID and transport;
- raw/normalized capability state;
- version/option preservation;
- no PIN collection;
- no credential enumeration.

This milestone may proceed while sensitive workflows are still under review.

### Milestone 2 — Native authentication foundation

Before credential inspection:

- native PIN/UV interaction module;
- scoped authorization model;
- token lifetime/invalidation;
- secret lifecycle tests;
- no automatic wrong-PIN retry;
- worker transaction reservation;
- hostile-renderer tests proving PIN is not available to WebView.

### Milestone 3 — Credential inspection

- authenticated bounded inspection transaction;
- enumerate RPs/credentials where fully supported;
- preserve RP hash + optional text;
- sanitize metadata;
- clear views/authorization on disconnect;
- explicit incomplete/unsupported states.

### Milestone 4 — PIN management

- set/change PIN through native interaction;
- structured retry/block/policy errors;
- explicit uncertain-outcome handling;
- no mutation release until native call finishes/reconciles.

### Milestone 5 — Credential deletion

- native final confirmation;
- backend-owned target description;
- one-shot authorization;
- stale/replay/race tests;
- uncertain-outcome semantics;
- real hardware validation on at least two independent authenticator implementations before a public mutation-capable build.

### Milestone 6 — Reset

- dedicated reset state machine;
- reconnect ambiguity handling;
- device-specific reset requirements;
- native re-confirmation after reconnect;
- sacrificial hardware tests only.

### Milestone 7 — Public alpha

A public alpha may expose only features whose security gates have passed.

Required before any mutation-capable alpha:

- renderer/IPC boundary review;
- native auth/confirmation review;
- platform process/elevation design;
- packaged-app security tests;
- signed build;
- security policy and advisory channel;
- SBOM and traceable build metadata;
- compatibility claim limited to hardware actually tested.

## 21. Explicit non-goals for initial MVP

Do not initially implement:

- passkey creation;
- WebAuthn login;
- SSH key management;
- PIV;
- OpenPGP;
- OTP/TOTP/HOTP;
- firmware updates;
- biometric enrollment;
- enterprise attestation configuration;
- NFC;
- BLE;
- remote device management;
- cloud synchronization;
- BooGooCypher in the initial FIDO MVP.

## 22. libfido2 / FFI policy

Use a narrow project-owned safe adapter over reviewed generated low-level bindings or a reviewed `-sys` crate.

Required properties:

- opaque native types;
- RAII ownership and documented free/close order;
- no borrowed pointer outliving its owner;
- checked lengths/counts/nullability/integer conversions;
- explicit embedded-NUL handling;
- no implicit `Send`/`Sync` assumptions;
- no unwinding across C callbacks;
- no raw pointers or secret native structures in frontend DTOs;
- documented native-library version and ABI policy.

Review `build.rs`, native acquisition, bindgen inputs, compiler flags, optional features and transitive native libraries.

Pin an approved libfido2 release. Do not download native libraries at application runtime.

## 23. Linking strategy

Initial preference, subject to platform validation:

### macOS

Prefer a bundled/static libfido2 arrangement where practical, with system Apple frameworks dynamically linked. Do not ship Homebrew build-machine paths.

### Windows

Prefer static libfido2 where practical to reduce private DLL loading complexity. Remaining runtime DLL loads still require audit.

### Linux

- distro packages (`.deb`/`.rpm`): prefer system shared libraries with explicit minimum versions;
- portable bundles: controlled bundled non-system dependencies with a documented patch/update obligation.

Static linking does not remove the obligation to track native dependency vulnerabilities.

## 24. Windows privilege/elevation feasibility gate

Windows process architecture is not considered final until an early Windows 11 spike verifies the exact access requirements for:

- enumeration;
- credential management;
- PIN operations;
- reset.

If privileged direct HID access is required, do not elevate the Tauri/WebView process.

Use a small on-demand native broker with:

- fixed typed operation protocol;
- authenticated local IPC;
- strict peer/session validation;
- no raw CTAP command interface;
- no arbitrary paths/DLL/executable input;
- native authorization inside the trusted operation path;
- minimal privileges and lifetime.

The broker boundary must be decided before substantial Windows-specific UI investment.

## 25. Tauri/WebView hardening

Production builds require:

- no remote JavaScript or remote fonts;
- restrictive CSP matched to the pinned Tauri IPC mechanism;
- constrained forms, frames, objects, navigation, new windows, downloads and custom protocols;
- no arbitrary external URL opening;
- explicit app-command permission manifest;
- no generic HTTP in the renderer;
- no shell/process-spawn access;
- no unrestricted filesystem/clipboard capability;
- no renderer-controlled update URLs, provider URLs or trust keys.

CSP is defense-in-depth, not the sole outbound-network sandbox.

## 26. Logging and diagnostics

Release logging is minimal.

Never log:

- PINs or PIN/UV tokens;
- provider API credentials;
- encryption keys;
- raw secret-bearing CTAP payloads;
- full credential IDs by default;
- USB serial numbers by default;
- RP/user metadata by default.

Diagnostic export must be explicit, previewable and redacted by default.

Treat metadata as ephemeral where practical. Clear credential views on disconnect and consider lock/inactivity clearing before public release.

Do not fetch RP favicons/logos because doing so could disclose account relationships.

## 27. Testing strategy

### Unit/property tests

Test:

- capability/state mapping;
- handle/session invalidation;
- authorization scope/lifetime;
- one-shot approval consumption;
- outcome transitions;
- queue expiry;
- reset state machine;
- export/provider isolation.

### Fake-backend integration tests

Simulate:

- insertion/removal;
- wrong PIN and block states;
- timeout/user-presence timeout;
- mutation success with lost response;
- stale/replayed/reordered requests;
- credential disappearance between enumeration and deletion;
- reconnect with another identical model;
- competing client changes;
- suspend/resume/session lock.

### Real adapter/native tests

Add:

- transport-level fault injection;
- sanitizer/instrumented native-library tests where practical;
- malformed-device response handling;
- FFI ownership/null/length cleanup tests;
- packaged-app tests for real IPC, navigation and library loading.

### Hostile renderer tests

Directly invoke every sensitive Tauri command without using intended UI and prove that renderer code cannot:

- obtain PINs;
- approve a destructive operation;
- replace a target credential/device;
- replay stale approvals;
- access provider/updater secrets.

### Hardware testing

Use dedicated sacrificial keys for destructive tests.

Before any public deletion/reset support, validate at least two independent authenticator implementations.

Never identify a destructive test target solely by model name.

## 28. Compatibility matrix

Maintain `docs/DEVICE_COMPATIBILITY.md` by exact tested combinations where practical:

- device/model;
- firmware;
- OS/version/architecture;
- detection;
- capability parsing;
- authentication;
- credential enumeration;
- PIN operations;
- deletion;
- reset;
- known limitations.

A successful Thetis test does not imply protocol-wide compatibility.

## 29. Optional BooGooCypher integration

BooGooCypher is a possible post-MVP provider for encrypted exports and explicitly user-initiated protected data flows.

It is not part of the FIDO management trust path and must never be required for ordinary authenticator management.

### Boundary

```text
fido-service
   │
   └── export orchestration
          │
          ▼
   EncryptionProvider
          │
          └── BooGooCypher client ──HTTPS──► BooGooCypher API
```

The renderer never calls BooGooCypher directly.

The FIDO core must not depend on BooGoo endpoints, headers, wire formats or availability.

### Reasonable future uses

- encrypted diagnostic exports;
- encrypted device-information reports;
- protected FidoManager configuration backups;
- compatibility/audit bundles;
- future metadata exports.

FidoManager must never claim to export/back up non-exportable FIDO private credential keys.

### Provider credential handling

If persistent API credentials such as `X-BooGoo-Key` are required, store them only through OS-protected secret storage:

- macOS Keychain;
- Windows Credential Manager / DPAPI-backed mechanisms;
- Linux Secret Service/keyring where available.

Provider credentials never cross into the WebView and never grant CTAP mutation authority.

### Network/provider policy

- provider disabled by default;
- local/LAN and remote HTTPS deployments use the same provider abstraction;
- endpoint is explicit and constrained;
- redirects, proxy behaviour, TLS validation and certificate errors require review;
- provider failure affects only the requested provider feature;
- core management remains offline-capable;
- updater and BooGoo trust roots/configuration remain separate.

### Data minimization

Encryption is not justification for collecting or persisting unnecessary metadata.

Prefer:

1. do not store it;
2. minimize it;
3. encrypt only legitimate retained/exported data.

### Future hardware-bound export research

A later design may investigate authenticator-supported mechanisms such as `hmac-secret` to derive/unwrap export protection keys.

This requires a separate ADR/security review covering:

- capability requirements;
- recovery after key loss/reset;
- multi-key recovery;
- salt/context binding;
- replay/cloning assumptions;
- rotation;
- portability/vendor neutrality;
- explicit unrecoverability warnings.

It is not part of MVP or the first BooGoo integration.

## 30. Network policy

Core authenticator operations require no network connection.

Only narrowly scoped backend modules may use networking:

- future signed update checks;
- explicitly enabled security providers such as BooGooCypher.

Neither may transmit authenticator metadata unless the user explicitly selected that data for export.

Network authority must not be shared with the FIDO operation layer.

## 31. Platform rollout

### macOS first

Primary development target:

- Apple Silicon macOS;
- Thetis authenticator.

Validate the packaged, quarantined/notarized application, not just development builds. Test hubs, reconnects, sleep/wake and minimum supported macOS.

### Windows second, but architecture spike early

Run the privilege/access feasibility spike before freezing cross-platform process boundaries.

Target Windows 11 x64 initially.

### Linux

Initial targets:

- Ubuntu LTS;
- current Fedora.

Distinguish access denied from device absent. Do not solve HID access by running the application as root or making all hidraw devices world writable.

Installation of system access rules is a separate administrative action.

## 32. CI pipeline

Every pull request should run:

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
cargo clippy -- -D warnings
cargo test --locked
```

### Security/build

- dependency policy/audit checks;
- lockfile verification;
- native dependency/version checks;
- Tauri compile/package smoke tests where practical;
- secret scanning;
- test that production capability manifests contain only expected commands.

Pin GitHub Actions by full commit SHA for release-sensitive workflows.

PR jobs never receive production signing or BooGoo credentials.

Do not execute untrusted PR code in privileged release contexts.

## 33. Release pipeline

Use semantic versioning.

```text
main
  ↓
approved release commit
  ↓
tag vX.Y.Z
  ↓
native OS build jobs
  ↓
artifact digest handoff
  ↓
isolated signing/notarization
  ↓
final checksums + SBOM + provenance
  ↓
GitHub Release
```

Requirements:

- release tags resolve to reviewed commits;
- protected release environments;
- minimal job token permissions;
- untrusted caches/artifacts are not blindly promoted into signing jobs;
- signing is bound to expected artifact digests;
- final checksums are generated after all artifact-changing steps.

## 34. Signing and packaging

### macOS

- Developer ID signing;
- Hardened Runtime;
- minimal entitlements;
- no release debugger entitlement;
- notarization and ticket stapling;
- validate nested helpers/libraries and final distributable.

### Windows

- Authenticode-sign binaries/helpers/installers;
- timestamp signatures;
- test clean install, upgrade, repair, uninstall and failure recovery;
- audit DLL search/loading even when libfido2 is statically linked;
- define WebView2 runtime servicing strategy.

### Linux

- checksums plus authenticated release metadata;
- define supported package/distro/runtime matrix;
- package-specific dependency/update policy.

## 35. Updater strategy

No silent automatic updater in initial alpha.

Alpha still requires:

- supported-version policy;
- authenticated download path;
- security-advisory channel;
- maintainer response process;
- practical urgent-fix distribution path.

Before an updater ships:

- trusted update public key bundled with app;
- signatures bound to application/version/platform/architecture/channel;
- downgrade prevention owned by Rust policy;
- key rotation and compromise recovery;
- atomic installation/interrupted-update recovery;
- updater blocked during active authenticator operations;
- no renderer-controlled URL/key/version comparator;
- no authenticator metadata in update requests.

Updater signing keys remain separate from OS code-signing identities and from BooGoo credentials.

## 36. Build provenance and SBOM

Record per artifact:

- source commit/tag;
- Rust toolchain;
- Node/pnpm;
- Tauri and plugins;
- libfido2 and native transitive dependency versions;
- compiler/SDK/build options;
- target architecture.

Generate an SBOM for the actual shipped artifact including bundled native libraries/helpers.

Distinguish:

- traceable build;
- repeatable build;
- bit-reproducible build.

Do not claim bit reproducibility merely because versions are pinned.

## 37. Security policy

Before public alpha add `SECURITY.md` with:

- private vulnerability reporting;
- supported versions;
- response targets;
- coordinated disclosure policy;
- advisory/urgent update communication path.

## 38. Branching strategy

```text
main       expected to build
feature/*  normal development
vX.Y.Z     immutable release tags
```

Use pull requests for implementation changes to `main` once bootstrap is complete. Require relevant CI before merge.

## 39. ADRs to create early

- ADR-001: desktop rather than web/mobile
- ADR-002: Tauri 2 + Rust presentation/native split
- ADR-003: libfido2 as CTAP implementation
- ADR-004: vendor-neutral capability/state model
- ADR-005: no cloud account and no telemetry
- ADR-006: no automatic updater during initial alpha
- ADR-007: native PIN/UV and native final confirmation; renderer not trusted for consent
- ADR-008: optional security-provider architecture; BooGooCypher outside core trust path
- ADR-009: `fido-service` owns workflows/policy independently of Tauri
- ADR-010: per-device worker serializes complete transactions
- ADR-011: explicit `OutcomeUnknown` mutation semantics
- ADR-012: reset uses a dedicated reconnect state machine
- ADR-013: Windows elevation/broker decision after feasibility spike
- ADR-014: FFI/binding and per-platform linking policy
- ADR-015: updater trust root and downgrade policy

## 40. Security gates

Sensitive functionality must not wait until 1.0 for review.

### Before credential inspection

- native PIN/UV path;
- secret lifecycle;
- authorization-token scope/lifetime;
- complete transaction serialization;
- RP hash/API semantics verified.

### Before any public mutation capability

- native operation-specific confirmation;
- hostile-renderer invocation tests;
- outcome-unknown handling;
- cancellation semantics;
- packaged-app IPC/navigation/library-loading review;
- at least two independent authenticator implementations tested;
- platform privilege model settled for that OS.

### Before reset

- reset state machine and reconnect ambiguity handling;
- sacrificial-hardware validation;
- warnings cover credentials not visible in enumeration.

### Before BooGoo public support

- provider interface review;
- exact exported fields documented;
- OS secret-store behaviour tested;
- TLS/endpoint/proxy/redirect policy reviewed;
- provider secrets proven absent from renderer;
- offline regression suite;
- security model includes provider/network boundary.

### Before updater

- trust root, downgrade policy, rotation/recovery, atomic install and active-operation exclusion reviewed.

## 41. Review questions for the next independent reviewers

1. Does the revised native PIN/native confirmation boundary adequately address a compromised renderer?
2. Is `fido-service` the correct owner of session, authorization and operation policy?
3. Are complete-transaction serialization and cancellation semantics sufficient?
4. Is the four-state mutation outcome model complete enough?
5. Is the reset reconnect state machine safe when identical keys are present?
6. Does the RP-hash/domain model avoid premature coupling to a libfido2 API limitation?
7. Is the proposed project-owned safe FFI adapter appropriate, or should another binding strategy be preferred?
8. Is the preliminary linking strategy sound per platform?
9. What must the early Windows feasibility spike prove before the process architecture is frozen?
10. Are the Tauri command restrictions and hostile-renderer tests sufficient?
11. Which CTAP capabilities/options still require architectural reservation before implementation?
12. Are public-alpha gates placed early enough?
13. Is the optional BooGooCypher boundary sufficient to preserve offline/local-first FIDO management?
14. Should encrypted export use a provider-independent envelope before provider-specific encryption?
15. Are provider credentials and updater trust roots sufficiently separated?
16. Which remaining assumptions are unsafe or insufficiently justified?
