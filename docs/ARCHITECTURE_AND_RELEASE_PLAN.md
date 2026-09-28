# FidoManager Architecture and Release Plan

Status: Proposed  
Target: Initial architecture and security review  
Repository: `mbzbugsy/fidomanager`

## 1. Purpose

FidoManager is a local, vendor-neutral desktop application for inspecting and managing FIDO2 / CTAP authenticators.

The project addresses a practical gap between vendor-specific management applications, limited browser management UIs, and powerful but low-level CLI tooling.

The application must not assume support based on vendor identity. All behaviour should be driven by authenticator-reported capabilities.

## 2. Core principles

### Local first

Authenticator management must work locally and offline. The application must not require an account, backend service, cloud storage, telemetry, analytics, or remote configuration.

No authenticator information should leave the machine unless the user explicitly initiates an export or future update check that is documented and narrowly scoped.

### Vendor neutrality

Core logic must depend on FIDO / CTAP capabilities rather than manufacturer checks.

Vendor-specific extensions may be added later, but only behind explicit extension boundaries.

### Capability-driven UI

The UI must expose only operations supported by the connected authenticator. Unsupported operations should remain hidden or be explicitly shown as unavailable.

### Safe failure

Ambiguous device state, CTAP errors, transport errors, malformed responses, disconnects, and timeouts must fail closed.

The application must never infer success for a destructive operation.

### Minimal privilege

The frontend must not have shell access, unrestricted filesystem access, arbitrary network access, or direct HID/USB access.

### Transparent security

The project should remain open source. Security-sensitive boundaries must be documented well enough for independent review.

## 3. Proposed technology stack

### Desktop shell

Tauri 2.

Rationale:

- cross-platform desktop packaging;
- Rust backend;
- smaller runtime footprint than Electron;
- explicit permissions/capabilities model;
- good fit for a thin frontend and security-sensitive native core.

### Native backend

Rust stable.

Rust owns:

- authenticator discovery;
- CTAP transport integration;
- libfido2 integration;
- capability parsing;
- PIN operations;
- credential management;
- reset operations;
- device-session lifecycle;
- error normalization;
- per-device operation serialization.

### FIDO implementation

libfido2.

Do not reimplement CTAP framing, USB HID transport, or CBOR handling without a compelling reason.

A small Rust adapter should wrap only the libfido2 functionality used by FidoManager. The rest of the application must depend on internal Rust interfaces rather than raw libfido2 symbols.

### Frontend

Proposed:

- Svelte;
- TypeScript;
- pnpm.

The frontend is intentionally thin and must contain no authenticator protocol logic.

## 4. Repository structure

```text
fidomanager/
├── src/
│   ├── components/
│   ├── pages/
│   ├── stores/
│   └── lib/
├── src-tauri/
│   ├── src/
│   │   ├── main.rs
│   │   ├── commands/
│   │   └── state.rs
│   ├── capabilities/
│   └── tauri.conf.json
├── crates/
│   ├── fido-core/
│   │   ├── device.rs
│   │   ├── capabilities.rs
│   │   ├── credential.rs
│   │   ├── errors.rs
│   │   └── traits.rs
│   └── fido-libfido2/
│       ├── discovery.rs
│       ├── device.rs
│       ├── credential_management.rs
│       ├── pin.rs
│       ├── reset.rs
│       └── ffi/
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

## 5. Architectural layers

### Domain layer: `fido-core`

Contains platform-independent concepts such as:

- `Device`
- `DeviceCapabilities`
- `Credential`
- `RelyingParty`
- `PinStatus`
- `AuthenticatorVersion`
- stable application error types
- backend traits/interfaces

This crate must not depend on Tauri, USB/HID APIs, or libfido2.

### Transport / implementation layer: `fido-libfido2`

Responsibilities:

- enumerate authenticators;
- open and close authenticator sessions;
- query authenticator information;
- perform CTAP operations;
- translate libfido2 errors into stable domain errors;
- own FFI memory and lifecycle rules.

No layer above this should understand libfido2 pointers or native error constants.

### Application service layer: Tauri backend

Responsibilities:

- application state;
- device session lifecycle;
- operation queues;
- timeout/cancellation policy;
- reconnect handling;
- destructive-operation confirmation state;
- mapping domain values into frontend DTOs.

### Presentation layer

Responsibilities:

- device list;
- device details;
- credential browser;
- capability display;
- PIN dialogs;
- destructive-operation confirmation;
- accessibility;
- error presentation.

The presentation layer must never perform direct FIDO/HID operations.

## 6. Backend abstraction

Define a backend interface conceptually equivalent to:

```text
AuthenticatorBackend
    enumerate_devices()
    open_device()
    get_info()
    get_pin_status()
    enumerate_credentials()
    set_pin()
    change_pin()
    delete_credential()
    reset()
```

libfido2 provides the production implementation.

Tests use a fake backend.

This allows deterministic testing of disconnects, capability differences, protocol failures, retries, and destructive-operation state.

## 7. Device identity and privacy

Do not create persistent fingerprints for authenticators.

AAGUID identifies an authenticator model, not necessarily an individual device. USB paths may change across reconnects.

FidoManager should therefore use an ephemeral session-scoped internal device ID.

Persistent device identity must not be added without a concrete use case and explicit privacy review.

## 8. Device operation model

Operations must be serialized per physical authenticator.

Multiple concurrent CTAP operations against the same device can create ambiguous state and poor UX.

Recommended model:

```text
DeviceWorker
  └── queue
      ├── GetInfo
      ├── EnumerateCredentials
      ├── ChangePin
      ├── DeleteCredential
      └── Reset
```

Only one operation runs per authenticator. Different authenticators may operate concurrently.

Operations should support explicit timeouts and device-removal detection. Cancellation should be supported where technically possible.

## 9. MVP functionality

### Phase 1: read-only device inspection

- enumerate connected authenticators;
- display transport;
- display product/manufacturer strings where available;
- display AAGUID;
- display supported CTAP versions;
- display capabilities;
- display PIN state/capability and retry information where available;
- handle insertion, removal, reconnect, and unsupported operations.

No mutation operations in the first implementation milestone.

### Phase 2: credential inspection

Where supported:

- enumerate relying parties;
- enumerate discoverable/resident credentials;
- display RP and user metadata;
- display abbreviated credential IDs;
- refresh state after reconnects.

Still read-only.

### Phase 3: PIN management

- set PIN;
- change PIN;
- report retries and blocked state accurately;
- never persist PIN values.

### Phase 4: credential deletion

- explicit confirmation;
- display RP/account details;
- execute once;
- refresh authenticator state after completion;
- never optimistically report success.

### Phase 5: reset

Reset belongs in a dedicated Danger Zone.

Requirements:

1. explicit navigation;
2. clear destructive-impact text;
3. deliberate confirmation;
4. physical-presence flow required by the authenticator;
5. full device re-enumeration after completion.

## 10. Explicit non-goals for MVP

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
- vendor-specific features;
- NFC;
- BLE;
- remote device management;
- cloud synchronization.

These features must be evaluated separately after the CTAP core is stable.

## 11. PIN and secret handling

PIN handling is security-sensitive.

Rules:

- never write a PIN to disk;
- never log a PIN;
- never include it in panic messages or diagnostics;
- never cache it between operations;
- zeroize native/Rust buffers where practical;
- destroy native buffers immediately after use.

### WebView limitation

A Tauri frontend means a PIN temporarily exists in JavaScript memory, which cannot be reliably and deterministically zeroized.

For the MVP:

- use a password input;
- disable autocomplete;
- never place the PIN in persistent frontend state;
- send it directly to the backend;
- clear the UI field immediately;
- ensure IPC payloads are never logged.

This limitation is explicitly provisional and must be reviewed before 1.0.

If a compromised-renderer threat must be mitigated more strongly, native secure input or a non-WebView UI architecture must be evaluated.

## 12. Tauri security configuration

Production builds should use a restrictive Content Security Policy.

Conceptual baseline:

```text
default-src 'self'
script-src 'self'
style-src 'self'
img-src 'self' data:
connect-src 'none'
```

No remote JavaScript, remote fonts, arbitrary navigation, or iframe content.

Do not expose shell execution, unrestricted filesystem APIs, process spawning, arbitrary HTTP, or clipboard access without an explicit feature requirement.

Sensitive native commands must validate operation state server-side rather than trusting frontend state.

## 13. Network policy

Core FIDO management must require no network connection.

The frontend should have no general-purpose HTTP capability.

A future signed application-update check is the only expected network feature, and it must remain isolated from authenticator management and must not transmit authenticator identifiers.

## 14. Logging

Release builds should log minimally.

Never log:

- PINs;
- credential secret material;
- full credential identifiers by default;
- USB serial numbers by default;
- user IDs from credentials unless part of an explicit diagnostic export.

Prefer stable error categories such as:

- `TransportUnavailable`
- `DeviceRemoved`
- `PinInvalid`
- `PinBlocked`
- `OperationDenied`
- `UnsupportedOperation`
- `UserPresenceRequired`
- `CredentialNotFound`
- `ProtocolError`

## 15. Error handling

Raw libfido2 errors should never reach the frontend.

Map them into stable application errors containing only what the UI requires, for example:

```json
{
  "code": "PIN_INVALID",
  "user_message": "The PIN was not accepted.",
  "retryable": true
}
```

Technical context must never expose secrets.

## 16. Destructive operations

Credential deletion and reset must be isolated from ordinary inspection flows.

The frontend must never be the sole authority for whether a destructive operation is permitted. The backend must validate that a matching user confirmation state exists and has not expired.

The backend must reject stale or replayed destructive requests.

## 17. Testing strategy

### Unit tests

`fido-core` should comprehensively test:

- capability mapping;
- operation eligibility;
- error mapping;
- state transitions;
- destructive-operation eligibility.

### Backend integration tests

Use a fake authenticator backend to simulate:

- insertion/removal;
- wrong PIN;
- blocked PIN;
- unsupported credential management;
- timeout;
- user-presence timeout;
- credential removal between enumeration and deletion;
- reconnect with a different device.

### FFI tests

Validate:

- ownership;
- null handling;
- native string conversion;
- buffer lengths;
- error conversion;
- cleanup on early-return paths.

### UI tests

Use Playwright or equivalent for:

- keyboard navigation;
- screen sizes;
- destructive-operation dialogs;
- unsupported-capability presentation;
- offline operation.

### Hardware-in-the-loop testing

CI cannot replace real authenticators.

Maintain a manual compatibility matrix. Initial reference hardware is a Thetis FIDO2 key. Before 1.0, validate against at least one YubiKey and one independent additional vendor.

## 18. Compatibility matrix

Maintain `docs/DEVICE_COMPATIBILITY.md`.

Example:

```text
| Device | OS | Detection | Info | PIN | Credentials | Delete | Reset |
|--------|----|-----------|------|-----|-------------|--------|-------|
| Thetis | macOS ARM64 | ✅ | ✅ | TBD | TBD | TBD | TBD |
```

One successful device must never be treated as proof of protocol-wide compatibility.

## 19. libfido2 integration and supply chain

Do not download an unpinned native library at application launch.

Build dependencies must be reproducible.

Recommended release strategy:

- pin an approved libfido2 release;
- verify source archive checksum;
- build/package it in CI;
- record the exact version in build metadata;
- preserve all required third-party licence notices.

Users should not need to install Homebrew or system packages on macOS or Windows.

Shared libraries must load only from trusted application locations.

## 20. Platform rollout

### Stage A: macOS development target

Primary target:

- Apple Silicon macOS;
- Thetis authenticator.

Produce signed/notarized packages for public alpha.

Intel/universal builds may follow once the native dependency story is stable.

### Stage B: Windows

Initial target:

- Windows 11 x64.

Produce a signed installer.

Explicitly validate interaction with Windows Hello and platform authenticators so they are not accidentally exposed as manageable roaming keys unless intentionally supported.

### Stage C: Linux

Initial targets:

- Ubuntu LTS;
- current Fedora.

Validate hidraw access and udev behaviour. Missing permissions must produce a useful explanation rather than a generic device-not-found error.

## 21. CI pipeline

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
cargo test
```

### Security and dependency checks

- `cargo audit`;
- dependency policy check;
- lockfile verification;
- Tauri compile smoke test.

PR builds must never receive production signing credentials.

## 22. Release pipeline

Use semantic versioning.

Examples:

```text
0.1.0-alpha.1
0.1.0-beta.1
0.1.0
1.0.0
```

Release flow:

```text
main
  ↓
release candidate
  ↓
tag vX.Y.Z
  ↓
GitHub Actions native build matrix
  ↓
sign
  ↓
notarize where applicable
  ↓
generate checksums
  ↓
generate SBOM
  ↓
publish GitHub Release
```

Prefer native runners for each target OS rather than cross-compiling security-sensitive installers without a clear reason.

## 23. Signing

### macOS

Public releases should use:

- Developer ID signing;
- hardened runtime;
- Apple notarization.

Signing credentials must be available only to protected release jobs.

### Windows

Production installers must be Authenticode signed with an appropriate trusted code-signing solution.

Signing secrets must not be exposed to normal PR workflows.

### Linux

At minimum provide:

- SHA-256 checksums;
- signed release metadata where practical.

## 24. Updates

Do not enable silent automatic updates in the first alpha.

Initial releases should require explicit user-initiated installation.

When an updater is introduced:

- update artifacts must be cryptographically signed;
- updater signing keys must be backed up securely;
- updater signing must use credentials separate from OS code-signing identities;
- update endpoints must use HTTPS;
- forced updates should be reserved for a separately documented emergency policy.

Authenticator management must continue working if the update service is unavailable.

## 25. Release artifacts

Expected artifacts:

### macOS

- signed `.dmg` or equivalent package.

### Windows

- signed `.msi` or NSIS installer.

### Linux

- AppImage and/or `.deb` initially.

Additionally:

- `SHA256SUMS`;
- SBOM;
- release notes;
- third-party notices.

## 26. Build provenance

Record for each build:

- FidoManager git commit;
- Rust toolchain version;
- Node/pnpm version;
- Tauri version;
- libfido2 version;
- target triple.

Pin GitHub Actions dependencies used by the release pipeline.

Generate an SBOM in SPDX or CycloneDX format.

Consider provenance attestations before stable release.

## 27. Branching strategy

Keep the branch model simple:

```text
main       expected to build
feature/*  normal development
vX.Y.Z     immutable release tags
```

Use pull requests for changes to `main`. Require CI before merge once repository bootstrap is complete.

## 28. Security policy

Before public alpha add `SECURITY.md` defining:

- private vulnerability-reporting process;
- supported release versions;
- expected response times;
- coordinated disclosure policy.

Security reports must not require a public GitHub issue.

## 29. Licensing

Proposal: Apache-2.0.

Reasons:

- permissive;
- explicit patent grant;
- appropriate for infrastructure/security tooling.

Third-party licences must be preserved in `THIRD_PARTY_NOTICES.md`.

Before branding is finalized, separately verify trademark requirements around use of `FIDO` in the product name or public marketing.

## 30. ADRs to create early

- ADR-001: Desktop application rather than web/mobile
- ADR-002: Tauri 2 + Rust
- ADR-003: libfido2 as CTAP implementation
- ADR-004: vendor-neutral capability-driven core
- ADR-005: no cloud account and no telemetry
- ADR-006: no automatic updater during initial alpha
- ADR-007: WebView PIN-memory limitation accepted provisionally for MVP, subject to review before 1.0

## 31. Milestones

### Milestone 0 — Repository foundation

- licence;
- README;
- architecture document;
- security model;
- review prompt;
- Tauri skeleton;
- CI;
- dependency policy.

No device mutation.

### Milestone 1 — Read-only device inspection

- enumerate devices;
- insertion/removal handling;
- `GetInfo`;
- capabilities;
- AAGUID;
- versions;
- PIN capability/state.

### Milestone 2 — Credential inspection

- enumerate relying parties;
- enumerate discoverable credentials;
- account presentation;
- refresh behaviour.

Still read-only.

### Milestone 3 — PIN management

- set PIN;
- change PIN;
- retry/error handling;
- secret-handling review.

### Milestone 4 — Credential deletion

- confirmation flow;
- backend authorization of destructive operation;
- delete;
- refresh;
- hardware validation.

### Milestone 5 — Reset

- Danger Zone;
- deliberate confirmation;
- physical-presence flow;
- reconnect/recovery behaviour.

### Milestone 6 — Public alpha

- signed macOS build;
- security documentation;
- compatibility documentation;
- release SBOM;
- reproducible release workflow.

Windows and Linux validation expand after the macOS core is stable.

## 32. Pre-1.0 security gates

Version 1.0 must not ship until these have been explicitly reviewed:

1. Tauri/WebView PIN exposure.
2. IPC attack surface.
3. CSP and navigation policy.
4. libfido2 library loading.
5. DLL/dylib search paths.
6. updater trust model.
7. release signing.
8. destructive-action UX and replay resistance.
9. logging/redaction.
10. dependency supply chain.
11. platform-specific HID permissions.
12. vendor-neutral behaviour on multiple authenticators.

## 33. Review questions

External reviewers should specifically challenge:

1. Is Tauri an appropriate UI boundary for a security-key manager?
2. Should PIN entry use a native UI rather than a WebView?
3. Is libfido2 the correct abstraction boundary?
4. Should the project maintain direct C FFI or use an existing Rust binding?
5. Should libfido2 be statically or dynamically linked per platform?
6. Is the per-device serialized operation model correct?
7. Are reset and credential deletion sufficiently isolated?
8. Are device identity/privacy assumptions correct?
9. Is the CI/CD model sufficient for signed binaries?
10. Is delaying automatic updates until after alpha the correct trade-off?
11. Which CTAP features would be expensive to add later if the abstraction is wrong?
12. Which platform-specific behaviours are currently missing from the plan?
