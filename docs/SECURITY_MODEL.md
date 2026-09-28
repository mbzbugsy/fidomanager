# FidoManager Security Model

Status: Initial draft for architecture review

## 1. Security objective

FidoManager is intended to manage real FIDO2/CTAP authenticators without introducing unnecessary trust, persistence, or network dependencies.

The application should reduce management friction without weakening the security properties of the authenticator itself.

## 2. Trust boundaries

The primary trust boundaries are:

1. User ↔ UI
2. WebView frontend ↔ Tauri command boundary
3. Tauri application layer ↔ Rust domain layer
4. Rust domain layer ↔ libfido2 adapter
5. libfido2 ↔ operating-system HID/USB stack
6. operating system ↔ physical authenticator
7. release pipeline ↔ distributed application binary

Each boundary should be treated explicitly rather than assuming the desktop process is uniformly trusted.

## 3. Assets to protect

FidoManager must protect:

- authenticator PINs;
- authenticator operation intent;
- credential metadata;
- account/user metadata stored in discoverable credentials;
- authenticator identifiers where exposed;
- integrity of destructive-operation confirmations;
- integrity of application binaries and updates;
- signing keys and release credentials.

FidoManager must not expose authenticator private keys. Standard FIDO authenticators are expected to keep those keys non-exportable.

## 4. Threats in scope

### Malicious or compromised renderer

A compromised WebView could attempt to invoke privileged Tauri commands directly.

Mitigations:

- strict CSP;
- no remote content;
- minimal Tauri permissions;
- backend validation for all sensitive operations;
- no destructive command accepted solely because the frontend requested it;
- confirmation state held or verified in the backend;
- no shell/process/network capability exposed to the renderer.

### IPC misuse or replay

A malicious frontend could replay or forge a prior destructive request.

Mitigations:

- backend-issued short-lived operation tokens/nonces for destructive actions;
- bind confirmations to device session, operation type, and target credential;
- single-use confirmation state;
- reject stale confirmation state after disconnect/reconnect.

### PIN disclosure

A PIN may be exposed through UI state, logs, crashes, diagnostics, or long-lived memory.

Mitigations:

- never persist PINs;
- never log IPC payloads containing PINs;
- avoid global frontend state for PINs;
- clear UI fields immediately after dispatch;
- zeroize Rust/native buffers where practical;
- avoid including PIN values in error strings, panic output, telemetry, or diagnostics.

Known limitation: JavaScript strings in a WebView cannot be deterministically zeroized. This remains an explicit pre-1.0 review item.

### Device confusion

A device could be removed and another inserted while an operation is pending.

Mitigations:

- session-scoped device IDs;
- invalidate destructive confirmation state on disconnect;
- re-open and re-validate device identity/capabilities before mutation;
- serialize operations per device.

### DLL/dylib hijacking

Native library loading can become an attack path if search paths are broad or writable.

Mitigations:

- load bundled libraries only from trusted application locations;
- avoid runtime downloads;
- pin and verify native dependencies;
- document per-platform loading rules;
- review rpath/DLL search behaviour before release.

### Supply-chain compromise

Dependencies, CI actions, or release workflows could be altered.

Mitigations:

- dependency lockfiles;
- pinned GitHub Actions;
- cargo audit/dependency policy checks;
- checksums for native source archives;
- SBOM generation;
- signing credentials restricted to protected release workflows;
- no signing credentials in PR jobs.

### Malicious update

A compromised updater or release endpoint could distribute attacker-controlled binaries.

Mitigations:

- no silent updater in initial alpha;
- cryptographically signed update artifacts when updater is introduced;
- updater signing key separate from OS code-signing credentials;
- HTTPS transport;
- explicit release provenance.

## 5. Threats not solved by FidoManager

FidoManager cannot protect against a fully compromised operating system with arbitrary process-memory access or kernel-level control.

It also cannot make a malicious authenticator trustworthy.

A connected authenticator is treated as an external device that may return malformed, unsupported, or unexpected data. All responses must therefore be parsed defensively.

## 6. Destructive operations

Credential deletion and authenticator reset require a stronger interaction model than read-only inspection.

### Credential deletion

The backend must verify:

- target device session is still valid;
- target credential belongs to the current enumeration state;
- user confirmation is fresh and operation-specific;
- the request has not already been consumed.

After deletion, state must be re-read from the authenticator.

### Reset

Reset must require:

- dedicated Danger Zone;
- explicit impact statement;
- deliberate confirmation;
- fresh backend confirmation state;
- required physical user presence;
- re-enumeration after completion.

The application must never report reset success before the authenticator confirms completion.

## 7. Logging and diagnostics

Release logging should be minimal.

Do not log:

- PINs;
- full credential IDs by default;
- discoverable user metadata by default;
- authenticator serial numbers by default;
- raw CTAP payloads containing sensitive metadata.

A future diagnostic export should be explicit, previewable, and redact sensitive data by default.

## 8. Network posture

Core authenticator management must function offline.

The frontend should not have arbitrary network access.

If update checks are added later, they must be isolated from authenticator data and must not include device identifiers.

## 9. Release trust

Public binaries should be signed and reproducible enough to identify the exact source revision and dependency versions used.

Expected release metadata:

- source commit;
- version tag;
- target triple;
- Rust toolchain;
- Node/pnpm version;
- Tauri version;
- libfido2 version;
- checksums;
- SBOM.

## 10. Open security questions

The following decisions are intentionally unresolved and require review:

1. Is a Tauri/WebView renderer acceptable for PIN entry?
2. Should PIN entry be implemented in native UI instead?
3. Direct libfido2 C FFI vs maintained Rust binding?
4. Static vs dynamic libfido2 linking per platform?
5. Best mechanism for backend-issued destructive-operation confirmation tokens?
6. Whether platform authenticators should ever be exposed in the same UI as roaming security keys?
7. Updater design and key management before stable release.
8. Minimum required sandboxing/hardening settings per operating system.

These questions should be resolved through ADRs rather than informal implementation decisions.
