# Fido Manager Product Roadmap

Status: active product roadmap  
Scope: macOS-first security-key management platform  
Principle: vendor parity is the floor; Fido Manager should go beyond vendor tools in inspection quality, trust boundaries, destructive-operation clarity, diagnostics, recovery semantics, and cross-vendor support.

## 1. Product direction

Fido Manager is evolving from a focused FIDO2 manager into a vendor-neutral security-key management platform.

The long-term product model is:

```text
Physical Security Key
|
+-- Device identity / presentation
|
+-- Transports
|   +-- USB
|   +-- NFC
|
+-- Applications
|   +-- FIDO2 / U2F
|   +-- PIV
|   +-- OATH
|   +-- OpenPGP
|   +-- OTP
|   +-- YubiHSM Auth
|   +-- other standard/vendor applications
|
+-- Per-application state
    +-- Supported
    +-- Enabled
    +-- Reachable
    +-- Manageable
    +-- Credentials / keys
    +-- Authentication / administration secrets
    +-- Reset domain
```

The application must distinguish physical-device state from application state. A key can contain multiple independent security applications with separate secrets, storage, mutation semantics, and reset domains.

## 2. Product principles

### 2.1 Parity plus

Where a supported vendor application exposes useful management functionality, Fido Manager should aim for at least equivalent capability and then add stronger inspection, validation, safety, and diagnostics.

Yubico Authenticator is a useful reference implementation, not a product ceiling.

### 2.2 Standard core, vendor extensions

Standards-based functionality belongs in protocol-specific core modules.

Vendor-specific functionality belongs behind explicit adapters/extensions.

Examples:

- FIDO2 credential management belongs in the FIDO/CTAP core.
- Standard PIV belongs in a PIV core.
- YubiKey application toggles and YubiKey-specific PIV extensions belong in a Yubico adapter.
- Thetis-specific management belongs in a Thetis adapter if and when an exposed management interface is verified.

The core must never infer behavior from brand/model when protocol capability evidence exists.

### 2.3 Application-scoped authority

Do not use a generic "security key PIN" abstraction.

Distinct secrets and authority domains remain distinct:

```text
FIDO2 PIN
!= PIV PIN
!= PIV PUK
!= PIV Management Key
!= OATH password
!= OpenPGP user/admin PIN
```

Reset is also application-scoped unless a device explicitly exposes a verified whole-device factory reset.

UI wording should prefer:

- Reset FIDO2...
- Reset PIV...
- Reset OATH...

rather than an ambiguous "Factory reset key".

### 2.4 Renderer is not authority

Existing security invariants continue to apply as the product expands:

- renderer/WebView never handles secret PIN/PUK/management-key material;
- renderer never creates approval evidence;
- sensitive prompts and operation identity are backend/native owned;
- exact device/application/generation/epoch binding is mandatory for mutation;
- operation outcome and execution quiescence remain separate concepts;
- uncertainty is represented explicitly rather than guessed away;
- raw protocol identifiers are not exposed merely because they are convenient for UI implementation.

### 2.5 Presentation identity is not authority identity

Local user-facing presentation metadata may include:

- label;
- color;
- icon;
- friendly aliases.

It must never become proof of physical-device identity or mutation authority.

## 3. Current baseline

Completed macOS milestones include:

- M1 read-only authenticator discovery;
- M1.5 killable child-process worker containment and libfido2 fit work;
- M2 native authentication foundation;
- M3 production read-only credential inspection;
- M4 production FIDO2 PIN set/change and recovery acknowledgement.

The next security-critical FIDO milestones remain:

- M5 credential deletion;
- M6 FIDO2 reset;
- M7 mutation-capable public alpha.

Linux and Windows mutation paths remain separate platform work. Windows broker work remains a distinct feasibility track.

## 4. Workstream A — FIDO2 over-and-beyond

### A1. Credential detail foundation

Extend trusted credential inspection with richer exact metadata before deletion is enabled.

Collect where the authenticator/API provides it:

- RP ID;
- authoritative 32-byte RP ID hash;
- display name;
- user name;
- user.id / user handle;
- credential ID;
- discoverability/type where available;
- relevant algorithm/protection metadata where safely available;
- inventory epoch and typed completeness evidence.

Presentation should provide a human-readable detail view while retaining the current opaque renderer handle model.

Raw credential IDs and user IDs must not be accepted back from the renderer as mutation identity.

Where raw identifiers are revealable/copyable, use an explicit reviewed path rather than silently widening renderer authority.

### A2. M5 — credential deletion

Deletion must be bound to a credential that was actually enumerated in the current valid inventory epoch.

Required properties:

- exact device + generation + inventory epoch binding;
- exact RP identity and credential identity held in trusted state;
- immutable deletion intent;
- native human authorization;
- no sensitive queue/admission bypass;
- one-use dispatch authority;
- durable mutation outcome handling appropriate to deletion;
- worker quiescence before authority release;
- no automatic retry after possible dispatch;
- uncertainty/reconciliation policy defined before production dispatch;
- sacrificial-hardware validation.

UI must show enough trusted presentation context to let the user understand exactly which passkey is being deleted.

### A3. M6 — FIDO2 reset

Retain the existing high-friction reset ceremony design:

- explicit FIDO2 scope;
- destructive-impact acknowledgement before timed reconnect;
- ResetCeremonyGrant;
- generation-bound ResetDispatchPermit;
- eligible-single-device requirement;
- measured reconnect/dispatch timing;
- reset-specific recovery/evidence rules;
- multi-vendor hardware validation.

The UI must explicitly state that FIDO2 reset does not imply PIV/OATH/OpenPGP reset unless device-specific evidence proves otherwise.

### A4. Advanced FIDO2

After M5/M6, add capability-driven support for:

- Bio Enrollment / fingerprint management;
- Enterprise Attestation;
- authenticator configuration;
- minPinLength and related PIN policy information;
- credential capacity/status;
- persistent credential-management read-only research;
- richer GetInfo inspection;
- firmware/device quirks represented as compatibility evidence, not hidden assumptions.

Persistent authorization mechanisms require a separate security fit review before implementation because they materially affect authority lifetime.

## 5. Workstream B — Device Experience 2.0

Make the physical security key a first-class product object.

Each device view should present, where available:

- manufacturer/vendor;
- model;
- firmware;
- current transport;
- available transports;
- AAGUID;
- VID/PID where appropriate;
- supported FIDO versions;
- application capabilities;
- application enabled state;
- management reachability;
- local label;
- local color;
- local icon.

The UI must distinguish:

```text
Supported -> Enabled -> Reachable -> Manageable
```

These are separate states.

Multi-device presentation must remain safe when multiple identical keys are connected. Friendly labels are presentation-only.

## 6. Workstream C — Application and transport management

Introduce a dedicated device/application-management boundary.

Target UX:

```text
Applications

                 USB       NFC
FIDO2             ON        ON
FIDO U2F          ON        ON
PIV                ON        ON
OATH               ON        ON
OpenPGP            ON        ON
YubiHSM Auth       ON        ON
OTP                ON        -
```

Implementation model:

```text
Device Management
|
+-- standard capability layer
|
+-- vendor adapters
    +-- Yubico
    +-- Thetis
    +-- future vendors
```

YubiKey transport/application toggles are an early target.

For Thetis, capability/toggle support must be discovered empirically and documented before mutation is implemented.

Application enable/disable is a real mutation. Disabling FIDO2 over a transport can make existing credentials unreachable without deleting them, so confirmation must state that consequence precisely.

## 7. Workstream D — PIV workstation

PIV should become a full PKI workstation rather than a minimal certificate viewer.

### D1. PIV inspection

Inspect standard and supported retired-key-management slots, including at least:

- 9a Authentication;
- 9c Digital Signature;
- 9d Key Management;
- 9e Card Authentication.

For each slot, model private-key state separately from certificate state.

Private-key presentation should include where verifiable:

- algorithm;
- generated-on-device vs imported origin;
- exportability semantics;
- attestation result;
- PIN policy;
- touch policy.

Certificate presentation should include:

- subject;
- issuer;
- serial;
- validity;
- fingerprints;
- key usage;
- extended key usage;
- SAN;
- chain information.

Where possible, verify that the certificate public key corresponds to the private key in the slot.

### D2. PIV key and certificate lifecycle

Target capability:

- generate private key on authenticator;
- import private key;
- export public key;
- move private key between supported slots;
- delete private key;
- import certificate;
- export certificate;
- delete certificate;
- generate CSR;
- generate self-signed certificate;
- verify private-key/certificate correspondence;
- verify supported attestation.

Private key and certificate are separate domain objects and separate destructive operations.

### D3. PIV security management

Model and manage separately:

- PIV PIN;
- PIV PUK;
- PIV Management Key.

Target operations:

- change PIN;
- unblock PIN with PUK;
- change PUK;
- rotate/change Management Key;
- expose supported Management Key algorithm/status;
- configure PIN/touch policy where supported;
- represent retries/status only when protocol evidence is safe and exact.

Management Key material must never pass through renderer-visible DTOs/logging.

### D4. PIV reset

PIV reset must show an impact preview describing:

- private keys that will be destroyed;
- certificates that will be removed;
- PIV PIN/PUK/Management Key state that will reset;
- other applications that will not be affected.

Vendor-specific reset behavior belongs in compatibility evidence.

## 8. Workstream E — OATH accounts

Target full OATH management for capable devices:

- TOTP;
- HOTP;
- QR enrollment;
- manual enrollment;
- issuer/account metadata;
- algorithm/digits/period where supported;
- touch requirement;
- rename;
- delete;
- search;
- local icons/favorites;
- OATH application password;
- OATH reset.

Account inspection should explain configuration rather than only displaying current OTP values.

## 9. Workstream F — YubiKey OTP

Implement as a Yubico vendor extension.

Target:

- short-touch slot;
- long-touch slot;
- Yubico OTP;
- static password;
- challenge-response;
- HOTP where exposed by the application;
- slot swap;
- slot clear;
- relevant keyboard/output configuration.

This must not be represented as standard FIDO functionality.

## 10. Workstream G — OpenPGP

First parity target:

- detect application;
- show application information;
- enabled/disabled state by transport where vendor management exposes it.

Later full-management research may cover:

- signing/encryption/authentication keys;
- fingerprints;
- user identity;
- user/admin PIN;
- touch policies;
- generate/import workflows;
- reset.

OpenPGP is a separate protocol/security domain.

## 11. Workstream H — YubiHSM Auth

Initial target:

- detection;
- application status;
- transport enable/disable where supported;
- capability/version information.

Full management requires separate protocol research and threat review.

## 12. Workstream I — Diagnostics Center

Build first-class safe diagnostics rather than unrestricted raw traffic logging.

Target diagnostic data:

- device/model/firmware;
- transports;
- applications/capabilities;
- enabled/reachable/manageable state;
- worker version/provenance;
- protocol versions;
- libfido2 build identity;
- PC/SC availability for PIV;
- worker generation/lifecycle;
- recovery-journal health;
- recovery barrier state;
- bundle/worker signature status in packaged builds;
- categorical sanitized errors.

Never include:

- PIN;
- PUK;
- Management Key;
- PUAT/token material;
- private keys;
- OTP seeds;
- secret-bearing APDUs/CTAP traffic;
- full credential IDs by default;
- unnecessary account/user identifiers.

Diagnostic export must be explicit, previewable, minimized, and safe for support use.

## 13. Workstream J — Packaging and release

Packaging should proceed before every future protocol is complete.

After M5/M6 are mature on macOS:

```text
Fido Manager.app
-> nested worker/helper signing
-> Hardened Runtime
-> Developer ID
-> notarization
-> stapled DMG
-> quarantine/clean-machine validation
```

The packaged worker must preserve exact backend-owned resolution and executable authenticity guarantees.

No updater should be added merely as part of first packaging.

## 14. Target architecture

The product should evolve toward protocol-isolated trusted services rather than one universal secret-bearing worker.

Conceptual direction:

```text
                    Fido Manager
                         |
                  Device Registry
                         |
          +--------------+--------------+
          |              |              |
        FIDO2           PIV            OATH
          |              |              |
     fido-worker     piv-worker     oath-worker
          |              |              |
       CTAP/HID        PC/SC        protocol/APDU
          |              |              |
          +--------------+--------------+
                         |
                   Physical key
```

Vendor device management remains a separate capability surface:

```text
vendor-management
|
+-- yubico
|   +-- application toggles
|   +-- transport configuration
|   +-- vendor-specific extensions
|
+-- thetis
    +-- only empirically verified capabilities
```

This is a direction, not permission to prematurely duplicate infrastructure. New process boundaries must be justified by the secret/authority domain and reviewed before implementation.

## 15. Development order

Current priority order:

1. Credential Detail Foundation, including user.id support.
2. M5 credential deletion.
3. M6 FIDO2 reset.
4. macOS packaging/signing/notarization.
5. Device/Application domain model.
6. Device Experience 2.0.
7. YubiKey application/transport toggles.
8. PIV read-only inspection.
9. PIV key/certificate lifecycle.
10. PIV PIN/PUK/Management Key and PIV reset.
11. Advanced FIDO2: Bio, Enterprise Attestation, authenticator configuration.
12. OATH.
13. YubiKey OTP.
14. Diagnostics Center.
15. OpenPGP.
16. YubiHSM Auth.
17. Broader vendor/device support.

Each item is an epic/workstream, not necessarily one pull request.

Security-critical mutations should continue to use small reviewable PRs, deterministic fault testing, explicit hardware gates, and independent review before merge.

## 16. Near-term M5 entry plan

The immediate implementation branch should begin by extending the M3 inventory safely so M5 deletion has exact trusted identity available.

Initial steps:

1. collect CTAP user.id into trusted inventory with strict bounds;
2. retain raw credential ID and user.id only in trusted backend state;
3. extend service-side credential handles so a current opaque handle resolves to exact device generation + inventory epoch + RP + credential identity;
4. add a read-only credential-detail query that accepts only the opaque current handle, never renderer-supplied raw IDs;
5. add a detail UI with RP ID, Display Name, User Name, User ID, Credential ID and completeness context;
6. define safe reveal/copy semantics for opaque identifiers;
7. add deletion intent/permit types without dispatch;
8. add worker protocol and adapter mutation only after deletion evidence/recovery semantics are explicitly defined;
9. validate deterministic stale-epoch, replay, duplicate-ID, timeout, crash and possible-dispatch paths;
10. run sacrificial-hardware deletion validation only under an explicit operator gate.

The first M5 implementation PR should remain a draft until its mutation authority/evidence model has been independently reviewed.

## 17. Compatibility evidence

Maintain device-specific compatibility data for every supported protocol/application.

A compatibility record should distinguish:

- hardware/model/firmware;
- OS/version/architecture;
- transport;
- supported application;
- enabled state;
- management interface;
- protocol version;
- operation support;
- destructive-operation semantics;
- known limitations;
- hardware validation status.

Do not infer one vendor/model's memory partitioning, reset behavior, feature toggles, or security semantics from another device.

## 18. Definition of "over and beyond"

A feature is not considered superior merely because it exposes more buttons.

Fido Manager should exceed vendor tooling by making these properties explicit:

- what object is being operated on;
- which application/security domain owns it;
- which transport is involved;
- what evidence proves its identity;
- what authority is required;
- what will be destroyed or changed;
- what will remain unaffected;
- whether execution is quiescent;
- whether the mutation outcome is confirmed, rejected, or unknown;
- how recovery is performed without guessing;
- what information is safe to expose to the renderer/logs;
- what capability is standard versus vendor-specific.

That is the product bar.
