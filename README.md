# FidoManager

FidoManager is a vendor-neutral desktop application, in pre-release development, for inspecting and managing FIDO2 / CTAP authenticators.

The project is motivated by a practical gap between vendor-specific management tools, limited browser UIs, and powerful but low-level CLI tooling. The goal is to provide a clear, local-first, auditable interface for standard authenticator management without requiring a cloud account or vendor ecosystem.

## Project status

**Pre-release, macOS-first. No signed, notarized or published release exists, and the
app is not release-ready.** "Merged" below means implemented on `main` with deterministic
tests; on its own it does not imply hardware validation or release.

Merged on `main`:

- **M1–M3:** read-only discovery, killable child-process worker, native authentication,
  pinned bounded libfido2 and read-only credential inspection.
- **M4:** macOS Set PIN / Change PIN and recovery acknowledgement. Change PIN is
  hardware-validated; Set PIN and recovery fault scenarios are not
  ([report](docs/validation/M4-pin-mutation-macos.md)).
- **M5:** macOS passkey deletion with durable recovery and native confirmation.
  Sacrificial-hardware deletion validation has not been performed.
- **M6.0:** FIDO2 Reset **design only**: [ADR-011](docs/adr/ADR-011-FIDO2-RESET.md)
  (proposed) and a non-destructive timing tool. **No Reset capability exists.**
- **M7.0–M7.2a:** unsigned/ad-hoc `.app` and DMG, pinned private static native
  dependencies, release-signing design
  ([ADR-017](docs/adr/ADR-017-MACOS-RELEASE-SIGNING.md), proposed) and runtime
  worker-authenticity enforcement. No Developer ID signing, notarization or stapling
  has been performed.
- **MAS.0–MAS.1:** App Sandbox flavor ([ADR-018](docs/adr/ADR-018-MACOS-APP-SANDBOX.md),
  proposed), validated locally with ad-hoc signing only; not Mac App Store signed,
  submitted or reviewed.
- **G5 Phase 1:** shared App Group recovery authority implemented; **G5 remains open**
  pending Apple-signed validation.

Open, unmerged: MAS.2 store worker authenticity (PR #42; its exec-trampoline gate is
blocked), M7.2 release preflight and verification/provenance (draft PRs #35, #36), and the
Windows broker spike (draft PR #20).

Mutation is macOS-only. Linux keeps a discovery-only build; Windows is a separate
feasibility track. See the [product roadmap](docs/PRODUCT_ROADMAP.md) for what comes next.

## Stack

- Tauri 2 desktop shell
- Rust native backend
- libfido2 adapter for CTAP/FIDO2 operations, in a separate worker process
- Svelte + TypeScript frontend
- Local-only operation; no backend service or account requirement

## Design goals

- Vendor-neutral, capability-driven behaviour
- Local-first operation
- No telemetry by default
- No cloud dependency for authenticator management
- Explicit separation between UI, application services, domain model, and CTAP transport
- Conservative handling of destructive operations
- Auditable secret handling and release pipeline
- Cross-platform path for macOS, Windows, and Linux

## Documentation

- [Product roadmap](docs/PRODUCT_ROADMAP.md)
- [Architecture and release plan](docs/ARCHITECTURE_AND_RELEASE_PLAN.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Architecture review prompt](docs/ARCHITECTURE_REVIEW_PROMPT.md)
- [Architecture decision records](docs/adr/)
- [Validation reports](docs/validation/)

## Review philosophy

This project manages security authenticators and should be treated as security-sensitive software from the first commit. Reviewers are explicitly encouraged to challenge the architecture rather than merely confirm that it appears reasonable.

In particular, the project needs independent review of:

- WebView/Tauri suitability for PIN entry
- frontend/backend IPC boundaries
- libfido2 FFI strategy
- static vs dynamic linking
- destructive CTAP operation controls
- platform-specific HID behaviour
- signing, packaging, updater, and supply-chain design

## Licence

Apache-2.0. See [LICENSE](LICENSE).

## macOS native worker development

The macOS worker builds a private, checksum-pinned libfido2 1.17.0 static archive
with a reviewed credential-management allocation bound. Its OpenSSL 3.5.9 (libcrypto)
and libcbor 0.14.0 dependencies are also built from checksum-pinned upstream source
as private static archives targeting macOS 11.0; Homebrew/system copies are never
used. Install Python 3.9+, Xcode Command Line Tools, CMake and pkg-config, then
prepare the sources:

```sh
brew install cmake pkg-config
python3 scripts/build-libfido2.py fetch
cargo build -p fido-worker --locked
python3 scripts/verify-libfido2-linkage.py target/debug/fido-worker
```

Cargo fails if a pinned source is missing or invalid; it never falls back to
Homebrew/system libfido2, libcrypto or libcbor on macOS. See the [build design and validation](docs/validation/M3-bounded-libfido2.md)
and [pinned static native dependencies](docs/validation/M7.1-static-native-deps.md)
for native tests, offline builds, limits and packaging implications. Linux retains
the existing discovery-only system-library build.

### Unsigned macOS app bundle (development only)

`python3 scripts/package-macos.py --dmg` builds an ad-hoc sealed `Fido Manager.app` and an
unsigned DMG under `target/macos-package/`. The bundle contains no third-party dylibs and
includes [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). It is not signed, notarized or
distributable; see
[docs/validation/M7.0-macos-packaging-foundation.md](docs/validation/M7.0-macos-packaging-foundation.md)
and [docs/validation/M7.1-static-native-deps.md](docs/validation/M7.1-static-native-deps.md).
