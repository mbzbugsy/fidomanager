# FidoManager

FidoManager is a planned vendor-neutral desktop application for inspecting and managing FIDO2 / CTAP authenticators.

The project is motivated by a practical gap between vendor-specific management tools, limited browser UIs, and powerful but low-level CLI tooling. The goal is to provide a clear, local-first, auditable interface for standard authenticator management without requiring a cloud account or vendor ecosystem.

## Project status

**Architecture review / pre-implementation.**

No production application code has been committed yet. The initial architecture, security boundaries, release strategy, and unresolved design decisions are being reviewed before the implementation is bootstrapped.

## Proposed stack

- Tauri 2 desktop shell
- Rust native backend
- libfido2 adapter for CTAP/FIDO2 operations
- Svelte + TypeScript frontend
- Local-only operation; no backend service or account requirement

The proposed stack is not considered final until the architecture review is complete.

## Design goals

- Vendor-neutral, capability-driven behaviour
- Local-first operation
- No telemetry by default
- No cloud dependency for authenticator management
- Explicit separation between UI, application services, domain model, and CTAP transport
- Conservative handling of destructive operations
- Auditable secret handling and release pipeline
- Cross-platform path for macOS, Windows, and Linux

## Initial scope

The first implementation milestone is intentionally read-only:

1. Discover connected authenticators
2. Display device information and CTAP versions
3. Display authenticator capabilities
4. Display PIN capability/state information where available
5. Handle insertion, removal, reconnect, and unsupported operations safely

Credential enumeration, PIN mutation, credential deletion, and authenticator reset are planned only after the read-only foundation and security model are reviewed.

## Documentation

- [Architecture and release plan](docs/ARCHITECTURE_AND_RELEASE_PLAN.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Architecture review prompt](docs/ARCHITECTURE_REVIEW_PROMPT.md)

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
