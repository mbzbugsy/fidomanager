# Independent Architecture and Security Review Prompt

Use this prompt unchanged for independent reviewers so their conclusions can be compared without cross-contamination.

---

You are acting as an independent architecture and security reviewer.

Project:
FidoManager
https://github.com/mbzbugsy/fidomanager

Purpose:
A vendor-neutral desktop application for inspecting and managing FIDO2 / CTAP authenticators such as Thetis, YubiKey, Feitian and similar security keys.

The proposed architecture uses:

- Tauri 2
- Rust
- a thin libfido2 adapter
- Svelte/TypeScript frontend
- no backend/cloud account
- no telemetry
- capability-driven vendor-neutral behaviour
- signed native desktop releases

Please review:

- `docs/ARCHITECTURE_AND_RELEASE_PLAN.md`
- `docs/SECURITY_MODEL.md`

Do NOT simply confirm that the design is reasonable.

Act as if this application will eventually be trusted to manage real security keys containing production credentials.

Review the proposal from the following perspectives:

1. Security architecture
2. Threat model
3. CTAP/FIDO2 correctness
4. libfido2 integration
5. Rust/FFI safety
6. Tauri/WebView attack surface
7. PIN handling and secret lifetime
8. Device identification and privacy
9. Credential deletion/reset safety
10. Cross-platform USB/HID behaviour
11. macOS deployment/signing/notarization
12. Windows deployment/signing/DLL loading
13. Linux permissions/udev/package behaviour
14. CI/CD and supply-chain security
15. Dependency management
16. Updater architecture
17. Testing strategy
18. Long-term maintainability
19. Vendor-neutral design
20. Architectural decisions that would be expensive to change later

Pay particular attention to these unresolved decisions:

A. Is Tauri appropriate for an application that accepts authenticator PINs, given that JavaScript strings cannot be reliably zeroized?

B. Should PIN entry use a native OS/Rust UI instead?

C. Should the libfido2 boundary use:
- direct C FFI maintained by this project,
- an existing Rust binding,
- or another design?

D. Should libfido2 be statically or dynamically linked on macOS, Windows and Linux?

E. Is the proposed per-device serialized operation model correct?

F. Is an ephemeral device identity sufficient, or are there legitimate cases requiring persistent identification?

G. Are there CTAP capabilities or future protocol additions that the proposed abstraction would make difficult to support later?

H. Is delaying automatic updates until after the first public alpha a good security decision?

I. What attack paths exist between the Tauri frontend and destructive CTAP operations?

J. What assumptions in this plan are incorrect or insufficiently justified?

Output your review using this structure:

## Executive assessment

Give a concise assessment of the overall architecture.

## Critical issues

Problems that should block implementation until resolved.

For each:
- issue
- why it matters
- realistic failure/attack scenario
- recommended change

## High-priority improvements

Important issues that should be addressed before public alpha.

## Medium/low-priority improvements

Useful hardening or maintainability improvements.

## Architecture decisions you agree with

Only include these when you can explain WHY they are sound.

## Architecture decisions you disagree with

Explain the alternative you recommend.

## Platform-specific concerns

Separate:
- macOS
- Windows
- Linux

## Release and supply-chain review

Review signing, packaging, dependency pinning, CI, SBOM and updater strategy.

## Missing threat scenarios

Identify realistic threats or misuse cases not addressed by the documents.

## Suggested revised architecture

If you recommend architectural changes, describe the revised component boundaries.

## Questions for the project owner

List questions that must be answered before implementation.

Be specific.
Prefer concrete technical criticism over generic best practices.
Do not redesign the entire project unless there is a material reason to do so.
