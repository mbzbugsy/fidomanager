# ADR-012: Single-instance management authority

Status: Accepted for MVP foundation

## Context

Two FidoManager application authorities in the same interactive user session would create avoidable races over handles, prompts, authorization state, and mutation recovery.

## Decision

MVP permits one FidoManager management instance per interactive user session. Tauri's single-instance plugin is registered before every other plugin. A second launch may focus the primary window and then exits.

Arguments and working-directory values delivered by a second launch are untrusted and are not processed by the Milestone 0 application.

The application-level singleton is a coordination mechanism, not a security boundary against other local processes. Browsers, vendor tools, other OS user sessions, and other FIDO clients remain external contention.

## Consequences

- All frontend windows resolve to one authority and canonical worker registry.
- M1 must surface external contention rather than assuming exclusive physical-device ownership.
- If Windows uses an elevated broker, ADR-013 must define the stronger broker-side singleton/authority model.

## Amendment (ADR-018)

Inside the macOS App Sandbox the plugin's `/tmp` socket is denied, so the plugin silently allows
a second instance. The `macos-app-sandbox` build flavor therefore registers, in the same first
position, a container-local exclusive lock instead of the plugin. The contract above is
unchanged: one authority per user session (per container), and second-launch input is never
processed.
