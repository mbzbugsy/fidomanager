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

## G5 Phase 1 amendment — production macOS authority

[Issue #38](https://github.com/mbzbugsy/fidomanager/issues/38) and the
[maintainer decision](https://github.com/mbzbugsy/fidomanager/pull/40#issuecomment-6102688283)
approve Team `7VGK9SN42B`, App Group `7VGK9SN42B.eu.fidomanager.authority`, Developer ID app
`eu.fidomanager.desktop` and store app `eu.fidomanager.desktop.mas`. The two installable apps
share one schema-1 journal and one process-lifetime `flock`; independent channel locks do not
exclude cross-channel concurrency.

Production startup validates its signed main identity and exact entitlement policy, resolves the
root with Foundation's `containerURLForSecurityApplicationGroupIdentifier`, opens every path
component without following symlinks, and checks the existing root is owned by the effective user
with mode `0700` and no extended ACL. It pins that directory descriptor and acquires the shared lock before recovery,
UI, IPC, plugins, discovery or worker initialization. Lock and recovery namespace creation both
use that same descriptor. A contender exits before journal initialization; unavailable/unsafe
storage exits without a substitute root. Lock descriptors are close-on-exec and retained through
app shutdown/worker cleanup until actual process termination; process death releases the lock without deleting its file.

This coordinates cooperating applications. It does not protect against a same-user process
that can deliberately remove/replace private directories or lock files, other local FIDO clients,
or privileged processes. Descriptor pinning prevents a path replacement from splitting lock
and journal within a running authority; it does not prove continuity after an externally replaced
container. Signed access, cross-channel contention and actual OS container permissions remain
G5 validation gates, not conclusions from synthetic tests.

Default unsigned builds retain the plugin and their existing storage. Ad-hoc sandbox tests retain
their disposable container-local lock. Neither enables the production shared-authority feature;
Windows behavior is unchanged. The production sandbox path stops before worker initialization
until MAS.2/G4 establishes store worker authenticity.

G5 remains OPEN pending signed validation. The maintainer's unresolved pre-release journal was
not accessed. A separately reviewed human-controlled transition is required before that install
switches authority; this implementation provides no migration, downgrade sentinel, schema 2 or
multi-incident UI. See [Phase 1 evidence](../validation/G5-phase1-shared-authority.md).
