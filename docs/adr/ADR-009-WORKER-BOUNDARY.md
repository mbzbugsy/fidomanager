# ADR-009: Process-transparent per-device worker boundary

Status: Accepted for Milestone 0 foundation

## Context

The Revision 3 focused gate found that delaying the worker process boundary could force a later rewrite if libfido2 hangs, malformed authenticator responses exhaust native resources, or Windows requires a brokered process boundary.

## Decision

`fido-service` communicates with the per-device worker through owned, serializable request/response messages with explicit request IDs and deadlines.

The protocol must not contain borrowed references, closures, process-local pointers, live libfido2 objects, or renderer-provided raw device paths/CTAP payloads.

Milestone 0 defines the protocol shape but does not decide worker deployment. The same semantic contract must support an in-process worker thread, child process, or Windows broker.

## Consequences

- M1 discovery work must be implemented behind the message boundary.
- The M1.5 hung-call/containment spike decides whether macOS/Linux require a child worker before credential management or mutation support.
- Moving a worker across a process boundary must not change `fido-service` operation semantics.
- Protocol versioning and bounded messages become part of compatibility testing.
