# M5 N1: credential proof before durable dispatch

Branch: `feature/m5-credential-deletion`. Reviewed baseline:
`b155808a83a209cd655dea025baeb134ec1e516b`. Draft
[PR #29](https://github.com/mbzbugsy/fidomanager/pull/29); not merged, not ready.
This pass changed only N1 and the tests and small supporting changes it needs.
No physical hardware was touched.

## Finding

At the baseline the PIN-bearing current-session credential proof ran inside
`ExecuteCredentialDeletion`, after the durable `DispatchCapable` record. The
journal forbids `DispatchCapable -> NotDispatched`, so every provable pre-delete
failure (wrong PIN, credential already gone, key unplugged, proof timeout,
changed identity) was recorded as `OutcomeUnknown` with a recovery barrier. A
wrong PIN cost an acknowledgement plus a fresh inspection instead of one retry.

## New ordering

```
native approval + PIN (protected secret frame)
  -> PrepareCredentialDeletion           (one native Device, one worker, one generation)
  -> ProveCredentialDeletion             (read-only; same open Device; PIN retained only on success)
       proof fails -> typed rejection / NotProved, device closed, PIN dropped,
                      NO journal record, NO barrier, worker retired
  -> durable Pending
  -> durable DispatchCapable            (mints the one-use dispatch permit)
  -> ExecuteCredentialDeletion           (no secret frame, no second proof, no GetInfo)
  -> exactly one fido_credman_del_dev_rk
```

After `DispatchCapable` the only native step left is the one real delete, so
uncertainty after the marker is uncertainty that can include a delete dispatch and
stays `OutcomeUnknown`. `DispatchCapable` is never relaxed to `NotDispatched`.

## Proof stays on the same worker, device and native session

`ProveCredentialDeletion` is accepted only on the prepared one-use deletion
session. It carries the same `AcquisitionBinding` (workflow, prompt, acquisition,
device generation, intent digest) and worker generation as Prepare, plus the exact
immutable identity (verified RP text, RP hash, credential ID, user.id). The worker
revalidates capabilities and retry context, enumerates only the verified RP, and
requires exactly one matching credential ID, matching user.id, and a well-formed,
duplicate-free row set. It keeps the native `Device`, the proven identity and the
zeroizing PIN inside the session. Execute is accepted only for the same identity
and consumes that session. Any other request, a restart, or a second Prove/Execute
tears the session down; the proof cannot migrate to another device.

## Secret lifetime

The PIN crosses only the existing protected secret frame, bound to acquisition and
request id, once, with the Prove request. It is never in JSON, never in the
renderer, and not sent again for Execute. A failed proof closes the device and
drops the PIN. After a successful proof the worker holds the zeroizing PIN only
until Execute consumes it, or until cancel, error, protocol violation, expiry,
revocation or retirement kills and reaps the worker. libfido2 1.17.0 acquires a
fresh PIN token per credential-management command, so no reusable token is
created or stored.

## Outcome semantics

| Situation | Result | Journal | Barrier |
| --- | --- | --- | --- |
| Wrong PIN, PIN blocked, auth blocked, PIN not set/required, unauthorized, parameters (explicit CTAP status during proof) | `Rejected` + typed reason | none | none |
| Credential absent | `Rejected(CredentialAbsent)`; card invalidated | none | none |
| Duplicate ID, changed user.id, malformed or out-of-bound rows | `Rejected(CredentialMismatch)`; card invalidated | none | none |
| Device unplugged, replaced, incompatible; budget exhausted; transport or parser failure during proof | `NotDispatched` | none | none |
| Worker hang, crash or lost response during proof | `NotDispatched`; worker killed and reaped | none | none |
| Proof ok, then storage failure, revocation or expiry before `DispatchCapable` | `NotDispatched` (Pending resolved as `NotDispatched`) | Pending only | none |
| Failure after the `DispatchCapable` marker that could include a delete | `OutcomeUnknown` | `DispatchCapable` | yes |
| Explicit CTAP rejection by the delete call | `Rejected` (unchanged classification) | resolved | none |
| Confirmed success | `ConfirmedSuccessful` | resolved | none |

Only the explicit CTAP statuses already allowlisted for deletion (0x02, 0x14, 0x2e,
0x31 to 0x36, 0x40) are typed; transport, timeout and unknown statuses are never
turned into a rejection.

## Conservative residual

A failure between the `DispatchCapable` write and the worker receiving Execute is
still `OutcomeUnknown`. That cannot be proven pre-delete from the service side, so
it stays conservative. The worker also holds the PIN across the two journal fsyncs;
the proof (at most 5 s native budget) plus the 1 s persistence margin must fit in
the 10 s permit lifetime, and an approval that no longer has that room is refused
before a PIN attempt is spent.

## Defence in depth added

- `resolve_recovery` now takes a `RecoveryFamily` and checks the journal's own
  operation: a PIN acknowledgement cannot resolve a deletion incident and deletion
  recovery cannot resolve a PIN incident, in both directions.
- Static assertions that `CredentialDeletionDispatchPermit` and
  `ExactCredentialTarget` are not `Clone`, `Copy`, `Debug`, `Display`,
  `Serialize` or `Deserialize`.
- The renderer-boundary checker requires the proof to complete before
  `write_delete_pending`, and forbids `dispatch_delete` from carrying a secret or
  re-proving; both rules have hostile-mutation regression tests.

## Tests

- Worker protocol (v8): `ProveCredentialDeletion` and `CredentialDeletionProved`
  validation.
- Worker engine: Prove before Prepare, Execute before Prove, Prove twice, Execute
  twice, replayed Prove and Execute, wrong workflow, prompt, acquisition, worker
  generation, device generation, intent digest and identity, malformed, truncated
  and trailing secret, unrelated request between Prove and Execute, session teardown
  on violation, and exactly one native delete.
- Libfido2 policy: proof never reaches the delete; every CTAP status is typed; guard
  failures; Execute repeats neither proof nor revalidation; exactly one delete per
  accepted Execute.
- Auth: `DeleteProofResult` typing, invalid pairings, wire shape, unchanged
  delete-stage classification.
- Service process tests against the production service, endpoint and worker engine
  (`credential_deletion.rs`): wrong PIN, PIN blocked, auth blocked, credential
  absent, wrong credential ID, duplicate ID, changed user.id, malformed rows, wrong
  device and proof unavailable (all clean, typed, journal untouched, gate free);
  proof hang, crash and lost response; proof ok then storage failure, revocation
  or expiry before `DispatchCapable` (no delete, no false `OutcomeUnknown`);
  `DispatchCapable` then lost response, crash, hang and unknown result (one
  entry, no retry, typed recovery); confirmed success and explicit delete-stage
  rejection; restart for Pending, DispatchCapable, Resolved and the M4 SetPin and
  ChangePin records; PIN incident not acknowledgeable through deletion recovery.
- The former test `proof_rejects_absence_ambiguity_changed_user_and_malformed_rows_without_delete`
  asserted `OutcomeUnknown` plus a barrier for these cases. It was replaced by
  `proof_stage_failures_are_typed_clean_and_never_reach_delete_or_a_barrier`, which
  asserts no journal write, no barrier and the typed result.

## Not verified here

The macOS-only native code (`native/deletion.rs`, `native/inspection.rs`) was
edited on a Linux host. It was type-checked and clippy-checked (`-D warnings`)
for `x86_64-apple-darwin` with the `native-libfido2` feature, using a temporary
local build-script bypass that is not part of this change. It was not linked or run
here: no pinned-libfido2 build, linkage or provenance check could run on this host,
and the macOS CI job must still confirm the build, link and symbol provenance. The
native session now sets the device timeout from Execute's own budget immediately
before the one delete, because the proof's timeout came from the proof request.
No real authenticator was used; the first hardware run remains a separate,
explicitly authorised step.
