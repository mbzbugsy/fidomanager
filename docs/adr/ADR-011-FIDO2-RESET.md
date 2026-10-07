# ADR-011: FIDO2 authenticator Reset ceremony

Status: Proposed for independent review (M6.0: architecture and non-destructive H0 timing
spike only).
Base: main `f444caa`, after merged PR #28. M5 credential deletion (Draft PR #29, head
`aaf64d0`) is still in progress and is not modified by this ADR's change.

**No Reset capability exists after M6.0.** This ADR documents intended interfaces; it does not
implement `ResetIntent`, `ResetCeremonyGrant`, `ResetDispatchPermit`, a Reset journal operation,
Reset recovery, a Reset worker protocol, a native Reset call or any Reset UI. The only code added
by M6.0 is the H0 timing tool (`crates/fido-h0-timing`), which is structurally incapable of Reset
(see [M6.0 H0 validation](../validation/M6.0-h0-reset-timing.md)).

This ADR fills the slot reserved in the architecture plan (section 25 and the ADR list), and
supersedes the plan where they differ (see "Changes to the architecture plan").

## Evidence labels

- [SPEC] text read from a published FIDO specification during design work.
- [SPEC-BASELINE] a CTAP 2.1/2.2 fact accepted as the reviewed baseline whose Proposed Standard
  text could not be retrieved in full from this environment; see "Specification provenance".
- [SOURCE] inspected source at the exact pinned libfido2 revision
  `b974e7cf2ee7392134cc12c08b76a068cf250dd8` (1.17.0, `native/libfido2/source.lock.json`).
- [REFIMPL] Google OpenSK, a CTAP reference implementation, at commit
  `a93efdb2a94a01607a8df2813fe06c3f6fb58292`. Evidence of one implementation, not the spec.
- [VENDOR] vendor behaviour documented by a third party; never universal CTAP behaviour.
- [POLICY] an application decision.
- [HW] requires hardware evidence that does not exist yet.

## Specification provenance

- [SPEC] CTAP 2.0 PS §5.6 (`fido-v2.0-ps-20190130`): Reset returns the authenticator to a
  factory default state, invalidating all generated credentials; user approval may be performed
  on the authenticator; the user flow is out of scope of the specification.
- [SPEC] CTAP 2.1 Review Draft §5.6 (`fido-v2.1-rd-20191217`, fetched during M6.0): Reset
  "invalidat[es] all generated credentials and any configuration maps"; "user presence is
  required"; "in case of authenticators with no display, request MUST have come to the
  authenticator within 10 seconds of powering up of the authenticator". Listed statuses:
  `CTAP2_OK`, `CTAP2_ERR_OPERATION_DENIED` (user declined), `CTAP2_ERR_USER_ACTION_TIMEOUT`,
  `CTAP2_ERR_NOT_ALLOWED` (request after the power-up window).
- [SPEC] CTAP 2.2 RD (`fido-v2.2-rd-20241003`) GetInfo members `longTouchForReset` (0x18) and
  `transportsForReset` (0x1A) are present; the pinned libfido2 parses both.
- [SPEC-BASELINE] CTAP 2.1 PS / 2.2 PS §6.6 `authenticatorReset (0x07)`. The section heading is in
  the published table of contents, but the body could not be read here: the fetch tool truncates
  the published HTML/PDF near 100,000 characters (before §6.6), and direct download from
  fidoalliance.org is denied by this environment's egress policy. The following are therefore
  recorded as the accepted reviewed baseline (task brief and architecture plan §25), consistent
  with the 2.1 RD text and with [REFIMPL], and **must be verified verbatim against PS §6.6 before
  any Reset-dispatching code (M6.2) merges**:
  - Reset invalidates all generated credentials, including CTAP1/U2F credentials;
  - Reset erases discoverable credentials and resets applicable authenticator-local FIDO state
    (PIN, and CTAP 2.1 state such as large-blob storage, where supported);
  - Reset requires user interaction as the authenticator implements it;
  - a displayless authenticator accepts Reset only within 10 seconds of power-up.
- [VENDOR] Yubico authenticators return `FIDO_ERR_NOT_ALLOWED` for Reset later than **5 seconds**
  after power-up and `FIDO_ERR_ACTION_TIMEOUT` if not touched within 30 seconds
  (pinned `man/fido_dev_set_pin.3` CAVEATS, `man/fido2-token.1` CAVEATS). Whether alwaysUv
  survives Reset is vendor-specific (same page). This is stricter than the CTAP window and is
  treated as vendor evidence only.

## Verified libfido2 facts [SOURCE]

- `fido_dev_reset(fido_dev_t *)` (`src/reset.c` 40–46) sends one CBOR byte, `CTAP_CBOR_RESET`
  (0x07, `src/fido/param.h` 54), in one `CTAPHID_CBOR` transmission (`reset.c` 11–21), then
  `fido_rx_cbor_status`. It takes no PIN or PUAT. `reset.c` is the only object that defines it
  or uses `CTAP_CBOR_RESET`; nothing else in the library references it.
- One budget, `dev->timeout_ms`, covers transmit and receive. Keepalives are consumed silently
  by `rx_preamble` (`io.c` 199), so the host gets no "touch now" signal.
- `tx_pkt` (`io.c` 34–48) can return failure after the HID write already happened
  (`fido_time_delta` runs after `io.write`), and a failed write does not prove the report was
  not delivered. **A transmit or receive error after entry cannot prove Reset was not sent.**
- Killing or reaping the calling process stops host-side waiting and closes the handle; it
  **cannot prove authenticator-side cancellation**. A late touch after the host gave up may still
  reset the key.
- macOS discovery (`src/hid_osx.c` `get_path`, 170–195) names devices `ioreg://<registry entry
  ID>`, which changes on every re-enumeration. The manifest exposes VID/PID, manufacturer and
  product strings only: **no stable cryptographic physical identity survives a replug**.
  `encIdentifier` needs a persistent PUAT (PIN) to decrypt and is not usable for Reset.
- `fido_dev_open` performs CTAPHID INIT and, for CBOR devices, one GetInfo internally
  (`dev.c` 168–201). The macOS open seizes the device exclusively (`hid_osx.c` 452, 504).

## Reference implementation facts [REFIMPL]

OpenSK `libraries/opensk/src/ctap/mod.rs`: the Reset permission is granted only at power-up
(`StatefulPermission::new_reset`, `RESET_TIMEOUT_DURATION_MS = 10000`), and **any command other
than GetInfo, Selection or (2.0-style) MakeCredential clears it** (`process_parsed_command`), as
does any vendor command. A late or disallowed Reset returns `CTAP2_ERR_NOT_ALLOWED`; Reset then
requires user presence.

Consequence [POLICY]: between reinsertion and Reset, the timed path sends **only CTAPHID INIT
and GetInfo**. No ClientPIN (including `getRetries`), credential management, selection or vendor
command may be added to it, because some authenticators would then refuse the Reset.

## Decisions

1. **Reset is its own destructive authority ceremony.** No M4/M5 permit, intent, receipt or
   outcome table is reused as Reset authority.
2. **Exactly one eligible security key must be connected** when the ceremony starts and when it
   is approved.
3. **Ceremony cardinality is 1 connected → 0 connected observed → exactly 1 candidate inserted.**
   Any second device at any point, or a candidate that vanishes, aborts before `DispatchCapable`.
4. **Cardinality does not cryptographically prove it is the same physical key.** FidoManager
   never claims physical continuity. The person physically chooses the key and the touch happens
   on the only connected authenticator. The trusted ceremony copy will instruct: *"Reinsert the
   same security key you just approved."*
5. **Same VID/PID, AAGUID, product string or list position are never reset authority.** They are
   mismatch-only safety evidence: any difference aborts, a match proves nothing.
6. **Pre-reset authority, reconnect correlation evidence and post-reset observation are distinct
   concepts** (table below) and are never merged.
7. **`ResetCommandOutcome` and `PostResetObservation` are separate.** Observation never upgrades
   `OutcomeUnknown` to `ConfirmedSuccessful`, never changes the journal and never authorizes.
8. **A dedicated fresh reset worker is the intended execution process.** It is spawned and
   handshaken before the unplug (keeping process start-up off the timed path), is the only
   process touching HID during the ceremony, makes at most one Reset call and is killed and reaped
   afterwards. Post-reset discovery uses a new worker generation.
9. **Reset recovery is its own family**, with a positive operation match (below).
10. **No automatic Reset retry.** Not on timeout, error, `NOT_ALLOWED`, crash or restart. A new
    attempt requires a new ceremony from the beginning, with new approval.
11. **Option A is the preferred durability architecture:** `ResetCeremonyGrant` → durable
    `Pending` → observe disconnect (zero devices) → observe exactly one candidate → validate
    candidate → durable `DispatchCapable` → (future) `ExecuteReset`, with `DispatchCapable`
    written as close as possible to `ExecuteReset`. `Pending` is armed **before** the
    unplug/replug wait; it is never written after candidate validation.
12. **Option B (writing `DispatchCapable` before reconnect) is not accepted** unless H0 proves
    Option A cannot meet the timing requirement. It would turn every crash or abort during the
    reconnect wait into `OutcomeUnknown` and needs a new provable resolution; it is a separate
    architecture decision.

### Authority, correlation and observation

| Concept | Content | Can authorize? |
|---|---|---|
| Pre-reset authority | `ResetIntent` built under the sensitive gate from the live registry target (exactly one eligible device); native approval; `ResetCeremonyGrant` | Grant authorizes only arming and waiting |
| Reconnect correlation evidence | cardinality trace 1 → 0 → 1; candidate native key differs from the pre-disconnect key; mismatch-only snapshot comparison; insertion within phase deadlines | Only enables minting `ResetDispatchPermit` after durable `DispatchCapable` |
| Post-reset observation | facts read by a fresh worker after the call (`clientPin`, credential counts, AAGUID/VIDPID match, count of devices) | Never |

### Outcome model

`ResetCommandOutcome` = `NotDispatched | Rejected(code) | ConfirmedSuccessful | OutcomeUnknown`,
from the native call and the dispatch phase only. `PostResetObservation` =
`NotObserved | ConsistentWithReset | Inconsistent | Ambiguous`, evidence only. A key that
reappears empty is `ConsistentWithReset`, not success: it cannot be shown to be the same key.

### Rejection policy (conservative initial rule)

The production classifier is **not** implemented in M6.0. The initial rule is:

- before native entry: `NotDispatched`, proven by phase;
- `FIDO_OK` → `ConfirmedSuccessful`;
- **every other result after native entry → `OutcomeUnknown`**, including TX/RX/INTERNAL errors,
  negative codes, timeouts, worker death, lost responses and every positive status.

A status may later become `Rejected` only if both the specification (PS §6.6, verified verbatim)
and validated vendor behaviour (sacrificial-hardware runs) prove it means the Reset was not
performed. Candidates to evaluate, none accepted: `CTAP2_ERR_NOT_ALLOWED` (0x30),
`CTAP2_ERR_OPERATION_DENIED` (0x27), `CTAP2_ERR_USER_ACTION_TIMEOUT` (0x2F),
`CTAP2_ERR_ACTION_TIMEOUT` (0x3A). Reset safety is never inferred from generic CTAP errors.

## Durability boundary (Option A)

The host can no longer prove Reset was not sent from the moment the service starts writing the
`ExecuteReset` frame to the reset worker. `DispatchCapable` must be durable before that and as
late as possible:

```text
Armed (durable Pending, written before unplug; reset worker already running)
→ 0 devices observed → exactly 1 candidate appears           ← host clock starts (HID notification)
→ T1 manifest → T2 open (INIT + GetInfo) → T3 GetInfo → T4 compare + serialize
→ runtime budget check (abort ⇒ NotDispatched)
→ T5 durable DispatchCapable (production DurableRecoveryFile::replace, F_FULLFSYNC on macOS)
→ T6 permit consumed, ExecuteReset frame received by the worker   ← H0 stops here
→ native call → first HID report reaches the authenticator          (not measured)
```

Any abort before T5 is `NotDispatched` (Pending is tombstoned). Any failure at or after durable
`DispatchCapable` is `OutcomeUnknown` plus the sensitive barrier, unless the native result is
`FIDO_OK`. The ceremony must check, before starting T5, that the elapsed time since the insertion
notification plus the bounded T5/T6 cost stays within the runtime budget; a slow candidate then
aborts as `NotDispatched` instead of being sent late.

## Intended interfaces (documentation only, not implemented)

- `fido-auth::reset`: `ResetExecutionBinding`; `reset_call_outcome(entered, code)` implementing
  the conservative rule above; table tests over every `err.h` code.
- `fido-service::reset`: `ResetIntent` (consumed by approval), `ResetCeremonyGrant` (can arm, never
  dispatch), typestate `ArmedCeremony → AwaitingReinsertion → CandidateValidated`,
  `ResetDispatchPermit` (minted only by marking `DispatchCapable`; owned, non-Clone, consumed by
  value into the one execute call; expires at `min(ceremony expiry, first_seen + runtime
  budget)`), `PostResetObservation`. Authority types have no public constructor, `Clone`,
  `serde` or `Display`.
- Journal: `RecoverableOperation::ResetFido2` (`"reset_fido2"`), schema 1 unchanged; separate
  `DurableResetDispatch` receipt. Older builds fail closed on the unknown variant.
- Worker protocol (dedicated reset worker): `ObserveResetCandidates` (read-only manifest and
  counts), `PrepareResetCandidate` (fresh open + GetInfo, keeps the seized handle),
  `ExecuteReset` (one call, consumes the session; worker exits). No generic CTAP request.
  `fido_dev_reset` gets exactly one call site, enforced by linkage checks.
- Native budget for the call: above the strictest documented touch timeout (Yubico 30 s), below
  `NativeDeadline::MAX_BUDGET`.

## Reset recovery family and the M5 routing hazard

`RecoveryFamily::Reset` owns exactly `ResetFido2` (positive match); PIN and deletion families keep
refusing it. Its sheet states only what is known, offers only *Acknowledge uncertainty*
(`AcknowledgedUnknown`), never retry, and clears inspection, PIN and verification caches globally
because identity is lost across the replug.

**Hazard to fix in M6 after M5 merges (not changed now):** at PR #29 head `aaf64d0`,
`src-tauri/src/authentication.rs` (around lines 163–169) routes the barrier menu with
`if operation == RecoverableOperation::DeleteCredential { DeletionRecovery } else { Recovery }`.
A new `ResetFido2` incident would fall into the PIN recovery sheet, which cannot acknowledge it
(a safe but unrecoverable dead end). M6 must replace this with an exhaustive `match` over
`RecoverableOperation` and add a Reset recovery action. The file belongs to M5's active work, so
M6.0 does not edit it.

## H0: Option A timing evidence and decision rule

H0 measures, without ever sending Reset, the host path from the OS insertion notification to the
point where an `ExecuteReset` frame would be received by an executor: T1 notification → manifest,
T2 manifest → open, T3 open → GetInfo, T4 validation → pre-write, T5 durable replace (the
production function and file layout), T6 post-sync → would-dispatch. It reports min, median, p95
and max per component and for the total, per model label.

Not measurable by H0: **T0**, authenticator power-up → HID service published (USB attach
debounce, reset and enumeration), and **T7**, frame receipt → first HID report written. Both are
covered by allowances below.

**Acceptance rule** (implemented in `fido-h0-timing::decision`, defaults shown):

```text
required = tail_factor × tail_adjusted_max(T1..T6)
         + power_up_allowance (T0)        1000 ms   [assumption until measured externally]
         + poll_allowance                  100 ms   production discovery cadence vs H0 tight poll
         + dispatch_allowance (T7)         250 ms
         + fixed_margin                   1000 ms
Option A accepted for a model  ⇔  required ≤ strictest supported vendor window (5000 ms)
                                  with ≥ 20 valid samples, no unexplained timed-path failures,
                                  and a durability-only run
tail_factor = 2.0; tail_adjusted_max = max observed total + any excess of the durability-only
run's worst replace over the worst replace seen during hardware samples
Option A not viable  ⇔  p95 total + allowances > window (without factor or margin)
otherwise            ⇒  MORE MEASUREMENT REQUIRED
```

Justification. A late Reset is not a silent failure: under the conservative rejection rule, the
resulting `NOT_ALLOWED` is `OutcomeUnknown` with a barrier, so a missed window costs the user a
recovery flow. The rule therefore uses the **maximum** rather than p95 (with 20 samples the
next sample exceeds the observed maximum with probability about 1/21), doubles it to cover tails
H0 cannot sample (F_FULLFSYNC under unrelated disk load, CPU contention, power management),
charges the separately sampled durability tail, and reserves fixed time for the parts of the
window H0 cannot see. With the defaults the measured host path must stay at or below
**1325 ms**, and the derived runtime abort budget (notification → would-dispatch) is
**2650 ms**. The 5000 ms window is the strictest documented one (Yubico); CTAP's 10 s is the
protocol maximum and is used only for a vendor profile whose window is validated. The T0
allowance is an engineering assumption, not a measurement; it must be replaced by measured or
vendor-stated values before release, and a vendor whose evidence shows a shorter window gets
its own profile.

**Current evidence (2026-10-07, [validation](../validation/M6.0-h0-reset-timing.md)):** one
YubiKey 5 series key (firmware 5.7.4) on a Mac16,1 with macOS 26.5.2, 20 valid samples, no
aborts, default policy. Total T1–T6: min 249.8, median 254.1, p95 258.2, max 261.5 ms; T2
(`fido_dev_open`, INIT plus libfido2's internal GetInfo) is about 225 ms of that, T5 durable
replace at most 14.5 ms (200-sample durability-only max 14.9 ms). Tail-adjusted max 261.8 ms
against the 1325 ms acceptable host path; `required` 2873.7 ms ≤ 5000 ms (margin 2126.3 ms).
**Verdict for this model and host: OPTION A VIABLE.** Other vendors, models, OS versions and
storage need their own samples; T0 and T7 remain allowances.

## Changes to the architecture plan

- Section 25 "At most one timed retry may reuse the same ResetCeremonyGrant": superseded by
  decision 10 (no automatic retry; a new ceremony needs new approval).
- Section 25 "a definitive NOT_ALLOWED may transition to the replug ceremony" and "attempt reset
  on the still-open pre-disconnect handle": not adopted. The replug is always required and no
  status is definitive until the rejection table is evidenced.
- Section 25 serial-text comparison: not available through the pinned macOS stack; out of MVP.

## Unresolved decisions

1. Verify CTAP 2.1/2.2 PS §6.6 verbatim (window, status list, reset scope including U2F,
   large-blob, minPINLength, enterprise attestation, alwaysUv, `encIdentifier` rotation) and
   record it here before M6.2.
2. Option A vs B: H0 supports Option A for the measured YubiKey 5 model on the measured Mac
   (see above); Option B is not needed on that evidence. Open: which further models and hosts
   must be sampled before release.
3. Vendor window profiles: one conservative global 5000 ms window, or per-vendor profiles backed
   by validation.
4. T0 allowance: how to measure power-up → HID publish (external power reference or vendor data).
5. Rejection allowlist: which statuses, if any, become `Rejected`, after spec and sacrificial
   hardware evidence (H3/H4).
6. Native confirmation friction (checkbox vs typed phrase) and copy for long-touch devices.
7. Display-equipped authenticators without a power-up window: the replug stays mandatory in M6.
8. Production discovery cadence on the timed path (notification-driven or ≤ 100 ms polling).
