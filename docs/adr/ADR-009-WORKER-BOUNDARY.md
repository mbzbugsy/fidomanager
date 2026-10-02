# ADR-009: Process-transparent per-device worker boundary

Status: Accepted for Milestone 0 foundation. Placement decided in Milestone 1.5 (see "Milestone 1.5 decision" below).

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

## Milestone 1.5 decision: killable child-process worker, now, for everything

Evidence is in `docs/spikes/M1.5-worker-containment.md`: a thread worker fails closed but can neither stop, join, nor prove quiescence of a hung native call, a queued request that the service already reported as timed out still runs later, replacing a stuck thread worker overlaps native execution, and a native crash takes the trusted authority down with it. A child process reused the unchanged protocol and `WorkerEndpoint` contract and fixed all four.

**On macOS and Linux all native FIDO work, including M1 read-only discovery, runs in the `fido-worker` child process.** The thread endpoint was deleted rather than kept as a second placement:

- one placement means the only worker the app can run is one whose hangs are killable (`fido_dev_info_manifest` accepts no timeout at all, so discovery needed the kill boundary on its own merits);
- the trusted authority (`fido-service`, the Tauri app) no longer links libfido2, so a memory-safety bug in native parsing cannot corrupt the process that owns policy and consent;
- the M2 prerequisite ("not PIN entry or any mutation on the thread endpoint") is met without a later migration.

### Contract (enforced in code and tests)

- **Lifecycle:** spawn, hello handshake (protocol version, worker generation, worker pid), health check, bounded exchanges, terminate, bounded wait/reap, proven quiescence, quarantine, replacement.
- **Kill/reap ordering:** the endpoint terminates and reaps the worker *before* it reports a timeout, crash, or protocol violation. `WorkerEndpoint::contain()` is idempotent and returns `Quiescent` only after the OS has handed back the exit status. If it cannot (a process stuck in an uninterruptible kernel wait) it returns `Active`, keeps the handle, and the coordinator refuses to replace the worker. A reaped process is never signalled again, so a recycled pid cannot be hit.
- **Replacement requires proof:** `DiscoveryCoordinator::replace_worker` asks the old endpoint to contain itself and refuses with `PreviousWorkerNotContained` unless `Quiescent` comes back. The supervisor proves containment *before* it launches a replacement, and replacements get a strictly higher `WorkerGeneration`; a generation handed to a failed launch is never reused.
- **Nested deadlines** (each layer owns exactly one):
  - transaction (`DiscoveryPolicy::transaction_budget_ms`, owner: coordinator), default 5 s;
  - exchange (native budget plus the endpoint's transport margin, default 100 ms, owner: endpoint), terminates the worker on expiry;
  - native (one `NativeDeadline` per request, owner: worker). Each native sub-call receives only the time that remains, so `open` followed by `get_cbor_info` cannot spend the budget twice.
  Later exchanges receive `min(operation budget, remaining transaction - transport margin)`. A transaction that runs out fails the whole refresh closed without quarantining an idle, healthy worker. The old 250 ms hidden slack is gone.
- **Restart policy:** exponential backoff (250 ms doubling to 5 s) on consecutive failures, and a crash-loop circuit breaker: 5 failures inside 60 s open the circuit for 60 s, after which exactly one probe launch is allowed and a failed probe re-opens it immediately. The result is a bounded respawn rate with no tight loop, that heals without the renderer asking for anything. Only a successful discovery refresh counts as success, so a worker that starts fine but crashes on its first request still loops into the breaker.
- **Parent death:** the worker exits on stdin EOF, and independently when its parent pid differs from the one declared in the handshake (polled every 100 ms from a thread that never touches native code), and on any panic. Both mechanisms are tested in isolation, including a worker blocked in native code and a pipe whose write end another process keeps open. The app also kills and reaps the worker on `RunEvent::Exit`.
- **Framing:** 4-byte big-endian length plus JSON. The declared length is checked against a per-direction bound before any payload is allocated (responses 1 MiB, requests 16 KiB, handshake 1 KiB); zero-length, truncated, oversized, malformed and unsolicited frames are protocol violations that terminate the worker; the response reader queue is bounded so a flooding worker is throttled by pipe back-pressure; a response that does not correlate with the single in-flight request is rejected at the endpoint.
- **No renderer influence on the worker:** the executable is resolved beside the running executable (the shape a Tauri sidecar takes) and never from `PATH`, the environment, or any renderer-influenced value; it must be a regular, executable, non-world-writable file. The command line is a compile-time constant (`&'static [&'static str]`), the production worker accepts none, and the child environment is cleared. Native device paths, native handles, and worker-local ids never cross to the renderer (unchanged).
- **Descriptor hygiene:** the worker closes every inherited descriptor above stderr before doing anything else.

### Parent-death mechanism: why stdin EOF plus a pid watchdog

The worker must not outlive the service even while its native thread is blocked inside libfido2, so the mechanism cannot run on the thread that makes native calls. Options considered:

- **Stdin EOF alone.** Instant and sufficient in the common case, but it fails if any other process holds a copy of the pipe's write end (a leaked descriptor), which is exactly the failure this must survive. Kept as the fast path; not trusted alone.
- **`kqueue` `EVFILT_PROC`/`NOTE_EXIT`.** Event driven and exact, but macOS/BSD only and needs hand-written `unsafe` `kevent` FFI, with a different mechanism still required on Linux. Rejected for complexity.
- **`PR_SET_PDEATHSIG`.** Linux only (macOS has no equivalent) and tied to the creating thread. Rejected.
- **Bounded `getppid` polling.** Portable, no FFI beyond `std::os::unix::process::parent_id`, immune to leaked descriptors, worst-case latency one poll interval (100 ms). Chosen, together with EOF.

Both run in threads that never touch native code and end the process with `_exit` (no exit handlers, which are not safe to run beside a blocked native thread). The service passes its pid in the handshake and the worker refuses to start unless that is really its parent, so a parent that died before the first poll is still caught. Each mechanism is tested in isolation: EOF while idle and while blocked in native code, and the watchdog alone with another process holding the pipe open (the test fails if the watchdog is removed).

### Timing constants

All are conservative first values, to be tuned with real-device P99 timings (spike open question 3). Structure and ownership matter more than the numbers.

| Constant | Value | Rationale |
| --- | --- | --- |
| list / GetInfo operation budget | 2 s each | Unchanged from M1; nothing here is tuned. |
| transaction budget | 5 s | Spike's suggested order of magnitude; covers `ListDevices` plus a slow `GetInfo` or two, and bounds worst-case time however many devices are present (progress is cached between transactions). |
| exchange margin | 100 ms | Transport and scheduling only; small and named, replacing the 250 ms slack that silently extended native work. |
| handshake timeout | 3 s | Process start, dynamic loading, `fido_init`; the first launch of a freshly linked binary can be slow on macOS. A miss backs off and retries. |
| health-check budget | 1 s | One trivial request over an already-working pipe. |
| reap timeout | 2 s | SIGKILL reaping normally takes milliseconds; past this the endpoint reports `Active` rather than guessing. |
| restart backoff | 250 ms doubling to 5 s | Also the (unmeasured) settle time after killing a worker mid-HID transaction. |
| crash-loop breaker | 5 failures in 60 s, 60 s open | Bounded respawn rate; one probe after the cooldown. |
| watchdog poll | 100 ms | Worst-case orphan lifetime when EOF does not arrive. |

### Descriptor audit

- Rust's standard library creates every descriptor it owns close-on-exec, including the pipes to the worker, so the worker's stdio pipes are the only descriptors intentionally inherited.
- Descriptors opened by C libraries inside the application (WebKit, IOKit, system frameworks) are not guaranteed close-on-exec and `Command` does not close them. The worker therefore closes every descriptor above stderr as the first thing `main` does, tested with deliberately leaked non-close-on-exec descriptors.
- Residual window: between `exec` and that sweep (dynamic loading and Rust runtime start) leaked descriptors exist in the worker, though no untrusted input is processed then. A parent-side `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT` would close it on macOS; `std::process::Command` cannot do that and it would need `unsafe` spawn FFI, so it is not used.
- Needs a packaged-app check: which descriptors the signed Tauri application actually leaks.

### Still open / deliberately out of scope

- **Per-device vs per-process workers.** One child serves all devices for now (read-only discovery). Per-device workers remain the M2+ target (`docs/ARCHITECTURE_AND_RELEASE_PLAN.md` section 15).
- **macOS TCC/Input Monitoring attribution** for HID access from the child, and whether a packaged, signed sidecar triggers a second prompt: needs the real-hardware validation in `docs/validation/M1.5-macos-hardware.md`, then a packaged build.
- **Packaged-app questions that no development build can answer:** the sidecar must be signed with the app's Developer ID and hardened runtime and be covered by notarization; with library validation on, a worker that loads Homebrew's libfido2 will not run in a signed bundle, so the static-versus-dynamic linking decision (and the helper's entitlements) must land before packaging; the bundled sidecar name carries a target-triple suffix on disk and lands beside the app executable, which is where resolution already looks; and first-launch Gatekeeper latency against the 3 s handshake timeout.
- **Post-kill device settle time** after killing a worker mid-HID-transaction: the restart backoff (250 ms minimum) is the current, unmeasured, answer.
- **Windows** is not served by this placement; it uses the elevated broker (ADR-013) behind the same protocol.
- **Mutation recovery** (`OutcomeUnknown`, reset admission, journal) is untouched: this change only provides the kill boundary those designs depend on.
