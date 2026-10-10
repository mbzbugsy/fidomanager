# MAS.0 — App Sandbox compatibility, local validation

Status: **the real GUI, worker IPC and FIDO2 discovery/inspection work under an enforced macOS
App Sandbox** (local, ad-hoc signed, isolated identity). This is **not** Mac App Store
distribution: nothing was signed with an Apple certificate, no provisioning profile exists,
nothing was uploaded to App Store Connect and Apple has not reviewed anything. See §7.

Design: [ADR-018](../adr/ADR-018-MACOS-APP-SANDBOX.md). Base: `main` at `9a8a89e` (PR #34).
Host: macOS 26.5.2 (25F84), arm64, SIP enabled, Command Line Tools only (no Xcode), Rust 1.98.1,
Tauri 2.12.0, Node 22.19.0, pnpm 10.17.1.

Evidence files are in [`data/mas.0-sandbox/`](data/mas.0-sandbox/), with the home directory
redacted to `~`.

## 1. Safety conditions held

| Condition | How |
| --- | --- |
| Existing `incident.json` / recovery state untouched | Every sandboxed run uses bundle id `eu.fidomanager.desktop.sandboxtest` (container `~/Library/Containers/eu.fidomanager.desktop.sandboxtest`). The sandbox itself prevents access to `~/Library/Application Support/eu.fidomanager.desktop`. The unsandboxed control runs (§5.2, §5.4) used the same test identifier, so their data went to `…/Application Support/eu.fidomanager.desktop.sandboxtest`. The real data directory was never written; for the §5.2 follow-up, the hash and mtime of the existing `incident.json` were recorded before and after and are unchanged |
| No destructive FIDO2 operation | The harness sends no FIDO command. The app performed discovery, and an operator ran read-only credential inspection. No PIN change or set, no Reset, no deletion |
| No production credentials | Only ad-hoc (`-`) signing. A Developer ID Application identity exists in this keychain and was **not** used. The packager refuses `APPLE_*` and `TAURI_SIGNING_*` variables |
| Nothing published | No upload, no App Store Connect, no release artifact. PR #35, PR #36 and the release-signer repository are untouched |
| No security mechanism disabled | SIP stayed enabled. No TCC grant was added: Accessibility and Screen Recording were left denied, so the visual checks were done by a human (§4) |

## 2. What was changed (smallest set)

| Change | Why (observed) |
| --- | --- |
| `packaging/macos-app-sandbox/app.entitlements`: `app-sandbox`, `network.client`, `device.usb` | F1 (WKWebView), F2 (HID); ADR-018 §1 |
| `packaging/macos-app-sandbox/worker.entitlements`: `app-sandbox`, `inherit` | Apple's helper-tool rule; inheritance matrix §3.1 |
| `crates/fido-platform/src/instance_lock.rs`, `fido_service::instance`, `src-tauri/src/sandbox_instance.rs`, feature `macos-app-sandbox` | F3: the single-instance plugin's `/tmp` socket is denied, so a second authority ran |
| `scripts/package-macos-sandbox.py`, `scripts/check-macos-sandbox-bundle.py` | Build and check the flavor, reusing the unchanged M7.1 worker build and bundle checks |
| `scripts/test-macos-sandbox-runtime.py`, `scripts/macos-sandbox-probe.c` | Runtime evidence: kernel sandbox state, Hardened Runtime status and log denials |
| `scripts/check-renderer-boundary.mjs` and its regression test | Pin the exact entitlements, the feature scope and the single-instance registration (10 new negative cases) |
| `.github/workflows/ci.yml` | Builds and checks the sandbox bundle in the secret-free `macos-packaging` job |

The Developer ID path is unchanged: `package-macos.py`, `sign-macos-bundle.py`,
`check-macos-bundle.py`, `tauri.macos-bundle.conf.json` and `worker_authenticity.rs` are untouched,
and the default feature set is the same. The only edit to `recovery_file.rs` widens one helper's
visibility to `pub(crate)`.

## 3. Investigation

### 3.1 Sandbox inheritance and USB (probe binaries)

Ad-hoc signed probes with an embedded `Info.plist`
([`probe-inheritance.c`](data/mas.0-sandbox/probe-inheritance.c),
[matrix](data/mas.0-sandbox/probe-inheritance-matrix.txt),
[denials](data/mas.0-sandbox/probe-sandbox-denials.txt)):

- Ad-hoc signing **does** enforce the App Sandbox: `sandbox_check(pid)=1`, `HOME` is the
  container, and writing `/private/tmp` is denied.
- Without `device.usb`, 15 of 15 non-keyboard HID devices fail `IOHIDDeviceOpen`
  (`deny(1) iokit-open-user-client IOHIDLibUserClient`). With it, all 15 open. Enumeration
  (`IOHIDManagerCopyDevices`) works either way.
- A child with `inherit` gets the parent's sandbox, so its USB access depends on the parent's
  grant. A child with its own `app-sandbox` is killed (`forbidden-sandbox-reinit`). An `inherit`
  child started without a sandboxed parent is killed (`SIGTRAP`, exit 133).

### 3.2 The current app under the sandbox (diagnostic builds)

The baseline bundle was re-signed with increasing entitlements and run under the test identity
([denials](data/mas.0-sandbox/diagnostic-denials-before-fixes.txt),
[WebKit](data/mas.0-sandbox/diagnostic-webkit-without-network-client.txt)):

| Entitlements on the app | Result |
| --- | --- |
| `app-sandbox` | **FAIL**: WebKit Network process crash loop, renderer never runs, no IPC, no worker |
| + `network.client` | Renderer and IPC run; the worker spawns sandboxed; worker `deny IOHIDLibUserClient`; `open -n` starts a **second** authority and worker (`deny file-write-create /private/tmp/eu_fidomanager_desktop_si.sock`) |
| + `device.usb` | HID denial gone; the single-instance denial remains, which the code fix in §2 addresses |

## 4. Final build: test matrix

Build: `python3 scripts/package-macos-sandbox.py` → `target/macos-sandbox-test/Fido Manager
Sandbox Test.app`. Runtime: `python3 scripts/test-macos-sandbox-runtime.py <app>`, run once with
no authenticator ([report](data/mas.0-sandbox/runtime-no-authenticator.json); this run used an
earlier, stricter revision of the harness that required the *same* worker pid throughout) and once
with two
connected ([report](data/mas.0-sandbox/runtime-two-authenticators.json)): a YubiKey FIDO+CCID
(1050:0406) and a FIDO HID key 1ea8:f829.

| # | Area | Test | Evidence | Result |
| --- | --- | --- | --- | --- |
| 1 | Sandbox enforced (not just declared) | `sandbox_check(pid)` on the running app and worker | `sandboxed: 1` for both, and for a replacement worker | **PASS** |
| 2 | Entitlements | exact reviewed sets on both executables | `check-macos-sandbox-bundle.py` | **PASS** |
| 3 | Worker cannot run unsandboxed | worker started outside a sandboxed parent | killed by `SIGTRAP` before `main` | **PASS** |
| 4 | Hardened Runtime | kernel code-signing status of the running processes | `cs_flags 0x22011311`: valid, hard, kill, runtime, for app and worker | **PASS** |
| 5 | Tauri GUI / WKWebView startup | renderer JavaScript runs and WebKit stays healthy | worker spawned by renderer IPC; no WebKit network-permission error or process crash; operator saw the normal UI | **PASS** |
| 6 | IPC commands | `list_authenticators` (spawns the worker), `foundation_status`, `boogoocypher_status` | worker spawned; no `network-outbound` denial; operator saw device cards and status | **PASS** |
| 7 | Native menus | "Security key" menu with per-key items | operator confirmed; app setup (which installs the menu) succeeded | **PASS** (human) |
| 8 | Worker spawn and handshake | worker is the app's child in `--authentication` mode; after 15–20 s one worker serves the app | harness | **PASS** |
| 9 | Health check | the supervisor keeps a worker only after the post-handshake health check | worker still in service after the observation window; no worker replacement without an operator action or the kill test (§5.2) | **PASS** |
| 10 | Worker termination and replacement | `SIGKILL` the worker → sandboxed replacement; `SIGTERM` the app → worker exits on its own | harness | **PASS** |
| 11 | FIDO2 discovery | two authenticators connected | both shown with details (operator); 0 denials | **PASS** |
| 12 | Read-only inspection | menu → inspect credentials → native PIN dialog → credential list | operator confirmed; 0 denials during the session | **PASS** (human) |
| 13 | USB/HID from the sandboxed worker | denial absent with `device.usb`; present without it (control on the final build, keys connected) | [control](data/mas.0-sandbox/control-final-build-without-device-usb.txt): 4 × `fido-worker deny iokit-open-user-client IOHIDLibUserClient`; with `device.usb`: none | **PASS** |
| 14 | Hot-plug | unplug and replug updates the cards | operator confirmed | **PASS** (human) |
| 15 | App data directory | inside the container, mode 0700 | harness | **PASS** |
| 16 | Recovery storage | `fido-authority-recovery-v1` created in the container, mode 0700; no journal written (no mutation) | harness | **PASS** |
| 17 | Single-instance | `open -n` second launch exits; one authority, at most one worker | harness (fails on the unfixed build, §3.2) | **PASS** |
| 18 | Sandbox denials | every denial for `fidomanager-app` / `fido-worker` during the runs | **0** in both harness runs and in the operator session | **PASS** |
| 19 | Developer ID flavor unaffected | M7.1 ad-hoc package, DMG, bundle-checker regression, packaged-worker handshake | §6 | **PASS** |
| 20 | Mac App Store distribution signing, upload, App Review, TestFlight | — | ADR-018 §5 | **BLOCKED** (needs Apple credentials and Apple; out of scope by instruction) |
| 21 | Automated menu/UI capture | Accessibility / Screen Recording | `osascript is not allowed assistive access (-1719)` | **BLOCKED** (deliberately not granted; human check substitutes) |

No test FAILED on the final build. The FAILs in §3.2 are the diagnostic findings that the changes
in §2 fix.

## 5. Observations

### 5.1 The GUI never opens HID devices

IORegistry user clients created by `fidomanager-app` during discovery were
`RootDomainUserClient`, `AGXDeviceUserClient` and `IOSurfaceRootUserClient` (power and graphics).
None was an `IOHIDLibUserClient`. Every HID denial in every diagnostic run was attributed to
`fido-worker`. Worker isolation (ADR-009) holds under the sandbox.

### 5.2 Worker replacement with authenticators connected (intentional, not a fault)

An earlier draft of this report said the worker was replaced "about every 10–17 s" with keys
connected, sandboxed or not. That was misattributed. A follow-up investigation used a temporary,
uncommitted instrumentation build that traced every exchange, termination, reap status and
supervisor transition. It found that every replacement had one of two intentional causes:

1. **Retirement after authentication.** Each credential inspection started from the
   "Security key" menu ends by retiring its worker, whether it is validated or cancelled. The
   supervisor kills and reaps the worker that held the PIN/UV session, enforces a 1 s settle
   interval, and launches a fresh generation on the next poll. This is not counted as a failure
   (`consecutive_failures` stays 0 and the crash-loop breaker stays closed).
2. **The harness's own `SIGKILL`** (§4 row 10). The next poll finds the worker dead
   (`Endpoint(Unavailable)`, reaped with signal 9), quarantines it, and replaces it after the
   250 ms backoff.

Process-level evidence from the original MAS.0 session (the unified log still held each worker's
first log line and every AppKit menu action) accounts for every replacement:

| MAS.0 run | Worker launches | Cause of each replacement |
| --- | --- | --- |
| Hardware run 2 (the run with the false "second launch spawned a worker" failure) | 2 | Operator menu action, PIN inspection `status=Validated`, device closed, new worker +1.02 s |
| Hardware session, next launch | 2 | Operator menu action, device closed, new worker +1.02 s |
| Unsandboxed control ("workers at t = 2 s, 20 s and 34 s") | 3 | Two operator menu actions, at t ≈ 11 s and t ≈ 25 s, followed 7.1 s and 8.5 s later by new workers (PIN entry, retirement, 1 s settle). The second inspection's device-close line comes exactly 1.0 s before its new worker |
| Hardware run 3 | 2 | Harness `SIGKILL` (no menu action, no device close beforehand) |
| Final run (§4) | 2 | One replacement. An operator menu action (inspection `status=Cancelled`) coincided with the harness `SIGKILL` |

A reproduction with both keys connected found no unprompted replacement:

| Run | Replacements |
| --- | --- |
| Debug build, unsandboxed, 90 s hands-off | 0 |
| Packaged Developer ID-flavor build, 150 s hands-off (145 discovery polls) | 0 |
| Sandbox build, 150 s hands-off | 0 |
| The §4 harness sequence (Developer ID flavor, and this flavor with the real harness, 19/19 PASS) | 1, the harness `SIGKILL` |
| Packaged build while an operator ran two inspections | 2, one after each inspection |

During that reproduction:
- **Discovery timings:** `ListDevices` took 0–4 ms and `GetDeviceInfo` 37–245 ms, against a 2,000 ms
  budget plus 100 ms margin.
- **Failures:** no exchange deadline expired, no worker exited on its own, and nothing else
  quarantined a worker.

Regression tests now pin this behaviour (`fido-service` supervisor unit tests and the
`supervisor_recovery` fixture test):
- ten minutes of 1 Hz polling with keys present never replaces the worker;
- ten retirements after authentication, faster than the crash-loop threshold allows, are never
  counted as failures, and each replacement waits out the settle interval after the old worker
  is proven stopped;
- a real worker process serves 50 consecutive polls as a single launch.

Data: [worker-replacement-attribution.txt](data/mas.0-sandbox/worker-replacement-attribution.txt).
The harness keeps asserting ownership (one authority, at most one worker, always its child)
rather than a fixed worker pid, because an operator may legitimately inspect during a run.

### 5.3 Controls

- Denial scan positive control: the same log predicate captured the F2/F3 denials in §3.2, so an
  empty result in §4 is meaningful.
- `device.usb` necessity: §4 row 13.
- Sandbox-independence of §5.2 and §5.4: unsandboxed control runs of the same code with no
  entitlements.

### 5.4 Renderer visibility, device polling and menu freshness

**Why this was checked.** One sandboxed run in the §5.2 follow-up showed the WKWebView renderer
suspended about 7 s after launch: device polling stopped and did not resume before the app quit.
This could have been an App Sandbox defect, because the renderer's 1 Hz `list_authenticators`
poll is also what republishes the native "Security key" menu.

**Method.** The comparison used two copies of one instrumented build:
- **Variants:** the sandbox build, and a byte-identical copy re-signed ad-hoc with Hardened
  Runtime and no entitlements. Only the entitlements differ.
- **Actions:** the window was minimized, hidden, restored or shown through a temporary
  in-app control (Accessibility is deliberately not granted).
- **Menu freshness probe:** did the same read-only discovery refresh that a menu selection
  does, then checked that every menu handle still resolved. It never republished the menu.
- **Worker replacement:** `SIGKILL` stood in for any replacement, such as retirement after
  authentication, because a replacement mints new device handles.

The display-sleep and screen-lock runs were done with the operator's consent. Both keys were
connected throughout.

| Condition | Sandboxed | Unsandboxed |
| --- | --- | --- |
| Visible, 20 s | 1 Hz polling; WebKit Foreground | same |
| Minimized 25 s, with a worker replacement | 1 Hz; Background, never suspended; menu republished within 1.3 s; probes FRESH | same |
| Hidden (Cmd-H) 25 s, with a worker replacement | same as minimized | same |
| App inactive (Finder frontmost) 20 s | 1 Hz; probes FRESH | same |
| Minimized and inactive for 5 min, with a worker replacement at 4 min | 273 polls in 300 s (longest gap 1.3 s); Background, never suspended; probes FRESH | 273 polls in 300 s (longest gap 1.3 s); same |
| Hidden 0.4 s after launch, before ever being visible | 27 polls in 30 s; not suspended | same |
| Display asleep and screen locked, after being visible | polling continued for 75.6 s, then stopped until the display woke; the replacement at 20 s was republished; first poll 0.3 s after unlock | continued for 53.9 s, then stopped until unlock; first poll 0.1 s after unlock; otherwise the same |
| Launched while the screen was locked | WebKit Suspended 6.5 s after launch; Foreground again when the display woke; first poll after unlock +0.58 s; 15 polls in the next 15 s; probes FRESH | Suspended at 6.7 s; Foreground at the same moment; first poll +0.54 s; 15 polls in 15 s; probes FRESH |

**Conclusion: normal macOS behaviour, not an application or sandbox defect.**
- The renderer is throttled or suspended only when its window cannot be seen at all (display
  asleep and locked, or never shown).
- Both variants behave the same, and polling resumes by itself within about 0.6 s of the window
  becoming visible.
- While the renderer can run but its window is minimized, hidden or behind other apps, polling
  continues at 1 Hz. So the native menu stays fresh whenever a user can reach it.

The original observation was a run started while the screen had auto-locked; the log shows the
lock at display dim and a new window that was "occluded" from creation.

The app also stays fail-closed if the menu is ever stale. A menu selection re-runs discovery
before acting and rejects a handle the current worker does not know ("key disconnected"). It never
rebinds the selection to another key.

Nothing was changed: no power-management assertion, no App Nap opt-out, and no backend poller.
Data: [renderer-visibility-comparison.txt](data/mas.0-sandbox/renderer-visibility-comparison.txt).

## 6. Regression

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` (CI form) | pass |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | pass (the two flavors are separate features and still compile together for lint coverage) |
| `cargo clippy -p fidomanager-app --all-targets --features macos-app-sandbox --locked -- -D warnings` | pass |
| `cargo test --workspace --all-targets --locked --no-fail-fast` | 498 passed, 0 failed, 1 ignored (`packaged_worker`): 495, plus the 3 §5.2 regression tests. The 503 recorded in the first draft of this report included the 8 doc tests below. In one earlier full run, `process_worker::…::path_checks_run_again_on_every_launch` (unchanged from `main`) failed at system load average ≈ 5: a `/bin/sh` stub that should exit before its 200 ms test handshake timeout did not, giving `HandshakeTimeout` instead of `SpawnFailed`. It then passed 30/30 isolated, 10/10 in the full `fido-service` suite and in the full run above. This is a pre-existing load-sensitive test, not a product failure |
| `cargo test -p fido-service --doc --locked` | 8 passed |
| `cargo test -p fido-platform` 40 consecutive runs (new `instance_lock` tests) | 40/40 pass. An early version flaked: a child forked concurrently by another test briefly shares the lock's open file description until its `exec`. The tests now allow a bounded release delay; the product holds the lock for its lifetime, so this does not affect it |
| `pnpm lint` / `pnpm typecheck` / `pnpm test` | pass / 0 errors / 45 passed |
| `pnpm security:renderer-boundary` | pass; 160 checker executions (10 new ADR-018 negative cases) |
| `python3 scripts/package-macos.py --dmg` (Developer ID-path ad-hoc flow, unchanged) | PASS, including link-map provenance, the checker with worker execution and the mounted-DMG re-check |
| `python3 scripts/test-macos-bundle-check.py` | PASS (33 mutated bundles rejected) |
| `packaged_worker -- --ignored` against the Developer ID-path package | 1 passed |
| Developer ID-flavor binaries | entitlements empty on both; single-instance socket code present, sandbox lock plugin absent. The sandbox flavor is the reverse |
| Worker code, Developer ID flavor vs sandbox flavor | byte-identical after `codesign --remove-signature`: only the signature (entitlements, identifier) differs |
| `python3 scripts/package-macos-sandbox.py` | PASS |
| `test-macos-sandbox-runtime.py` on that final artifact (two authenticators) | 19/19 PASS, 0 denials. Re-run after the §5.2/§5.4 follow-up: 19/19 PASS, 0 denials, no WebKit failure, one worker for the whole observation window |
| `git status` after both packaging flows | clean (no tracked file modified, no untracked output) |

CI scope: the `macos-packaging` job builds and checks the sandbox bundle, including the
unsandboxed-start refusal. It does not launch the GUI or read the unified log on hosted runners.
That would be unproven there, since the runners run with SIP disabled. The runtime harness is a
local, operator-run gate.

## 7. Locally sandbox-tested vs. still requiring Apple

| Locally established (this report) | Requires Mac App Store signing, App Store Connect or App Review |
| --- | --- |
| The App Sandbox is enforced by the kernel on both processes with these entitlements | That Apple's distribution signature plus provisioning profile produces the same sandbox (G1, G8) |
| Inheritance model; the worker cannot run unsandboxed | Store re-signing effects on the ADR-017 exact cdhash pin (G4) |
| WKWebView, IPC, menus, PIN prompt, discovery, read-only inspection, hot-plug | App Review acceptance of `device.usb` and `network.client` (G3) |
| Container data, recovery storage and single-instance lock | Upload validation, `productbuild` installer, privacy manifest (G2, G6) |
| Hardened Runtime compatibility (ad-hoc) | Mac App Store worker-authenticity enforcement flavor (G4) |
| Zero sandbox denials in normal use | Recovery evidence across Developer ID and store installs (G5) |

## 8. Reproduce

```sh
python3 scripts/build-libfido2.py fetch
python3 scripts/package-macos-sandbox.py
python3 scripts/test-macos-sandbox-runtime.py "target/macos-sandbox-test/Fido Manager Sandbox Test.app" --report /tmp/report.json
```

Manual hardware test (an operator is required for the PIN and the visual checks). Connect one or
more FIDO2 keys and launch the test app. Then confirm:

1. the window renders and each key appears as a card;
2. the "Security key" menu lists per-key items;
3. inspect credentials for one key, enter its PIN in the native dialog, and see the credential
   list. Read-only: never use PIN change or set, Reset or delete;
4. unplugging a key removes its card and replugging restores it;
5. afterwards, `log show --last 15m --predicate 'sender == "Sandbox"' | grep -E
   "Sandbox: (fidomanager-app|fido-worker)\("` prints nothing.

Cleanup of the test container (test data only): quit the app and remove
`~/Library/Containers/eu.fidomanager.desktop.sandboxtest`. macOS may ask for confirmation.
