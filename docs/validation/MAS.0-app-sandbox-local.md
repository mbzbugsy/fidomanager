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
| Existing `incident.json` / recovery state untouched | Every sandboxed run uses bundle id `eu.fidomanager.desktop.sandboxtest` (container `~/Library/Containers/eu.fidomanager.desktop.sandboxtest`). The sandbox itself prevents access to `~/Library/Application Support/eu.fidomanager.desktop`. The single unsandboxed control run (§5.3) used the same test identifier, so its data went to `…/Application Support/eu.fidomanager.desktop.sandboxtest`. The real data directory was never read, listed or written |
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
| 9 | Health check | the supervisor keeps a worker only after the post-handshake health check | worker still in service after the observation window; no restart churn without hardware | **PASS** |
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

### 5.2 Worker replacement with authenticators connected (pre-existing, not sandbox-related)

With keys connected, the worker process is replaced about every 10–17 s. The **same build without
the sandbox** (re-signed with no entitlements, same test identity) shows the same pattern: workers
at t = 2 s, 20 s and 34 s. This is existing supervisor behaviour and is outside this change. The
harness asserts ownership (one authority, at most one worker, always its child) rather than a
fixed worker pid. It is worth a separate look; nothing here depends on it.

### 5.3 Controls

- Denial scan positive control: the same log predicate captured the F2/F3 denials in §3.2, so an
  empty result in §4 is meaningful.
- `device.usb` necessity: §4 row 13.
- Sandbox-independence of §5.2: the unsandboxed control run.

## 6. Regression

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` (CI form) | pass |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | pass (the two flavors are separate features and still compile together for lint coverage) |
| `cargo clippy -p fidomanager-app --all-targets --features macos-app-sandbox --locked -- -D warnings` | pass |
| `cargo test --workspace --all-targets --locked` | 503 passed, 0 failed, 1 ignored (`packaged_worker`) |
| `cargo test -p fido-service --doc --locked` | 8 passed |
| `cargo test -p fido-platform` 40 consecutive runs (new `instance_lock` tests) | 40/40 pass. An early version flaked: a child forked concurrently by another test briefly shares the lock's open file description until its `exec`. The tests now allow a bounded release delay; the product holds the lock for its lifetime, so this does not affect it |
| `pnpm lint` / `pnpm typecheck` / `pnpm test` | pass / 0 errors / 45 passed |
| `pnpm security:renderer-boundary` | pass; 160 checker executions (10 new ADR-018 negative cases) |
| `python3 scripts/package-macos.py --dmg` (Developer ID-path ad-hoc flow, unchanged) | PASS, including link-map provenance, the checker with worker execution and the mounted-DMG re-check |
| `python3 scripts/test-macos-bundle-check.py` | PASS (33 mutated bundles rejected) |
| `packaged_worker -- --ignored` against the M7.1 package | 1 passed |
| Developer ID-flavor binaries | entitlements empty on both; single-instance socket code present, sandbox lock plugin absent. The sandbox flavor is the reverse |
| Worker code, Developer ID flavor vs sandbox flavor | byte-identical after `codesign --remove-signature`: only the signature (entitlements, identifier) differs |
| `python3 scripts/package-macos-sandbox.py` | PASS |
| `test-macos-sandbox-runtime.py` on that final artifact (two authenticators) | 19/19 PASS, 0 denials |
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
