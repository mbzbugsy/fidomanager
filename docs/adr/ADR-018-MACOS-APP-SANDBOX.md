# ADR-018: macOS App Sandbox flavor for Mac App Store compatibility

Status: **Proposed for review.** The flavor has been validated locally under an enforced App
Sandbox with ad-hoc signing (see the
[validation report](../validation/MAS.0-app-sandbox-local.md)). It has **not** been signed for Mac
App Store distribution, uploaded to App Store Connect or reviewed by Apple.

Base: `main` at `9a8a89e` (PR #34, M7.2a worker authenticity merged).

ADR-017 §3.3 says that adopting the App Sandbox "would be a separate ADR". This is that ADR. It
adds a **second, separate build flavor**. It does not change the Developer ID flavor, which keeps
every ADR-017 invariant: zero entitlements (D3), `sign-macos-bundle.py` never applying
entitlements, the bundle overlay `tauri.macos-bundle.conf.json` with
`signingIdentity: null, entitlements: null`, the checker `check-macos-bundle.py` rejecting any
entitlement, and the `macos-release-signing` enforcement flavor.

## Evidence labels

- [LOCAL] Observed on macOS 26.5.2 (25F84, arm64, SIP enabled) with ad-hoc signed code, using the
  kernel's own report (`sandbox_check`, `csops`) and Sandbox denials from the unified log.
- [APPLE] Behaviour Apple documents for the App Sandbox or the Mac App Store.
- [INFERENCE] Reasoning from the above.
- [OPEN] Requires Mac App Store distribution signing, App Store Connect or App Review. It cannot be
  established locally and is not claimed.

## 1. Context: what breaks under the sandbox

The current app was run unchanged under the App Sandbox. It was ad-hoc signed with the minimal
entitlements and given an isolated test bundle identifier. Each failure below was observed, not
predicted [LOCAL]:

| # | Failure | Evidence |
| --- | --- | --- |
| F1 | WKWebView never loads. The WebKit Network process crash-loops (≈100 restarts in a few seconds) and the renderer never runs | `WebContent[0] Application does not have permission to communicate with network resources. rc=1 : errno=34`, `NetworkProcessProxy::didClose (Network Process 0 crash)` |
| F2 | The worker cannot open any HID device, so FIDO2 discovery fails | `Sandbox: fido-worker deny(1) iokit-open-user-client IOHIDLibUserClient` |
| F3 | Single-instance silently breaks. `open -n` started a second authority with its own worker, both sharing one container's recovery journal (an ADR-012 violation) | `Sandbox: fidomanager-app deny(1) file-write-create /private/tmp/eu_fidomanager_desktop_si.sock` |

`tauri-plugin-single-instance` 2.4.5 on macOS uses a hard-coded `/tmp/<identifier>_si.sock`. When
`bind` fails it logs at debug level and "launches normally", so F3 produces no visible error.

## 2. Decisions

| # | Decision |
| --- | --- |
| S1 | **Separate compile-time flavor.** A Cargo feature `macos-app-sandbox` exists on the app crate only, is never a default and enables nothing else. Only `scripts/package-macos-sandbox.py` turns it on. There is no runtime, environment, argument, `Info.plist` or renderer switch. The renderer-boundary checker enforces this. |
| S2 | **Exact entitlements**, stored as reviewed files in `packaging/macos-app-sandbox/`. Main app: `app-sandbox`, `network.client`, `device.usb`. Worker: `app-sandbox`, `inherit`. Nothing else, in particular no temporary exception, file access, `network.server`, application group, `get-task-allow`, `disable-library-validation`, JIT or unsigned-memory entitlement. Two independent checkers pin the exact sets. |
| S3 | **The worker runs in the app's inherited sandbox.** It stays a separate, killable child process under ADR-009. No in-process placement exists, and none is introduced. |
| S4 | **Single-instance in the sandbox flavor** uses an exclusive `flock` on `single-instance.lock` (mode 0600) in the framework-derived application data directory, which lies inside the container. The lock is taken during plugin initialization, before any window, IPC, worker or recovery startup. A second process exits. Errors fail closed. The Developer ID flavor keeps `tauri-plugin-single-instance` unchanged. |
| S5 | **Hardened Runtime stays on** in the sandbox flavor (`--options runtime`). The App Sandbox does not require it; keeping it means one runtime policy for both flavors. |
| S6 | **Local testing uses only ad-hoc signing with an isolated identity.** The bundle identifier is `eu.fidomanager.desktop.sandboxtest`, which gives a separate container. The product name is "Fido Manager Sandbox Test". The packager refuses `APPLE_*` and `TAURI_SIGNING_*` variables, never selects a certificate, and does not sign for distribution. |

### 2.1 Why each app entitlement is necessary [LOCAL]

| Entitlement | Without it | With it |
| --- | --- | --- |
| `com.apple.security.network.client` | F1: the renderer never loads | WKWebView loads `tauri://localhost`, the renderer runs and IPC works. Also carries the existing BooGooCypher readiness request, which is today's behaviour, not a new capability. |
| `com.apple.security.device.usb` | F2: the worker is denied `IOHIDLibUserClient`, also in the **final** build with two authenticators connected | No denial. Both authenticators are discovered and read-only credential inspection works |

Neither is an exception entitlement. Both are ordinary App Sandbox capabilities [APPLE].

### 2.2 Sandbox inheritance (why the USB grant sits on the app)

Probe binaries signed in every combination gave these results [LOCAL]:

| Parent | Child entitlements | Result |
| --- | --- | --- |
| sandboxed | `app-sandbox` + `inherit` | child sandboxed with the **parent's** profile and container `HOME`; it can open HID devices only if the parent has `device.usb` |
| sandboxed | `app-sandbox` + `device.usb` (own sandbox) | child **killed** (`SIGTRAP`; `Sandbox: … deny(1) forbidden-sandbox-reinit`) |
| sandboxed | none | child sandboxed anyway (the sandbox is inherited by the kernel) |
| not sandboxed | `app-sandbox` + `inherit` | child **killed** (`SIGTRAP`, exit 133) |

Consequences:

- A worker with its own, narrower sandbox profile cannot be spawned with `posix_spawn`/`fork+exec`
  from the sandboxed app. The worker therefore holds exactly `app-sandbox` + `inherit`, which is
  also what Apple requires of an embedded helper tool [APPLE].
- The worker's effective sandbox **is** the app's sandbox. `device.usb` must be granted to the
  app, and the worker also receives `network.client`.
- The packaged sandbox worker cannot run outside a sandboxed parent. `check-macos-sandbox-bundle.py`
  asserts this: it starts the worker directly and requires `SIGTRAP` before `main`.

### 2.3 Least privilege and worker isolation: what changes and what does not

Unchanged (ADR-009, M2, M7.1):

- the worker is a separate process; kill, reap, containment and replacement work under the
  sandbox (§4 of the validation report);
- the worker is resolved only beside the canonical executable, with a cleared environment,
  `'static` arguments, the PIN/PUAT secret only on the CLOEXEC fd-3 socket after the handshake,
  and the parent-death watchdog;
- only the worker links libfido2, OpenSSL and libcbor. Its dynamic dependencies stay exactly
  libz, CoreFoundation, IOKit, libiconv and libSystem, and it links no network library;
- the GUI process never opens a HID device. During discovery no `IOHIDLibUserClient` was ever
  attributed to `fidomanager-app` in the IORegistry, and every HID denial in the diagnostic runs
  was attributed to `fido-worker` [LOCAL].

What the sandbox adds: both processes lose access to everything outside the container except
what the profile grants. Examples: writing `/private/tmp` is denied, and `HOME` is the container.
The Developer ID build has no sandbox at all, so every grant here is strictly narrower than today
for both processes.

**Accepted trade-off.** Because inheritance gives the child the parent's profile, the GUI holds
`device.usb`, which it does not use, and the worker holds `network.client`, which it does not use.
A sandbox scoped to each process would need the worker to be an XPC service with its own
entitlements: USB only for the worker, network only for the app. That replaces ADR-009's
`posix_spawn` launch, kill and reap model with launchd-managed XPC lifecycle semantics, so it
needs its own ADR. Recorded as future option **X1**; it is not part of this change.

### 2.4 Data, recovery storage and single-instance

- Tauri's `app_data_dir()` resolves inside the container, at
  `~/Library/Containers/<id>/Data/Library/Application Support/<id>`. The recovery journal
  (`fido-authority-recovery-v1`, 0700, `F_FULLFSYNC`, `O_NOFOLLOW`, ownership and mode checks) works
  there unchanged [LOCAL].
- The lock (S4) shares that root, is created through the same no-follow, 0700-ancestor primitive,
  and rejects symlinked or permissive files and directories. It is held for the process lifetime
  and is CLOEXEC, so a worker never inherits it. The kernel releases it on any exit, including
  `SIGKILL`, so no stale state remains.
- Exactly one single-instance mechanism is registered per flavor, and it is registered first. The
  boundary checker enforces both.
- A second launch through Launch Services activates the running app; Launch Services does not
  start a second process. Only `open -n` or a direct exec reaches the lock, and that process exits.
  Second-launch arguments are never read, as before.

### 2.5 Worker authenticity (ADR-017 §5)

The sandbox flavor builds `WorkerAuthenticity::UnsignedDevelopment`: per-spawn path checks and
the `build_id` consistency check, the same as every non-release build today. The
`macos-release-signing` requirement is Developer ID-only by design: ADR-017 §5.1 drops the
Mac App Store branch. A Mac App Store distribution build therefore needs its own enforcing flavor
before it may ship (gate **G4**). Nothing in this ADR weakens or bypasses ADR-017; the two
flavors are separate features.

## 3. Rejected alternatives

| Alternative | Why not |
| --- | --- |
| Add `com.apple.security.temporary-exception.files.absolute-path.read-write` for `/private/tmp/` so the plugin's socket works | A broad, undocumented-scope exception that App Review challenges, and `/tmp` is shared across users |
| Patch or fork `tauri-plugin-single-instance` | A vendored dependency fork for one path. The in-tree lock is about 100 reviewed lines |
| Give the worker its own sandbox (`app-sandbox` + `device.usb`, no `inherit`) | Killed at launch: `forbidden-sandbox-reinit` [LOCAL] |
| Let the GUI open HID devices itself | Violates ADR-009: the GUI never links or runs native FIDO code |
| `com.apple.security.application-groups` for a shared socket | Requires a provisioning profile and a Team ID prefix, and is not needed |

## 4. Observed benign denial (no exception granted)

`Sandbox: fidomanager-app deny(1) mach-lookup com.apple.Safari.SafeBrowsing.Service`. This is
WebKit's Safe Browsing lookup from the UI process. The app only loads its bundled frontend, so
nothing depends on it. It appeared in the diagnostic runs and **not** in the final validation
runs. The runtime harness tolerates exactly this denial and fails on anything else.

## 5. What remains before Mac App Store distribution [OPEN]

| Gate | Item |
| --- | --- |
| G1 | Apple Distribution (or "3rd Party Mac Developer Application") signing of both executables, a Mac App Store provisioning profile at `Contents/embedded.provisionprofile`, and the `com.apple.application-identifier` / `com.apple.developer.team-identifier` entitlements that come with it. The checker allowlists must then admit exactly those additions |
| G2 | `productbuild` with a Mac Installer Distribution identity; App Store Connect upload validation |
| G3 | App Review accepting `device.usb` (FIDO2 security keys over USB HID) and `network.client` (WebKit; BooGooCypher status) with their justifications; App Privacy disclosure for the BooGooCypher request |
| G4 | A Mac App Store worker-authenticity flavor (ADR-017 §5 equivalent). Open question: whether the exact cdhash pin (ADR-017 D14) survives Apple's re-signing of store builds; if Apple re-signs, the expected identity cannot be fixed before submission. Needs a store-signed (TestFlight) build to answer |
| G5 | Recovery evidence across distribution channels. A Mac App Store install cannot see a Developer ID install's journal in `~/Library/Application Support/eu.fidomanager.desktop`, so an uncertain incident would not raise the recovery barrier there. Decide between Apple's container migration (`container-migration.plist`), a documented "one channel per Mac" rule, or an explicit user-selected import. Until then, do not ship both channels to the same users |
| G6 | Privacy manifest (`PrivacyInfo.xcprivacy`) review for required-reason APIs (for example the file-metadata `stat`/`fstat` calls in the recovery and lock code) |
| G7 | Architecture policy for the store (arm64-only vs universal; ADR-017 M7.1 gate 4) |
| G8 | A store-signed build exercised through TestFlight on a clean Mac: sandbox, USB, WKWebView and single-instance behaviour under Apple's signature rather than ad-hoc |
| G9 | Native menus, the PIN prompt and the rendered UI were confirmed by a human operator in this run. An automated check needs Accessibility/Screen Recording grants, which were deliberately not given to the test host |

## 6. Consequences

- Two build flavors exist. CI builds and checks the sandbox flavor's bundle (ad-hoc) in the
  existing secret-free `macos-packaging` job. It does not launch the GUI there (§ validation
  report, "CI scope").
- Any new entitlement, a second plugin, or a feature that the sandbox flavor enables in another
  crate fails the renderer-boundary checker and needs an amendment to this ADR.
- ADR-012 now has two implementations (socket for Developer ID, container lock for the sandbox)
  with the same contract.
