# M3 BooGooCypher readiness status (issue #23)

Implemented on PR #25 (`feature/m3-credential-inspection`). This delivers the minimum M3
requirement of issue #23, “M3 UI: show BooGooCypher online status”. Issues #23 and #14 are
referenced, not closed by this change.

**This is a status indicator only. It is NOT FIDO cryptographic integration.** BooGooCypher
does not currently protect, receive, process or authorize PINs, PUATs, credentials, RP
identities, authenticator traffic or any FIDO operation, and the chip must not imply that it does.

## Behavior

| Item | Value |
| --- | --- |
| Endpoint | `https://boogoocypher.foladigroup.com/health/ready` (fixed constant; no user-configurable URL) |
| Method / request | HTTPS `GET`; no query, body, cookies, authorization or application headers, no identifiers |
| Request timeout | **2,500 ms** total (connect + TLS + response head), enforced by the HTTP client and again around the whole attempt |
| Retries | None within a check |
| Cache TTL | **30 s**, for both Online and Offline results |
| Redirects | Disabled (`Policy::none()`); a 3xx is Offline, and a response whose final URL differs from the request is never Online |
| TLS | Normal certificate validation against the platform trust store; verification is never disabled; plain `http` is refused (`https_only`) |
| Online | Exactly HTTP **200** from the fixed URL |
| Offline | Timeout, TLS/transport failure, any redirect, any non-200 status (including 204), or a client that could not be built |
| Checking | No settled result exists yet and a check is running |
| Body | Never read or buffered; the response is dropped after the status line |

Online means only “the readiness endpoint answered healthy”. Offline is informational (neutral
indicator, not the warning color) and does not mean FidoManager or any security key is unavailable.

A refresh is performed by exactly one caller (single flight). Concurrent callers return at once
with the last settled result, or Checking if there has been none; a cancelled leader releases the
in-flight marker. While a refresh is running after expiry, the previous result is still reported
(at most TTL + timeout old), which avoids flicker. Renderer polling performs no network request
itself: the backend serves the cached state, and a call after the 30 s TTL expires may cause the backend to
start the one fixed readiness request. No request is issued while a result is fresh, and Offline can take
up to the TTL to recover.

## Trust boundary

- The renderer never performs the request. CSP `connect-src` stays `ipc: http://ipc.localhost`; the
  renderer contains no URL, no `fetch`/XHR/WebSocket and no HTTP plugin.
- One new parameterless command, `boogoocypher_status`, with ACL permission
  `allow-boogoocypher-status`, returns a bare typed value: `"checking" | "online" | "offline"`.
- The probe lives in the new `boogoocypher-status` crate, which depends on **no other project crate**
  (only `reqwest` with `native-tls`, `serde`, `tokio`). It therefore cannot receive a PIN, PUAT, raw
  credential ID, RP hash, user ID, AcquisitionBinding, WorkflowId, PromptInstanceId or auth-operation
  DeviceHandle. No FIDO crate depends on it, and the status is never read by credential inspection,
  discovery or authentication, so there is no path credential inspection → BooGooCypher or
  BooGooCypher response → authorization decision.
- BooGooCypher failure cannot block startup (nothing is requested at startup; the first check runs
  asynchronously after the window mounts), discovery, inspection, PIN prompts or any local FIDO operation.

`scripts/check-renderer-boundary.mjs` enforces: the exact command/permission allowlist including
the new command; no project-crate or FIDO dependency in the crate; none of the identifiers above in
the crate's source; the fixed endpoint constant and exactly one URL literal; no input-accepting
`HealthRequest` constructor; the renderer enum is exactly Checking/Online/Offline; the command reads
only the readiness service; no other command, crate or native module references BooGooCypher; no
renderer network API or endpoint; and the CSP is unchanged. `scripts/test-renderer-boundary.mjs`
proves each rule fails when violated.

## HTTP dependency

`reqwest 0.13.5` was already in the lockfile through Tauri without a TLS backend. It is now declared
directly with `default-features = false, features = ["native-tls"]`: Security.framework on macOS and
the system OpenSSL on Linux, no cookie store, no redirect following, no compression, no HTTP/2.
No renderer HTTP plugin was added (the single-instance plugin remains the only Tauri plugin).

## Deterministic validation

No test contacts the public endpoint. A `HealthTransport` seam and tokio's paused clock make policy
and cache behavior deterministic (15 Rust tests in `boogoocypher-status`):

- 200 → Online; 100/201/204/3xx/4xx/5xx → Offline; a followed redirect → Offline;
  transport error and timeout → Offline; a hanging transport is bounded at exactly 2,500 ms with one request.
- A fresh result (Online or Offline) is served without another request; an expired result permits
  exactly one refresh; eight simultaneous callers produce one request; a refresh in flight reports
  the last settled result; a cancelled leader does not wedge later checks.
- The request is the fixed parameterless GET with no headers; the status serializes only as
  `"checking"`, `"online"` or `"offline"`.
- The real HTTP client runs against a loopback listener: a 302 is returned as a non-200 status, the
  redirect target is never requested, and the request line carries no query, authorization, cookie
  or proxy-authorization header. The production client refuses plain `http`.

Frontend tests (SSR of the real `App.svelte`) cover the checking, online and offline chips, their
placement beside Native service and libfido2, the neutral offline style and the readiness-only
explanation.
