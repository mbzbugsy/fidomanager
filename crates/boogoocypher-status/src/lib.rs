//! Backend-owned BooGooCypher readiness status (status only).
//!
//! "Online" means exactly one thing: the fixed readiness endpoint answered the expected success
//! response. It says nothing about, and never influences, any local operation. This crate
//! has no dependency on any other project crate, so no local security-key or secret
//! state can reach it; its only inputs are the clock and one fixed, parameterless request.

mod http;

pub use http::ReqwestTransport;

use std::future::Future;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;
use tokio::time::Instant;

/// The only endpoint ever contacted. Not configurable in M3.
pub const READINESS_URL: &str = "https://boogoocypher.foladigroup.com/health/ready";
/// One attempt per check, bounded in total (connect + TLS + response head).
pub const REQUEST_TIMEOUT: Duration = Duration::from_millis(2_500);
/// A settled Online/Offline result is reused for this long before the next request.
pub const CACHE_TTL: Duration = Duration::from_secs(30);
/// The single HTTP status that means Online. Anything else, including 204 and every 3xx, is Offline.
pub const READY_STATUS: u16 = 200;

/// The only value that ever crosses to the renderer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadinessStatus {
    Checking,
    Online,
    Offline,
}

/// The one fixed request. It has no constructor that accepts input: method, URL and headers are
/// constants, with no query, body, cookies or authorization material.
#[derive(Debug)]
pub struct HealthRequest {
    url: &'static str,
}

impl HealthRequest {
    pub const fn fixed() -> Self {
        Self { url: READINESS_URL }
    }

    pub const fn url(&self) -> &'static str {
        self.url
    }

    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Always empty: no application headers are ever attached.
    pub const fn headers(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    #[cfg(test)]
    pub(crate) const fn for_test(url: &'static str) -> Self {
        Self { url }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: u16,
    /// The response did not come from the requested URL (a redirect was followed).
    pub redirected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Timeout,
    Transport,
}

/// Seam for deterministic tests; production uses [`ReqwestTransport`].
pub trait HealthTransport: Send + Sync {
    fn get(
        &self,
        request: &HealthRequest,
    ) -> impl Future<Output = Result<HealthResponse, TransportError>> + Send;
}

fn classify(result: Result<HealthResponse, TransportError>) -> ReadinessStatus {
    match result {
        Ok(response) if response.status == READY_STATUS && !response.redirected => {
            ReadinessStatus::Online
        }
        _ => ReadinessStatus::Offline,
    }
}

struct State {
    // Only Online or Offline are ever stored here.
    last: Option<(ReadinessStatus, Instant)>,
    in_flight: bool,
}

pub struct ReadinessService<T> {
    transport: T,
    state: Mutex<State>,
}

enum Begin<'a> {
    Settled(ReadinessStatus),
    Lead(FlightGuard<'a>),
}

/// Clears the in-flight marker even if the leading caller is cancelled mid-request.
struct FlightGuard<'a> {
    state: &'a Mutex<State>,
}

impl FlightGuard<'_> {
    fn finish(self, status: ReadinessStatus) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.last = Some((status, Instant::now()));
    }
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .in_flight = false;
    }
}

impl<T: HealthTransport> ReadinessService<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: Mutex::new(State {
                last: None,
                in_flight: false,
            }),
        }
    }

    fn begin(&self) -> Begin<'_> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((status, at)) = state.last
            && at.elapsed() < CACHE_TTL
        {
            return Begin::Settled(status);
        }
        if state.in_flight {
            // A request is already running: never start a second one. Report the last settled
            // result, or Checking when there has been none yet.
            return Begin::Settled(state.last.map_or(ReadinessStatus::Checking, |(s, _)| s));
        }
        state.in_flight = true;
        Begin::Lead(FlightGuard { state: &self.state })
    }

    /// Current status. Serves a fresh cached result; otherwise exactly one caller performs the
    /// single bounded request while concurrent callers return immediately. Never fails.
    pub async fn status(&self) -> ReadinessStatus {
        let guard = match self.begin() {
            Begin::Settled(status) => return status,
            Begin::Lead(guard) => guard,
        };
        let request = HealthRequest::fixed();
        let result = match tokio::time::timeout(REQUEST_TIMEOUT, self.transport.get(&request)).await
        {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout),
        };
        let status = classify(result);
        guard.finish(status);
        status
    }
}

#[cfg(test)]
mod tests;
