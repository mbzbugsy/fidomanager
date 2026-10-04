use std::future::Future;

use reqwest::redirect::Policy;

use crate::{HealthRequest, HealthResponse, HealthTransport, REQUEST_TIMEOUT, TransportError};

/// HTTPS GET with normal certificate validation against the platform trust store.
///
/// No redirects are followed, no cookie store exists, no default or authorization headers are set,
/// no connection is kept alive between checks, and the response body is never read.
pub struct ReqwestTransport {
    client: Option<reqwest::Client>,
}

impl ReqwestTransport {
    pub fn new() -> Self {
        Self::build(true, true)
    }

    fn build(https_only: bool, system_proxy: bool) -> Self {
        let mut builder = reqwest::Client::builder()
            .redirect(Policy::none())
            .referer(false)
            .https_only(https_only)
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .pool_max_idle_per_host(0);
        if !system_proxy {
            builder = builder.no_proxy();
        }
        // A client that cannot be built is simply a permanently Offline status.
        Self {
            client: builder.build().ok(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_local_test() -> Self {
        Self::build(false, false)
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthTransport for ReqwestTransport {
    fn get(
        &self,
        request: &HealthRequest,
    ) -> impl Future<Output = Result<HealthResponse, TransportError>> + Send {
        let client = self.client.clone();
        let url = request.url();
        async move {
            let client = client.ok_or(TransportError::Transport)?;
            let response = client.get(url).send().await.map_err(|error| {
                if error.is_timeout() {
                    TransportError::Timeout
                } else {
                    TransportError::Transport
                }
            })?;
            // Only the status line matters; the body is dropped unread.
            Ok(HealthResponse {
                status: response.status().as_u16(),
                redirected: response.url().as_str() != url,
            })
        }
    }
}
