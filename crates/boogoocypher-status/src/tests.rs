use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

use super::*;

/// Fake transport: counts requests, records what it was asked, and either answers at once or
/// waits for a release.
struct Fake {
    calls: AtomicUsize,
    seen: Mutex<Vec<(String, String, usize)>>,
    reply: Mutex<Result<HealthResponse, TransportError>>,
    gate: Option<Arc<Notify>>,
    hang: bool,
}

impl Fake {
    fn answering(reply: Result<HealthResponse, TransportError>) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            reply: Mutex::new(reply),
            gate: None,
            hang: false,
        })
    }
    fn gated(reply: Result<HealthResponse, TransportError>, gate: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            reply: Mutex::new(reply),
            gate: Some(gate),
            hang: false,
        })
    }
    fn hanging() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            reply: Mutex::new(Err(TransportError::Transport)),
            gate: None,
            hang: true,
        })
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn set_reply(&self, reply: Result<HealthResponse, TransportError>) {
        *self.reply.lock().unwrap_or_else(PoisonError::into_inner) = reply;
    }
}

impl HealthTransport for Arc<Fake> {
    fn get(
        &self,
        request: &HealthRequest,
    ) -> impl Future<Output = Result<HealthResponse, TransportError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((
                request.url().to_owned(),
                request.method().to_owned(),
                request.headers().len(),
            ));
        let this = Arc::clone(self);
        async move {
            if this.hang {
                std::future::pending::<()>().await;
            }
            if let Some(gate) = &this.gate {
                gate.notified().await;
            }
            *this.reply.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }
}

const OK: Result<HealthResponse, TransportError> = Ok(HealthResponse {
    status: 200,
    redirected: false,
});

fn status_only(status: u16) -> Result<HealthResponse, TransportError> {
    Ok(HealthResponse {
        status,
        redirected: false,
    })
}

#[tokio::test]
async fn http_success_is_online() {
    let fake = Fake::answering(OK);
    let service = ReadinessService::new(Arc::clone(&fake));
    assert_eq!(service.status().await, ReadinessStatus::Online);
    assert_eq!(fake.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn non_success_statuses_are_offline() {
    for status in [
        100, 201, 204, 301, 302, 303, 307, 308, 400, 401, 404, 500, 503,
    ] {
        let fake = Fake::answering(status_only(status));
        let service = ReadinessService::new(Arc::clone(&fake));
        assert_eq!(
            service.status().await,
            ReadinessStatus::Offline,
            "status {status}"
        );
    }
}

#[tokio::test]
async fn a_followed_redirect_is_never_online() {
    let fake = Fake::answering(Ok(HealthResponse {
        status: 200,
        redirected: true,
    }));
    let service = ReadinessService::new(Arc::clone(&fake));
    assert_eq!(service.status().await, ReadinessStatus::Offline);
}

#[tokio::test]
async fn transport_and_timeout_errors_are_offline() {
    for error in [TransportError::Transport, TransportError::Timeout] {
        let service = ReadinessService::new(Fake::answering(Err(error)));
        assert_eq!(service.status().await, ReadinessStatus::Offline);
    }
}

#[tokio::test(start_paused = true)]
async fn a_hanging_transport_is_bounded_by_the_request_timeout() {
    let fake = Fake::hanging();
    let service = ReadinessService::new(Arc::clone(&fake));
    let started = Instant::now();
    assert_eq!(service.status().await, ReadinessStatus::Offline);
    assert_eq!(started.elapsed(), REQUEST_TIMEOUT);
    assert_eq!(fake.calls(), 1, "no retry within a single check");
}

#[tokio::test(start_paused = true)]
async fn fresh_results_are_cached_including_offline() {
    let fake = Fake::answering(status_only(503));
    let service = ReadinessService::new(Arc::clone(&fake));
    assert_eq!(service.status().await, ReadinessStatus::Offline);
    fake.set_reply(OK);
    tokio::time::advance(CACHE_TTL - Duration::from_millis(1)).await;
    assert_eq!(service.status().await, ReadinessStatus::Offline);
    assert_eq!(
        fake.calls(),
        1,
        "a fresh cached result avoids another request"
    );
}

#[tokio::test(start_paused = true)]
async fn an_expired_result_permits_one_refresh() {
    let fake = Fake::answering(OK);
    let service = ReadinessService::new(Arc::clone(&fake));
    assert_eq!(service.status().await, ReadinessStatus::Online);
    fake.set_reply(status_only(500));
    tokio::time::advance(CACHE_TTL).await;
    assert_eq!(service.status().await, ReadinessStatus::Offline);
    assert_eq!(fake.calls(), 2);
    assert_eq!(service.status().await, ReadinessStatus::Offline);
    assert_eq!(fake.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn simultaneous_callers_share_one_request() {
    let gate = Arc::new(Notify::new());
    let fake = Fake::gated(OK, Arc::clone(&gate));
    let service = Arc::new(ReadinessService::new(Arc::clone(&fake)));
    let leader = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.status().await })
    };
    tokio::task::yield_now().await;
    let followers = call_concurrently(&service, 8).await;
    assert!(followers.iter().all(|s| *s == ReadinessStatus::Checking));
    assert_eq!(fake.calls(), 1, "no request storm");
    gate.notify_one();
    assert_eq!(leader.await.ok(), Some(ReadinessStatus::Online));
    assert_eq!(service.status().await, ReadinessStatus::Online);
    assert_eq!(fake.calls(), 1);
}

async fn call_concurrently(
    service: &Arc<ReadinessService<Arc<Fake>>>,
    count: usize,
) -> Vec<ReadinessStatus> {
    let mut tasks = Vec::new();
    for _ in 0..count {
        let service = Arc::clone(service);
        tasks.push(tokio::spawn(async move { service.status().await }));
    }
    let mut out = Vec::new();
    for task in tasks {
        out.push(task.await.unwrap_or(ReadinessStatus::Offline));
    }
    out
}

#[tokio::test(start_paused = true)]
async fn a_refresh_in_flight_reports_the_last_settled_result() {
    let gate = Arc::new(Notify::new());
    let fake = Fake::gated(OK, Arc::clone(&gate));
    let service = Arc::new(ReadinessService::new(Arc::clone(&fake)));
    gate.notify_one();
    assert_eq!(service.status().await, ReadinessStatus::Online);
    tokio::time::advance(CACHE_TTL).await;
    let refresh = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.status().await })
    };
    tokio::task::yield_now().await;
    assert_eq!(service.status().await, ReadinessStatus::Online);
    assert_eq!(fake.calls(), 2);
    gate.notify_one();
    assert_eq!(refresh.await.ok(), Some(ReadinessStatus::Online));
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_leader_does_not_wedge_later_checks() {
    let gate = Arc::new(Notify::new());
    let fake = Fake::gated(OK, Arc::clone(&gate));
    let service = Arc::new(ReadinessService::new(Arc::clone(&fake)));
    let leader = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.status().await })
    };
    tokio::task::yield_now().await;
    leader.abort();
    let _ = leader.await;
    gate.notify_one();
    assert_eq!(service.status().await, ReadinessStatus::Online);
    assert_eq!(fake.calls(), 2);
}

#[tokio::test]
async fn the_request_is_the_fixed_parameterless_get() {
    let fake = Fake::answering(OK);
    let service = ReadinessService::new(Arc::clone(&fake));
    let _ = service.status().await;
    let seen = fake.seen.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(
        seen.as_slice(),
        [(READINESS_URL.to_owned(), "GET".to_owned(), 0)]
    );
    assert_eq!(
        READINESS_URL,
        "https://boogoocypher.foladigroup.com/health/ready"
    );
    for forbidden in ['?', '#', '@', ' '] {
        assert!(!READINESS_URL.contains(forbidden));
    }
    assert!(HealthRequest::fixed().headers().is_empty());
}

#[test]
fn the_renderer_only_ever_receives_a_bare_typed_status() {
    for (status, text) in [
        (ReadinessStatus::Checking, "\"checking\""),
        (ReadinessStatus::Online, "\"online\""),
        (ReadinessStatus::Offline, "\"offline\""),
    ] {
        assert_eq!(serde_json::to_string(&status).ok().as_deref(), Some(text));
    }
}

#[test]
fn documented_constants() {
    assert_eq!(REQUEST_TIMEOUT, Duration::from_millis(2_500));
    assert_eq!(CACHE_TTL, Duration::from_secs(30));
    assert_eq!(READY_STATUS, 200);
}

// Real client policy against a loopback server (no public network): redirects are not followed
// and no cookies, authorization header, query or body are sent.
#[tokio::test]
async fn the_real_client_does_not_follow_redirects_or_send_extra_material() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
        panic!("loopback bind failed");
    };
    let Ok(addr) = listener.local_addr() else {
        panic!("no local address");
    };
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = Arc::clone(&requests);
    let location = format!("http://{addr}/second");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(String::from_utf8_lossy(&buffer[..read]).into_owned());
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });

    let url: &'static str = Box::leak(format!("http://{addr}/health/ready").into_boxed_str());
    let response = ReqwestTransport::for_local_test()
        .get(&HealthRequest::for_test(url))
        .await;
    assert_eq!(
        response,
        Ok(HealthResponse {
            status: 302,
            redirected: false
        })
    );
    assert_eq!(classify(response), ReadinessStatus::Offline);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen = requests.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(seen.len(), 1, "the redirect target must never be requested");
    let head = seen[0].to_ascii_lowercase();
    assert!(head.starts_with("get /health/ready http/1.1\r\n"));
    for forbidden in ["authorization:", "cookie:", "proxy-authorization:", "?"] {
        assert!(!head.contains(forbidden), "{forbidden} must not be sent");
    }
}

#[tokio::test]
async fn the_production_client_refuses_plain_http() {
    let transport = ReqwestTransport::new();
    let response = transport
        .get(&HealthRequest::for_test("http://127.0.0.1:9/health/ready"))
        .await;
    assert!(response.is_err(), "https_only must reject plain http");
}
