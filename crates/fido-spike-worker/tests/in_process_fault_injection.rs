//! M1.5 fault injection against the *merged, unmodified* in-process worker.
//!
//! A `GateBackend` stands in for a native call that blocks until the test releases it. Counters
//! observe what the worker thread is really doing, independent of what the service was told.

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fido_core::DeviceReadStatus;
use fido_libfido2::{
    NativeDeviceInfo, NativeDeviceKey, NativeDiscoveredDevice, NativeDiscoveryBackend, NativeError,
};
use fido_service::{
    DiscoveryCoordinator, DiscoveryError, DiscoveryPolicy, InProcessWorkerEndpoint, WorkerEndpoint,
    WorkerEndpointError, WorkerGeneration,
};
use fido_worker_protocol::{
    CancellationId, RequestBudgetMs, WORKER_PROTOCOL_VERSION, WorkerRequest, WorkerRequestEnvelope,
    WorkerRequestId,
};

type TestResult = Result<(), Box<dyn Error>>;

/// Mirrors `in_process_worker::HARD_DEADLINE_SLACK_MS` (private there).
const SLACK_MS: u64 = 250;

#[derive(Default)]
struct Gate {
    released: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        let mut released = self.released.lock().unwrap_or_else(|p| p.into_inner());
        while !*released {
            released = self
                .changed
                .wait(released)
                .unwrap_or_else(|p| p.into_inner());
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.changed.notify_all();
    }
}

/// Process-wide view of "native" activity, shared by every backend instance the test creates (the
/// stand-in for one physical HID stack / one authenticator).
#[derive(Default)]
struct NativeActivity {
    entered: AtomicUsize,
    completed: AtomicUsize,
    in_native: AtomicUsize,
    max_concurrent: AtomicUsize,
}

impl NativeActivity {
    fn enter(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let now = self.in_native.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_concurrent.fetch_max(now, Ordering::SeqCst);
    }

    fn leave(&self) {
        self.in_native.fetch_sub(1, Ordering::SeqCst);
        self.completed.fetch_add(1, Ordering::SeqCst);
    }
}

struct GateBackend {
    activity: Arc<NativeActivity>,
    /// `Some` => every native call blocks (ignoring its budget) until released.
    gate: Option<Arc<Gate>>,
    devices: u8,
    get_info_delay: Duration,
}

impl NativeDiscoveryBackend for GateBackend {
    fn manifest(&mut self, _budget_ms: u64) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
        self.activity.enter();
        if let Some(gate) = &self.gate {
            gate.wait();
        }
        let mut out = Vec::new();
        for index in 0..self.devices {
            out.push(NativeDiscoveredDevice {
                key: NativeDeviceKey::from_bytes(vec![b'k', b'0' + index])?,
                vendor_id: 0x1234,
                product_id: 0x5678,
                manufacturer: Some("Spike".to_owned()),
                product: Some("Fake".to_owned()),
            });
        }
        self.activity.leave();
        Ok(out)
    }

    fn get_info(
        &mut self,
        _key: &NativeDeviceKey,
        _budget_ms: u64,
    ) -> Result<NativeDeviceInfo, NativeError> {
        self.activity.enter();
        thread::sleep(self.get_info_delay);
        self.activity.leave();
        Ok(NativeDeviceInfo {
            aaguid: Some([7; 16]),
            versions: vec!["FIDO_2_1".to_owned()],
            extensions: Vec::new(),
            transports: vec!["usb".to_owned()],
            options: Vec::new(),
            max_message_size: Some(1_200),
            firmware_version: Some(1),
        })
    }
}

fn backend(activity: &Arc<NativeActivity>, gate: Option<&Arc<Gate>>) -> GateBackend {
    GateBackend {
        activity: Arc::clone(activity),
        gate: gate.map(Arc::clone),
        devices: 1,
        get_info_delay: Duration::ZERO,
    }
}

fn wait_until(what: &str, condition: impl Fn() -> bool) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for: {what}").into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn policy(budget_ms: u64) -> DiscoveryPolicy {
    DiscoveryPolicy {
        list_devices_budget_ms: budget_ms,
        get_device_info_budget_ms: budget_ms,
    }
}

fn list_request(generation: WorkerGeneration, id: u64, budget_ms: u64) -> WorkerRequestEnvelope {
    WorkerRequestEnvelope {
        protocol_version: WORKER_PROTOCOL_VERSION,
        request_id: WorkerRequestId(id),
        cancellation_id: CancellationId(id),
        operation_class: WorkerRequest::ListDevices.operation_class(),
        worker_generation: generation,
        device_generation: None,
        budget_ms: RequestBudgetMs(budget_ms),
        request: WorkerRequest::ListDevices,
    }
}

/// Steps A-G from the spike brief, in one narrated timeline.
#[test]
fn service_timeout_is_not_quiescence() -> TestResult {
    let activity = Arc::new(NativeActivity::default());
    let gate = Arc::new(Gate::default());
    let generation = WorkerGeneration(1);
    let endpoint = InProcessWorkerEndpoint::spawn(backend(&activity, Some(&gate)), generation)?;
    let mut coordinator = DiscoveryCoordinator::new(endpoint, generation, policy(50))?;

    // A. request begins (the native call enters and blocks).
    let started = Instant::now();
    let result = coordinator.refresh();
    let elapsed = started.elapsed();
    println!(
        "A. native call entered: {}",
        activity.entered.load(Ordering::SeqCst)
    );

    // B/C. the service deadline (budget 50 + slack 250) expired and the service failed closed.
    println!("B/C. refresh -> {result:?} after {elapsed:?}");
    assert!(matches!(
        result,
        Err(DiscoveryError::Endpoint(
            WorkerEndpointError::TransportFailure
        ))
    ));
    assert!(elapsed >= Duration::from_millis(50 + SLACK_MS));
    assert!(
        elapsed < Duration::from_secs(2),
        "service must stay responsive"
    );

    // D. ...but the native operation is STILL executing.
    assert_eq!(activity.entered.load(Ordering::SeqCst), 1);
    assert_eq!(activity.in_native.load(Ordering::SeqCst), 1);
    assert_eq!(activity.completed.load(Ordering::SeqCst), 0);
    println!("D. native still in flight: in_native=1, completed=0");

    // E. Nothing in the endpoint/coordinator surface can report quiescence: the only evidence type
    //    (`ExecutionQuiescence`) rides on a *response*, and no response exists. The service can
    //    only infer "unknown", so it must assume Active.

    // F. quarantine prevents reuse and issues no new native work.
    assert!(matches!(
        coordinator.refresh(),
        Err(DiscoveryError::WorkerQuarantined)
    ));
    assert_eq!(activity.entered.load(Ordering::SeqCst), 1);
    println!("F. quarantined: second refresh rejected with no new native entry");

    // G. release the blocked call: it completes, but the old worker must stay non-authoritative.
    gate.release();
    wait_until("blocked native call to complete", || {
        activity.completed.load(Ordering::SeqCst) == 1
    })?;
    assert_eq!(activity.in_native.load(Ordering::SeqCst), 0);
    assert!(matches!(
        coordinator.refresh(),
        Err(DiscoveryError::WorkerQuarantined)
    ));
    assert_eq!(
        activity.entered.load(Ordering::SeqCst),
        1,
        "late completion must not trigger or authorize further native work"
    );
    println!("G. released: native completed, coordinator still quarantined");
    Ok(())
}

/// A request that timed out while *queued* behind the blocked call still executes natively once the
/// call is released, with nobody waiting for the result.
#[test]
fn abandoned_queued_request_executes_after_release() -> TestResult {
    let activity = Arc::new(NativeActivity::default());
    let gate = Arc::new(Gate::default());
    let generation = WorkerGeneration(1);
    let mut endpoint = InProcessWorkerEndpoint::spawn(backend(&activity, Some(&gate)), generation)?;

    assert_eq!(
        endpoint.exchange(list_request(generation, 1, 50)),
        Err(WorkerEndpointError::TransportFailure)
    );
    // Second request queues behind the stuck worker thread; it times out without entering native.
    assert_eq!(
        endpoint.exchange(list_request(generation, 2, 50)),
        Err(WorkerEndpointError::TransportFailure)
    );
    assert_eq!(activity.entered.load(Ordering::SeqCst), 1);

    gate.release();
    wait_until("abandoned request to run natively", || {
        activity.completed.load(Ordering::SeqCst) == 2
    })?;
    println!(
        "abandoned request #2 executed natively after release: entered={}",
        activity.entered.load(Ordering::SeqCst)
    );
    // This is why a thread endpoint can never be allowed to carry a mutation: a request the service
    // already reported as failed/timed-out can still execute later.
    assert_eq!(activity.entered.load(Ordering::SeqCst), 2);
    Ok(())
}

/// `replace_worker` is accepted by the API while the old thread is still inside native code, so two
/// workers can be in native code against the same device stack at once.
#[test]
fn in_process_replacement_overlaps_stuck_native_call() -> TestResult {
    let activity = Arc::new(NativeActivity::default());
    let gate = Arc::new(Gate::default());
    let old = WorkerGeneration(1);
    let endpoint = InProcessWorkerEndpoint::spawn(backend(&activity, Some(&gate)), old)?;
    let mut coordinator = DiscoveryCoordinator::new(endpoint, old, policy(50))?;
    assert!(coordinator.refresh().is_err());
    assert_eq!(activity.in_native.load(Ordering::SeqCst), 1);

    let new = WorkerGeneration(2);
    let replacement = InProcessWorkerEndpoint::spawn(backend(&activity, None), new)?;
    // Nothing forces the caller to prove the old worker is quiescent.
    coordinator.replace_worker(replacement, new)?;
    let snapshot = coordinator.refresh()?;
    assert_eq!(snapshot.devices.len(), 1);
    assert_eq!(snapshot.devices[0].read_status, DeviceReadStatus::Ready);

    println!(
        "max concurrent native calls observed: {}",
        activity.max_concurrent.load(Ordering::SeqCst)
    );
    assert_eq!(activity.max_concurrent.load(Ordering::SeqCst), 2);

    gate.release();
    wait_until("old worker to finish", || {
        activity.in_native.load(Ordering::SeqCst) == 0
    })?;
    // The old worker's late response went to a dropped channel; the new generation is unaffected.
    assert!(coordinator.refresh().is_ok());
    Ok(())
}

/// Dropping an endpoint neither stops nor joins a stuck worker thread.
#[test]
fn dropping_endpoint_leaves_stuck_thread_running() -> TestResult {
    let activity = Arc::new(NativeActivity::default());
    let gate = Arc::new(Gate::default());
    let generation = WorkerGeneration(1);
    let mut endpoint = InProcessWorkerEndpoint::spawn(backend(&activity, Some(&gate)), generation)?;
    assert!(endpoint.exchange(list_request(generation, 1, 50)).is_err());

    let started = Instant::now();
    drop(endpoint);
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "drop must not block"
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        activity.in_native.load(Ordering::SeqCst),
        1,
        "thread is detached and still in native code after the endpoint is gone"
    );
    gate.release(); // cooperative cleanup only: the service had no way to force this
    wait_until("detached thread to exit", || {
        activity.in_native.load(Ordering::SeqCst) == 0
    })
}

/// The 250 ms slack hides budget violations, and no deadline bounds the whole transaction.
#[test]
fn service_has_no_transaction_deadline_and_slack_hides_overrun() -> TestResult {
    let activity = Arc::new(NativeActivity::default());
    let generation = WorkerGeneration(1);
    let endpoint = InProcessWorkerEndpoint::spawn(
        GateBackend {
            activity: Arc::clone(&activity),
            gate: None,
            devices: 4,
            // 3x the 100 ms budget, still inside budget + slack (350 ms).
            get_info_delay: Duration::from_millis(300),
        },
        generation,
    )?;
    let mut coordinator = DiscoveryCoordinator::new(endpoint, generation, policy(100))?;

    let started = Instant::now();
    let snapshot = coordinator.refresh()?;
    let elapsed = started.elapsed();
    println!("refresh with 100 ms budgets took {elapsed:?} for 4 devices");

    assert_eq!(snapshot.devices.len(), 4);
    assert!(
        snapshot
            .devices
            .iter()
            .all(|device| device.read_status == DeviceReadStatus::Ready)
    );
    // Every native call blew its budget 3x, yet each was accepted as success, and the transaction
    // as a whole ran for 4 * 300 ms: unbounded by any single configured value.
    assert!(elapsed >= Duration::from_millis(1_200));
    Ok(())
}
