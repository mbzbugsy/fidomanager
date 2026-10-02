//! Worker supervision: launch, recovery, backoff, and crash-loop protection.
//!
//! `DiscoverySupervisor` owns the discovery coordinator and the only path that creates workers. It
//! turns "the worker hung/crashed" into deterministic recovery without restarting the app:
//!
//! ```text
//!   refresh() -> worker fails -> coordinator quarantines + contains it -> error to the caller
//!   refresh() -> backoff elapsed -> prove old worker contained -> launch generation N+1 -> refresh
//! ```
//!
//! Restart behaviour is bounded in two ways. Consecutive failures back off exponentially up to a
//! cap. And too many failures inside a sliding window open a circuit that stops launching for a
//! long cooldown; after it, exactly one probe launch is allowed, and a failed probe re-opens the
//! circuit immediately. The result is a bounded respawn *rate* with no tight loop, that heals by
//! itself, and that never needs the renderer to ask for a restart.

use std::collections::VecDeque;

use fido_core::{DeviceHandle, DeviceListSnapshot, ExecutionQuiescence};
use thiserror::Error;

use crate::{
    DiscoveryCoordinator, DiscoveryError, DiscoveryPolicy, DiscoveryPolicyError, LaunchError,
    MonotonicClock, RegisteredDeviceTarget, SystemMonotonicClock, WorkerEndpoint, WorkerGeneration,
};

/// Creates workers. Implementations decide where a worker runs; the supervisor decides when.
pub trait WorkerLauncher {
    type Endpoint: WorkerEndpoint;

    fn launch(&mut self, generation: WorkerGeneration) -> Result<Self::Endpoint, LaunchError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    /// Delay after the first failure; doubles for each consecutive failure.
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    /// This many failures within `crash_loop_window_ms` open the circuit.
    pub crash_loop_threshold: u32,
    pub crash_loop_window_ms: u64,
    /// How long an open circuit refuses to launch before allowing one probe.
    pub crash_loop_cooldown_ms: u64,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicyError {
    #[error("restart policy durations and thresholds must be greater than zero")]
    Zero,
    #[error("initial backoff must not exceed the maximum backoff")]
    InitialBackoffAboveMaximum,
}

impl RestartPolicy {
    pub fn validate(self) -> Result<Self, RestartPolicyError> {
        if self.initial_backoff_ms == 0
            || self.max_backoff_ms == 0
            || self.crash_loop_threshold == 0
            || self.crash_loop_window_ms == 0
            || self.crash_loop_cooldown_ms == 0
        {
            return Err(RestartPolicyError::Zero);
        }
        if self.initial_backoff_ms > self.max_backoff_ms {
            return Err(RestartPolicyError::InitialBackoffAboveMaximum);
        }
        Ok(self)
    }
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            initial_backoff_ms: 250,
            max_backoff_ms: 5_000,
            crash_loop_threshold: 5,
            crash_loop_window_ms: 60_000,
            crash_loop_cooldown_ms: 60_000,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorConfigError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryPolicyError),
    #[error(transparent)]
    Restart(#[from] RestartPolicyError),
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error("could not start the native worker: {0}")]
    Launch(LaunchError),
    #[error("the native worker is restarting; try again shortly")]
    RestartBackoff { retry_after_ms: u64 },
    #[error("the native worker keeps failing; automatic restarts are paused")]
    CrashLoop { retry_after_ms: u64 },
    #[error("the previous native worker could not be proven stopped")]
    WorkerNotContained,
    #[error("worker generation space is exhausted")]
    GenerationExhausted,
    #[error("the native discovery policy is invalid")]
    InvalidDiscoveryPolicy,
    #[error("the native worker was shut down")]
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Circuit {
    Closed,
    Open { until_ms: u64 },
    HalfOpen,
}

#[derive(Debug)]
struct FailureLedger {
    policy: RestartPolicy,
    recent_failures: VecDeque<u64>,
    consecutive_failures: u32,
    circuit: Circuit,
    next_attempt_at_ms: u64,
}

enum Denial {
    Backoff { retry_after_ms: u64 },
    CrashLoop { retry_after_ms: u64 },
}

impl FailureLedger {
    fn new(policy: RestartPolicy) -> Self {
        Self {
            policy,
            recent_failures: VecDeque::new(),
            consecutive_failures: 0,
            circuit: Circuit::Closed,
            next_attempt_at_ms: 0,
        }
    }

    /// May a launch be attempted now?
    fn admit(&mut self, now_ms: u64) -> Result<(), Denial> {
        if let Circuit::Open { until_ms } = self.circuit {
            if now_ms < until_ms {
                return Err(Denial::CrashLoop {
                    retry_after_ms: until_ms - now_ms,
                });
            }
            // Cooldown over: allow exactly one probe.
            self.circuit = Circuit::HalfOpen;
        }
        if now_ms < self.next_attempt_at_ms {
            return Err(Denial::Backoff {
                retry_after_ms: self.next_attempt_at_ms - now_ms,
            });
        }
        Ok(())
    }

    fn record_failure(&mut self, now_ms: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.recent_failures.push_back(now_ms);
        let oldest_counted = now_ms.saturating_sub(self.policy.crash_loop_window_ms);
        while self
            .recent_failures
            .front()
            .is_some_and(|failed_at| *failed_at < oldest_counted)
        {
            self.recent_failures.pop_front();
        }

        let trips = match self.circuit {
            // A failed probe re-opens immediately.
            Circuit::HalfOpen => true,
            Circuit::Closed => {
                let counted = u32::try_from(self.recent_failures.len()).unwrap_or(u32::MAX);
                counted >= self.policy.crash_loop_threshold
            }
            Circuit::Open { .. } => true,
        };

        if trips {
            let until_ms = now_ms.saturating_add(self.policy.crash_loop_cooldown_ms);
            self.circuit = Circuit::Open { until_ms };
            self.next_attempt_at_ms = until_ms;
        } else {
            self.next_attempt_at_ms = now_ms.saturating_add(self.backoff_ms());
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.next_attempt_at_ms = 0;
        if self.circuit == Circuit::HalfOpen {
            // The probe worked: the loop is over, forget the old failures.
            self.circuit = Circuit::Closed;
            self.recent_failures.clear();
        }
        // In the closed state recent failures are kept on purpose so a worker that alternates
        // success and failure still trips the breaker.
    }

    fn backoff_ms(&self) -> u64 {
        let exponent = self.consecutive_failures.saturating_sub(1).min(20);
        self.policy
            .initial_backoff_ms
            .saturating_mul(1u64 << exponent)
            .min(self.policy.max_backoff_ms)
    }

    fn denial_for(&self, now_ms: u64) -> Option<Denial> {
        match self.circuit {
            Circuit::Open { until_ms } if now_ms < until_ms => Some(Denial::CrashLoop {
                retry_after_ms: until_ms - now_ms,
            }),
            _ if now_ms < self.next_attempt_at_ms => Some(Denial::Backoff {
                retry_after_ms: self.next_attempt_at_ms - now_ms,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    /// No worker has been launched yet.
    NoWorker,
    Running,
    /// Waiting out a backoff before the next launch.
    Restarting {
        retry_after_ms: u64,
    },
    /// Circuit open: launches are paused.
    CrashLoop {
        retry_after_ms: u64,
    },
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorStatus {
    pub state: SupervisorState,
    pub worker_generation: Option<WorkerGeneration>,
    pub launches: u64,
    pub consecutive_failures: u32,
}

pub struct DiscoverySupervisor<L: WorkerLauncher, C = SystemMonotonicClock> {
    launcher: L,
    clock: C,
    discovery_policy: DiscoveryPolicy,
    coordinator: Option<DiscoveryCoordinator<L::Endpoint, C>>,
    ledger: FailureLedger,
    next_generation: u64,
    launches: u64,
    stopped: bool,
}

impl<L: WorkerLauncher> DiscoverySupervisor<L, SystemMonotonicClock> {
    pub fn new(
        launcher: L,
        discovery_policy: DiscoveryPolicy,
        restart_policy: RestartPolicy,
    ) -> Result<Self, SupervisorConfigError> {
        Self::with_clock(
            launcher,
            discovery_policy,
            restart_policy,
            SystemMonotonicClock::new(),
        )
    }
}

impl<L, C> DiscoverySupervisor<L, C>
where
    L: WorkerLauncher,
    C: MonotonicClock + Clone,
{
    pub fn with_clock(
        launcher: L,
        discovery_policy: DiscoveryPolicy,
        restart_policy: RestartPolicy,
        clock: C,
    ) -> Result<Self, SupervisorConfigError> {
        Ok(Self {
            launcher,
            clock,
            discovery_policy: discovery_policy.validate()?,
            coordinator: None,
            ledger: FailureLedger::new(restart_policy.validate()?),
            next_generation: 1,
            launches: 0,
            stopped: false,
        })
    }

    /// One discovery transaction, recovering the worker first if it is out of service.
    ///
    /// A failure that takes the worker out of service is reported to the caller once; the next
    /// call performs the replacement (after any backoff).
    pub fn refresh(&mut self) -> Result<DeviceListSnapshot, SupervisorError> {
        if self.stopped {
            return Err(SupervisorError::Stopped);
        }
        self.ensure_worker()?;

        let Some(coordinator) = self.coordinator.as_mut() else {
            // `ensure_worker` guarantees a coordinator on success.
            return Err(SupervisorError::Stopped);
        };
        match coordinator.refresh() {
            Ok(snapshot) => {
                self.ledger.record_success();
                Ok(snapshot)
            }
            Err(error) => {
                if coordinator.is_quarantined() {
                    self.ledger.record_failure(self.clock.now().as_millis());
                }
                Err(SupervisorError::Discovery(error))
            }
        }
    }

    pub fn resolve_handle(&self, handle: DeviceHandle) -> Option<RegisteredDeviceTarget> {
        self.coordinator
            .as_ref()
            .and_then(|coordinator| coordinator.resolve_handle(handle))
    }

    /// Stops the worker for good. Used at application exit; afterwards `refresh` fails closed.
    pub fn shutdown(&mut self) -> ExecutionQuiescence {
        self.stopped = true;
        match self.coordinator.as_mut() {
            Some(coordinator) => coordinator.contain_worker(),
            None => ExecutionQuiescence::Quiescent,
        }
    }

    pub fn status(&self) -> SupervisorStatus {
        let now_ms = self.clock.now().as_millis();
        let worker_usable = self
            .coordinator
            .as_ref()
            .is_some_and(|coordinator| !coordinator.is_quarantined());
        let state = if self.stopped {
            SupervisorState::Stopped
        } else if worker_usable {
            SupervisorState::Running
        } else {
            match self.ledger.denial_for(now_ms) {
                Some(Denial::CrashLoop { retry_after_ms }) => {
                    SupervisorState::CrashLoop { retry_after_ms }
                }
                Some(Denial::Backoff { retry_after_ms }) => {
                    SupervisorState::Restarting { retry_after_ms }
                }
                None if self.coordinator.is_some() => {
                    SupervisorState::Restarting { retry_after_ms: 0 }
                }
                None => SupervisorState::NoWorker,
            }
        };
        SupervisorStatus {
            state,
            worker_generation: self
                .coordinator
                .as_ref()
                .map(DiscoveryCoordinator::worker_generation),
            launches: self.launches,
            consecutive_failures: self.ledger.consecutive_failures,
        }
    }

    fn ensure_worker(&mut self) -> Result<(), SupervisorError> {
        let needs_worker = self
            .coordinator
            .as_ref()
            .is_none_or(DiscoveryCoordinator::is_quarantined);
        if !needs_worker {
            return Ok(());
        }

        let now_ms = self.clock.now().as_millis();
        self.ledger.admit(now_ms).map_err(|denial| match denial {
            Denial::Backoff { retry_after_ms } => {
                SupervisorError::RestartBackoff { retry_after_ms }
            }
            Denial::CrashLoop { retry_after_ms } => SupervisorError::CrashLoop { retry_after_ms },
        })?;

        // 1. Prove the previous worker is stopped *before* a replacement can exist.
        if let Some(coordinator) = self.coordinator.as_mut() {
            if coordinator.contain_worker() != ExecutionQuiescence::Quiescent {
                self.ledger.record_failure(now_ms);
                return Err(SupervisorError::WorkerNotContained);
            }
        }

        // 2. Launch the replacement under a strictly higher generation. Generations are consumed
        //    on every attempt so a number is never reused for a different process.
        let generation = WorkerGeneration(self.next_generation);
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(SupervisorError::GenerationExhausted)?;
        let endpoint = match self.launcher.launch(generation) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                self.ledger.record_failure(now_ms);
                return Err(SupervisorError::Launch(error));
            }
        };
        self.launches += 1;

        // 3. Install it. `replace_worker` re-verifies containment of the old worker itself.
        match self.coordinator.as_mut() {
            Some(coordinator) => {
                if let Err(error) = coordinator.replace_worker(endpoint, generation) {
                    self.ledger.record_failure(now_ms);
                    return Err(SupervisorError::Discovery(error));
                }
            }
            None => {
                let coordinator = DiscoveryCoordinator::with_clock(
                    endpoint,
                    generation,
                    self.discovery_policy,
                    self.clock.clone(),
                )
                .map_err(|_| SupervisorError::InvalidDiscoveryPolicy)?;
                self.coordinator = Some(coordinator);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use fido_core::DeviceGeneration;
    use fido_worker_protocol::{
        WORKER_PROTOCOL_VERSION, WorkerDeviceId, WorkerDeviceInfo, WorkerDiscoveredDevice,
        WorkerRequest, WorkerRequestEnvelope, WorkerResponse, WorkerResponseEnvelope,
        WorkerResponseEvidence,
    };

    use super::*;
    use crate::WorkerEndpointError;
    use crate::test_support::FakeClock;

    #[derive(Default)]
    struct World {
        /// Ordered record of launches, containment requests and exchanges.
        log: Vec<String>,
        launch_attempts: u64,
        fail_exchanges: bool,
        launch_failure: Option<LaunchError>,
        containment_active: bool,
    }

    struct ScriptEndpoint {
        generation: WorkerGeneration,
        world: Rc<RefCell<World>>,
    }

    impl WorkerEndpoint for ScriptEndpoint {
        fn exchange(
            &mut self,
            request: WorkerRequestEnvelope,
        ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
            let mut world = self.world.borrow_mut();
            world.log.push(format!("exchange g{}", self.generation.0));
            if world.fail_exchanges {
                return Err(WorkerEndpointError::ExchangeDeadlineExceeded);
            }
            let device_id = WorkerDeviceId(1);
            let response = match &request.request {
                WorkerRequest::ListDevices => WorkerResponse::DevicesListed {
                    devices: vec![WorkerDiscoveredDevice {
                        device_id,
                        device_generation: DeviceGeneration(1),
                        vendor_id: 1,
                        product_id: 2,
                        manufacturer: None,
                        product: None,
                    }],
                },
                _ => WorkerResponse::DeviceInfo {
                    info: WorkerDeviceInfo {
                        device_id,
                        aaguid: None,
                        versions: Vec::new(),
                        extensions: Vec::new(),
                        transports: Vec::new(),
                        options: Vec::new(),
                        max_message_size: None,
                        firmware_version: None,
                    },
                },
            };
            Ok(WorkerResponseEnvelope {
                protocol_version: WORKER_PROTOCOL_VERSION,
                request_id: request.request_id,
                worker_generation: self.generation,
                device_generation: request.device_generation,
                evidence: WorkerResponseEvidence {
                    execution_quiescence: ExecutionQuiescence::Quiescent,
                    mutation_outcome: None,
                },
                response,
            })
        }

        fn transport_margin_ms(&self) -> u64 {
            0
        }

        fn contain(&mut self) -> ExecutionQuiescence {
            let mut world = self.world.borrow_mut();
            world.log.push(format!("contain g{}", self.generation.0));
            if world.containment_active {
                ExecutionQuiescence::Active
            } else {
                ExecutionQuiescence::Quiescent
            }
        }
    }

    struct FakeLauncher {
        world: Rc<RefCell<World>>,
    }

    impl WorkerLauncher for FakeLauncher {
        type Endpoint = ScriptEndpoint;

        fn launch(&mut self, generation: WorkerGeneration) -> Result<ScriptEndpoint, LaunchError> {
            let mut world = self.world.borrow_mut();
            world.launch_attempts += 1;
            world.log.push(format!("launch g{}", generation.0));
            if let Some(error) = world.launch_failure {
                return Err(error);
            }
            Ok(ScriptEndpoint {
                generation,
                world: Rc::clone(&self.world),
            })
        }
    }

    type TestSupervisor = DiscoverySupervisor<FakeLauncher, FakeClock>;

    fn policy(threshold: u32) -> RestartPolicy {
        RestartPolicy {
            initial_backoff_ms: 250,
            max_backoff_ms: 1_000,
            crash_loop_threshold: threshold,
            crash_loop_window_ms: 60_000,
            crash_loop_cooldown_ms: 10_000,
        }
    }

    fn supervisor(
        restart: RestartPolicy,
    ) -> Result<(TestSupervisor, Rc<RefCell<World>>, FakeClock), SupervisorConfigError> {
        let world = Rc::new(RefCell::new(World::default()));
        let clock = FakeClock::default();
        let supervisor = DiscoverySupervisor::with_clock(
            FakeLauncher {
                world: Rc::clone(&world),
            },
            DiscoveryPolicy::default(),
            restart,
            clock.clone(),
        )?;
        Ok((supervisor, world, clock))
    }

    fn generation_of(supervisor: &TestSupervisor) -> Option<u64> {
        supervisor.status().worker_generation.map(|value| value.0)
    }

    fn is_endpoint_failure(result: &Result<DeviceListSnapshot, SupervisorError>) -> bool {
        matches!(
            result,
            Err(SupervisorError::Discovery(DiscoveryError::Endpoint(_)))
        )
    }

    #[test]
    fn first_refresh_launches_generation_one() -> Result<(), Box<dyn std::error::Error>> {
        let (mut supervisor, world, _clock) = supervisor(policy(5))?;
        assert_eq!(supervisor.status().state, SupervisorState::NoWorker);

        let snapshot = supervisor.refresh()?;
        assert_eq!(snapshot.devices.len(), 1);
        assert_eq!(generation_of(&supervisor), Some(1));
        assert_eq!(supervisor.status().state, SupervisorState::Running);
        assert_eq!(world.borrow().launch_attempts, 1);
        Ok(())
    }

    #[test]
    fn failed_worker_is_replaced_on_the_next_refresh_with_a_higher_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut supervisor, world, clock) = supervisor(policy(5))?;
        let first = supervisor.refresh()?;
        let stale_handle = first.devices[0].handle;
        assert!(supervisor.resolve_handle(stale_handle).is_some());

        world.borrow_mut().fail_exchanges = true;
        assert!(is_endpoint_failure(&supervisor.refresh()));
        assert_eq!(
            supervisor.status().state,
            SupervisorState::Restarting {
                retry_after_ms: 250
            }
        );
        assert!(
            supervisor.resolve_handle(stale_handle).is_none(),
            "handles from a failed worker stop resolving immediately"
        );

        // Inside the backoff nothing is launched.
        world.borrow_mut().fail_exchanges = false;
        assert_eq!(
            supervisor.refresh().err(),
            Some(SupervisorError::RestartBackoff {
                retry_after_ms: 250
            })
        );
        assert_eq!(world.borrow().launch_attempts, 1);

        clock.advance(250);
        let recovered = supervisor.refresh()?;
        assert_eq!(generation_of(&supervisor), Some(2));
        assert_eq!(recovered.devices.len(), 1);
        assert_ne!(recovered.devices[0].handle, stale_handle);
        assert!(supervisor.resolve_handle(stale_handle).is_none());
        assert_eq!(supervisor.status().consecutive_failures, 0);
        Ok(())
    }

    #[test]
    fn replacement_is_never_launched_before_the_previous_worker_is_proven_contained()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut supervisor, world, clock) = supervisor(policy(5))?;
        supervisor.refresh()?;

        {
            let mut world = world.borrow_mut();
            world.fail_exchanges = true;
            // The old worker cannot prove it has stopped.
            world.containment_active = true;
        }
        assert!(is_endpoint_failure(&supervisor.refresh()));

        clock.advance(250);
        assert_eq!(
            supervisor.refresh().err(),
            Some(SupervisorError::WorkerNotContained)
        );
        assert_eq!(
            world.borrow().launch_attempts,
            1,
            "no replacement may exist while the old worker is not proven stopped"
        );

        // Containment becomes provable; after the (longer) backoff the replacement launches.
        {
            let mut world = world.borrow_mut();
            world.fail_exchanges = false;
            world.containment_active = false;
        }
        clock.advance(500);
        supervisor.refresh()?;
        assert_eq!(generation_of(&supervisor), Some(2));

        // The entry right before the replacement's launch is the proof that g1 is stopped. (The
        // later `contain g1` is `replace_worker` re-verifying the same proof; containment is
        // idempotent.)
        let log = world.borrow().log.clone();
        let launch_two = log
            .iter()
            .position(|entry| entry == "launch g2")
            .ok_or("g2 was never launched")?;
        assert!(
            launch_two > 0 && log[launch_two - 1] == "contain g1",
            "{log:?}"
        );
        Ok(())
    }

    #[test]
    fn backoff_doubles_and_is_capped() -> Result<(), Box<dyn std::error::Error>> {
        let (mut supervisor, world, clock) = supervisor(policy(100))?;
        world.borrow_mut().launch_failure = Some(LaunchError::SpawnFailed);

        let mut observed = Vec::new();
        for _ in 0..5 {
            let attempt = supervisor.refresh();
            assert!(matches!(attempt, Err(SupervisorError::Launch(_))));
            let SupervisorState::Restarting { retry_after_ms } = supervisor.status().state else {
                return Err("expected a backoff state".into());
            };
            observed.push(retry_after_ms);
            clock.advance(retry_after_ms);
        }
        assert_eq!(observed, vec![250, 500, 1_000, 1_000, 1_000]);
        Ok(())
    }

    #[test]
    fn crash_loop_opens_the_circuit_and_stops_launching() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut supervisor, world, clock) = supervisor(policy(3))?;
        world.borrow_mut().launch_failure = Some(LaunchError::HandshakeTimeout);

        for _ in 0..3 {
            assert!(matches!(
                supervisor.refresh(),
                Err(SupervisorError::Launch(_))
            ));
            clock.advance(1_000);
        }
        assert_eq!(world.borrow().launch_attempts, 3);
        assert!(matches!(
            supervisor.status().state,
            SupervisorState::CrashLoop { .. }
        ));

        // Hammering refresh while the circuit is open must not spawn anything.
        for _ in 0..50 {
            assert!(matches!(
                supervisor.refresh(),
                Err(SupervisorError::CrashLoop { .. })
            ));
            clock.advance(100);
        }
        assert_eq!(
            world.borrow().launch_attempts,
            3,
            "an open circuit never launches"
        );
        Ok(())
    }

    #[test]
    fn half_open_probe_failure_reopens_the_circuit_immediately()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut supervisor, world, clock) = supervisor(policy(2))?;
        world.borrow_mut().launch_failure = Some(LaunchError::SpawnFailed);
        for _ in 0..2 {
            let _ = supervisor.refresh();
            clock.advance(1_000);
        }
        assert!(matches!(
            supervisor.status().state,
            SupervisorState::CrashLoop { .. }
        ));

        // Cooldown elapses: exactly one probe is allowed, and its failure re-opens at once.
        clock.advance(10_000);
        assert!(matches!(
            supervisor.refresh(),
            Err(SupervisorError::Launch(_))
        ));
        assert_eq!(world.borrow().launch_attempts, 3);
        assert!(matches!(
            supervisor.refresh(),
            Err(SupervisorError::CrashLoop { .. })
        ));
        assert_eq!(world.borrow().launch_attempts, 3);
        Ok(())
    }

    #[test]
    fn half_open_probe_success_closes_the_circuit() -> Result<(), Box<dyn std::error::Error>> {
        let (mut supervisor, world, clock) = supervisor(policy(2))?;
        world.borrow_mut().launch_failure = Some(LaunchError::SpawnFailed);
        for _ in 0..2 {
            let _ = supervisor.refresh();
            clock.advance(1_000);
        }
        world.borrow_mut().launch_failure = None;
        clock.advance(10_000);

        supervisor.refresh()?;
        assert_eq!(supervisor.status().state, SupervisorState::Running);
        assert_eq!(supervisor.status().consecutive_failures, 0);

        // The old failures were forgotten: one new failure is an ordinary backoff, not a trip.
        world.borrow_mut().fail_exchanges = true;
        assert!(is_endpoint_failure(&supervisor.refresh()));
        assert!(matches!(
            supervisor.status().state,
            SupervisorState::Restarting { .. }
        ));
        Ok(())
    }

    #[test]
    fn flapping_worker_trips_the_breaker_even_if_it_recovers_between_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut supervisor, world, clock) = supervisor(policy(3))?;
        supervisor.refresh()?;

        for round in 1..=3 {
            world.borrow_mut().fail_exchanges = true;
            assert!(is_endpoint_failure(&supervisor.refresh()), "round {round}");
            if round < 3 {
                world.borrow_mut().fail_exchanges = false;
                clock.advance(250);
                supervisor.refresh()?;
                assert_eq!(
                    supervisor.status().consecutive_failures,
                    0,
                    "a successful refresh resets the consecutive count"
                );
            }
        }
        assert!(
            matches!(supervisor.status().state, SupervisorState::CrashLoop { .. }),
            "three failures inside the window trip the breaker despite interleaved successes"
        );
        Ok(())
    }

    #[test]
    fn generations_are_consumed_by_failed_launches() -> Result<(), Box<dyn std::error::Error>> {
        let (mut supervisor, world, clock) = supervisor(policy(5))?;
        world.borrow_mut().launch_failure = Some(LaunchError::HealthCheckFailed);
        assert!(matches!(
            supervisor.refresh(),
            Err(SupervisorError::Launch(LaunchError::HealthCheckFailed))
        ));

        world.borrow_mut().launch_failure = None;
        clock.advance(250);
        supervisor.refresh()?;
        assert_eq!(
            generation_of(&supervisor),
            Some(2),
            "a generation handed to a failed launch is never reused"
        );
        Ok(())
    }

    #[test]
    fn shutdown_contains_the_worker_and_refuses_further_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut supervisor, world, _clock) = supervisor(policy(5))?;
        supervisor.refresh()?;

        assert_eq!(supervisor.shutdown(), ExecutionQuiescence::Quiescent);
        assert!(world.borrow().log.iter().any(|entry| entry == "contain g1"));
        assert_eq!(supervisor.status().state, SupervisorState::Stopped);
        assert_eq!(supervisor.refresh().err(), Some(SupervisorError::Stopped));
        assert_eq!(world.borrow().launch_attempts, 1);
        Ok(())
    }

    #[test]
    fn invalid_restart_policy_is_rejected() {
        let mut broken = policy(3);
        broken.initial_backoff_ms = broken.max_backoff_ms + 1;
        assert_eq!(
            broken.validate(),
            Err(RestartPolicyError::InitialBackoffAboveMaximum)
        );
        broken = policy(0);
        assert_eq!(broken.validate(), Err(RestartPolicyError::Zero));
    }
}
