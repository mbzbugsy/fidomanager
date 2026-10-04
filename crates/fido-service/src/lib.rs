//! Offline FIDO policy and workflow coordination.

#[cfg(all(feature = "native-ui-spike", target_os = "macos"))]
pub mod native_ui_spike;

pub mod activity;
pub mod authentication;
pub mod discovery_presentation;
pub mod inspection;
pub mod mutation;
pub mod presentation;
pub mod recovery;

mod discovery;
mod process_worker;
mod supervisor;
#[cfg(test)]
mod test_support;

pub use discovery::{
    DiscoveryCoordinator, DiscoveryError, DiscoveryPolicy, DiscoveryPolicyError,
    RegisteredDeviceTarget, WorkerEndpoint, WorkerEndpointError,
};
pub use process_worker::{
    LaunchError, ProcessWorkerConfig, ProcessWorkerConfigError, ProcessWorkerEndpoint,
    ProcessWorkerLauncher, ResolvedWorkerExecutable,
};
pub use supervisor::{
    DiscoverySupervisor, RestartPolicy, RestartPolicyError, SupervisorConfigError, SupervisorError,
    SupervisorState, SupervisorStatus, WorkerLauncher,
};

pub use fido_worker_protocol::WorkerGeneration;

use std::collections::VecDeque;
use std::time::Instant;

use fido_core::{ExecutionQuiescence, RecoveryAdmission, SensitiveWorkflowKind, WorkflowId};
use thiserror::Error;

pub const REVIEWED_LIBFIDO2_BASELINE: &str = "1.17.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationInfo {
    pub phase: &'static str,
    pub worker_protocol_version: u16,
    pub reviewed_libfido2_baseline: &'static str,
}

pub const fn foundation_info() -> FoundationInfo {
    FoundationInfo {
        phase: if cfg!(target_os = "macos") {
            "milestone-4-native-pin-mutation"
        } else {
            "milestone-1-read-only-discovery"
        },
        worker_protocol_version: fido_worker_protocol::WORKER_PROTOCOL_VERSION,
        reviewed_libfido2_baseline: REVIEWED_LIBFIDO2_BASELINE,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionPolicy {
    pub interruption_budget: usize,
    pub interruption_window_ms: u64,
    pub cooldown_ms: u64,
}

impl AdmissionPolicy {
    pub fn validate(self) -> Result<Self, AdmissionPolicyError> {
        if self.interruption_budget == 0 {
            return Err(AdmissionPolicyError::ZeroInterruptionBudget);
        }
        if self.interruption_window_ms == 0 {
            return Err(AdmissionPolicyError::ZeroInterruptionWindow);
        }
        if self.cooldown_ms == 0 {
            return Err(AdmissionPolicyError::ZeroCooldown);
        }
        Ok(self)
    }
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            interruption_budget: 3,
            interruption_window_ms: 60_000,
            cooldown_ms: 30_000,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionPolicyError {
    #[error("interruption budget must be greater than zero")]
    ZeroInterruptionBudget,
    #[error("interruption window must be greater than zero")]
    ZeroInterruptionWindow,
    #[error("cooldown duration must be greater than zero")]
    ZeroCooldown,
}

/// Elapsed milliseconds from an authority-owned monotonic clock origin.
///
/// Wall-clock timestamps and renderer-controlled time values must not be used here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonotonicMillis(u64);

impl MonotonicMillis {
    pub const fn from_millis(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

/// Source of authority-owned monotonic time.
///
/// Policy code (transaction deadlines, restart backoff) reads time only through this trait so it
/// can be tested deterministically. It is never fed by renderer-supplied or wall-clock values.
pub trait MonotonicClock {
    fn now(&self) -> MonotonicMillis;
}

/// Real monotonic clock, measured from the moment it was created.
#[derive(Debug, Clone, Copy)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> MonotonicMillis {
        let elapsed = self.origin.elapsed().as_millis();
        MonotonicMillis::from_millis(u64::try_from(elapsed).unwrap_or(u64::MAX))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowCompletion {
    Succeeded,
    Cancelled,
    TimedOut,
    Rejected,
    Failed,
}

/// Authority-minted admission ticket for exactly one active workflow generation.
///
/// This type is intentionally neither `Clone` nor `Copy` and cannot be constructed by callers.
#[derive(Debug, PartialEq, Eq)]
pub struct WorkflowAdmission {
    workflow_id: WorkflowId,
    kind: SensitiveWorkflowKind,
}

impl WorkflowAdmission {
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    pub const fn kind(&self) -> SensitiveWorkflowKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowReleaseEvidence {
    pub execution_quiescence: ExecutionQuiescence,
    pub recovery_admission: RecoveryAdmission,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("another sensitive workflow is active")]
    OperationInProgress,
    #[error("sensitive workflow admission is cooling down")]
    CoolingDown,
    #[error("recovery admission barrier blocks ordinary sensitive workflows")]
    RecoveryBarrier,
    #[error("workflow identity space is exhausted")]
    WorkflowIdExhausted,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CompletionError {
    #[error("workflow is not the active sensitive workflow")]
    NotActiveWorkflow,
    #[error("native execution is not proven quiescent")]
    ExecutionNotQuiescent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveWorkflow {
    workflow_id: WorkflowId,
    kind: SensitiveWorkflowKind,
}

#[derive(Debug)]
pub struct SensitiveWorkflowGate {
    policy: AdmissionPolicy,
    active: Option<ActiveWorkflow>,
    recovery_admission: RecoveryAdmission,
    persistent_barrier: bool,
    next_workflow_raw: u128,
    interruptions: VecDeque<u64>,
    cooldown_until_ms: Option<u64>,
}

impl SensitiveWorkflowGate {
    pub fn new(policy: AdmissionPolicy) -> Result<Self, AdmissionPolicyError> {
        Ok(Self::from_valid_policy(policy.validate()?))
    }

    pub fn try_begin(
        &mut self,
        kind: SensitiveWorkflowKind,
        now: MonotonicMillis,
    ) -> Result<WorkflowAdmission, AdmissionError> {
        let now_ms = now.as_millis();
        self.prune_interruptions(now_ms);

        if self.active.is_some() {
            return Err(AdmissionError::OperationInProgress);
        }

        if self.recovery_admission == RecoveryAdmission::Barrier
            && kind != SensitiveWorkflowKind::Recovery
        {
            return Err(AdmissionError::RecoveryBarrier);
        }

        if self
            .cooldown_until_ms
            .is_some_and(|cooldown_until| now_ms < cooldown_until)
        {
            return Err(AdmissionError::CoolingDown);
        }

        let workflow_id = WorkflowId::from_raw(self.next_workflow_raw);
        self.next_workflow_raw = self
            .next_workflow_raw
            .checked_add(1)
            .ok_or(AdmissionError::WorkflowIdExhausted)?;

        self.cooldown_until_ms = None;
        self.active = Some(ActiveWorkflow { workflow_id, kind });

        Ok(WorkflowAdmission { workflow_id, kind })
    }

    pub fn finish(
        &mut self,
        admission: &WorkflowAdmission,
        completion: WorkflowCompletion,
        release_evidence: WorkflowReleaseEvidence,
        now: MonotonicMillis,
    ) -> Result<(), CompletionError> {
        let expected = ActiveWorkflow {
            workflow_id: admission.workflow_id,
            kind: admission.kind,
        };
        if self.active != Some(expected) {
            return Err(CompletionError::NotActiveWorkflow);
        }
        if release_evidence.execution_quiescence != ExecutionQuiescence::Quiescent {
            return Err(CompletionError::ExecutionNotQuiescent);
        }

        // Quiescence permits the exclusion lock to release. Recovery admission remains a
        // separate authority state and may continue to block ordinary workflows afterwards.
        self.active = None;
        self.recovery_admission = if self.persistent_barrier {
            RecoveryAdmission::Barrier
        } else {
            release_evidence.recovery_admission
        };

        if matches!(
            completion,
            WorkflowCompletion::Cancelled
                | WorkflowCompletion::TimedOut
                | WorkflowCompletion::Rejected
        ) {
            let now_ms = now.as_millis();
            self.interruptions.push_back(now_ms);
            self.prune_interruptions(now_ms);

            if self.interruptions.len() >= self.policy.interruption_budget {
                self.cooldown_until_ms = Some(now_ms.saturating_add(self.policy.cooldown_ms));
            }
        }

        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }

    pub const fn recovery_admission(&self) -> RecoveryAdmission {
        self.recovery_admission
    }

    pub(crate) fn set_persistent_barrier(&mut self, barrier: bool) {
        self.persistent_barrier = barrier;
        self.recovery_admission = if barrier {
            RecoveryAdmission::Barrier
        } else {
            RecoveryAdmission::Open
        };
    }

    pub(crate) fn matches(&self, admission: &WorkflowAdmission) -> bool {
        self.active
            == Some(ActiveWorkflow {
                workflow_id: admission.workflow_id,
                kind: admission.kind,
            })
    }

    fn from_valid_policy(policy: AdmissionPolicy) -> Self {
        Self {
            policy,
            active: None,
            recovery_admission: RecoveryAdmission::Open,
            persistent_barrier: false,
            next_workflow_raw: 1,
            interruptions: VecDeque::new(),
            cooldown_until_ms: None,
        }
    }

    fn prune_interruptions(&mut self, now_ms: u64) {
        let oldest_allowed = now_ms.saturating_sub(self.policy.interruption_window_ms);
        while self
            .interruptions
            .front()
            .is_some_and(|timestamp| *timestamp < oldest_allowed)
        {
            self.interruptions.pop_front();
        }
    }
}

impl Default for SensitiveWorkflowGate {
    fn default() -> Self {
        Self::from_valid_policy(AdmissionPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE_OK: WorkflowReleaseEvidence = WorkflowReleaseEvidence {
        execution_quiescence: ExecutionQuiescence::Quiescent,
        recovery_admission: RecoveryAdmission::Open,
    };

    #[test]
    fn sensitive_workflows_are_never_queued() -> Result<(), Box<dyn std::error::Error>> {
        let mut gate = SensitiveWorkflowGate::default();
        let _first = gate.try_begin(
            SensitiveWorkflowKind::CredentialInspection,
            MonotonicMillis::from_millis(0),
        )?;

        assert_eq!(
            gate.try_begin(
                SensitiveWorkflowKind::ChangePin,
                MonotonicMillis::from_millis(1),
            ),
            Err(AdmissionError::OperationInProgress)
        );
        Ok(())
    }

    #[test]
    fn repeated_interruptions_and_rejections_trigger_cooldown()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut gate = SensitiveWorkflowGate::new(AdmissionPolicy {
            interruption_budget: 2,
            interruption_window_ms: 1_000,
            cooldown_ms: 500,
        })?;

        let first = gate.try_begin(
            SensitiveWorkflowKind::CredentialInspection,
            MonotonicMillis::from_millis(10),
        )?;
        gate.finish(
            &first,
            WorkflowCompletion::Cancelled,
            RELEASE_OK,
            MonotonicMillis::from_millis(10),
        )?;

        let second = gate.try_begin(
            SensitiveWorkflowKind::ChangePin,
            MonotonicMillis::from_millis(20),
        )?;
        gate.finish(
            &second,
            WorkflowCompletion::Rejected,
            RELEASE_OK,
            MonotonicMillis::from_millis(20),
        )?;

        assert_eq!(
            gate.try_begin(
                SensitiveWorkflowKind::SetPin,
                MonotonicMillis::from_millis(21),
            ),
            Err(AdmissionError::CoolingDown)
        );
        assert!(
            gate.try_begin(
                SensitiveWorkflowKind::SetPin,
                MonotonicMillis::from_millis(520),
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn gate_stays_held_until_native_execution_is_quiescent()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut gate = SensitiveWorkflowGate::default();
        let admission = gate.try_begin(
            SensitiveWorkflowKind::ChangePin,
            MonotonicMillis::from_millis(0),
        )?;

        assert_eq!(
            gate.finish(
                &admission,
                WorkflowCompletion::TimedOut,
                WorkflowReleaseEvidence {
                    execution_quiescence: ExecutionQuiescence::Active,
                    recovery_admission: RecoveryAdmission::Open,
                },
                MonotonicMillis::from_millis(1),
            ),
            Err(CompletionError::ExecutionNotQuiescent)
        );
        assert!(gate.is_active());
        Ok(())
    }

    #[test]
    fn recovery_barrier_remains_separate_after_workflow_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut gate = SensitiveWorkflowGate::default();
        let admission = gate.try_begin(
            SensitiveWorkflowKind::ChangePin,
            MonotonicMillis::from_millis(0),
        )?;

        gate.finish(
            &admission,
            WorkflowCompletion::TimedOut,
            WorkflowReleaseEvidence {
                execution_quiescence: ExecutionQuiescence::Quiescent,
                recovery_admission: RecoveryAdmission::Barrier,
            },
            MonotonicMillis::from_millis(1),
        )?;

        assert!(!gate.is_active());
        assert_eq!(gate.recovery_admission(), RecoveryAdmission::Barrier);
        assert_eq!(
            gate.try_begin(
                SensitiveWorkflowKind::CredentialInspection,
                MonotonicMillis::from_millis(2),
            ),
            Err(AdmissionError::RecoveryBarrier)
        );

        let recovery = gate.try_begin(
            SensitiveWorkflowKind::Recovery,
            MonotonicMillis::from_millis(2),
        )?;
        gate.finish(
            &recovery,
            WorkflowCompletion::Succeeded,
            RELEASE_OK,
            MonotonicMillis::from_millis(3),
        )?;
        assert_eq!(gate.recovery_admission(), RecoveryAdmission::Open);
        Ok(())
    }

    #[test]
    fn stale_admission_cannot_release_a_new_workflow() -> Result<(), Box<dyn std::error::Error>> {
        let mut gate = SensitiveWorkflowGate::default();
        let first = gate.try_begin(
            SensitiveWorkflowKind::CredentialInspection,
            MonotonicMillis::from_millis(0),
        )?;
        gate.finish(
            &first,
            WorkflowCompletion::Succeeded,
            RELEASE_OK,
            MonotonicMillis::from_millis(1),
        )?;

        let second = gate.try_begin(
            SensitiveWorkflowKind::CredentialInspection,
            MonotonicMillis::from_millis(2),
        )?;
        assert_eq!(
            gate.finish(
                &first,
                WorkflowCompletion::Succeeded,
                RELEASE_OK,
                MonotonicMillis::from_millis(3),
            ),
            Err(CompletionError::NotActiveWorkflow)
        );
        assert_eq!(
            gate.finish(
                &second,
                WorkflowCompletion::Succeeded,
                RELEASE_OK,
                MonotonicMillis::from_millis(4),
            ),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn invalid_policy_is_rejected() {
        let result = SensitiveWorkflowGate::new(AdmissionPolicy {
            interruption_budget: 0,
            interruption_window_ms: 1_000,
            cooldown_ms: 500,
        });
        assert!(matches!(
            result,
            Err(AdmissionPolicyError::ZeroInterruptionBudget)
        ));
    }
}
