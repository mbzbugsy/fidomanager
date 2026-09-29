//! Offline FIDO policy and workflow coordination.

use std::collections::VecDeque;

use fido_core::WorkflowId;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionPolicy {
    pub interruption_budget: usize,
    pub interruption_window_ms: u64,
    pub cooldown_ms: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowCompletion {
    Succeeded,
    Cancelled,
    TimedOut,
    Failed,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("another sensitive workflow is active")]
    OperationInProgress,
    #[error("sensitive workflow admission is cooling down")]
    CoolingDown,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CompletionError {
    #[error("workflow is not the active sensitive workflow")]
    NotActiveWorkflow,
}

#[derive(Debug)]
pub struct SensitiveWorkflowGate {
    policy: AdmissionPolicy,
    active: Option<WorkflowId>,
    interruptions: VecDeque<u64>,
    cooldown_until_ms: Option<u64>,
}

impl SensitiveWorkflowGate {
    pub fn new(policy: AdmissionPolicy) -> Self {
        Self {
            policy,
            active: None,
            interruptions: VecDeque::new(),
            cooldown_until_ms: None,
        }
    }

    pub fn try_begin(
        &mut self,
        workflow_id: WorkflowId,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        self.prune_interruptions(now_ms);

        if self.active.is_some() {
            return Err(AdmissionError::OperationInProgress);
        }

        if self
            .cooldown_until_ms
            .is_some_and(|cooldown_until| now_ms < cooldown_until)
        {
            return Err(AdmissionError::CoolingDown);
        }

        self.cooldown_until_ms = None;
        self.active = Some(workflow_id);
        Ok(())
    }

    pub fn finish(
        &mut self,
        workflow_id: WorkflowId,
        completion: WorkflowCompletion,
        now_ms: u64,
    ) -> Result<(), CompletionError> {
        if self.active != Some(workflow_id) {
            return Err(CompletionError::NotActiveWorkflow);
        }

        self.active = None;

        if matches!(
            completion,
            WorkflowCompletion::Cancelled | WorkflowCompletion::TimedOut
        ) {
            self.interruptions.push_back(now_ms);
            self.prune_interruptions(now_ms);

            if self.policy.interruption_budget > 0
                && self.interruptions.len() >= self.policy.interruption_budget
            {
                self.cooldown_until_ms = Some(now_ms.saturating_add(self.policy.cooldown_ms));
            }
        }

        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.active.is_some()
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
        Self::new(AdmissionPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_workflows_are_never_queued() {
        let mut gate = SensitiveWorkflowGate::default();
        let first = WorkflowId::from_raw(1);
        let second = WorkflowId::from_raw(2);

        assert_eq!(gate.try_begin(first, 0), Ok(()));
        assert_eq!(
            gate.try_begin(second, 1),
            Err(AdmissionError::OperationInProgress)
        );
    }

    #[test]
    fn repeated_interruptions_trigger_cooldown() -> Result<(), Box<dyn std::error::Error>> {
        let mut gate = SensitiveWorkflowGate::new(AdmissionPolicy {
            interruption_budget: 2,
            interruption_window_ms: 1_000,
            cooldown_ms: 500,
        });

        for (workflow, now) in [(WorkflowId::from_raw(1), 10), (WorkflowId::from_raw(2), 20)] {
            gate.try_begin(workflow, now)?;
            gate.finish(workflow, WorkflowCompletion::Cancelled, now)?;
        }

        assert_eq!(
            gate.try_begin(WorkflowId::from_raw(3), 21),
            Err(AdmissionError::CoolingDown)
        );
        assert_eq!(gate.try_begin(WorkflowId::from_raw(3), 520), Ok(()));
        Ok(())
    }
}
