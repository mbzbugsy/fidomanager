//! Native sensitive-interaction contracts.
//!
//! Platform UI implementations are deliberately deferred to the Milestone 1.5 modality/threading
//! spike. This crate establishes prompt-instance binding without choosing a toolkit prematurely.

use fido_core::{PromptInstanceId, WorkflowId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptBinding {
    pub workflow_id: WorkflowId,
    pub prompt_instance_id: PromptInstanceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptOutcome {
    Approved(PromptBinding),
    Cancelled(PromptBinding),
    TimedOut(PromptBinding),
}
