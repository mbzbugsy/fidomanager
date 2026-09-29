//! Platform-independent domain contracts for FidoManager.

use serde::{Deserialize, Serialize};

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(u128);

        impl $name {
            pub const fn from_raw(raw: u128) -> Self {
                Self(raw)
            }

            pub const fn as_raw(self) -> u128 {
                self.0
            }
        }
    };
}

opaque_id!(DeviceHandle);
opaque_id!(CredentialHandle);
opaque_id!(DeviceSessionId);
opaque_id!(WorkflowId);
opaque_id!(PromptInstanceId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGeneration(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumerationEpoch(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationOutcome {
    NotDispatched,
    Rejected,
    ConfirmedSuccessful,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionQuiescence {
    Active,
    Quiescent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewFreshness {
    Fresh,
    Stale,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAdmission {
    Open,
    Barrier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveWorkflowKind {
    CredentialInspection,
    SetPin,
    ChangePin,
    DeleteCredential,
    Reset,
    Recovery,
    SensitiveExport,
}
