//! Platform-independent domain contracts for FidoManager.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! renderer_handle {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(u128);

        impl $name {
            pub const fn from_raw(raw: u128) -> Self {
                Self(raw)
            }

            pub const fn as_raw(self) -> u128 {
                self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&format!("{:032x}", self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let encoded = String::deserialize(deserializer)?;
                let is_lower_hex = encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());

                if encoded.len() != 32 || !is_lower_hex {
                    return Err(serde::de::Error::custom(
                        "opaque renderer handle must be exactly 32 lowercase hexadecimal characters",
                    ));
                }

                u128::from_str_radix(&encoded, 16)
                    .map(Self)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! opaque_internal_id {
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

renderer_handle!(DeviceHandle);
renderer_handle!(CredentialHandle);
opaque_internal_id!(DeviceSessionId);
opaque_internal_id!(WorkflowId);
opaque_internal_id!(PromptInstanceId);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_handles_use_fixed_lowercase_hex_strings() -> Result<(), Box<dyn std::error::Error>>
    {
        let handle = DeviceHandle::from_raw(0x1234);
        let encoded = serde_json::to_string(&handle)?;
        assert_eq!(encoded, "\"00000000000000000000000000001234\"");

        let decoded: DeviceHandle = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, handle);
        Ok(())
    }

    #[test]
    fn renderer_handles_reject_json_numbers() {
        let decoded = serde_json::from_str::<CredentialHandle>("1234");
        assert!(decoded.is_err());
    }
}
