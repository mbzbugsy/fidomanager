//! Platform-independent domain contracts for FidoManager.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn is_exact_lower_hex(encoded: &str, expected_len: usize) -> bool {
    encoded.len() == expected_len
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

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

                if !is_exact_lower_hex(&encoded, 32) {
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

/// Canonical 16-byte authenticator AAGUID.
///
/// Renderer serialization is fixed lowercase hexadecimal so JavaScript never needs to interpret
/// the identifier numerically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aaguid([u8; 16]);

impl Aaguid {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Serialize for Aaguid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:032x}", u128::from_be_bytes(self.0)))
    }
}

impl<'de> Deserialize<'de> for Aaguid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if !is_exact_lower_hex(&encoded, 32) {
            return Err(serde::de::Error::custom(
                "AAGUID must be exactly 32 lowercase hexadecimal characters",
            ));
        }

        u128::from_str_radix(&encoded, 16)
            .map(|value| Self(value.to_be_bytes()))
            .map_err(serde::de::Error::custom)
    }
}

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

/// Result of the latest bounded read-only inspection for a discovered authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceReadStatus {
    Ready,
    Busy,
    AccessDenied,
    TimedOut,
    Unsupported,
    Unavailable,
    Malformed,
    Error,
}

/// One authenticator option exactly as reported by GetInfo, after native-boundary validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceOption {
    pub name: String,
    pub enabled: bool,
}

/// Sanitized renderer-safe read-only snapshot for one currently discovered authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSnapshot {
    pub handle: DeviceHandle,
    pub generation: DeviceGeneration,
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub aaguid: Option<Aaguid>,
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub transports: Vec<String>,
    pub options: Vec<DeviceOption>,
    pub max_message_size: Option<u64>,
    pub firmware_version: Option<u64>,
    pub read_status: DeviceReadStatus,
    pub freshness: ViewFreshness,
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
    fn renderer_handles_reject_noncanonical_encodings() {
        for encoded in [
            "1234",
            "\"0000000000000000000000000000123\"",
            "\"000000000000000000000000000012345\"",
            "\"0000000000000000000000000000123A\"",
            "\"0000000000000000000000000000+123\"",
            "\"0000000000000000000000000000zzzz\"",
        ] {
            assert!(serde_json::from_str::<CredentialHandle>(encoded).is_err());
        }
    }

    #[test]
    fn aaguid_uses_canonical_hex_wire_format() -> Result<(), Box<dyn std::error::Error>> {
        let aaguid = Aaguid::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65,
            0x43, 0x21,
        ]);
        let encoded = serde_json::to_string(&aaguid)?;
        assert_eq!(encoded, "\"1234567890abcdeffedcba0987654321\"");
        let decoded: Aaguid = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, aaguid);
        Ok(())
    }
}
