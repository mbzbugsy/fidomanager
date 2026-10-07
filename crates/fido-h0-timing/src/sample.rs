//! Serializable sample records. They hold timings and model-level labels only: no native path,
//! IORegistry identifier, serial number, PIN, credential or journal content.

use serde::{Deserialize, Serialize};

/// Model-level label used to group samples. It is a grouping key for reporting, never evidence
/// that two samples came from the same physical key, and never authority of any kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceLabel {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: String,
    pub product: String,
    /// Hex AAGUID from GetInfo; model-level, not instance-unique.
    pub aaguid: String,
    pub firmware_version: Option<u64>,
}

/// One Option A component breakdown, in microseconds of the process monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Components {
    /// T1: OS insertion notification → candidate visible in the libfido2 manifest. May be negative
    /// when the manifest poll sees the device before the notification callback runs.
    pub t1_insertion_to_manifest_us: i64,
    /// T2: manifest visibility → `fido_dev_open` returned (libfido2 open performs CTAPHID INIT and
    /// one GetInfo internally).
    pub t2_manifest_to_open_us: i64,
    /// T3: open → explicit GetInfo returned.
    pub t3_open_to_get_info_us: i64,
    /// T4: GetInfo returned → snapshot compared and DispatchCapable bytes serialized.
    pub t4_validation_us: i64,
    /// T5: production `DurableRecoveryFile::replace` of the DispatchCapable-sized record.
    pub t5_durable_replace_us: i64,
    /// T6: durable replace returned → would-be dispatch frame received by the executor stub.
    pub t6_sync_to_would_dispatch_us: i64,
}

impl Components {
    pub const NAMES: [&'static str; 6] = [
        "t1_insertion_to_manifest",
        "t2_manifest_to_open",
        "t3_open_to_get_info",
        "t4_validation",
        "t5_durable_replace",
        "t6_sync_to_would_dispatch",
    ];

    pub fn values(&self) -> [i64; 6] {
        [
            self.t1_insertion_to_manifest_us,
            self.t2_manifest_to_open_us,
            self.t3_open_to_get_info_us,
            self.t4_validation_us,
            self.t5_durable_replace_us,
            self.t6_sync_to_would_dispatch_us,
        ]
    }

    /// Total Option A pre-send latency from the insertion notification: T1 + … + T6.
    pub fn total_us(&self) -> i64 {
        self.values().iter().sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum AbortReason {
    InsertionTimeout,
    MultipleDevices { count: usize },
    NoInsertionNotification,
    DiscoveryFailed { code: i32 },
    OpenFailed { code: i32 },
    GetInfoFailed { code: i32 },
    SnapshotMismatch { field: String },
    DurabilityFailed,
    WouldDispatchStubFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum SampleOutcome {
    Measured {
        components: Components,
        total_us: i64,
    },
    Aborted {
        #[serde(flatten)]
        reason: AbortReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareSample {
    pub format: String,
    pub index: u32,
    pub recorded_unix_secs: u64,
    pub device: Option<DeviceLabel>,
    /// Manifest calls made while waiting (including the one that saw the device).
    pub manifest_polls: u32,
    /// Duration of the manifest call that first returned the candidate.
    pub manifest_call_us: Option<i64>,
    pub outcome: SampleOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurabilitySample {
    pub format: String,
    pub index: u32,
    pub replace_us: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn components() -> Components {
        Components {
            t1_insertion_to_manifest_us: -5,
            t2_manifest_to_open_us: 20,
            t3_open_to_get_info_us: 30,
            t4_validation_us: 1,
            t5_durable_replace_us: 400,
            t6_sync_to_would_dispatch_us: 4,
        }
    }

    #[test]
    fn total_is_the_signed_sum_of_components() {
        assert_eq!(components().total_us(), 450);
    }

    #[test]
    fn sample_round_trips_and_carries_no_path_fields() -> Result<(), serde_json::Error> {
        let sample = HardwareSample {
            format: crate::FORMAT.into(),
            index: 3,
            recorded_unix_secs: 1,
            device: None,
            manifest_polls: 9,
            manifest_call_us: Some(800),
            outcome: SampleOutcome::Measured {
                components: components(),
                total_us: 450,
            },
        };
        let text = serde_json::to_string(&sample)?;
        assert!(!text.contains("path") && !text.contains("ioreg"));
        assert_eq!(serde_json::from_str::<HardwareSample>(&text)?, sample);

        let aborted = HardwareSample {
            outcome: SampleOutcome::Aborted {
                reason: AbortReason::MultipleDevices { count: 2 },
            },
            ..sample
        };
        let text = serde_json::to_string(&aborted)?;
        assert!(text.contains("\"status\":\"aborted\""));
        assert!(text.contains("\"reason\":\"multiple_devices\""));
        assert_eq!(serde_json::from_str::<HardwareSample>(&text)?, aborted);
        Ok(())
    }
}
