//! Non-authorizing discovery presentation. Only trusted backend state classifies settling.
use serde::{Deserialize, Serialize};

/// `IntegrityFailure` is the terminal ADR-017 §5.7 category ("could not verify its own
/// components"). It carries no path, status code, Team ID, cdhash, certificate or record detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiscoveryPresentation<T> {
    Fresh { list: T },
    Settling {},
    Unavailable {},
    IntegrityFailure {},
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renderer_contract_has_only_reviewed_data_and_rejects_hostile_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        for response in [
            DiscoveryPresentation::Fresh {
                list: Vec::<u8>::new(),
            },
            DiscoveryPresentation::Settling {},
            DiscoveryPresentation::Unavailable {},
            DiscoveryPresentation::IntegrityFailure {},
        ] {
            let value = serde_json::to_value(&response)?;
            let fields = value.as_object().ok_or("object")?;
            assert!(fields.keys().all(|f| f == "state" || f == "list"));
            for field in [
                "pin",
                "puat",
                "binding",
                "worker_id",
                "workflow_id",
                "prompt_id",
                "device_id",
                "error",
                "team_id",
                "cdhash",
                "build_id",
                "requirement",
                "record",
                "path",
                "status",
                "verification_mode",
            ] {
                let mut hostile = value.clone();
                hostile[field] = serde_json::json!("hostile");
                assert!(serde_json::from_value::<DiscoveryPresentation<Vec<u8>>>(hostile).is_err());
            }
        }
        assert!(
            serde_json::from_value::<DiscoveryPresentation<Vec<u8>>>(
                serde_json::json!({"state":"unknown"})
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(DiscoveryPresentation::<Vec<u8>>::IntegrityFailure {})?,
            serde_json::json!({"state":"integrity_failure"})
        );
        Ok(())
    }
}
