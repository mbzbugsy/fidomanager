//! Backend-owned snapshots and epoch-scoped identity. This module grants no operation authority.
pub use fido_core::inventory::{CredentialTotal, InspectionError};
use fido_core::{DeviceHandle, inventory::*};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnumerationEpoch(String);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialHandle(String);
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialDisplay {
    pub handle: CredentialHandle,
    pub user_name: Option<String>,
    pub display_name: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpDisplay {
    pub verified_text: Option<String>,
    pub issue: Option<RpIssue>,
    pub credentials: Vec<CredentialDisplay>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectionSnapshot {
    pub epoch: EnumerationEpoch,
    pub authenticator: String,
    pub assessment: Assessment,
    pub rps: Vec<RpDisplay>,
}
struct Identity {
    handle: CredentialHandle,
    rp_hash: [u8; 32],
    credential_id: Vec<u8>,
}
#[derive(Default)]
pub struct InspectionStore {
    snapshot: Option<InspectionSnapshot>,
    device: Option<DeviceHandle>,
    identities: Vec<Identity>,
}
fn nonce() -> Result<String, InspectionError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| InspectionError::NativeFailure)?;
    Ok(format!("{:032x}", u128::from_be_bytes(bytes)))
}
impl InspectionStore {
    pub fn latest(&self) -> Option<InspectionSnapshot> {
        self.snapshot.clone()
    }
    pub fn clear(&mut self) {
        self.snapshot = None;
        self.device = None;
        self.identities.clear();
    }
    pub fn replace(
        &mut self,
        device: DeviceHandle,
        label: String,
        inventory: OwnedInventory,
    ) -> Result<(), InspectionError> {
        // Retire old handles even if validating/allocating a fresh snapshot fails.
        let previous_epoch = self.snapshot.as_ref().map(|s| s.epoch.clone());
        self.clear();
        if !inventory.within_bounds()
            || !safe_text(&label, 1024)
            || inventory.rps.iter().any(|rp| {
                rp.verified_text
                    .as_ref()
                    .is_some_and(|t| <[u8; 32]>::from(Sha256::digest(t.as_bytes())) != rp.hash)
            })
        {
            return Err(InspectionError::Malformed);
        }
        let epoch = EnumerationEpoch(nonce()?);
        if previous_epoch.as_ref() == Some(&epoch) {
            return Err(InspectionError::NativeFailure);
        }
        let assessment = inventory.assess();
        let mut identities = Vec::new();
        let mut rps = Vec::new();
        for rp in inventory.rps {
            let mut credentials = Vec::new();
            for c in rp.credentials {
                let handle = CredentialHandle(nonce()?);
                if identities.iter().any(|i: &Identity| i.handle == handle) {
                    return Err(InspectionError::NativeFailure);
                }
                identities.push(Identity {
                    handle: handle.clone(),
                    rp_hash: rp.hash,
                    credential_id: c.id,
                });
                credentials.push(CredentialDisplay {
                    handle,
                    user_name: c.user_name,
                    display_name: c.display_name,
                });
            }
            rps.push(RpDisplay {
                verified_text: rp.verified_text,
                issue: rp.issue,
                credentials,
            });
        }
        self.identities = identities;
        self.device = Some(device);
        self.snapshot = Some(InspectionSnapshot {
            epoch,
            authenticator: label,
            assessment,
            rps,
        });
        Ok(())
    }
    /// Trusted backend lookup only. Future mutation must additionally acquire fresh native approval
    /// and re-resolve the exact device generation. This mapping itself authorizes nothing.
    pub fn resolve(
        &self,
        device: DeviceHandle,
        epoch: &EnumerationEpoch,
        handle: &CredentialHandle,
    ) -> Option<(&[u8; 32], &[u8])> {
        if self.device != Some(device) || &self.snapshot.as_ref()?.epoch != epoch {
            return None;
        }
        let id = self.identities.iter().find(|i| &i.handle == handle)?;
        Some((&id.rp_hash, &id.credential_id))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn inventory() -> OwnedInventory {
        OwnedInventory {
            metadata_existing: 1,
            rps: vec![OwnedRp {
                hash: Sha256::digest(b"example.com").into(),
                verified_text: Some("example.com".into()),
                issue: None,
                credentials: vec![OwnedCredential {
                    id: vec![17, 19, 23],
                    user_name: Some("Account".into()),
                    display_name: None,
                }],
            }],
        }
    }
    #[test]
    fn renderer_dto_and_stale_handle_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = InspectionStore::default();
        let device = DeviceHandle::from_raw(9);
        store
            .replace(device, "Thetis".into(), inventory())
            .map_err(|_| "replace")?;
        let snapshot = store.latest().ok_or("snapshot")?;
        let handle = &snapshot.rps[0].credentials[0].handle;
        assert_eq!(
            store
                .resolve(device, &snapshot.epoch, handle)
                .map(|(_, id)| id),
            Some([17, 19, 23].as_slice())
        );
        assert!(
            store
                .resolve(DeviceHandle::from_raw(10), &snapshot.epoch, handle)
                .is_none()
        );
        let value = serde_json::to_value(&snapshot)?;
        assert_eq!(value.as_object().ok_or("object")?.len(), 4);
        assert_eq!(value["rps"][0].as_object().ok_or("rp")?.len(), 3);
        assert_eq!(
            value["rps"][0]["credentials"][0]
                .as_object()
                .ok_or("credential")?
                .len(),
            3
        );
        for field in [
            "id",
            "hash",
            "binding",
            "pin",
            "token",
            "permissions",
            "acquisition_id",
            "workflow_id",
            "path",
            "device_id",
            "unknown_sensitive",
        ] {
            let mut hostile = value.clone();
            hostile[field] = serde_json::json!("hostile");
            assert!(serde_json::from_value::<InspectionSnapshot>(hostile).is_err());
            let mut hostile = value.clone();
            hostile["rps"][0][field] = serde_json::json!("hostile");
            assert!(serde_json::from_value::<InspectionSnapshot>(hostile).is_err());
            let mut hostile = value.clone();
            hostile["rps"][0]["credentials"][0][field] = serde_json::json!("hostile");
            assert!(serde_json::from_value::<InspectionSnapshot>(hostile).is_err());
        }
        let json = serde_json::to_string(&snapshot)?;
        assert!(!json.contains("17,19,23"));
        store
            .replace(device, "Thetis".into(), inventory())
            .map_err(|_| "replace")?;
        assert_ne!(snapshot.epoch, store.latest().ok_or("new")?.epoch);
        assert!(store.resolve(device, &snapshot.epoch, handle).is_none());
        Ok(())
    }
}
