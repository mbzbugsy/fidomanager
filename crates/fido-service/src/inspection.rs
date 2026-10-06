//! Backend-owned snapshots and epoch-scoped identity. This module grants no operation authority.
use crate::WorkerGeneration;
pub use fido_core::ExecutionQuiescence;
pub use fido_core::inventory::{CredentialTotal, InspectionError};
use fido_core::{DeviceGeneration, DeviceHandle, DeviceSnapshot, inventory::*};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnumerationEpoch(String);
impl EnumerationEpoch {
    pub fn as_wire(&self) -> &str {
        &self.0
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialHandle(String);
impl CredentialHandle {
    pub fn as_wire(&self) -> &str {
        &self.0
    }
}
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
/// Presentation identity only, in a separate type domain from worker operation DeviceHandle.
/// It is never accepted by AuthenticationAuthority or DiscoverySupervisor::resolve_handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DisplayDeviceHandle(#[serde(with = "display_handle_wire")] u128);
mod display_handle_wire {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(raw: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{raw:032x}"))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 32
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom("invalid display handle"));
        }
        u128::from_str_radix(&s, 16).map_err(serde::de::Error::custom)
    }
}
impl DisplayDeviceHandle {
    pub fn as_wire(self) -> String {
        format!("{:032x}", self.0)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryDevice {
    pub handle: DisplayDeviceHandle,
    pub generation: DeviceGeneration,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectionSnapshot {
    pub device_handle: DisplayDeviceHandle,
    pub device_generation: String,
    pub epoch: EnumerationEpoch,
    pub authenticator: String,
    pub assessment: Assessment,
    pub rps: Vec<RpDisplay>,
}
struct Identity {
    handle: CredentialHandle,
    rp_hash: [u8; 32],
    credential_id: Vec<u8>,
    user_id: Option<Vec<u8>>,
}
struct StoredInspection {
    generation: DeviceGeneration,
    snapshot: InspectionSnapshot,
    identities: Vec<Identity>,
}
/// Backend-only exact credential identity resolved from an opaque current-epoch handle.
pub struct ResolvedCredentialIdentity<'a> {
    pub native_handle: DeviceHandle,
    pub native_generation: DeviceGeneration,
    pub rp_hash: &'a [u8; 32],
    pub credential_id: &'a [u8],
    pub user_id: Option<&'a [u8]>,
    pub rp_text: Option<&'a str>,
    pub user_name: Option<&'a str>,
    pub display_name: Option<&'a str>,
}

struct ConnectedDevice {
    // Existing app/connection-scoped IORegistry display correlation; never operation authority.
    connection: Option<[u8; 32]>,
    native_handle: DeviceHandle,
    native_generation: DeviceGeneration,
    vendor_id: u16,
    product_id: u16,
    worker: WorkerGeneration,
    readable: bool,
    device: InventoryDevice,
}
#[derive(Default)]
pub struct InspectionStore {
    entries: BTreeMap<DisplayDeviceHandle, StoredInspection>,
    connected: Vec<ConnectedDevice>,
    next_display_handle: u128,
    retired_worker: Option<WorkerGeneration>,
    current: bool,
}
fn nonce() -> Result<String, InspectionError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| InspectionError::NativeFailure)?;
    Ok(format!("{:032x}", u128::from_be_bytes(bytes)))
}
impl InspectionStore {
    /// Exact presentation identity follows a connected generation. Worker-operation handles are
    /// still invalidated by retirement, unchanged. Only explicit, proven orderly retirement may
    /// preserve display continuity into the next manifest, using unique connection correlation.
    pub fn reconcile_connected(
        &mut self,
        devices: &[DeviceSnapshot],
        worker: WorkerGeneration,
    ) -> Result<Vec<InventoryDevice>, InspectionError> {
        use fido_worker_protocol::MAX_DISCOVERED_DEVICES;
        if devices.len() > MAX_DISCOVERED_DEVICES {
            self.clear();
            return Err(InspectionError::BoundExceeded);
        }
        if self.retired_worker.is_some_and(|old| worker.0 <= old.0) {
            self.clear();
            return Err(InspectionError::Malformed);
        }
        let permitted = self.connected.first().is_none_or(|c| c.worker == worker)
            || self.retired_worker.is_some_and(|old| {
                self.connected.iter().all(|c| c.worker == old) && worker.0 > old.0
            });
        if !permitted {
            self.clear();
        }
        self.current = false;
        let mut next = Vec::with_capacity(devices.len());
        for d in devices {
            let unique = d.verification_history_id.filter(|id| {
                devices
                    .iter()
                    .filter(|d| d.verification_history_id == Some(*id))
                    .count()
                    == 1
            });
            let previous = self.connected.iter().find(|c| {
                unique.is_some() && c.connection == unique
                    || unique.is_none()
                        && c.worker == worker
                        && c.native_handle == d.handle
                        && c.native_generation == d.generation
            });
            let device = if let Some(c) = previous {
                let changed = c.vendor_id != d.vendor_id
                    || c.product_id != d.product_id
                    || c.worker == worker
                        && (c.native_handle != d.handle || c.native_generation != d.generation);
                let generation = if changed {
                    DeviceGeneration(
                        c.device
                            .generation
                            .0
                            .checked_add(1)
                            .ok_or(InspectionError::NativeFailure)?,
                    )
                } else {
                    c.device.generation
                };
                InventoryDevice {
                    handle: c.device.handle,
                    generation,
                }
            } else {
                self.next_display_handle = self
                    .next_display_handle
                    .checked_add(1)
                    .ok_or(InspectionError::NativeFailure)?;
                InventoryDevice {
                    handle: DisplayDeviceHandle(self.next_display_handle),
                    generation: DeviceGeneration(1),
                }
            };
            next.push(ConnectedDevice {
                connection: unique,
                native_handle: d.handle,
                native_generation: d.generation,
                vendor_id: d.vendor_id,
                product_id: d.product_id,
                worker,
                readable: d.read_status == fido_core::DeviceReadStatus::Ready
                    && d.freshness == fido_core::ViewFreshness::Fresh,
                device,
            });
        }
        self.connected = next;
        self.entries.retain(|handle, e| {
            self.connected.iter().any(|c| {
                c.readable && c.device.handle == *handle && c.device.generation == e.generation
            })
        });
        self.retired_worker = None;
        self.current = true;
        Ok(self.connected.iter().map(|c| c.device).collect())
    }
    pub fn proven_retirement(&mut self, worker: WorkerGeneration) {
        if self.connected.iter().any(|c| c.worker != worker) {
            self.clear();
            return;
        }
        self.retired_worker = Some(worker);
        self.current = false; // no snapshot publication or identity lookup during the refresh gap
    }
    pub fn awaiting_retired_worker(&self) -> bool {
        self.retired_worker.is_some()
    }
    /// Classify a failed trusted refresh. Retained presentation grants no operation authority:
    /// lookup/publication remain suspended until a fresh manifest reconciles this store.
    pub fn discovery_problem<T>(
        &mut self,
        error: crate::SupervisorError,
    ) -> crate::discovery_presentation::DiscoveryPresentation<T> {
        use crate::discovery_presentation::DiscoveryPresentation;
        if self.awaiting_retired_worker()
            && matches!(error, crate::SupervisorError::RestartBackoff { .. })
        {
            DiscoveryPresentation::Settling {}
        } else {
            self.clear();
            DiscoveryPresentation::Unavailable {}
        }
    }
    pub fn clear(&mut self) {
        self.entries.clear();
        self.connected.clear();
        self.retired_worker = None;
        self.current = false;
    }
    pub fn invalidate(&mut self, device: InventoryDevice) {
        if self
            .entries
            .get(&device.handle)
            .is_some_and(|e| e.generation == device.generation)
        {
            self.entries.remove(&device.handle);
        }
    }
    pub fn snapshot_for(&self, device: InventoryDevice) -> Option<InspectionSnapshot> {
        if !self.current || !self.connected.iter().any(|c| c.device == device) {
            return None;
        }
        self.entries
            .get(&device.handle)
            .filter(|e| e.generation == device.generation)
            .map(|e| e.snapshot.clone())
    }
    pub fn replace(
        &mut self,
        device: InventoryDevice,
        label: String,
        inventory: OwnedInventory,
    ) -> Result<(), InspectionError> {
        // Retire old handles even if validating/allocating a fresh snapshot fails.
        let previous_epoch = self
            .entries
            .get(&device.handle)
            .map(|e| e.snapshot.epoch.clone());
        self.invalidate(device);
        // A completed inspection may publish only into its exact known connected generation.
        if !self.connected.iter().any(|c| c.device == device) {
            return Err(InspectionError::DeviceAbsent);
        }
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
                    user_id: c.user_id,
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
        self.entries.insert(
            device.handle,
            StoredInspection {
                generation: device.generation,
                identities,
                snapshot: InspectionSnapshot {
                    device_handle: device.handle,
                    device_generation: device.generation.0.to_string(),
                    epoch,
                    authenticator: label,
                    assessment,
                    rps,
                },
            },
        );
        Ok(())
    }
    /// Backend-only lookup; all four identity dimensions must match a verified current device.
    /// Display continuity authorizes nothing. Any future operation must independently resolve a
    /// fresh worker operation handle and exact AcquisitionBinding; no projection enters that path.
    pub fn resolve(
        &self,
        device: DisplayDeviceHandle,
        generation: DeviceGeneration,
        epoch: &EnumerationEpoch,
        handle: &CredentialHandle,
    ) -> Option<(&[u8; 32], &[u8])> {
        let identity = self.resolve_for_mutation(device, generation, epoch, handle)?;
        Some((identity.rp_hash, identity.credential_id))
    }

    /// Backend-only resolution for an exact current credential. This exposes no renderer DTO and
    /// grants no mutation authority by itself; M5 must still bind an immutable intent and one-use
    /// dispatch permit to a freshly resolved worker/device authority.
    pub fn resolve_for_mutation(
        &self,
        device: DisplayDeviceHandle,
        generation: DeviceGeneration,
        epoch: &EnumerationEpoch,
        handle: &CredentialHandle,
    ) -> Option<ResolvedCredentialIdentity<'_>> {
        if !self.current
            || !self
                .connected
                .iter()
                .any(|c| c.device.handle == device && c.device.generation == generation)
        {
            return None;
        }
        let connected = self
            .connected
            .iter()
            .find(|c| c.device.handle == device && c.device.generation == generation)?;
        let e = self.entries.get(&device)?;
        if e.generation != generation || &e.snapshot.epoch != epoch {
            return None;
        }
        let id = e.identities.iter().find(|i| &i.handle == handle)?;
        let (rp, credential) = e.snapshot.rps.iter().find_map(|rp| {
            rp.credentials
                .iter()
                .find(|credential| &credential.handle == handle)
                .map(|credential| (rp, credential))
        })?;
        Some(ResolvedCredentialIdentity {
            native_handle: connected.native_handle,
            native_generation: connected.native_generation,
            rp_hash: &id.rp_hash,
            credential_id: &id.credential_id,
            user_id: id.user_id.as_deref(),
            rp_text: rp.verified_text.as_deref(),
            user_name: credential.user_name.as_deref(),
            display_name: credential.display_name.as_deref(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum InspectionDisplay {
    NotInspected {},
    Inspected { snapshot: InspectionSnapshot },
}
impl InspectionStore {
    pub fn display_for(&self, device: InventoryDevice) -> InspectionDisplay {
        self.snapshot_for(device)
            .map_or(InspectionDisplay::NotInspected {}, |snapshot| {
                InspectionDisplay::Inspected { snapshot }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_core::{DeviceReadStatus, ViewFreshness};
    fn inventory() -> OwnedInventory {
        OwnedInventory {
            metadata_existing: 1,
            rps: vec![OwnedRp {
                hash: Sha256::digest(b"example.com").into(),
                verified_text: Some("example.com".into()),
                issue: None,
                credentials: vec![OwnedCredential {
                    id: vec![17, 19, 23],
                    user_id: Some(vec![29, 31, 37]),
                    user_name: Some("Account".into()),
                    display_name: None,
                }],
            }],
        }
    }
    fn device(raw: u128, gen_value: u64, connection: u8) -> DeviceSnapshot {
        DeviceSnapshot {
            verification_history_id: Some([connection; 32]),
            handle: DeviceHandle::from_raw(raw),
            generation: DeviceGeneration(gen_value),
            vendor_id: 1,
            product_id: 2,
            manufacturer: Some("Thetis".into()),
            product: Some("Same label".into()),
            aaguid: None,
            versions: Vec::new(),
            extensions: Vec::new(),
            transports: vec!["usb".into()],
            options: Vec::new(),
            max_message_size: None,
            firmware_version: None,
            read_status: DeviceReadStatus::Ready,
            freshness: ViewFreshness::Fresh,
        }
    }
    fn replace(store: &mut InspectionStore, device: InventoryDevice) {
        assert!(
            store
                .replace(device, "Same label".into(), inventory())
                .is_ok()
        );
    }
    fn snapshot(store: &InspectionStore, device: InventoryDevice) -> InspectionSnapshot {
        store
            .snapshot_for(device)
            .unwrap_or_else(|| panic!("snapshot"))
    }
    #[test]
    fn two_identical_labels_inspect_b_then_reinspect_a_preserves_b()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = InspectionStore::default();
        let ds = [device(1, 1, 1), device(2, 1, 2)];
        let ids = store
            .reconcile_connected(&ds, WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        replace(&mut store, ids[0]);
        let a = snapshot(&store, ids[0]);
        replace(&mut store, ids[1]);
        let b = snapshot(&store, ids[1]);
        assert_ne!(a.device_handle, b.device_handle);
        assert_eq!(a.epoch, snapshot(&store, ids[0]).epoch);
        let ah = &a.rps[0].credentials[0].handle;
        let bh = &b.rps[0].credentials[0].handle;
        let exact = store
            .resolve_for_mutation(ids[0].handle, ids[0].generation, &a.epoch, ah)
            .ok_or("exact identity")?;
        assert_eq!(exact.native_handle, DeviceHandle::from_raw(1));
        assert_eq!(exact.native_generation, DeviceGeneration(1));
        let expected_rp_hash: [u8; 32] = Sha256::digest(b"example.com").into();
        assert_eq!(exact.rp_hash, &expected_rp_hash);
        assert_eq!(exact.credential_id, &[17, 19, 23]);
        assert_eq!(exact.user_id, Some([29, 31, 37].as_slice()));
        assert_eq!(exact.rp_text, Some("example.com"));
        assert_eq!(exact.user_name, Some("Account"));
        assert_eq!(exact.display_name, None);
        assert!(
            store
                .resolve(ids[1].handle, ids[1].generation, &a.epoch, ah)
                .is_none()
        );
        assert!(
            store
                .resolve(ids[0].handle, DeviceGeneration(2), &a.epoch, ah)
                .is_none()
        );
        store.invalidate(ids[0]); // failed/cancelled new A inspection cannot clear B
        assert!(store.snapshot_for(ids[0]).is_none());
        assert!(
            store
                .resolve(ids[1].handle, ids[1].generation, &b.epoch, bh)
                .is_some()
        );
        replace(&mut store, ids[0]);
        assert_ne!(a.epoch, snapshot(&store, ids[0]).epoch);
        assert!(
            store
                .resolve(ids[0].handle, ids[0].generation, &a.epoch, ah)
                .is_none()
        );
        assert_eq!(b.epoch, snapshot(&store, ids[1]).epoch);
        assert!(
            store
                .resolve(ids[1].handle, ids[1].generation, &b.epoch, bh)
                .is_some()
        );
        Ok(())
    }
    #[test]
    fn generation_change_clears_the_correlated_cards_old_issue()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::activity::{ActivityOutcome, ActivityTracker};
        use std::sync::Arc;

        let mut store = InspectionStore::default();
        let tracker = Arc::new(ActivityTracker::default());
        let connected = store
            .reconcile_connected(&[device(1, 1, 1), device(2, 1, 2)], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        let claim = tracker.try_claim().ok_or("claim")?;
        claim.target(connected[0]);
        claim.finish(ActivityOutcome::Issue("Incorrect PIN. No retry was made."));
        tracker.retain_connected(&connected);
        assert!(tracker.view().issue.is_some());

        // Expected retirement/backoff supplies no new identity: keep the same presentation.
        let issue = tracker.view().issue;
        store.proven_retirement(WorkerGeneration(1));
        assert_eq!(
            store.discovery_problem::<()>(crate::SupervisorError::RestartBackoff {
                retry_after_ms: 100,
            }),
            crate::discovery_presentation::DiscoveryPresentation::Settling {}
        );
        assert_eq!(tracker.view().issue, issue);
        let refreshed = store
            .reconcile_connected(&[device(9, 1, 1), device(10, 1, 2)], WorkerGeneration(2))
            .map_err(|_| "refresh")?;
        assert_eq!(refreshed, connected);
        tracker.retain_connected(&refreshed);
        assert_eq!(tracker.view().issue, issue);

        let changed = store
            .reconcile_connected(&[device(9, 2, 1), device(10, 1, 2)], WorkerGeneration(2))
            .map_err(|_| "reconcile")?;
        assert_eq!(changed[0].handle, connected[0].handle);
        assert_ne!(changed[0].generation, connected[0].generation);
        assert_eq!(changed[1], connected[1]);
        tracker.retain_connected(&changed);
        assert!(
            tracker.view().issue.is_none(),
            "old generation's issue survived"
        );
        Ok(())
    }

    #[test]
    fn generation_disconnect_reconnect_and_discovery_uncertainty()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = InspectionStore::default();
        let a = device(1, 1, 1);
        let b = device(2, 1, 2);
        let ids = store
            .reconcile_connected(&[a.clone(), b.clone()], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        replace(&mut store, ids[0]);
        replace(&mut store, ids[1]);
        let old = snapshot(&store, ids[0]);
        let h = &old.rps[0].credentials[0].handle;
        let only_b = store
            .reconcile_connected(std::slice::from_ref(&b), WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        assert_eq!(store.entries.len(), 1);
        assert!(
            store
                .resolve(ids[0].handle, ids[0].generation, &old.epoch, h)
                .is_none()
        );
        assert!(store.snapshot_for(only_b[0]).is_some());
        let replugged = store
            .reconcile_connected(&[device(3, 2, 3), b.clone()], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        assert!(matches!(
            store.display_for(replugged[0]),
            InspectionDisplay::NotInspected {}
        ));
        replace(&mut store, replugged[0]);
        let changed = store
            .reconcile_connected(&[device(3, 3, 3), b], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        assert_eq!(changed[0].handle, replugged[0].handle);
        assert_ne!(changed[0].generation, replugged[0].generation);
        assert!(store.snapshot_for(changed[0]).is_none());
        assert!(store.snapshot_for(changed[1]).is_some());
        let mut unreadable_b = device(2, 1, 2);
        unreadable_b.freshness = ViewFreshness::Incomplete;
        unreadable_b.read_status = DeviceReadStatus::Unavailable;
        store
            .reconcile_connected(&[device(3, 3, 3), unreadable_b], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        assert!(store.entries.is_empty()); // present but no longer a current readable view
        store.clear();
        assert!(store.entries.is_empty());
        assert!(store.connected.is_empty());
        Ok(())
    }
    #[test]
    fn orderly_retirement_preserves_only_display_continuity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = InspectionStore::default();
        let ids = store
            .reconcile_connected(&[device(1, 1, 1), device(2, 1, 2)], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        replace(&mut store, ids[0]);
        replace(&mut store, ids[1]);
        let a = snapshot(&store, ids[0]);
        let b = snapshot(&store, ids[1]);
        store.proven_retirement(WorkerGeneration(1));
        assert!(
            store
                .resolve(
                    ids[0].handle,
                    ids[0].generation,
                    &a.epoch,
                    &a.rps[0].credentials[0].handle
                )
                .is_none()
        );
        assert!(store.snapshot_for(ids[0]).is_none());
        let next = store
            .reconcile_connected(&[device(9, 1, 1), device(10, 1, 2)], WorkerGeneration(2))
            .map_err(|_| "reconcile")?;
        assert_eq!(ids, next); // worker routing handles changed; display connection did not
        assert_eq!(a.epoch, snapshot(&store, next[0]).epoch);
        assert_eq!(b.epoch, snapshot(&store, next[1]).epoch);
        // Unannounced/crashed replacement is uncertainty, not display continuity.
        let unexpected = store
            .reconcile_connected(&[device(19, 1, 1), device(20, 1, 2)], WorkerGeneration(3))
            .map_err(|_| "reconcile")?;
        assert!(store.entries.is_empty());
        assert_ne!(next, unexpected);
        Ok(())
    }
    #[test]
    fn renderer_collection_hostile_fields_and_owned_ids() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut store = InspectionStore::default();
        let ids = store
            .reconcile_connected(&[device(1, 1, 1), device(2, 1, 2)], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        for d in &ids {
            replace(&mut store, *d);
        }
        let displays: Vec<_> = ids.iter().map(|d| store.display_for(*d)).collect();
        let value = serde_json::to_value(&displays)?;
        assert_eq!(value.as_array().ok_or("array")?.len(), 2);
        let serialized = serde_json::to_string(&displays)?;
        assert!(!serialized.contains("17,19,23"));
        assert!(!serialized.contains("29,31,37"));
        for field in [
            "id",
            "hash",
            "binding",
            "device_id",
            "pin",
            "puat",
            "workflow_id",
            "permissions",
            "unknown_sensitive",
        ] {
            for depth in 0..4 {
                let mut hostile = value[0].clone();
                let target = match depth {
                    0 => &mut hostile,
                    1 => &mut hostile["snapshot"],
                    2 => &mut hostile["snapshot"]["rps"][0],
                    _ => &mut hostile["snapshot"]["rps"][0]["credentials"][0],
                };
                target[field] = serde_json::json!("hostile");
                assert!(serde_json::from_value::<InspectionDisplay>(hostile).is_err());
            }
        }
        Ok(())
    }
    #[test]
    fn retired_worker_cannot_republish_and_unknown_uninspected_fields_fail()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = InspectionStore::default();
        let ds = [device(1, 1, 1)];
        let ids = store
            .reconcile_connected(&ds, WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        replace(&mut store, ids[0]);
        store.proven_retirement(WorkerGeneration(1));
        assert!(store.reconcile_connected(&ds, WorkerGeneration(1)).is_err());
        assert!(store.entries.is_empty());
        for field in ["pin", "puat", "binding", "id", "hash", "device_id"] {
            let mut value = serde_json::json!({"state": "not_inspected"});
            value[field] = serde_json::json!("hostile");
            assert!(serde_json::from_value::<InspectionDisplay>(value).is_err());
        }
        Ok(())
    }
    #[test]
    fn collection_has_enforced_device_bound_and_bounded_serialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = InspectionStore::default();
        let ds: Vec<_> = (1..=64).map(|n| device(n, 1, n as u8)).collect();
        let ids = store
            .reconcile_connected(&ds, WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        for d in &ids {
            let text = "\\".repeat(254);
            let large = OwnedInventory {
                metadata_existing: 128,
                rps: (0..64)
                    .map(|_| OwnedRp {
                        hash: Sha256::digest(text.as_bytes()).into(),
                        verified_text: Some(text.clone()),
                        issue: None,
                        credentials: (0..2)
                            .map(|_| OwnedCredential {
                                id: vec![255; 512],
                                user_id: Some(vec![255; MAX_USER_ID_BYTES]),
                                user_name: Some("\\".repeat(256)),
                                display_name: Some("\\".repeat(256)),
                            })
                            .collect(),
                    })
                    .collect(),
            };
            store
                .replace(*d, "\\".repeat(1024), large)
                .map_err(|_| "replace")?;
        }
        let displays: Vec<_> = ids.iter().map(|d| store.display_for(*d)).collect();
        assert!(serde_json::to_vec(&displays)?.len() < 16 * 1024 * 1024);
        let mut excessive = ds;
        excessive.push(device(65, 1, 65));
        assert!(
            store
                .reconcile_connected(&excessive, WorkerGeneration(1))
                .is_err()
        );
        assert!(store.entries.is_empty());
        Ok(())
    }
    #[test]
    fn only_proven_retirement_backoff_settles_without_reviving_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{SupervisorError, discovery_presentation::DiscoveryPresentation};
        let mut store = InspectionStore::default();
        let ds = [device(1, 1, 1), device(2, 1, 2)];
        let ids = store
            .reconcile_connected(&ds, WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        replace(&mut store, ids[0]);
        replace(&mut store, ids[1]);
        let old = snapshot(&store, ids[1]);
        store.invalidate(ids[0]); // success or cancel begins by retiring only A's old view
        store.proven_retirement(WorkerGeneration(1));
        for _ in 0..2 {
            assert_eq!(
                store.discovery_problem::<()>(SupervisorError::RestartBackoff {
                    retry_after_ms: 100
                }),
                DiscoveryPresentation::Settling {}
            );
            assert!(store.awaiting_retired_worker());
            assert!(store.snapshot_for(ids[1]).is_none());
            assert!(
                store
                    .resolve(
                        ids[1].handle,
                        ids[1].generation,
                        &old.epoch,
                        &old.rps[0].credentials[0].handle
                    )
                    .is_none()
            );
        }
        let fresh = store
            .reconcile_connected(&[device(3, 1, 1), device(4, 1, 2)], WorkerGeneration(2))
            .map_err(|_| "fresh")?;
        assert_eq!(ids, fresh);
        assert!(store.snapshot_for(fresh[0]).is_none());
        assert_eq!(old.epoch, snapshot(&store, fresh[1]).epoch);
        assert!(!store.awaiting_retired_worker());
        // An unrelated backoff after successful reconciliation has no continuity proof.
        assert_eq!(
            store.discovery_problem::<()>(SupervisorError::RestartBackoff {
                retry_after_ms: 100
            }),
            DiscoveryPresentation::Unavailable {}
        );
        assert!(store.entries.is_empty());
        Ok(())
    }
    #[test]
    fn uncertain_discovery_errors_clear_even_after_orderly_retirement()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{SupervisorError, discovery_presentation::DiscoveryPresentation};
        for error in [
            SupervisorError::Discovery(crate::DiscoveryError::UnexpectedResponse),
            SupervisorError::WorkerNotContained,
            SupervisorError::CrashLoop {
                retry_after_ms: 100,
            },
            SupervisorError::GenerationExhausted,
            SupervisorError::InvalidDiscoveryPolicy,
            SupervisorError::Stopped,
        ] {
            let mut store = InspectionStore::default();
            let ids = store
                .reconcile_connected(&[device(1, 1, 1)], WorkerGeneration(1))
                .map_err(|_| "reconcile")?;
            replace(&mut store, ids[0]);
            store.proven_retirement(WorkerGeneration(1));
            assert_eq!(
                store.discovery_problem::<()>(error),
                DiscoveryPresentation::Unavailable {}
            );
            assert!(store.entries.is_empty() && store.connected.is_empty());
            assert!(!store.awaiting_retired_worker());
        }
        Ok(())
    }
    #[test]
    fn no_devices_uninspected_mixed_and_ambiguous_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = InspectionStore::default();
        assert!(
            store
                .reconcile_connected(&[], WorkerGeneration(1))
                .map_err(|_| "empty")?
                .is_empty()
        );
        let ids = store
            .reconcile_connected(&[device(1, 1, 1), device(2, 1, 1)], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        assert_ne!(ids[0], ids[1]);
        assert!(
            ids.iter()
                .all(|d| matches!(store.display_for(*d), InspectionDisplay::NotInspected {}))
        );
        replace(&mut store, ids[0]);
        assert!(matches!(
            store.display_for(ids[0]),
            InspectionDisplay::Inspected { .. }
        ));
        assert!(matches!(
            store.display_for(ids[1]),
            InspectionDisplay::NotInspected {}
        ));
        store.proven_retirement(WorkerGeneration(1));
        let next = store
            .reconcile_connected(&[device(9, 1, 1), device(10, 1, 1)], WorkerGeneration(2))
            .map_err(|_| "reconcile")?;
        assert!(store.entries.is_empty()); // ambiguous correlation cannot survive retirement
        assert_ne!(ids, next);
        Ok(())
    }
}
