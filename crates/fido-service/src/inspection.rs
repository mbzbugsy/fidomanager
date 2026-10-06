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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InspectionAuthority {
    worker: WorkerGeneration,
    native_handle: DeviceHandle,
    native_generation: DeviceGeneration,
}
struct StoredInspection {
    generation: DeviceGeneration,
    authority: InspectionAuthority,
    snapshot: InspectionSnapshot,
    identities: Vec<Identity>,
}
/// Owned, immutable exact credential identity resolved from one current inspection epoch.
/// This is data only, never dispatch authority. Native worker/device authority must be resolved
/// freshly under the sensitive-workflow gate immediately before permit consumption/dispatch.
pub struct ExactCredentialTarget {
    device: InventoryDevice,
    epoch: EnumerationEpoch,
    handle: CredentialHandle,
    authenticator: String,
    completeness: Completeness,
    rp_hash: [u8; 32],
    credential_id: Vec<u8>,
    user_id: Option<Vec<u8>>,
    rp_text: String,
    user_name: Option<String>,
    display_name: Option<String>,
}
impl ExactCredentialTarget {
    pub(crate) fn device(&self) -> InventoryDevice {
        self.device
    }
    pub(crate) fn epoch(&self) -> &EnumerationEpoch {
        &self.epoch
    }
    pub(crate) fn handle(&self) -> &CredentialHandle {
        &self.handle
    }
    pub(crate) fn authenticator(&self) -> &str {
        &self.authenticator
    }
    pub(crate) fn completeness(&self) -> Completeness {
        self.completeness
    }
    pub(crate) fn rp_hash(&self) -> &[u8; 32] {
        &self.rp_hash
    }
    pub(crate) fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
    pub(crate) fn user_id(&self) -> Option<&[u8]> {
        self.user_id.as_deref()
    }
    pub(crate) fn rp_text(&self) -> &str {
        &self.rp_text
    }
    pub(crate) fn user_name(&self) -> Option<&str> {
        self.user_name.as_deref()
    }
    pub(crate) fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
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
        let mut seen_display_handles = std::collections::BTreeSet::new();
        if next
            .iter()
            .any(|connected| !seen_display_handles.insert(connected.device.handle))
        {
            self.clear();
            return Err(InspectionError::Malformed);
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
        let connected = self
            .connected
            .iter()
            .find(|connected| connected.device == device)
            .ok_or(InspectionError::DeviceAbsent)?;
        let authority = InspectionAuthority {
            worker: connected.worker,
            native_handle: connected.native_handle,
            native_generation: connected.native_generation,
        };
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
                authority,
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
        if !self.current
            || !self
                .connected
                .iter()
                .any(|c| c.device.handle == device && c.device.generation == generation)
        {
            return None;
        }
        let e = self.entries.get(&device)?;
        if e.generation != generation || &e.snapshot.epoch != epoch {
            return None;
        }
        let id = e.identities.iter().find(|i| &i.handle == handle)?;
        Some((&id.rp_hash, &id.credential_id))
    }

    /// Backend-only resolution for an exact current credential. Incomplete inventories may still
    /// contain exact listed credentials; inconsistent inventories cannot safely support deletion.
    /// The returned value is owned so no InspectionStore lock/borrow survives a native prompt.
    pub fn resolve_for_mutation(
        &self,
        device: DisplayDeviceHandle,
        generation: DeviceGeneration,
        epoch: &EnumerationEpoch,
        handle: &CredentialHandle,
    ) -> Option<ExactCredentialTarget> {
        if !self.current {
            return None;
        }
        let connected = self.connected.iter().find(|connected| {
            connected.device.handle == device && connected.device.generation == generation
        })?;
        let e = self.entries.get(&device)?;
        if e.generation != generation
            || &e.snapshot.epoch != epoch
            || e.snapshot.assessment.completeness == Completeness::Inconsistent
            || e.authority
                != (InspectionAuthority {
                    worker: connected.worker,
                    native_handle: connected.native_handle,
                    native_generation: connected.native_generation,
                })
        {
            return None;
        }
        let id = e.identities.iter().find(|i| &i.handle == handle)?;
        let (rp, credential) = e.snapshot.rps.iter().find_map(|rp| {
            rp.credentials
                .iter()
                .find(|credential| &credential.handle == handle)
                .map(|credential| (rp, credential))
        })?;
        let rp_text = rp.verified_text.as_ref()?.clone();
        Some(ExactCredentialTarget {
            device: InventoryDevice {
                handle: device,
                generation,
            },
            epoch: epoch.clone(),
            handle: handle.clone(),
            authenticator: e.snapshot.authenticator.clone(),
            completeness: e.snapshot.assessment.completeness,
            rp_hash: id.rp_hash,
            credential_id: id.credential_id.clone(),
            user_id: id.user_id.clone(),
            rp_text,
            user_name: credential.user_name.clone(),
            display_name: credential.display_name.clone(),
        })
    }

    /// Revalidate the complete exact target immediately before mutation authority is consumed.
    /// Presentation continuity alone cannot satisfy this check: the current store, display
    /// generation, enumeration epoch, opaque handle and trusted identity bytes must all match.
    pub(crate) fn matches_exact_target(&self, target: &ExactCredentialTarget) -> bool {
        let Some(current) = self.resolve_for_mutation(
            target.device.handle,
            target.device.generation,
            &target.epoch,
            &target.handle,
        ) else {
            return false;
        };
        current.device == target.device
            && current.epoch == target.epoch
            && current.handle == target.handle
            && current.authenticator == target.authenticator
            && current.completeness == target.completeness
            && current.rp_hash == target.rp_hash
            && current.credential_id == target.credential_id
            && current.user_id == target.user_id
            && current.rp_text == target.rp_text
            && current.user_name == target.user_name
            && current.display_name == target.display_name
    }

    /// Current native addressing for an exact credential that was enumerated under this same
    /// worker/device authority. If the worker was orderly replaced, the card may remain visible
    /// but mutation resolution fails until a fresh credential inspection creates a new epoch.
    pub(crate) fn operation_authority(
        &self,
        target: &ExactCredentialTarget,
    ) -> Option<(DeviceHandle, DeviceGeneration, WorkerGeneration)> {
        if !self.matches_exact_target(target) {
            return None;
        }
        let entry = self.entries.get(&target.device.handle)?;
        Some((
            entry.authority.native_handle,
            entry.authority.native_generation,
            entry.authority.worker,
        ))
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
        assert_eq!(exact.device(), ids[0]);
        assert_eq!(exact.epoch(), &a.epoch);
        assert_eq!(exact.handle(), ah);
        let expected_rp_hash: [u8; 32] = Sha256::digest(b"example.com").into();
        assert_eq!(exact.rp_hash(), &expected_rp_hash);
        assert_eq!(exact.credential_id(), &[17, 19, 23]);
        assert_eq!(exact.user_id(), Some([29, 31, 37].as_slice()));
        assert_eq!(exact.rp_text(), "example.com");
        assert_eq!(exact.user_name(), Some("Account"));
        assert_eq!(exact.display_name(), None);
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
    fn mutation_resolution_allows_exact_incomplete_but_refuses_inconsistent()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = InspectionStore::default();
        let ids = store
            .reconcile_connected(&[device(1, 1, 1)], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;

        let mut incomplete = inventory();
        incomplete.metadata_existing = 2;
        incomplete.rps.push(OwnedRp {
            hash: [7; 32],
            verified_text: None,
            issue: Some(RpIssue::TextUnavailable),
            credentials: Vec::new(),
        });
        assert_eq!(incomplete.assess().completeness, Completeness::Incomplete);
        store
            .replace(ids[0], "Same label".into(), incomplete)
            .map_err(|_| "replace incomplete")?;
        let incomplete_snapshot = snapshot(&store, ids[0]);
        let handle = &incomplete_snapshot.rps[0].credentials[0].handle;
        assert!(
            store
                .resolve_for_mutation(
                    ids[0].handle,
                    ids[0].generation,
                    &incomplete_snapshot.epoch,
                    handle
                )
                .is_some()
        );

        let mut inconsistent = inventory();
        inconsistent.metadata_existing = 2;
        inconsistent.rps[0].credentials.push(OwnedCredential {
            id: vec![17, 19, 23],
            user_id: Some(vec![41]),
            user_name: Some("Duplicate".into()),
            display_name: None,
        });
        assert_eq!(
            inconsistent.assess().completeness,
            Completeness::Inconsistent
        );
        assert!(inconsistent.assess().duplicate_credentials);
        store
            .replace(ids[0], "Same label".into(), inconsistent)
            .map_err(|_| "replace inconsistent")?;
        let inconsistent_snapshot = snapshot(&store, ids[0]);
        for credential in &inconsistent_snapshot.rps[0].credentials {
            assert!(
                store
                    .resolve_for_mutation(
                        ids[0].handle,
                        ids[0].generation,
                        &inconsistent_snapshot.epoch,
                        &credential.handle
                    )
                    .is_none()
            );
        }
        Ok(())
    }

    #[test]
    fn mutation_resolution_rejects_unknown_handle_and_survives_only_as_owned_display_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = InspectionStore::default();
        let ids = store
            .reconcile_connected(&[device(1, 1, 1)], WorkerGeneration(1))
            .map_err(|_| "reconcile")?;
        replace(&mut store, ids[0]);
        let before = snapshot(&store, ids[0]);
        let known = &before.rps[0].credentials[0].handle;
        assert!(
            store
                .resolve_for_mutation(
                    ids[0].handle,
                    ids[0].generation,
                    &before.epoch,
                    &CredentialHandle("00000000000000000000000000000000".into())
                )
                .is_none()
        );
        let target = store
            .resolve_for_mutation(ids[0].handle, ids[0].generation, &before.epoch, known)
            .ok_or("target")?;
        assert_eq!(target.device(), ids[0]);
        assert!(store.matches_exact_target(&target));

        store.proven_retirement(WorkerGeneration(1));
        assert!(!store.matches_exact_target(&target));
        assert!(
            store
                .resolve_for_mutation(ids[0].handle, ids[0].generation, &before.epoch, known)
                .is_none()
        );
        let next = store
            .reconcile_connected(&[device(9, 1, 1)], WorkerGeneration(2))
            .map_err(|_| "refresh")?;
        assert_eq!(next, ids);
        assert!(
            store
                .resolve_for_mutation(next[0].handle, next[0].generation, &before.epoch, known)
                .is_none(),
            "presentation continuity must not revive mutation authority"
        );
        assert!(!store.matches_exact_target(&target));

        // A fresh inspection under worker 2 establishes a new epoch and new exact target.
        replace(&mut store, next[0]);
        let after = snapshot(&store, next[0]);
        let refreshed = store
            .resolve_for_mutation(
                next[0].handle,
                next[0].generation,
                &after.epoch,
                &after.rps[0].credentials[0].handle,
            )
            .ok_or("fresh target")?;
        assert!(store.matches_exact_target(&refreshed));
        assert_eq!(
            store.operation_authority(&refreshed),
            Some((
                DeviceHandle::from_raw(9),
                DeviceGeneration(1),
                WorkerGeneration(2)
            ))
        );
        Ok(())
    }

    #[test]
    fn reconcile_rejects_duplicate_live_display_handles() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut store = InspectionStore::default();
        let first = device(1, 1, 1);
        store
            .reconcile_connected(std::slice::from_ref(&first), WorkerGeneration(1))
            .map_err(|_| "initial")?;

        let claimed = device(2, 1, 1);
        let mut old_native_without_connection = device(1, 1, 2);
        old_native_without_connection.verification_history_id = None;
        assert!(
            store
                .reconcile_connected(
                    &[claimed, old_native_without_connection],
                    WorkerGeneration(1)
                )
                .is_err()
        );
        assert!(store.connected.is_empty());
        assert!(store.entries.is_empty());
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
