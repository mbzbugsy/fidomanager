//! Read-only authenticator discovery coordination.
//!
//! This module owns renderer-handle minting and translates the process-transparent worker
//! protocol into sanitized domain snapshots. Native device paths and native handles never cross
//! this boundary.

use fido_core::{
    DeviceHandle, DeviceListSnapshot, DeviceOption, DeviceReadStatus, DeviceSnapshot,
    EnumerationEpoch, ExecutionQuiescence, ViewFreshness,
};
use fido_worker_protocol::{
    CancellationId, MAX_DEVICE_STRING_ITEMS, MAX_DEVICE_TEXT_BYTES, MAX_DISCOVERED_DEVICES,
    RequestBudgetMs, WORKER_PROTOCOL_VERSION, WorkerDeviceId, WorkerDeviceInfo,
    WorkerDiscoveredDevice, WorkerErrorCode, WorkerGeneration, WorkerRequest,
    WorkerRequestEnvelope, WorkerRequestId, WorkerResponse, WorkerResponseEnvelope,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryPolicy {
    pub list_devices_budget_ms: u64,
    pub get_device_info_budget_ms: u64,
}

impl DiscoveryPolicy {
    pub fn validate(self) -> Result<Self, DiscoveryPolicyError> {
        if self.list_devices_budget_ms == 0 {
            return Err(DiscoveryPolicyError::ZeroListDevicesBudget);
        }
        if self.get_device_info_budget_ms == 0 {
            return Err(DiscoveryPolicyError::ZeroGetDeviceInfoBudget);
        }
        Ok(self)
    }
}

impl Default for DiscoveryPolicy {
    fn default() -> Self {
        Self {
            list_devices_budget_ms: 2_000,
            get_device_info_budget_ms: 2_000,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryPolicyError {
    #[error("list-devices execution budget must be greater than zero")]
    ZeroListDevicesBudget,
    #[error("GetInfo execution budget must be greater than zero")]
    ZeroGetDeviceInfoBudget,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WorkerEndpointError {
    #[error("worker endpoint is unavailable")]
    Unavailable,
    #[error("worker transport failed")]
    TransportFailure,
    #[error("worker frame exceeded the configured transport bound")]
    FrameTooLarge,
}

/// Service-facing worker endpoint.
///
/// Implementations may use an in-process worker thread today and a child/elevated process later;
/// service semantics must not depend on that placement.
pub trait WorkerEndpoint {
    fn exchange(
        &mut self,
        request: WorkerRequestEnvelope,
    ) -> Result<WorkerResponseEnvelope, WorkerEndpointError>;
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryError {
    #[error(transparent)]
    Endpoint(#[from] WorkerEndpointError),
    #[error("worker returned error {0:?}")]
    Worker(WorkerErrorCode),
    #[error("worker is quarantined and must be replaced before reuse")]
    WorkerQuarantined,
    #[error("service constructed an invalid worker request")]
    InvalidWorkerRequest,
    #[error("worker response did not correlate with the request")]
    ResponseCorrelation,
    #[error("worker returned a response variant that does not match the request")]
    UnexpectedResponse,
    #[error("read-only worker response contained mutation evidence")]
    MutationEvidenceOnReadOnly,
    #[error("worker native execution is not proven quiescent")]
    WorkerNotQuiescent,
    #[error("worker device identity/generation contract was violated")]
    DeviceIdentityViolation,
    #[error("replacement worker generation must strictly increase")]
    NonIncreasingWorkerGeneration,
    #[error("worker returned too many discovered devices")]
    TooManyDevices,
    #[error("worker returned duplicate device identities in one enumeration")]
    DuplicateDevice,
    #[error("worker returned device data outside the approved output bounds")]
    MalformedDeviceData,
    #[error("authority identifier space is exhausted")]
    IdentifierSpaceExhausted,
}

impl DiscoveryError {
    fn requires_worker_quarantine(self) -> bool {
        matches!(
            self,
            Self::Endpoint(_)
                | Self::ResponseCorrelation
                | Self::UnexpectedResponse
                | Self::MutationEvidenceOnReadOnly
                | Self::WorkerNotQuiescent
                | Self::DeviceIdentityViolation
                | Self::TooManyDevices
                | Self::DuplicateDevice
                | Self::Worker(
                    WorkerErrorCode::ProtocolMismatch | WorkerErrorCode::WorkerUnavailable
                )
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredDeviceTarget {
    pub worker_device_id: WorkerDeviceId,
    pub device_generation: fido_core::DeviceGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegisteredDevice {
    handle: DeviceHandle,
    worker_device_id: WorkerDeviceId,
    device_generation: fido_core::DeviceGeneration,
    vendor_id: u16,
    product_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceIdentityHistory {
    worker_device_id: WorkerDeviceId,
    highest_generation: fido_core::DeviceGeneration,
    vendor_id: u16,
    product_id: u16,
    present: bool,
}

#[derive(Debug, Clone)]
struct CachedDeviceInfo {
    worker_device_id: WorkerDeviceId,
    device_generation: fido_core::DeviceGeneration,
    vendor_id: u16,
    product_id: u16,
    info: WorkerDeviceInfo,
}

#[derive(Debug, Default)]
struct DeviceRegistry {
    devices: Vec<RegisteredDevice>,
    history: Vec<DeviceIdentityHistory>,
    next_handle_raw: u128,
}

impl DeviceRegistry {
    fn new() -> Self {
        Self {
            devices: Vec::new(),
            history: Vec::new(),
            next_handle_raw: 1,
        }
    }

    fn reconcile(
        &mut self,
        discovered: &[WorkerDiscoveredDevice],
    ) -> Result<Vec<(WorkerDiscoveredDevice, DeviceHandle)>, DiscoveryError> {
        // Reconciliation is transactional: no registry/history state is committed until every
        // discovered identity has passed the worker-generation contract checks.
        let mut next_devices = Vec::with_capacity(discovered.len());
        let mut resolved = Vec::with_capacity(discovered.len());
        let mut next_history = self.history.clone();
        let mut next_handle_raw = self.next_handle_raw;

        for device in discovered {
            if let Some(history) = next_history
                .iter_mut()
                .find(|history| history.worker_device_id == device.device_id)
            {
                if device.device_generation.0 < history.highest_generation.0 {
                    return Err(DiscoveryError::DeviceIdentityViolation);
                }

                if device.device_generation == history.highest_generation {
                    if !history.present
                        || history.vendor_id != device.vendor_id
                        || history.product_id != device.product_id
                    {
                        return Err(DiscoveryError::DeviceIdentityViolation);
                    }
                } else {
                    history.highest_generation = device.device_generation;
                    history.vendor_id = device.vendor_id;
                    history.product_id = device.product_id;
                }
                history.present = true;
            } else {
                next_history.push(DeviceIdentityHistory {
                    worker_device_id: device.device_id,
                    highest_generation: device.device_generation,
                    vendor_id: device.vendor_id,
                    product_id: device.product_id,
                    present: true,
                });
            }

            let handle = match self.devices.iter().find(|registered| {
                registered.worker_device_id == device.device_id
                    && registered.device_generation == device.device_generation
                    && registered.vendor_id == device.vendor_id
                    && registered.product_id == device.product_id
            }) {
                Some(registered) => registered.handle,
                None => {
                    let raw = next_handle_raw;
                    next_handle_raw = next_handle_raw
                        .checked_add(1)
                        .ok_or(DiscoveryError::IdentifierSpaceExhausted)?;
                    DeviceHandle::from_raw(raw)
                }
            };

            next_devices.push(RegisteredDevice {
                handle,
                worker_device_id: device.device_id,
                device_generation: device.device_generation,
                vendor_id: device.vendor_id,
                product_id: device.product_id,
            });
            resolved.push((device.clone(), handle));
        }

        for history in &mut next_history {
            if !discovered
                .iter()
                .any(|device| device.device_id == history.worker_device_id)
            {
                history.present = false;
            }
        }

        self.devices = next_devices;
        self.history = next_history;
        self.next_handle_raw = next_handle_raw;
        Ok(resolved)
    }

    fn resolve(&self, handle: DeviceHandle) -> Option<RegisteredDeviceTarget> {
        self.devices
            .iter()
            .find(|registered| registered.handle == handle)
            .map(|registered| RegisteredDeviceTarget {
                worker_device_id: registered.worker_device_id,
                device_generation: registered.device_generation,
            })
    }

    fn clear_active(&mut self) {
        self.devices.clear();
    }

    fn reset_for_worker(&mut self) {
        self.devices.clear();
        self.history.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerState {
    Usable,
    Quarantined,
}

pub struct DiscoveryCoordinator<E> {
    endpoint: E,
    worker_generation: WorkerGeneration,
    worker_state: WorkerState,
    policy: DiscoveryPolicy,
    registry: DeviceRegistry,
    info_cache: Vec<CachedDeviceInfo>,
    next_request_id: u64,
    next_cancellation_id: u64,
    next_enumeration_epoch: u64,
}

impl<E: WorkerEndpoint> DiscoveryCoordinator<E> {
    pub fn new(
        endpoint: E,
        worker_generation: WorkerGeneration,
        policy: DiscoveryPolicy,
    ) -> Result<Self, DiscoveryPolicyError> {
        Ok(Self {
            endpoint,
            worker_generation,
            worker_state: WorkerState::Usable,
            policy: policy.validate()?,
            registry: DeviceRegistry::new(),
            info_cache: Vec::new(),
            next_request_id: 1,
            next_cancellation_id: 1,
            next_enumeration_epoch: 1,
        })
    }

    pub fn refresh(&mut self) -> Result<DeviceListSnapshot, DiscoveryError> {
        if self.worker_state == WorkerState::Quarantined {
            return Err(DiscoveryError::WorkerQuarantined);
        }

        let result = self.refresh_inner();
        if let Err(error) = result {
            // If enumeration cannot complete coherently, old renderer handles are no longer
            // authoritative evidence of current device presence.
            self.registry.clear_active();
            if error.requires_worker_quarantine() {
                self.worker_state = WorkerState::Quarantined;
            }
        }
        result
    }

    pub fn resolve_handle(&self, handle: DeviceHandle) -> Option<RegisteredDeviceTarget> {
        self.registry.resolve(handle)
    }

    /// Replace a quarantined or retired worker with a fresh worker instance.
    ///
    /// The caller must ensure the previous worker can no longer execute native calls. A strictly
    /// increasing generation prevents stale responses from a prior worker incarnation from being
    /// accepted after replacement.
    pub fn replace_worker(
        &mut self,
        endpoint: E,
        worker_generation: WorkerGeneration,
    ) -> Result<(), DiscoveryError> {
        if worker_generation.0 <= self.worker_generation.0 {
            return Err(DiscoveryError::NonIncreasingWorkerGeneration);
        }

        self.endpoint = endpoint;
        self.worker_generation = worker_generation;
        self.worker_state = WorkerState::Usable;
        self.registry.reset_for_worker();
        self.info_cache.clear();
        Ok(())
    }

    fn refresh_inner(&mut self) -> Result<DeviceListSnapshot, DiscoveryError> {
        let list_response = self.exchange_read_only(
            WorkerRequest::ListDevices,
            None,
            self.policy.list_devices_budget_ms,
        )?;

        let discovered = match list_response.response {
            WorkerResponse::DevicesListed { devices } => devices,
            WorkerResponse::Error { code } => return Err(DiscoveryError::Worker(code)),
            _ => return Err(DiscoveryError::UnexpectedResponse),
        };

        validate_discovered_devices(&discovered)?;
        let registered = self.registry.reconcile(&discovered)?;
        self.prune_info_cache(&discovered);
        let epoch = self.mint_enumeration_epoch()?;
        let mut snapshots = Vec::with_capacity(registered.len());

        for (device, handle) in registered {
            let mut snapshot = base_snapshot(&device, handle);

            if let Some(info) = self.cached_device_info(&device) {
                let discovery_metadata_was_malformed =
                    snapshot.read_status == DeviceReadStatus::Malformed;
                apply_device_info(&mut snapshot, info);
                if !discovery_metadata_was_malformed {
                    snapshot.read_status = DeviceReadStatus::Ready;
                    snapshot.freshness = ViewFreshness::Fresh;
                }
                snapshots.push(snapshot);
                continue;
            }

            let info_response = self.exchange_read_only(
                WorkerRequest::GetDeviceInfo {
                    device_id: device.device_id,
                },
                Some(device.device_generation),
                self.policy.get_device_info_budget_ms,
            )?;

            match info_response.response {
                WorkerResponse::DeviceInfo { info } => {
                    if info.device_id != device.device_id {
                        return Err(DiscoveryError::ResponseCorrelation);
                    }

                    if validate_device_info(&info).is_ok() {
                        let discovery_metadata_was_malformed =
                            snapshot.read_status == DeviceReadStatus::Malformed;
                        self.cache_device_info(&device, &info);
                        apply_device_info(&mut snapshot, info);
                        if !discovery_metadata_was_malformed {
                            snapshot.read_status = DeviceReadStatus::Ready;
                            snapshot.freshness = ViewFreshness::Fresh;
                        }
                    } else {
                        // Authenticator-originated malformed metadata is isolated to this device;
                        // protocol/correlation failures still fail the whole transaction.
                        snapshot.read_status = DeviceReadStatus::Malformed;
                        snapshot.freshness = ViewFreshness::Incomplete;
                    }
                }
                WorkerResponse::Error { code } => {
                    snapshot.read_status = read_status_for_error(code)?;
                    snapshot.freshness = ViewFreshness::Incomplete;
                }
                _ => return Err(DiscoveryError::UnexpectedResponse),
            }

            snapshots.push(snapshot);
        }

        Ok(DeviceListSnapshot {
            enumeration_epoch: epoch,
            devices: snapshots,
        })
    }

    fn cached_device_info(
        &self,
        device: &WorkerDiscoveredDevice,
    ) -> Option<WorkerDeviceInfo> {
        self.info_cache
            .iter()
            .find(|cached| {
                cached.worker_device_id == device.device_id
                    && cached.device_generation == device.device_generation
                    && cached.vendor_id == device.vendor_id
                    && cached.product_id == device.product_id
            })
            .map(|cached| cached.info.clone())
    }

    fn cache_device_info(&mut self, device: &WorkerDiscoveredDevice, info: &WorkerDeviceInfo) {
        if let Some(cached) = self.info_cache.iter_mut().find(|cached| {
            cached.worker_device_id == device.device_id
                && cached.device_generation == device.device_generation
                && cached.vendor_id == device.vendor_id
                && cached.product_id == device.product_id
        }) {
            cached.info = info.clone();
            return;
        }

        self.info_cache.push(CachedDeviceInfo {
            worker_device_id: device.device_id,
            device_generation: device.device_generation,
            vendor_id: device.vendor_id,
            product_id: device.product_id,
            info: info.clone(),
        });
    }

    fn prune_info_cache(&mut self, discovered: &[WorkerDiscoveredDevice]) {
        self.info_cache.retain(|cached| {
            discovered.iter().any(|device| {
                cached.worker_device_id == device.device_id
                    && cached.device_generation == device.device_generation
                    && cached.vendor_id == device.vendor_id
                    && cached.product_id == device.product_id
            })
        });
    }

    fn exchange_read_only(
        &mut self,
        request: WorkerRequest,
        device_generation: Option<fido_core::DeviceGeneration>,
        budget_ms: u64,
    ) -> Result<WorkerResponseEnvelope, DiscoveryError> {
        let request_id = WorkerRequestId(self.take_request_id()?);
        let cancellation_id = CancellationId(self.take_cancellation_id()?);
        let envelope = WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id,
            cancellation_id,
            operation_class: request.operation_class(),
            worker_generation: self.worker_generation,
            device_generation,
            budget_ms: RequestBudgetMs(budget_ms),
            request,
        };
        envelope
            .validate()
            .map_err(|_| DiscoveryError::InvalidWorkerRequest)?;

        let response = self.endpoint.exchange(envelope.clone())?;
        validate_response(&envelope, &response)?;
        Ok(response)
    }

    fn take_request_id(&mut self) -> Result<u64, DiscoveryError> {
        let value = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(DiscoveryError::IdentifierSpaceExhausted)?;
        Ok(value)
    }

    fn take_cancellation_id(&mut self) -> Result<u64, DiscoveryError> {
        let value = self.next_cancellation_id;
        self.next_cancellation_id = self
            .next_cancellation_id
            .checked_add(1)
            .ok_or(DiscoveryError::IdentifierSpaceExhausted)?;
        Ok(value)
    }

    fn mint_enumeration_epoch(&mut self) -> Result<EnumerationEpoch, DiscoveryError> {
        let value = self.next_enumeration_epoch;
        self.next_enumeration_epoch = self
            .next_enumeration_epoch
            .checked_add(1)
            .ok_or(DiscoveryError::IdentifierSpaceExhausted)?;
        Ok(EnumerationEpoch(value))
    }
}

fn validate_response(
    request: &WorkerRequestEnvelope,
    response: &WorkerResponseEnvelope,
) -> Result<(), DiscoveryError> {
    if response.protocol_version != WORKER_PROTOCOL_VERSION
        || response.request_id != request.request_id
        || response.worker_generation != request.worker_generation
        || response.device_generation != request.device_generation
    {
        return Err(DiscoveryError::ResponseCorrelation);
    }

    if response.evidence.mutation_outcome.is_some() {
        return Err(DiscoveryError::MutationEvidenceOnReadOnly);
    }
    if response.evidence.execution_quiescence != ExecutionQuiescence::Quiescent {
        return Err(DiscoveryError::WorkerNotQuiescent);
    }

    let response_matches = matches!(
        (&request.request, &response.response),
        (
            WorkerRequest::ListDevices,
            WorkerResponse::DevicesListed { .. }
        ) | (WorkerRequest::ListDevices, WorkerResponse::Error { .. })
            | (
                WorkerRequest::GetDeviceInfo { .. },
                WorkerResponse::DeviceInfo { .. }
            )
            | (
                WorkerRequest::GetDeviceInfo { .. },
                WorkerResponse::Error { .. }
            )
    );

    if !response_matches {
        return Err(DiscoveryError::UnexpectedResponse);
    }

    Ok(())
}

fn validate_discovered_devices(devices: &[WorkerDiscoveredDevice]) -> Result<(), DiscoveryError> {
    if devices.len() > MAX_DISCOVERED_DEVICES {
        return Err(DiscoveryError::TooManyDevices);
    }

    let mut seen = Vec::with_capacity(devices.len());
    for device in devices {
        if seen.contains(&device.device_id) {
            return Err(DiscoveryError::DuplicateDevice);
        }
        seen.push(device.device_id);
    }

    Ok(())
}

fn validate_device_info(info: &WorkerDeviceInfo) -> Result<(), DiscoveryError> {
    if info.versions.len() > MAX_DEVICE_STRING_ITEMS
        || info.extensions.len() > MAX_DEVICE_STRING_ITEMS
        || info.transports.len() > MAX_DEVICE_STRING_ITEMS
        || info.options.len() > MAX_DEVICE_STRING_ITEMS
    {
        return Err(DiscoveryError::MalformedDeviceData);
    }

    let strings_are_valid = info
        .versions
        .iter()
        .chain(info.extensions.iter())
        .chain(info.transports.iter())
        .all(|value| text_is_valid(value));
    let options_are_valid = info
        .options
        .iter()
        .all(|option| text_is_valid(&option.name));
    let collections_are_unique = strings_are_unique(&info.versions)
        && strings_are_unique(&info.extensions)
        && strings_are_unique(&info.transports)
        && option_names_are_unique(&info.options);

    if !strings_are_valid || !options_are_valid || !collections_are_unique {
        return Err(DiscoveryError::MalformedDeviceData);
    }

    Ok(())
}

fn strings_are_unique(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[index + 1..].contains(value))
}

fn option_names_are_unique(options: &[fido_worker_protocol::WorkerDeviceOption]) -> bool {
    options.iter().enumerate().all(|(index, option)| {
        !options[index + 1..]
            .iter()
            .any(|candidate| candidate.name == option.name)
    })
}

fn optional_text_is_valid(value: &Option<String>) -> bool {
    value.as_ref().is_none_or(|text| text_is_valid(text))
}

fn text_is_valid(value: &str) -> bool {
    value.len() <= MAX_DEVICE_TEXT_BYTES
        && !value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2060}'..='\u{2069}'
                )
        })
}

fn base_snapshot(device: &WorkerDiscoveredDevice, handle: DeviceHandle) -> DeviceSnapshot {
    let manufacturer_is_valid = optional_text_is_valid(&device.manufacturer);
    let product_is_valid = optional_text_is_valid(&device.product);
    let discovery_metadata_is_valid = manufacturer_is_valid && product_is_valid;

    DeviceSnapshot {
        handle,
        generation: device.device_generation,
        vendor_id: device.vendor_id,
        product_id: device.product_id,
        manufacturer: device
            .manufacturer
            .clone()
            .filter(|_| manufacturer_is_valid),
        product: device.product.clone().filter(|_| product_is_valid),
        aaguid: None,
        versions: Vec::new(),
        extensions: Vec::new(),
        transports: Vec::new(),
        options: Vec::new(),
        max_message_size: None,
        firmware_version: None,
        read_status: if discovery_metadata_is_valid {
            DeviceReadStatus::Ready
        } else {
            DeviceReadStatus::Malformed
        },
        freshness: ViewFreshness::Incomplete,
    }
}

fn apply_device_info(snapshot: &mut DeviceSnapshot, info: WorkerDeviceInfo) {
    snapshot.aaguid = info.aaguid;
    snapshot.versions = info.versions;
    snapshot.extensions = info.extensions;
    snapshot.transports = info.transports;
    snapshot.options = info
        .options
        .into_iter()
        .map(|option| DeviceOption {
            name: option.name,
            enabled: option.enabled,
        })
        .collect();
    snapshot.max_message_size = info.max_message_size;
    snapshot.firmware_version = info.firmware_version;
}

fn read_status_for_error(code: WorkerErrorCode) -> Result<DeviceReadStatus, DiscoveryError> {
    match code {
        WorkerErrorCode::DeviceAbsent => Ok(DeviceReadStatus::Unavailable),
        WorkerErrorCode::DeviceBusy => Ok(DeviceReadStatus::Busy),
        WorkerErrorCode::AccessDenied => Ok(DeviceReadStatus::AccessDenied),
        WorkerErrorCode::DeadlineExpired => Ok(DeviceReadStatus::TimedOut),
        WorkerErrorCode::UnsupportedDevice => Ok(DeviceReadStatus::Unsupported),
        WorkerErrorCode::MalformedDeviceData => Ok(DeviceReadStatus::Malformed),
        WorkerErrorCode::Cancelled | WorkerErrorCode::InternalFailure => {
            Ok(DeviceReadStatus::Error)
        }
        WorkerErrorCode::ProtocolMismatch | WorkerErrorCode::WorkerUnavailable => {
            Err(DiscoveryError::Worker(code))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_core::{Aaguid, DeviceGeneration, MutationOutcome};
    use fido_worker_protocol::{MAX_DEVICE_TEXT_BYTES, WorkerDeviceOption, WorkerResponseEvidence};

    #[derive(Debug, Clone)]
    struct FakeDevice {
        discovered: WorkerDiscoveredDevice,
        info: Result<WorkerDeviceInfo, WorkerErrorCode>,
    }

    #[derive(Debug)]
    struct FakeEndpoint {
        generation: WorkerGeneration,
        devices: Vec<FakeDevice>,
        force_active_response: bool,
        force_transport_failure: bool,
        exchange_count: usize,
    }

    impl FakeEndpoint {
        fn new(generation: WorkerGeneration, devices: Vec<FakeDevice>) -> Self {
            Self {
                generation,
                devices,
                force_active_response: false,
                force_transport_failure: false,
                exchange_count: 0,
            }
        }

        fn response(
            &self,
            request: &WorkerRequestEnvelope,
            response: WorkerResponse,
        ) -> WorkerResponseEnvelope {
            WorkerResponseEnvelope {
                protocol_version: WORKER_PROTOCOL_VERSION,
                request_id: request.request_id,
                worker_generation: self.generation,
                device_generation: request.device_generation,
                evidence: WorkerResponseEvidence {
                    execution_quiescence: if self.force_active_response {
                        ExecutionQuiescence::Active
                    } else {
                        ExecutionQuiescence::Quiescent
                    },
                    mutation_outcome: None,
                },
                response,
            }
        }
    }

    impl WorkerEndpoint for FakeEndpoint {
        fn exchange(
            &mut self,
            request: WorkerRequestEnvelope,
        ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
            self.exchange_count += 1;
            if self.force_transport_failure {
                return Err(WorkerEndpointError::TransportFailure);
            }

            let response = match &request.request {
                WorkerRequest::ListDevices => WorkerResponse::DevicesListed {
                    devices: self
                        .devices
                        .iter()
                        .map(|device| device.discovered.clone())
                        .collect(),
                },
                WorkerRequest::GetDeviceInfo { device_id } => {
                    let Some(device) = self
                        .devices
                        .iter()
                        .find(|device| device.discovered.device_id == *device_id)
                    else {
                        return Ok(self.response(
                            &request,
                            WorkerResponse::Error {
                                code: WorkerErrorCode::DeviceAbsent,
                            },
                        ));
                    };

                    match &device.info {
                        Ok(info) => WorkerResponse::DeviceInfo { info: info.clone() },
                        Err(code) => WorkerResponse::Error { code: *code },
                    }
                }
                _ => WorkerResponse::Error {
                    code: WorkerErrorCode::InternalFailure,
                },
            };

            Ok(self.response(&request, response))
        }
    }

    fn fake_device(generation: u64) -> FakeDevice {
        fake_device_with_id(7, generation)
    }

    fn fake_device_with_id(device_id: u64, generation: u64) -> FakeDevice {
        let device_id = WorkerDeviceId(device_id);
        FakeDevice {
            discovered: WorkerDiscoveredDevice {
                device_id,
                device_generation: DeviceGeneration(generation),
                vendor_id: 0x1050,
                product_id: 0x0407,
                manufacturer: Some("Example Security".to_owned()),
                product: Some("Roaming Authenticator".to_owned()),
            },
            info: Ok(WorkerDeviceInfo {
                device_id,
                aaguid: Some(Aaguid::from_bytes([0x11; 16])),
                versions: vec!["FIDO_2_1".to_owned()],
                extensions: vec!["credProtect".to_owned()],
                transports: vec!["usb".to_owned()],
                options: vec![WorkerDeviceOption {
                    name: "rk".to_owned(),
                    enabled: true,
                }],
                max_message_size: Some(1_200),
                firmware_version: Some(42),
            }),
        }
    }

    fn coordinator(
        devices: Vec<FakeDevice>,
    ) -> Result<DiscoveryCoordinator<FakeEndpoint>, DiscoveryPolicyError> {
        let worker_generation = WorkerGeneration(3);
        DiscoveryCoordinator::new(
            FakeEndpoint::new(worker_generation, devices),
            worker_generation,
            DiscoveryPolicy::default(),
        )
    }

    #[test]
    fn refresh_publishes_sanitized_snapshot_and_registry_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(9)])?;
        let snapshot = coordinator.refresh()?;

        assert_eq!(snapshot.enumeration_epoch, EnumerationEpoch(1));
        assert_eq!(snapshot.devices.len(), 1);
        let device = &snapshot.devices[0];
        assert_eq!(device.read_status, DeviceReadStatus::Ready);
        assert_eq!(device.freshness, ViewFreshness::Fresh);
        assert_eq!(device.versions, vec!["FIDO_2_1"]);
        assert_eq!(device.transports, vec!["usb"]);
        assert_eq!(
            coordinator.resolve_handle(device.handle),
            Some(RegisteredDeviceTarget {
                worker_device_id: WorkerDeviceId(7),
                device_generation: DeviceGeneration(9),
            })
        );
        Ok(())
    }

    #[test]
    fn cached_get_info_is_not_reissued_for_same_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;

        let first = coordinator.refresh()?;
        assert_eq!(first.devices[0].read_status, DeviceReadStatus::Ready);
        assert_eq!(coordinator.endpoint.exchange_count, 2);

        let second = coordinator.refresh()?;
        assert_eq!(second.devices[0].read_status, DeviceReadStatus::Ready);
        assert_eq!(second.devices[0].aaguid, first.devices[0].aaguid);
        assert_eq!(coordinator.endpoint.exchange_count, 3);

        Ok(())
    }

    #[test]
    fn removal_invalidates_old_handle_and_replug_gets_fresh_handle()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        let first = coordinator.refresh()?;
        let first_handle = first.devices[0].handle;

        coordinator.endpoint.devices.clear();
        let removed = coordinator.refresh()?;
        assert!(removed.devices.is_empty());
        assert_eq!(coordinator.resolve_handle(first_handle), None);

        coordinator.endpoint.devices.push(fake_device(2));
        let replugged = coordinator.refresh()?;
        let second_handle = replugged.devices[0].handle;
        assert_ne!(first_handle, second_handle);
        assert_eq!(coordinator.resolve_handle(first_handle), None);
        Ok(())
    }

    #[test]
    fn busy_get_info_is_explicitly_incomplete() -> Result<(), Box<dyn std::error::Error>> {
        let mut device = fake_device(1);
        device.info = Err(WorkerErrorCode::DeviceBusy);
        let mut coordinator = coordinator(vec![device])?;
        let snapshot = coordinator.refresh()?;

        assert_eq!(snapshot.devices[0].read_status, DeviceReadStatus::Busy);
        assert_eq!(snapshot.devices[0].freshness, ViewFreshness::Incomplete);
        Ok(())
    }

    #[test]
    fn active_native_execution_fails_closed_and_invalidates_registry()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        let initial = coordinator.refresh()?;
        let handle = initial.devices[0].handle;

        coordinator.endpoint.force_active_response = true;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerNotQuiescent)
        );
        assert_eq!(coordinator.resolve_handle(handle), None);

        let exchanges_after_quarantine = coordinator.endpoint.exchange_count;
        coordinator.endpoint.force_active_response = false;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerQuarantined)
        );
        assert_eq!(
            coordinator.endpoint.exchange_count,
            exchanges_after_quarantine
        );
        Ok(())
    }

    #[test]
    fn transport_failure_quarantines_worker_until_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        coordinator.endpoint.force_transport_failure = true;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::Endpoint(
                WorkerEndpointError::TransportFailure
            ))
        );

        let exchanges_after_failure = coordinator.endpoint.exchange_count;
        coordinator.endpoint.force_transport_failure = false;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerQuarantined)
        );
        assert_eq!(coordinator.endpoint.exchange_count, exchanges_after_failure);

        coordinator.replace_worker(
            FakeEndpoint::new(WorkerGeneration(4), vec![fake_device(2)]),
            WorkerGeneration(4),
        )?;
        assert_eq!(coordinator.refresh()?.devices.len(), 1);
        Ok(())
    }

    #[test]
    fn malformed_native_text_is_isolated_to_affected_device()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut device = fake_device(1);
        device.discovered.product = Some("x".repeat(MAX_DEVICE_TEXT_BYTES + 1));
        let mut coordinator = coordinator(vec![device])?;

        let snapshot = coordinator.refresh()?;
        assert_eq!(snapshot.devices[0].read_status, DeviceReadStatus::Malformed);
        assert_eq!(snapshot.devices[0].freshness, ViewFreshness::Incomplete);
        assert_eq!(snapshot.devices[0].product, None);
        Ok(())
    }

    #[test]
    fn malformed_get_info_does_not_hide_other_devices() -> Result<(), Box<dyn std::error::Error>> {
        let ready = fake_device_with_id(7, 1);
        let mut malformed = fake_device_with_id(8, 1);
        if let Ok(info) = &mut malformed.info {
            info.versions = vec!["x".repeat(MAX_DEVICE_TEXT_BYTES + 1)];
        }
        let mut coordinator = coordinator(vec![ready, malformed])?;

        let snapshot = coordinator.refresh()?;
        assert_eq!(snapshot.devices.len(), 2);
        assert_eq!(snapshot.devices[0].read_status, DeviceReadStatus::Ready);
        assert_eq!(snapshot.devices[0].freshness, ViewFreshness::Fresh);
        assert_eq!(snapshot.devices[1].read_status, DeviceReadStatus::Malformed);
        assert_eq!(snapshot.devices[1].freshness, ViewFreshness::Incomplete);
        assert!(snapshot.devices[1].versions.is_empty());
        Ok(())
    }

    #[test]
    fn bidi_override_in_device_metadata_is_not_published_as_trusted_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut device = fake_device(1);
        if let Ok(info) = &mut device.info {
            info.versions = vec!["FIDO_2_1\u{202e}spoof".to_owned()];
        }
        let mut coordinator = coordinator(vec![device])?;

        let snapshot = coordinator.refresh()?;
        assert_eq!(snapshot.devices[0].read_status, DeviceReadStatus::Malformed);
        assert!(snapshot.devices[0].versions.is_empty());
        Ok(())
    }

    #[test]
    fn identity_generation_regression_quarantines_worker() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut coordinator = coordinator(vec![fake_device(2)])?;
        coordinator.refresh()?;
        coordinator.endpoint.devices = vec![fake_device(1)];

        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::DeviceIdentityViolation)
        );
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerQuarantined)
        );
        Ok(())
    }

    #[test]
    fn identity_generation_cannot_be_reused_after_observed_absence()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        coordinator.refresh()?;
        coordinator.endpoint.devices.clear();
        coordinator.refresh()?;
        coordinator.endpoint.devices.push(fake_device(1));

        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::DeviceIdentityViolation)
        );
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerQuarantined)
        );
        Ok(())
    }

    #[test]
    fn same_identity_generation_with_changed_vid_pid_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        coordinator.refresh()?;
        coordinator.endpoint.devices[0].discovered.product_id ^= 1;

        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::DeviceIdentityViolation)
        );
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerQuarantined)
        );
        Ok(())
    }

    #[test]
    fn replacement_worker_generation_must_increase() -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        assert_eq!(
            coordinator.replace_worker(
                FakeEndpoint::new(WorkerGeneration(3), vec![fake_device(2)]),
                WorkerGeneration(3),
            ),
            Err(DiscoveryError::NonIncreasingWorkerGeneration)
        );
        Ok(())
    }

    #[test]
    fn read_only_response_rejects_mutation_evidence() -> Result<(), Box<dyn std::error::Error>> {
        struct MutationEvidenceEndpoint;

        impl WorkerEndpoint for MutationEvidenceEndpoint {
            fn exchange(
                &mut self,
                request: WorkerRequestEnvelope,
            ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
                Ok(WorkerResponseEnvelope {
                    protocol_version: WORKER_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    worker_generation: request.worker_generation,
                    device_generation: request.device_generation,
                    evidence: WorkerResponseEvidence {
                        execution_quiescence: ExecutionQuiescence::Quiescent,
                        mutation_outcome: Some(MutationOutcome::NotDispatched),
                    },
                    response: WorkerResponse::DevicesListed {
                        devices: Vec::new(),
                    },
                })
            }
        }

        let generation = WorkerGeneration(1);
        let mut coordinator = DiscoveryCoordinator::new(
            MutationEvidenceEndpoint,
            generation,
            DiscoveryPolicy::default(),
        )?;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::MutationEvidenceOnReadOnly)
        );
        Ok(())
    }
}
