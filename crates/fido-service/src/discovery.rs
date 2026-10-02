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

use crate::{MonotonicClock, SystemMonotonicClock};

/// Nested deadlines for one discovery refresh. Each layer owns exactly one deadline and is shorter
/// than the layer above it:
///
/// ```text
/// transaction   whole refresh                     owner: DiscoveryCoordinator
///   exchange    one request, budget + margin      owner: WorkerEndpoint
///     native    budget, split across sub-calls    owner: the worker / native adapter
/// ```
///
/// Later exchanges in a transaction receive what is *left* of the transaction, never a fresh
/// operation budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryPolicy {
    pub list_devices_budget_ms: u64,
    pub get_device_info_budget_ms: u64,
    /// Upper bound for one whole `refresh()`: `ListDevices` plus every uncached `GetDeviceInfo`.
    pub transaction_budget_ms: u64,
}

impl DiscoveryPolicy {
    pub fn validate(self) -> Result<Self, DiscoveryPolicyError> {
        if self.list_devices_budget_ms == 0 {
            return Err(DiscoveryPolicyError::ZeroListDevicesBudget);
        }
        if self.get_device_info_budget_ms == 0 {
            return Err(DiscoveryPolicyError::ZeroGetDeviceInfoBudget);
        }
        if self.transaction_budget_ms
            < self
                .list_devices_budget_ms
                .max(self.get_device_info_budget_ms)
        {
            return Err(DiscoveryPolicyError::TransactionBudgetBelowOperationBudget);
        }
        Ok(self)
    }
}

impl Default for DiscoveryPolicy {
    fn default() -> Self {
        Self {
            list_devices_budget_ms: 2_000,
            get_device_info_budget_ms: 2_000,
            // Order of magnitude from the M1.5 spike; to be tuned against real-device timings.
            transaction_budget_ms: 5_000,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryPolicyError {
    #[error("list-devices execution budget must be greater than zero")]
    ZeroListDevicesBudget,
    #[error("GetInfo execution budget must be greater than zero")]
    ZeroGetDeviceInfoBudget,
    #[error("transaction budget must cover at least one full operation budget")]
    TransactionBudgetBelowOperationBudget,
}

/// Smallest native budget worth dispatching. When less than this remains in the transaction the
/// refresh fails closed instead of starting an exchange that cannot finish.
const MIN_EXCHANGE_BUDGET_MS: u64 = 20;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WorkerEndpointError {
    #[error("worker endpoint is unavailable")]
    Unavailable,
    #[error("worker transport failed")]
    TransportFailure,
    #[error("worker frame exceeded the configured transport bound")]
    FrameTooLarge,
    #[error("worker sent a malformed, truncated, or unsolicited frame")]
    MalformedFrame,
    #[error("worker did not answer before the exchange deadline and was terminated")]
    ExchangeDeadlineExceeded,
}

/// Service-facing worker endpoint.
///
/// Implementations place the worker in a killable child process today and behind an elevated
/// broker later; service semantics must not depend on that placement.
pub trait WorkerEndpoint {
    fn exchange(
        &mut self,
        request: WorkerRequestEnvelope,
    ) -> Result<WorkerResponseEnvelope, WorkerEndpointError>;

    /// Time the endpoint adds *beyond* a request's native budget before it declares the exchange
    /// dead. It is transport time (framing, scheduling) and is never available to native code, so
    /// the coordinator subtracts it when fitting an exchange into the transaction deadline.
    fn transport_margin_ms(&self) -> u64;

    /// Force native execution to stop and report what is *proven*.
    ///
    /// `Quiescent` means the worker can no longer execute native calls (for a process worker: it
    /// has been killed **and reaped**). Anything the endpoint cannot prove is `Active`. The call
    /// is idempotent and may be retried: an `Active` result means "try again", not "gone".
    fn contain(&mut self) -> ExecutionQuiescence;
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
    #[error("previous worker is not proven quiescent, so it cannot be replaced")]
    PreviousWorkerNotContained,
    #[error("discovery transaction deadline expired before every exchange completed")]
    TransactionDeadlineExceeded,
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

pub struct DiscoveryCoordinator<E, C = SystemMonotonicClock> {
    endpoint: E,
    clock: C,
    worker_generation: WorkerGeneration,
    worker_state: WorkerState,
    policy: DiscoveryPolicy,
    registry: DeviceRegistry,
    info_cache: Vec<CachedDeviceInfo>,
    next_request_id: u64,
    next_cancellation_id: u64,
    next_enumeration_epoch: u64,
}

impl<E: WorkerEndpoint> DiscoveryCoordinator<E, SystemMonotonicClock> {
    pub fn new(
        endpoint: E,
        worker_generation: WorkerGeneration,
        policy: DiscoveryPolicy,
    ) -> Result<Self, DiscoveryPolicyError> {
        Self::with_clock(
            endpoint,
            worker_generation,
            policy,
            SystemMonotonicClock::new(),
        )
    }
}

impl<E: WorkerEndpoint, C: MonotonicClock> DiscoveryCoordinator<E, C> {
    pub fn with_clock(
        endpoint: E,
        worker_generation: WorkerGeneration,
        policy: DiscoveryPolicy,
        clock: C,
    ) -> Result<Self, DiscoveryPolicyError> {
        Ok(Self {
            endpoint,
            clock,
            worker_generation,
            worker_state: WorkerState::Usable,
            policy: policy.validate()?,
            registry: DeviceRegistry::new(),
            info_cache: Vec::new(),
            // Id 0 is reserved for exchanges the endpoint issues itself (health check).
            next_request_id: 1,
            next_cancellation_id: 1,
            next_enumeration_epoch: 1,
        })
    }

    pub fn worker_generation(&self) -> WorkerGeneration {
        self.worker_generation
    }

    /// Whether the worker has been taken out of service and must be replaced before reuse.
    pub fn is_quarantined(&self) -> bool {
        self.worker_state == WorkerState::Quarantined
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
                // Take the worker out of native execution *now*. Waiting for a replacement to ask
                // would leave a misbehaving worker running; the proof is re-checked, not assumed,
                // when `replace_worker` is called.
                let _ = self.endpoint.contain();
            }
        }
        result
    }

    pub fn resolve_handle(&self, handle: DeviceHandle) -> Option<RegisteredDeviceTarget> {
        self.registry.resolve(handle)
    }

    /// Retire the current worker: take it out of service and force it to stop.
    ///
    /// Returns what the endpoint can *prove*. Only `Quiescent` permits replacement; `Active` means
    /// containment must be retried and no replacement may be started yet.
    pub fn contain_worker(&mut self) -> ExecutionQuiescence {
        self.worker_state = WorkerState::Quarantined;
        self.registry.clear_active();
        self.endpoint.contain()
    }

    /// Replace a quarantined or retired worker with a fresh worker instance.
    ///
    /// The previous worker must be **proven** quiescent: this method asks the endpoint to contain
    /// it and refuses the replacement unless that proof comes back. (Containment is idempotent, so
    /// a worker that was already killed and reaped answers immediately.) A strictly increasing
    /// generation additionally prevents stale responses from a prior worker incarnation from being
    /// accepted after replacement. On refusal the new endpoint is dropped and the current worker
    /// stays quarantined.
    pub fn replace_worker(
        &mut self,
        endpoint: E,
        worker_generation: WorkerGeneration,
    ) -> Result<(), DiscoveryError> {
        if worker_generation.0 <= self.worker_generation.0 {
            return Err(DiscoveryError::NonIncreasingWorkerGeneration);
        }
        if self.contain_worker() != ExecutionQuiescence::Quiescent {
            return Err(DiscoveryError::PreviousWorkerNotContained);
        }

        self.endpoint = endpoint;
        self.worker_generation = worker_generation;
        self.worker_state = WorkerState::Usable;
        self.registry.reset_for_worker();
        self.info_cache.clear();
        Ok(())
    }

    fn refresh_inner(&mut self) -> Result<DeviceListSnapshot, DiscoveryError> {
        let transaction_deadline_ms = self
            .clock
            .now()
            .as_millis()
            .saturating_add(self.policy.transaction_budget_ms);

        let list_response = self.exchange_read_only(
            WorkerRequest::ListDevices,
            None,
            self.policy.list_devices_budget_ms,
            transaction_deadline_ms,
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
                transaction_deadline_ms,
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

    fn cached_device_info(&self, device: &WorkerDiscoveredDevice) -> Option<WorkerDeviceInfo> {
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
        operation_budget_ms: u64,
        transaction_deadline_ms: u64,
    ) -> Result<WorkerResponseEnvelope, DiscoveryError> {
        // The native budget is what is left of the transaction after the endpoint's own transport
        // margin, capped by the operation budget. It is never a fresh full budget.
        let remaining_ms = transaction_deadline_ms.saturating_sub(self.clock.now().as_millis());
        let native_budget_ms = remaining_ms
            .saturating_sub(self.endpoint.transport_margin_ms())
            .min(operation_budget_ms);
        if native_budget_ms < operation_budget_ms.min(MIN_EXCHANGE_BUDGET_MS) {
            // The worker is idle and healthy; the refresh simply ran out of time. Fail the whole
            // refresh closed without quarantining anything.
            return Err(DiscoveryError::TransactionDeadlineExceeded);
        }

        let request_id = WorkerRequestId(self.take_request_id()?);
        let cancellation_id = CancellationId(self.take_cancellation_id()?);
        let envelope = WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id,
            cancellation_id,
            operation_class: request.operation_class(),
            worker_generation: self.worker_generation,
            device_generation,
            budget_ms: RequestBudgetMs(native_budget_ms),
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
    use crate::test_support::FakeClock;
    use fido_core::{Aaguid, DeviceGeneration, MutationOutcome};
    use fido_worker_protocol::{
        MAX_DEVICE_TEXT_BYTES, WorkerDeviceOption, WorkerRequestId, WorkerResponseEvidence,
    };

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
        contain_count: usize,
        containment: ExecutionQuiescence,
        transport_margin_ms: u64,
        budgets_seen: Vec<u64>,
        clock: Option<FakeClock>,
        exchange_cost_ms: std::collections::VecDeque<u64>,
        /// Rewrites every response, to model a worker that violates the protocol.
        tamper: Option<fn(&mut WorkerResponseEnvelope)>,
    }

    impl FakeEndpoint {
        fn new(generation: WorkerGeneration, devices: Vec<FakeDevice>) -> Self {
            Self {
                generation,
                devices,
                force_active_response: false,
                force_transport_failure: false,
                exchange_count: 0,
                contain_count: 0,
                containment: ExecutionQuiescence::Quiescent,
                transport_margin_ms: 0,
                budgets_seen: Vec::new(),
                clock: None,
                exchange_cost_ms: std::collections::VecDeque::new(),
                tamper: None,
            }
        }

        fn response(
            &self,
            request: &WorkerRequestEnvelope,
            response: WorkerResponse,
        ) -> WorkerResponseEnvelope {
            let mut envelope = WorkerResponseEnvelope {
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
            };
            if let Some(tamper) = self.tamper {
                tamper(&mut envelope);
            }
            envelope
        }
    }

    impl WorkerEndpoint for FakeEndpoint {
        fn transport_margin_ms(&self) -> u64 {
            self.transport_margin_ms
        }

        fn contain(&mut self) -> ExecutionQuiescence {
            self.contain_count += 1;
            self.containment
        }

        fn exchange(
            &mut self,
            request: WorkerRequestEnvelope,
        ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
            self.exchange_count += 1;
            self.budgets_seen.push(request.budget_ms.0);
            if let Some(clock) = &self.clock {
                let cost = self.exchange_cost_ms.pop_front().unwrap_or(0);
                clock.advance(cost);
            }
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

    fn policy_with(list: u64, info: u64, transaction: u64) -> DiscoveryPolicy {
        DiscoveryPolicy {
            list_devices_budget_ms: list,
            get_device_info_budget_ms: info,
            transaction_budget_ms: transaction,
        }
    }

    /// Coordinator over a fake endpoint whose exchanges consume fake time.
    fn timed_coordinator(
        devices: Vec<FakeDevice>,
        policy: DiscoveryPolicy,
        margin_ms: u64,
        exchange_costs_ms: Vec<u64>,
    ) -> Result<
        (DiscoveryCoordinator<FakeEndpoint, FakeClock>, FakeClock),
        Box<dyn std::error::Error>,
    > {
        let clock = FakeClock::default();
        let generation = WorkerGeneration(3);
        let mut endpoint = FakeEndpoint::new(generation, devices);
        endpoint.clock = Some(clock.clone());
        endpoint.transport_margin_ms = margin_ms;
        endpoint.exchange_cost_ms = exchange_costs_ms.into();
        let coordinator =
            DiscoveryCoordinator::with_clock(endpoint, generation, policy, clock.clone())?;
        Ok((coordinator, clock))
    }

    #[test]
    fn policy_rejects_transaction_budget_below_operation_budget() {
        assert_eq!(
            policy_with(2_000, 2_000, 1_999).validate(),
            Err(DiscoveryPolicyError::TransactionBudgetBelowOperationBudget)
        );
        assert_eq!(
            policy_with(2_000, 3_000, 2_999).validate(),
            Err(DiscoveryPolicyError::TransactionBudgetBelowOperationBudget)
        );
        assert!(policy_with(2_000, 2_000, 2_000).validate().is_ok());
    }

    #[test]
    fn later_exchanges_receive_the_remaining_transaction_time_not_a_fresh_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut coordinator, _clock) = timed_coordinator(
            vec![fake_device_with_id(7, 1), fake_device_with_id(8, 1)],
            policy_with(2_000, 2_000, 3_000),
            0,
            // ListDevices takes 1.2 s, the first GetInfo takes 1.0 s.
            vec![1_200, 1_000, 0],
        )?;

        let snapshot = coordinator.refresh()?;
        assert_eq!(snapshot.devices.len(), 2);
        assert_eq!(
            coordinator.endpoint.budgets_seen,
            vec![2_000, 1_800, 800],
            "each exchange gets min(operation budget, what is left of the transaction)"
        );
        Ok(())
    }

    #[test]
    fn transport_margin_is_subtracted_from_the_native_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut coordinator, _clock) = timed_coordinator(
            vec![fake_device(1)],
            policy_with(2_000, 2_000, 2_050),
            100,
            vec![0, 0],
        )?;

        coordinator.refresh()?;
        // 2_050 ms left minus the 100 ms the endpoint adds beyond the native budget.
        assert_eq!(coordinator.endpoint.budgets_seen, vec![1_950, 1_950]);
        Ok(())
    }

    #[test]
    fn transaction_deadline_exhaustion_fails_closed_without_quarantining_the_worker()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut coordinator, _clock) = timed_coordinator(
            vec![fake_device(1)],
            policy_with(2_000, 2_000, 2_000),
            0,
            // ListDevices leaves 10 ms of the 2 s transaction: too little to dispatch GetInfo.
            vec![1_990],
        )?;

        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::TransactionDeadlineExceeded)
        );
        assert_eq!(
            coordinator.endpoint.exchange_count, 1,
            "no exchange may be dispatched once the transaction has run out"
        );
        assert!(
            !coordinator.is_quarantined(),
            "an idle, healthy worker is not at fault for a slow transaction"
        );
        assert_eq!(coordinator.endpoint.contain_count, 0);

        // The next transaction starts fresh and the worker is still usable.
        assert!(coordinator.refresh().is_ok());
        Ok(())
    }

    #[test]
    fn quarantine_asks_the_endpoint_to_contain_the_worker_immediately()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        coordinator.endpoint.force_transport_failure = true;
        assert!(coordinator.refresh().is_err());

        assert!(coordinator.is_quarantined());
        assert_eq!(
            coordinator.endpoint.contain_count, 1,
            "a quarantined worker must be stopped now, not when a replacement asks"
        );
        Ok(())
    }

    #[test]
    fn replace_worker_requires_proof_of_quiescence() -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        coordinator.endpoint.force_transport_failure = true;
        assert!(coordinator.refresh().is_err());
        // The old worker cannot prove it stopped.
        coordinator.endpoint.containment = ExecutionQuiescence::Active;

        assert_eq!(
            coordinator.replace_worker(
                FakeEndpoint::new(WorkerGeneration(4), vec![fake_device(2)]),
                WorkerGeneration(4),
            ),
            Err(DiscoveryError::PreviousWorkerNotContained)
        );
        assert_eq!(coordinator.worker_generation(), WorkerGeneration(3));
        assert!(coordinator.is_quarantined());
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerQuarantined)
        );

        // Once the endpoint can prove it, the same replacement is accepted.
        coordinator.endpoint.containment = ExecutionQuiescence::Quiescent;
        coordinator.replace_worker(
            FakeEndpoint::new(WorkerGeneration(4), vec![fake_device(2)]),
            WorkerGeneration(4),
        )?;
        assert_eq!(coordinator.worker_generation(), WorkerGeneration(4));
        assert_eq!(coordinator.refresh()?.devices.len(), 1);
        Ok(())
    }

    #[test]
    fn contain_worker_retires_a_usable_worker_and_blocks_reuse()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        let handle = coordinator.refresh()?.devices[0].handle;

        assert_eq!(coordinator.contain_worker(), ExecutionQuiescence::Quiescent);
        assert!(coordinator.is_quarantined());
        assert_eq!(coordinator.resolve_handle(handle), None);
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerQuarantined)
        );
        Ok(())
    }

    /// Every protocol violation below must take the worker out of service *and* stop it.
    fn assert_violation_quarantines_and_contains(
        tamper: fn(&mut WorkerResponseEnvelope),
        expected: DiscoveryError,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        coordinator.endpoint.tamper = Some(tamper);

        assert_eq!(coordinator.refresh().err(), Some(expected));
        assert!(coordinator.is_quarantined());
        assert_eq!(
            coordinator.endpoint.contain_count, 1,
            "a violating worker must be stopped, not merely ignored"
        );
        assert_eq!(
            coordinator.refresh().err(),
            Some(DiscoveryError::WorkerQuarantined)
        );
        Ok(())
    }

    #[test]
    fn response_from_another_worker_generation_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_violation_quarantines_and_contains(
            |response| response.worker_generation = WorkerGeneration(99),
            DiscoveryError::ResponseCorrelation,
        )
    }

    #[test]
    fn late_response_to_another_request_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        assert_violation_quarantines_and_contains(
            |response| response.request_id = WorkerRequestId(response.request_id.0 + 41),
            DiscoveryError::ResponseCorrelation,
        )
    }

    #[test]
    fn response_with_another_protocol_version_is_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_violation_quarantines_and_contains(
            |response| response.protocol_version += 1,
            DiscoveryError::ResponseCorrelation,
        )
    }

    #[test]
    fn response_for_another_device_generation_is_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_violation_quarantines_and_contains(
            |response| response.device_generation = Some(DeviceGeneration(77)),
            DiscoveryError::ResponseCorrelation,
        )
    }

    #[test]
    fn response_variant_that_does_not_match_the_request_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_violation_quarantines_and_contains(
            |response| response.response = WorkerResponse::Healthy,
            DiscoveryError::UnexpectedResponse,
        )
    }

    #[test]
    fn old_worker_generation_cannot_regain_authority_after_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        coordinator.endpoint.force_transport_failure = true;
        assert!(coordinator.refresh().is_err());

        // The replacement is generation 4, but whatever answers still speaks as generation 3.
        coordinator.replace_worker(
            FakeEndpoint::new(WorkerGeneration(3), vec![fake_device(1)]),
            WorkerGeneration(4),
        )?;
        assert_eq!(
            coordinator.refresh().err(),
            Some(DiscoveryError::ResponseCorrelation)
        );
        assert!(coordinator.is_quarantined());
        Ok(())
    }

    #[test]
    fn many_devices_cannot_stretch_the_transaction_beyond_its_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let devices = (1..=10).map(|id| fake_device_with_id(id, 1)).collect();
        // Every exchange takes a full second; the transaction allows five.
        let (mut coordinator, clock) = timed_coordinator(
            devices,
            policy_with(2_000, 2_000, 5_000),
            0,
            vec![1_000; 40],
        )?;

        assert_eq!(
            coordinator.refresh().err(),
            Some(DiscoveryError::TransactionDeadlineExceeded)
        );
        assert_eq!(
            coordinator.endpoint.exchange_count, 5,
            "list plus four GetInfo"
        );
        assert!(
            clock.now().as_millis() <= 5_000,
            "the transaction must stop at its budget, took {} ms",
            clock.now().as_millis()
        );
        assert!(!coordinator.is_quarantined());

        // Progress is kept (completed GetInfo results are cached), so repeated transactions
        // converge instead of restarting from scratch.
        let mut attempts = 1;
        let snapshot = loop {
            attempts += 1;
            match coordinator.refresh() {
                Ok(snapshot) => break snapshot,
                Err(DiscoveryError::TransactionDeadlineExceeded) if attempts < 6 => {}
                Err(other) => return Err(format!("unexpected: {other:?}").into()),
            }
        };
        assert_eq!(snapshot.devices.len(), 10);
        assert_eq!(
            attempts, 3,
            "40 devices-worth of work finishes in bounded transactions"
        );
        Ok(())
    }

    #[test]
    fn read_only_response_rejects_mutation_evidence() -> Result<(), Box<dyn std::error::Error>> {
        struct MutationEvidenceEndpoint;

        impl WorkerEndpoint for MutationEvidenceEndpoint {
            fn transport_margin_ms(&self) -> u64 {
                0
            }

            fn contain(&mut self) -> ExecutionQuiescence {
                ExecutionQuiescence::Quiescent
            }

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
