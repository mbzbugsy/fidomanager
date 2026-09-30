from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


discovery_path = Path("crates/fido-service/src/discovery.rs")
text = discovery_path.read_text()

old = '''    #[error("worker returned error {0:?}")]
    Worker(WorkerErrorCode),
    #[error("worker response did not correlate with the request")]
    ResponseCorrelation,
    #[error("worker returned a response variant that does not match the request")]
    UnexpectedResponse,
    #[error("read-only worker response contained mutation evidence")]
    MutationEvidenceOnReadOnly,
    #[error("worker native execution is not proven quiescent")]
    WorkerNotQuiescent,
'''
new = '''    #[error("worker returned error {0:?}")]
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
'''
text = replace_once(text, old, new, "discovery error variants")

old = '''    #[error("authority identifier space is exhausted")]
    IdentifierSpaceExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredDeviceTarget {
'''
new = '''    #[error("authority identifier space is exhausted")]
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
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredDeviceTarget {
'''
text = replace_once(text, old, new, "quarantine classification")

old = '''#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegisteredDevice {
    handle: DeviceHandle,
    worker_device_id: WorkerDeviceId,
    device_generation: fido_core::DeviceGeneration,
}

#[derive(Debug, Default)]
struct DeviceRegistry {
    devices: Vec<RegisteredDevice>,
    next_handle_raw: u128,
}

impl DeviceRegistry {
    fn new() -> Self {
        Self {
            devices: Vec::new(),
            next_handle_raw: 1,
        }
    }

    fn reconcile(
        &mut self,
        discovered: &[WorkerDiscoveredDevice],
    ) -> Result<Vec<(WorkerDiscoveredDevice, DeviceHandle)>, DiscoveryError> {
        let mut next_devices = Vec::with_capacity(discovered.len());
        let mut resolved = Vec::with_capacity(discovered.len());

        for device in discovered {
            let handle = match self.devices.iter().find(|registered| {
                registered.worker_device_id == device.device_id
                    && registered.device_generation == device.device_generation
            }) {
                Some(registered) => registered.handle,
                None => self.mint_handle()?,
            };

            next_devices.push(RegisteredDevice {
                handle,
                worker_device_id: device.device_id,
                device_generation: device.device_generation,
            });
            resolved.push((device.clone(), handle));
        }

        self.devices = next_devices;
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

    fn clear(&mut self) {
        self.devices.clear();
    }

    fn mint_handle(&mut self) -> Result<DeviceHandle, DiscoveryError> {
        let raw = self.next_handle_raw;
        self.next_handle_raw = self
            .next_handle_raw
            .checked_add(1)
            .ok_or(DiscoveryError::IdentifierSpaceExhausted)?;
        Ok(DeviceHandle::from_raw(raw))
    }
}
'''
new = '''#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
'''
text = replace_once(text, old, new, "device registry")

old = '''pub struct DiscoveryCoordinator<E> {
    endpoint: E,
    worker_generation: WorkerGeneration,
    policy: DiscoveryPolicy,
    registry: DeviceRegistry,
'''
new = '''#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
'''
text = replace_once(text, old, new, "worker state struct")

old = '''            endpoint,
            worker_generation,
            policy: policy.validate()?,
'''
new = '''            endpoint,
            worker_generation,
            worker_state: WorkerState::Usable,
            policy: policy.validate()?,
'''
text = replace_once(text, old, new, "worker state init")

old = '''    pub fn refresh(&mut self) -> Result<DeviceListSnapshot, DiscoveryError> {
        let result = self.refresh_inner();
        if result.is_err() {
            // If enumeration cannot complete coherently, old renderer handles are no longer
            // authoritative evidence of current device presence.
            self.registry.clear();
        }
        result
    }
'''
new = '''    pub fn refresh(&mut self) -> Result<DeviceListSnapshot, DiscoveryError> {
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
'''
text = replace_once(text, old, new, "refresh quarantine")

old = '''    pub fn replace_worker(&mut self, endpoint: E, worker_generation: WorkerGeneration) {
        self.endpoint = endpoint;
        self.worker_generation = worker_generation;
        self.registry.clear();
    }
'''
new = '''    /// Replace a quarantined or retired worker with a fresh worker instance.
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
        Ok(())
    }
'''
text = replace_once(text, old, new, "replace worker")

old = '''                WorkerResponse::DeviceInfo { info } => {
                    validate_device_info(&info, device.device_id)?;
                    apply_device_info(&mut snapshot, info);
                }
'''
new = '''                WorkerResponse::DeviceInfo { info } => {
                    if info.device_id != device.device_id {
                        return Err(DiscoveryError::ResponseCorrelation);
                    }

                    if validate_device_info(&info).is_ok() {
                        let discovery_metadata_was_malformed =
                            snapshot.read_status == DeviceReadStatus::Malformed;
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
'''
text = replace_once(text, old, new, "malformed info isolation")

old = '''        envelope
            .validate()
            .map_err(|_| DiscoveryError::UnexpectedResponse)?;
'''
new = '''        envelope
            .validate()
            .map_err(|_| DiscoveryError::InvalidWorkerRequest)?;
'''
text = replace_once(text, old, new, "request validation error")

old = '''        if !optional_text_is_valid(&device.manufacturer) || !optional_text_is_valid(&device.product)
        {
            return Err(DiscoveryError::MalformedDeviceData);
        }
'''
text = replace_once(text, old, "", "manifest metadata isolation")

old = '''fn validate_device_info(
    info: &WorkerDeviceInfo,
    expected_device_id: WorkerDeviceId,
) -> Result<(), DiscoveryError> {
    if info.device_id != expected_device_id
        || info.versions.len() > MAX_DEVICE_STRING_ITEMS
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

    if !strings_are_valid || !options_are_valid {
        return Err(DiscoveryError::MalformedDeviceData);
    }

    Ok(())
}
'''
new = '''fn validate_device_info(info: &WorkerDeviceInfo) -> Result<(), DiscoveryError> {
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
'''
text = replace_once(text, old, new, "device info validation")

old = '''fn text_is_valid(value: &str) -> bool {
    value.len() <= MAX_DEVICE_TEXT_BYTES && !value.chars().any(char::is_control)
}
'''
new = '''fn text_is_valid(value: &str) -> bool {
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
'''
text = replace_once(text, old, new, "unicode hardening")

old = '''fn base_snapshot(device: &WorkerDiscoveredDevice, handle: DeviceHandle) -> DeviceSnapshot {
    DeviceSnapshot {
        handle,
        generation: device.device_generation,
        vendor_id: device.vendor_id,
        product_id: device.product_id,
        manufacturer: device.manufacturer.clone(),
        product: device.product.clone(),
'''
new = '''fn base_snapshot(device: &WorkerDiscoveredDevice, handle: DeviceHandle) -> DeviceSnapshot {
    let manufacturer_is_valid = optional_text_is_valid(&device.manufacturer);
    let product_is_valid = optional_text_is_valid(&device.product);
    let discovery_metadata_is_valid = manufacturer_is_valid && product_is_valid;

    DeviceSnapshot {
        handle,
        generation: device.device_generation,
        vendor_id: device.vendor_id,
        product_id: device.product_id,
        manufacturer: device.manufacturer.clone().filter(|_| manufacturer_is_valid),
        product: device.product.clone().filter(|_| product_is_valid),
'''
text = replace_once(text, old, new, "base snapshot sanitization")

old = '''        read_status: DeviceReadStatus::Ready,
        freshness: ViewFreshness::Incomplete,
    }
}
'''
new = '''        read_status: if discovery_metadata_is_valid {
            DeviceReadStatus::Ready
        } else {
            DeviceReadStatus::Malformed
        },
        freshness: ViewFreshness::Incomplete,
    }
}
'''
text = replace_once(text, old, new, "base snapshot status")

old = '''    snapshot.max_message_size = info.max_message_size;
    snapshot.firmware_version = info.firmware_version;
    snapshot.read_status = DeviceReadStatus::Ready;
    snapshot.freshness = ViewFreshness::Fresh;
}
'''
new = '''    snapshot.max_message_size = info.max_message_size;
    snapshot.firmware_version = info.firmware_version;
}
'''
text = replace_once(text, old, new, "apply device info status")

old = '''    struct FakeEndpoint {
        generation: WorkerGeneration,
        devices: Vec<FakeDevice>,
        force_active_response: bool,
    }
'''
new = '''    struct FakeEndpoint {
        generation: WorkerGeneration,
        devices: Vec<FakeDevice>,
        force_active_response: bool,
        force_transport_failure: bool,
        exchange_count: usize,
    }
'''
text = replace_once(text, old, new, "fake endpoint fields")

old = '''                generation,
                devices,
                force_active_response: false,
            }
'''
new = '''                generation,
                devices,
                force_active_response: false,
                force_transport_failure: false,
                exchange_count: 0,
            }
'''
text = replace_once(text, old, new, "fake endpoint init")

old = '''        fn exchange(
            &mut self,
            request: WorkerRequestEnvelope,
        ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
            let response = match &request.request {
'''
new = '''        fn exchange(
            &mut self,
            request: WorkerRequestEnvelope,
        ) -> Result<WorkerResponseEnvelope, WorkerEndpointError> {
            self.exchange_count += 1;
            if self.force_transport_failure {
                return Err(WorkerEndpointError::TransportFailure);
            }

            let response = match &request.request {
'''
text = replace_once(text, old, new, "fake endpoint exchange")

old = '''    fn fake_device(generation: u64) -> FakeDevice {
        let device_id = WorkerDeviceId(7);
        FakeDevice {
'''
new = '''    fn fake_device(generation: u64) -> FakeDevice {
        fake_device_with_id(7, generation)
    }

    fn fake_device_with_id(device_id: u64, generation: u64) -> FakeDevice {
        let device_id = WorkerDeviceId(device_id);
        FakeDevice {
'''
text = replace_once(text, old, new, "fake device helper")

old = '''        coordinator.endpoint.force_active_response = true;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerNotQuiescent)
        );
        assert_eq!(coordinator.resolve_handle(handle), None);
        Ok(())
    }
'''
new = '''        coordinator.endpoint.force_active_response = true;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::WorkerNotQuiescent)
        );
        assert_eq!(coordinator.resolve_handle(handle), None);

        let exchanges_after_quarantine = coordinator.endpoint.exchange_count;
        coordinator.endpoint.force_active_response = false;
        assert_eq!(coordinator.refresh(), Err(DiscoveryError::WorkerQuarantined));
        assert_eq!(coordinator.endpoint.exchange_count, exchanges_after_quarantine);
        Ok(())
    }

    #[test]
    fn transport_failure_quarantines_worker_until_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        coordinator.endpoint.force_transport_failure = true;
        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::Endpoint(WorkerEndpointError::TransportFailure))
        );

        let exchanges_after_failure = coordinator.endpoint.exchange_count;
        coordinator.endpoint.force_transport_failure = false;
        assert_eq!(coordinator.refresh(), Err(DiscoveryError::WorkerQuarantined));
        assert_eq!(coordinator.endpoint.exchange_count, exchanges_after_failure);

        coordinator.replace_worker(
            FakeEndpoint::new(WorkerGeneration(4), vec![fake_device(2)]),
            WorkerGeneration(4),
        )?;
        assert_eq!(coordinator.refresh()?.devices.len(), 1);
        Ok(())
    }
'''
text = replace_once(text, old, new, "quarantine tests")

old = '''    fn malformed_native_text_is_rejected_before_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut device = fake_device(1);
        device.discovered.product = Some("x".repeat(MAX_DEVICE_TEXT_BYTES + 1));
        let mut coordinator = coordinator(vec![device])?;

        assert_eq!(
            coordinator.refresh(),
            Err(DiscoveryError::MalformedDeviceData)
        );
        Ok(())
    }
'''
new = '''    fn malformed_native_text_is_isolated_to_affected_device()
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
    fn malformed_get_info_does_not_hide_other_devices()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn identity_generation_regression_quarantines_worker()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(2)])?;
        coordinator.refresh()?;
        coordinator.endpoint.devices = vec![fake_device(1)];

        assert_eq!(coordinator.refresh(), Err(DiscoveryError::DeviceIdentityViolation));
        assert_eq!(coordinator.refresh(), Err(DiscoveryError::WorkerQuarantined));
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

        assert_eq!(coordinator.refresh(), Err(DiscoveryError::DeviceIdentityViolation));
        assert_eq!(coordinator.refresh(), Err(DiscoveryError::WorkerQuarantined));
        Ok(())
    }

    #[test]
    fn same_identity_generation_with_changed_vid_pid_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut coordinator = coordinator(vec![fake_device(1)])?;
        coordinator.refresh()?;
        coordinator.endpoint.devices[0].discovered.product_id ^= 1;

        assert_eq!(coordinator.refresh(), Err(DiscoveryError::DeviceIdentityViolation));
        assert_eq!(coordinator.refresh(), Err(DiscoveryError::WorkerQuarantined));
        Ok(())
    }

    #[test]
    fn replacement_worker_generation_must_increase()
    -> Result<(), Box<dyn std::error::Error>> {
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
'''
text = replace_once(text, old, new, "malformed and identity tests")

discovery_path.write_text(text)

protocol_path = Path("crates/fido-worker-protocol/src/lib.rs")
protocol = protocol_path.read_text()

old = '''pub enum WorkerRequestValidationError {
    ProtocolMismatch,
    OperationClassMismatch,
    InvalidDeviceGeneration,
    ZeroExecutionBudget,
}
'''
new = '''pub enum WorkerRequestValidationError {
    ProtocolMismatch,
    OperationClassMismatch,
    InvalidDeviceGeneration,
    InvalidCancellationTarget,
    ZeroExecutionBudget,
}
'''
protocol = replace_once(protocol, old, new, "cancel validation enum")

old = '''        if !generation_is_valid {
            return Err(WorkerRequestValidationError::InvalidDeviceGeneration);
        }

        Ok(())
'''
new = '''        if !generation_is_valid {
            return Err(WorkerRequestValidationError::InvalidDeviceGeneration);
        }

        if let WorkerRequest::Cancel {
            target_request_id,
            target_cancellation_id,
        } = &self.request
        {
            if target_request_id.0 == 0
                || target_cancellation_id.0 == 0
                || *target_request_id == self.request_id
                || *target_cancellation_id == self.cancellation_id
            {
                return Err(WorkerRequestValidationError::InvalidCancellationTarget);
            }
        }

        Ok(())
'''
protocol = replace_once(protocol, old, new, "cancel validation")

old = '''/// Minimal discovery record returned before a device is opened for GetInfo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
'''
new = '''/// Minimal discovery record returned before a device is opened for GetInfo.
///
/// Within one `WorkerGeneration`, the worker MUST strictly increase `device_generation` whenever a
/// `WorkerDeviceId` is rebound/reopened after observed absence or represents a different device
/// incarnation. The service deliberately treats regression or reuse-after-absence as a protocol
/// violation and quarantines that worker generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
'''
protocol = replace_once(protocol, old, new, "generation contract docs")

old = '''    #[test]
    fn operation_class_is_derived_from_request() {
        let mut envelope = request_envelope(WorkerRequest::ListDevices, None);
        envelope.operation_class = WorkerOperationClass::Mutation;
        assert_eq!(
            envelope.validate(),
            Err(WorkerRequestValidationError::OperationClassMismatch)
        );
    }
'''
new = '''    #[test]
    fn operation_class_is_derived_from_request() {
        let mut envelope = request_envelope(WorkerRequest::ListDevices, None);
        envelope.operation_class = WorkerOperationClass::Mutation;
        assert_eq!(
            envelope.validate(),
            Err(WorkerRequestValidationError::OperationClassMismatch)
        );
    }

    #[test]
    fn cancel_cannot_target_itself_or_zero_identifiers() {
        let self_target = request_envelope(
            WorkerRequest::Cancel {
                target_request_id: WorkerRequestId(7),
                target_cancellation_id: CancellationId(11),
            },
            None,
        );
        assert_eq!(
            self_target.validate(),
            Err(WorkerRequestValidationError::InvalidCancellationTarget)
        );

        let zero_target = request_envelope(
            WorkerRequest::Cancel {
                target_request_id: WorkerRequestId(0),
                target_cancellation_id: CancellationId(9),
            },
            None,
        );
        assert_eq!(
            zero_target.validate(),
            Err(WorkerRequestValidationError::InvalidCancellationTarget)
        );
    }
'''
protocol = replace_once(protocol, old, new, "cancel validation test")

protocol_path.write_text(protocol)
