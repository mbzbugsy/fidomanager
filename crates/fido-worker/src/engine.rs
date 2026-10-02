//! Worker engine: validates requests and runs them against a native discovery backend.
//!
//! The engine owns native device keys and device-generation tracking. It has no notion of where it
//! runs: the child-process runtime drives it today, and the same engine can sit behind an
//! elevated broker later. Native paths and libfido2 objects never leave this side of the boundary.

use fido_core::{Aaguid, DeviceGeneration, ExecutionQuiescence};
use fido_libfido2::{
    NativeDeadline, NativeDeviceInfo, NativeDeviceKey, NativeDiscoveredDevice,
    NativeDiscoveryBackend, NativeError, NativeErrorKind,
};
use fido_worker_protocol::{
    MAX_DISCOVERED_DEVICES, WORKER_PROTOCOL_VERSION, WorkerDeviceId, WorkerDeviceInfo,
    WorkerDeviceOption, WorkerErrorCode, WorkerGeneration, WorkerRequest, WorkerRequestEnvelope,
    WorkerResponse, WorkerResponseEnvelope, WorkerResponseEvidence,
};
use std::time::Duration;

#[derive(Debug, Clone)]
struct WorkerSlot {
    device_id: WorkerDeviceId,
    generation: DeviceGeneration,
    key: NativeDeviceKey,
    vendor_id: u16,
    product_id: u16,
    manufacturer: Option<String>,
    product: Option<String>,
    present: bool,
}

pub struct WorkerEngine<B> {
    backend: B,
    generation: WorkerGeneration,
    slots: Vec<WorkerSlot>,
    next_device_id: u64,
}

impl<B: NativeDiscoveryBackend> WorkerEngine<B> {
    pub fn new(backend: B, generation: WorkerGeneration) -> Self {
        Self {
            backend,
            generation,
            slots: Vec::new(),
            next_device_id: 1,
        }
    }

    /// Handles one request. The request's budget becomes **one** deadline, started here, that is
    /// shared by every native sub-call the request makes.
    pub fn handle(&mut self, request: WorkerRequestEnvelope) -> WorkerResponseEnvelope {
        if request.validate().is_err() || request.worker_generation != self.generation {
            return self.response(
                &request,
                WorkerResponse::Error {
                    code: WorkerErrorCode::ProtocolMismatch,
                },
            );
        }

        let deadline = NativeDeadline::after(Duration::from_millis(request.budget_ms.0));
        let response = match &request.request {
            WorkerRequest::HealthCheck => WorkerResponse::Healthy,
            // The process worker implements cancellation by termination: the service kills the
            // process at its deadline. A `Cancel` only reaches here while the worker is idle.
            WorkerRequest::Cancel { .. } => WorkerResponse::CancellationAccepted,
            WorkerRequest::ListDevices => match self.list_devices(deadline) {
                Ok(devices) => WorkerResponse::DevicesListed { devices },
                Err(code) => WorkerResponse::Error { code },
            },
            WorkerRequest::GetDeviceInfo { device_id } => {
                let Some(device_generation) = request.device_generation else {
                    return self.response(
                        &request,
                        WorkerResponse::Error {
                            code: WorkerErrorCode::ProtocolMismatch,
                        },
                    );
                };
                match self.get_device_info(*device_id, device_generation, deadline) {
                    Ok(info) => WorkerResponse::DeviceInfo { info },
                    Err(code) => WorkerResponse::Error { code },
                }
            }
        };

        self.response(&request, response)
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
                execution_quiescence: ExecutionQuiescence::Quiescent,
                mutation_outcome: None,
            },
            response,
        }
    }

    fn list_devices(
        &mut self,
        deadline: NativeDeadline,
    ) -> Result<Vec<fido_worker_protocol::WorkerDiscoveredDevice>, WorkerErrorCode> {
        let discovered = self
            .backend
            .manifest(deadline)
            .map_err(|error| map_native_error(&error, NativeOperation::Manifest))?;
        if discovered.len() > MAX_DISCOVERED_DEVICES {
            return Err(WorkerErrorCode::MalformedDeviceData);
        }
        if has_duplicate_native_keys(&discovered) {
            return Err(WorkerErrorCode::InternalFailure);
        }

        let next_slots = self.reconcile_manifest(discovered)?;
        let output = next_slots
            .iter()
            .filter(|slot| slot.present)
            .map(|slot| fido_worker_protocol::WorkerDiscoveredDevice {
                device_id: slot.device_id,
                device_generation: slot.generation,
                vendor_id: slot.vendor_id,
                product_id: slot.product_id,
                manufacturer: slot.manufacturer.clone(),
                product: slot.product.clone(),
            })
            .collect();
        self.slots = next_slots;
        Ok(output)
    }

    fn reconcile_manifest(
        &mut self,
        discovered: Vec<NativeDiscoveredDevice>,
    ) -> Result<Vec<WorkerSlot>, WorkerErrorCode> {
        let previous = self.slots.clone();
        let mut next = previous
            .iter()
            .cloned()
            .map(|mut slot| {
                slot.present = false;
                slot
            })
            .collect::<Vec<_>>();
        let mut next_device_id = self.next_device_id;

        for device in discovered {
            if let Some(index) = previous.iter().position(|slot| slot.key == device.key) {
                let prior = &previous[index];
                let slot = &mut next[index];
                let identity_changed =
                    prior.vendor_id != device.vendor_id || prior.product_id != device.product_id;
                if !prior.present || identity_changed {
                    slot.generation = DeviceGeneration(
                        slot.generation
                            .0
                            .checked_add(1)
                            .ok_or(WorkerErrorCode::InternalFailure)?,
                    );
                }
                slot.vendor_id = device.vendor_id;
                slot.product_id = device.product_id;
                slot.manufacturer = device.manufacturer;
                slot.product = device.product;
                slot.present = true;
            } else {
                let device_id = WorkerDeviceId(next_device_id);
                next_device_id = next_device_id
                    .checked_add(1)
                    .ok_or(WorkerErrorCode::InternalFailure)?;
                next.push(WorkerSlot {
                    device_id,
                    generation: DeviceGeneration(1),
                    key: device.key,
                    vendor_id: device.vendor_id,
                    product_id: device.product_id,
                    manufacturer: device.manufacturer,
                    product: device.product,
                    present: true,
                });
            }
        }

        self.next_device_id = next_device_id;
        Ok(next)
    }

    fn get_device_info(
        &mut self,
        device_id: WorkerDeviceId,
        device_generation: DeviceGeneration,
        deadline: NativeDeadline,
    ) -> Result<WorkerDeviceInfo, WorkerErrorCode> {
        let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.device_id == device_id)
        else {
            return Err(WorkerErrorCode::DeviceAbsent);
        };
        if !self.slots[index].present || self.slots[index].generation != device_generation {
            return Err(WorkerErrorCode::DeviceAbsent);
        }

        let key = self.slots[index].key.clone();
        match self.backend.get_info(&key, deadline) {
            Ok(info) => Ok(to_worker_device_info(device_id, info)),
            Err(error) => {
                if error.kind() == NativeErrorKind::Absent {
                    // Treat a mid-refresh disappearance as observed absence so a same-path replug
                    // must advance generation on the next manifest.
                    self.slots[index].present = false;
                }
                Err(map_native_error(&error, NativeOperation::GetInfo))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum NativeOperation {
    Manifest,
    GetInfo,
}

fn map_native_error(error: &NativeError, operation: NativeOperation) -> WorkerErrorCode {
    match error.kind() {
        NativeErrorKind::Busy => WorkerErrorCode::DeviceBusy,
        NativeErrorKind::AccessDenied => WorkerErrorCode::AccessDenied,
        NativeErrorKind::TimedOut => WorkerErrorCode::DeadlineExpired,
        NativeErrorKind::Unsupported => WorkerErrorCode::UnsupportedDevice,
        NativeErrorKind::Absent => WorkerErrorCode::DeviceAbsent,
        NativeErrorKind::Malformed => WorkerErrorCode::MalformedDeviceData,
        NativeErrorKind::Unavailable => match operation {
            NativeOperation::Manifest => WorkerErrorCode::WorkerUnavailable,
            NativeOperation::GetInfo => WorkerErrorCode::DeviceAbsent,
        },
        NativeErrorKind::Internal => WorkerErrorCode::InternalFailure,
    }
}

fn has_duplicate_native_keys(devices: &[NativeDiscoveredDevice]) -> bool {
    devices.iter().enumerate().any(|(index, device)| {
        devices[index + 1..]
            .iter()
            .any(|candidate| candidate.key == device.key)
    })
}

fn to_worker_device_info(device_id: WorkerDeviceId, info: NativeDeviceInfo) -> WorkerDeviceInfo {
    WorkerDeviceInfo {
        device_id,
        aaguid: info.aaguid.map(Aaguid::from_bytes),
        versions: info.versions,
        extensions: info.extensions,
        transports: info.transports,
        options: info
            .options
            .into_iter()
            .map(|option| WorkerDeviceOption {
                name: option.name,
                enabled: option.enabled,
            })
            .collect(),
        max_message_size: info.max_message_size,
        firmware_version: info.firmware_version,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use fido_libfido2::NativeDeviceOption;
    use fido_worker_protocol::{CancellationId, RequestBudgetMs, WorkerRequestId};

    use super::*;

    struct ScriptedBackend {
        manifests: VecDeque<Result<Vec<NativeDiscoveredDevice>, NativeError>>,
        infos: VecDeque<Result<NativeDeviceInfo, NativeError>>,
    }

    impl NativeDiscoveryBackend for ScriptedBackend {
        fn manifest(
            &mut self,
            _deadline: NativeDeadline,
        ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
            self.manifests.pop_front().unwrap_or_else(|| Ok(Vec::new()))
        }

        fn get_info(
            &mut self,
            _key: &NativeDeviceKey,
            _deadline: NativeDeadline,
        ) -> Result<NativeDeviceInfo, NativeError> {
            self.infos.pop_front().unwrap_or_else(|| Ok(native_info()))
        }
    }

    fn key(value: u8) -> Result<NativeDeviceKey, NativeError> {
        NativeDeviceKey::from_bytes(vec![value])
    }

    fn native_device(value: u8) -> Result<NativeDiscoveredDevice, NativeError> {
        Ok(NativeDiscoveredDevice {
            key: key(value)?,
            vendor_id: 0x1234,
            product_id: 0x5678,
            manufacturer: Some("Example".to_owned()),
            product: Some("Authenticator".to_owned()),
        })
    }

    fn native_info() -> NativeDeviceInfo {
        NativeDeviceInfo {
            aaguid: Some([0x11; 16]),
            versions: vec!["FIDO_2_1".to_owned()],
            extensions: vec!["credProtect".to_owned()],
            transports: vec!["usb".to_owned()],
            options: vec![NativeDeviceOption {
                name: "rk".to_owned(),
                enabled: true,
            }],
            max_message_size: Some(1_200),
            firmware_version: Some(42),
        }
    }

    fn request(
        generation: WorkerGeneration,
        request_id: u64,
        request: WorkerRequest,
        device_generation: Option<DeviceGeneration>,
    ) -> WorkerRequestEnvelope {
        WorkerRequestEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            request_id: WorkerRequestId(request_id),
            cancellation_id: CancellationId(request_id + 100),
            operation_class: request.operation_class(),
            worker_generation: generation,
            device_generation,
            budget_ms: RequestBudgetMs(100),
            request,
        }
    }

    fn listed_device(
        response: WorkerResponseEnvelope,
    ) -> Option<fido_worker_protocol::WorkerDiscoveredDevice> {
        match response.response {
            WorkerResponse::DevicesListed { mut devices } if devices.len() == 1 => devices.pop(),
            _ => None,
        }
    }

    #[test]
    fn observed_absence_then_same_native_key_advances_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(7);
        let device = native_device(1)?;
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![device.clone()]), Ok(Vec::new()), Ok(vec![device])]),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);

        let first =
            listed_device(engine.handle(request(generation, 1, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("first device missing"))?;
        assert!(
            listed_device(engine.handle(request(generation, 2, WorkerRequest::ListDevices, None,)))
                .is_none()
        );
        let replugged =
            listed_device(engine.handle(request(generation, 3, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("replugged device missing"))?;

        assert_eq!(first.device_id, replugged.device_id);
        assert_eq!(first.device_generation, DeviceGeneration(1));
        assert_eq!(replugged.device_generation, DeviceGeneration(2));
        Ok(())
    }

    #[test]
    fn get_info_absence_forces_generation_bump_on_next_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(3);
        let device = native_device(2)?;
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![device.clone()]), Ok(vec![device])]),
            infos: VecDeque::from([Err(NativeError::new(NativeErrorKind::Absent, None))]),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let first =
            listed_device(engine.handle(request(generation, 1, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("first device missing"))?;

        let info_response = engine.handle(request(
            generation,
            2,
            WorkerRequest::GetDeviceInfo {
                device_id: first.device_id,
            },
            Some(first.device_generation),
        ));
        assert!(matches!(
            info_response.response,
            WorkerResponse::Error {
                code: WorkerErrorCode::DeviceAbsent
            }
        ));

        let second =
            listed_device(engine.handle(request(generation, 3, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("second device missing"))?;
        assert_eq!(second.device_id, first.device_id);
        assert_eq!(second.device_generation, DeviceGeneration(2));
        Ok(())
    }

    #[test]
    fn changed_vid_pid_advances_generation_without_retargeting_same_incarnation()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(4);
        let first_device = native_device(3)?;
        let mut changed = first_device.clone();
        changed.product_id = 0x9999;
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![first_device]), Ok(vec![changed])]),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let first =
            listed_device(engine.handle(request(generation, 1, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("first device missing"))?;
        let second =
            listed_device(engine.handle(request(generation, 2, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("second device missing"))?;
        assert_eq!(first.device_id, second.device_id);
        assert_eq!(second.device_generation, DeviceGeneration(2));
        Ok(())
    }

    #[test]
    fn stale_get_info_generation_is_rejected_before_native_call()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(5);
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![native_device(4)?])]),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let listed =
            listed_device(engine.handle(request(generation, 1, WorkerRequest::ListDevices, None)))
                .ok_or_else(|| std::io::Error::other("device missing"))?;
        let response = engine.handle(request(
            generation,
            2,
            WorkerRequest::GetDeviceInfo {
                device_id: listed.device_id,
            },
            Some(DeviceGeneration(999)),
        ));
        assert!(matches!(
            response.response,
            WorkerResponse::Error {
                code: WorkerErrorCode::DeviceAbsent
            }
        ));
        Ok(())
    }

    #[test]
    fn responses_report_quiescence_only_after_the_native_call_returned()
    -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(9);
        let backend = ScriptedBackend {
            manifests: VecDeque::from([Ok(vec![native_device(5)?])]),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let response = engine.handle(request(generation, 1, WorkerRequest::ListDevices, None));
        assert!(matches!(
            response.response,
            WorkerResponse::DevicesListed { ref devices } if devices.len() == 1
        ));
        assert_eq!(
            response.evidence.execution_quiescence,
            ExecutionQuiescence::Quiescent
        );
        Ok(())
    }

    /// Records the deadline each native call receives.
    #[derive(Default)]
    struct DeadlineRecorder {
        manifest_remaining: Option<Duration>,
        info_remaining: Option<Duration>,
    }

    impl NativeDiscoveryBackend for DeadlineRecorder {
        fn manifest(
            &mut self,
            deadline: NativeDeadline,
        ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
            self.manifest_remaining = Some(deadline.remaining());
            Ok(vec![NativeDiscoveredDevice {
                key: NativeDeviceKey::from_bytes(vec![1])?,
                vendor_id: 1,
                product_id: 2,
                manufacturer: None,
                product: None,
            }])
        }

        fn get_info(
            &mut self,
            _key: &NativeDeviceKey,
            deadline: NativeDeadline,
        ) -> Result<NativeDeviceInfo, NativeError> {
            self.info_remaining = Some(deadline.remaining());
            Ok(native_info())
        }
    }

    #[test]
    fn request_budget_becomes_the_native_deadline() -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(2);
        let mut engine = WorkerEngine::new(DeadlineRecorder::default(), generation);

        let mut list = request(generation, 1, WorkerRequest::ListDevices, None);
        list.budget_ms = RequestBudgetMs(5_000);
        let listed = listed_device(engine.handle(list))
            .ok_or_else(|| std::io::Error::other("device missing"))?;

        let mut info = request(
            generation,
            2,
            WorkerRequest::GetDeviceInfo {
                device_id: listed.device_id,
            },
            Some(listed.device_generation),
        );
        info.budget_ms = RequestBudgetMs(700);
        engine.handle(info);

        let manifest_remaining = engine
            .backend
            .manifest_remaining
            .ok_or_else(|| std::io::Error::other("manifest not called"))?;
        let info_remaining = engine
            .backend
            .info_remaining
            .ok_or_else(|| std::io::Error::other("get_info not called"))?;

        // The native call sees (almost) exactly the request budget: not a larger value, and not
        // a budget carried over from a previous request.
        assert!(manifest_remaining <= Duration::from_millis(5_000));
        assert!(manifest_remaining > Duration::from_millis(4_000));
        assert!(info_remaining <= Duration::from_millis(700));
        assert!(info_remaining > Duration::from_millis(200));
        Ok(())
    }

    #[test]
    fn worker_generation_mismatch_is_protocol_error() -> Result<(), Box<dyn std::error::Error>> {
        let generation = WorkerGeneration(10);
        let backend = ScriptedBackend {
            manifests: VecDeque::new(),
            infos: VecDeque::new(),
        };
        let mut engine = WorkerEngine::new(backend, generation);
        let response = engine.handle(request(
            WorkerGeneration(11),
            1,
            WorkerRequest::ListDevices,
            None,
        ));
        assert_eq!(response.worker_generation, generation);
        assert!(matches!(
            response.response,
            WorkerResponse::Error {
                code: WorkerErrorCode::ProtocolMismatch
            }
        ));
        Ok(())
    }
}
