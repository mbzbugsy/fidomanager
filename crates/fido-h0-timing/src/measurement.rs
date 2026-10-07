//! The Option A pre-send pipeline, measured end to end and stopped at the would-be dispatch point.
//!
//! The pipeline is generic over its device, notification, durability and executor-stub seams so
//! the exact ordering and abort rules are tested deterministically without hardware. The macOS
//! implementations live in `crate::macos`; none of the seams has an operation that can change
//! authenticator state, because the only device operations that exist are discovery, open,
//! GetInfo and close.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::sample::{AbortReason, Components, DeviceLabel, HardwareSample, SampleOutcome};

/// Manifest entry for the single eligible candidate. Holds no native path: the opaque `token`
/// stays inside the device implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestLabel {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: String,
    pub product: String,
}

#[derive(Debug)]
pub struct Manifest<T> {
    pub count: usize,
    /// Present iff `count == 1`.
    pub single: Option<(ManifestLabel, T)>,
}

/// Model-level GetInfo facts compared on the timed path, mirroring the mismatch-only safety
/// snapshot of ADR-011. Not identity, not authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoSnapshot {
    pub aaguid: String,
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub options: Vec<(String, bool)>,
    pub firmware_version: Option<u64>,
    pub max_msg_size: u64,
    pub transports_for_reset: Vec<String>,
    pub long_touch_for_reset: bool,
}

/// Read-only device seam: discovery, open, GetInfo, close. Nothing else exists on purpose.
pub trait ReadOnlyDevice {
    type Token;
    type Session;
    fn manifest(&mut self) -> Result<Manifest<Self::Token>, i32>;
    fn open(&mut self, token: &Self::Token) -> Result<Self::Session, i32>;
    fn get_info(&mut self, session: &mut Self::Session) -> Result<InfoSnapshot, i32>;
    fn close(&mut self, session: Self::Session);
}

/// OS-level insertion notifications for eligible (FIDO usage page) HID services.
pub trait InsertionWatch {
    /// Forget events seen so far; later arrivals belong to the next sample.
    fn arm(&mut self);
    /// Earliest arrival timestamp since `arm`, waiting at most `wait` for one to be delivered.
    fn arrival_since_arm(&mut self, wait: Duration) -> Option<Instant>;
}

/// Scratch journal written with the production durability primitive.
pub trait ScratchDurability {
    fn write_pending(&mut self) -> std::io::Result<()>;
    /// Serialized DispatchCapable record; built inside T4 like the production `persist` does.
    fn dispatch_capable_bytes(&self) -> Vec<u8>;
    fn replace(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    fn write_resolved(&mut self) -> std::io::Result<()>;
}

/// Executor stub: returns when a would-be dispatch frame has been received by a thread that owns
/// no device. The returned instant is the "ready to send" point.
pub trait WouldDispatch {
    fn deliver(&mut self, frame: &[u8]) -> std::io::Result<Instant>;
}

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub insertion_timeout: Duration,
    /// Pause between empty manifest polls. Small, so T1 approximates the platform lower bound;
    /// a production polling interval is accounted for separately by the decision rule.
    pub poll_pause: Duration,
    /// How long to wait, after the sample, for a late-delivered insertion notification.
    pub notification_grace: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            insertion_timeout: Duration::from_secs(120),
            poll_pause: Duration::from_millis(1),
            notification_grace: Duration::from_secs(1),
        }
    }
}

fn micros(later: Instant, earlier: Instant) -> i64 {
    match later.checked_duration_since(earlier) {
        Some(d) => i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
        None => -i64::try_from(earlier.duration_since(later).as_micros()).unwrap_or(i64::MAX),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// First differing comparable field, if any. Fields absent on both sides compare equal.
pub fn snapshot_mismatch(
    baseline: &InfoSnapshot,
    candidate: &InfoSnapshot,
) -> Option<&'static str> {
    if baseline.aaguid != candidate.aaguid {
        return Some("aaguid");
    }
    if baseline.versions != candidate.versions {
        return Some("versions");
    }
    if baseline.extensions != candidate.extensions {
        return Some("extensions");
    }
    if baseline.firmware_version != candidate.firmware_version {
        return Some("firmware_version");
    }
    if baseline.max_msg_size != candidate.max_msg_size {
        return Some("max_msg_size");
    }
    if baseline.transports_for_reset != candidate.transports_for_reset {
        return Some("transports_for_reset");
    }
    if baseline.long_touch_for_reset != candidate.long_touch_for_reset {
        return Some("long_touch_for_reset");
    }
    // `clientPin` and credential counts are option values the same key keeps across a replug, so
    // the whole option map is compared; a mismatch aborts like in the production design.
    if baseline.options != candidate.options {
        return Some("options");
    }
    None
}

pub struct Baseline {
    pub manifest: ManifestLabel,
    pub info: InfoSnapshot,
}

/// Measures one Option A pass. The caller has already observed zero eligible devices, armed the
/// watch and written the scratch `Pending` record (all untimed, as in production where they happen
/// before the unplug). Returns the sample; the device session is always closed.
#[allow(clippy::too_many_arguments)]
pub fn measure_once<D, W, J, X>(
    index: u32,
    device: &mut D,
    watch: &mut W,
    journal: &mut J,
    executor: &mut X,
    baseline: &mut Option<Baseline>,
    timing: Timing,
) -> HardwareSample
where
    D: ReadOnlyDevice,
    W: InsertionWatch,
    J: ScratchDurability,
    X: WouldDispatch,
{
    let mut sample = HardwareSample {
        format: crate::FORMAT.into(),
        index,
        recorded_unix_secs: unix_now(),
        device: None,
        manifest_polls: 0,
        manifest_call_us: None,
        outcome: SampleOutcome::Aborted {
            reason: AbortReason::InsertionTimeout,
        },
    };
    let abort = |mut sample: HardwareSample, reason| {
        sample.outcome = SampleOutcome::Aborted { reason };
        sample
    };

    // Discovery: poll the manifest until exactly one candidate (or a cardinality violation).
    let deadline = Instant::now() + timing.insertion_timeout;
    let (label, token, t_manifest) = loop {
        let before = Instant::now();
        let manifest = match device.manifest() {
            Ok(manifest) => manifest,
            Err(code) => return abort(sample, AbortReason::DiscoveryFailed { code }),
        };
        let after = Instant::now();
        sample.manifest_polls = sample.manifest_polls.saturating_add(1);
        match (manifest.count, manifest.single) {
            (0, _) => {}
            (1, Some((label, token))) => {
                sample.manifest_call_us = Some(micros(after, before));
                break (label, token, after);
            }
            (count, _) => return abort(sample, AbortReason::MultipleDevices { count }),
        }
        if after >= deadline {
            return abort(sample, AbortReason::InsertionTimeout);
        }
        std::thread::sleep(timing.poll_pause);
    };

    // Open (CTAPHID INIT + GetInfo inside libfido2), then the explicit GetInfo.
    let mut session = match device.open(&token) {
        Ok(session) => session,
        Err(code) => return abort(sample, AbortReason::OpenFailed { code }),
    };
    let t_open = Instant::now();
    let info = match device.get_info(&mut session) {
        Ok(info) => info,
        Err(code) => {
            device.close(session);
            return abort(sample, AbortReason::GetInfoFailed { code });
        }
    };
    let t_info = Instant::now();

    // Validation: mismatch-only comparison and record serialization, both on the timed path.
    let mismatch = match baseline {
        Some(base) if base.manifest.vendor_id != label.vendor_id => Some("vendor_id"),
        Some(base) if base.manifest.product_id != label.product_id => Some("product_id"),
        Some(base) if base.manifest.product != label.product => Some("product"),
        Some(base) => snapshot_mismatch(&base.info, &info),
        None => None,
    };
    let record = journal.dispatch_capable_bytes();
    let t_validated = Instant::now();
    sample.device = Some(DeviceLabel {
        vendor_id: label.vendor_id,
        product_id: label.product_id,
        manufacturer: label.manufacturer.clone(),
        product: label.product.clone(),
        aaguid: info.aaguid.clone(),
        firmware_version: info.firmware_version,
    });
    if let Some(field) = mismatch {
        device.close(session);
        return abort(
            sample,
            AbortReason::SnapshotMismatch {
                field: field.into(),
            },
        );
    }
    if baseline.is_none() {
        *baseline = Some(Baseline {
            manifest: label,
            info,
        });
    }

    // Durable DispatchCapable, with the production primitive.
    if journal.replace(&record).is_err() {
        device.close(session);
        return abort(sample, AbortReason::DurabilityFailed);
    }
    let t_synced = Instant::now();

    // Would-be dispatch: a marker frame reaches a thread that owns no device, and is discarded.
    let frame = format!(
        "{{\"format\":\"{}\",\"kind\":\"h0_would_dispatch_marker\",\"sample\":{index}}}",
        crate::FORMAT
    );
    let t_ready = match executor.deliver(frame.as_bytes()) {
        Ok(at) => at,
        Err(_) => {
            device.close(session);
            return abort(sample, AbortReason::WouldDispatchStubFailed);
        }
    };
    device.close(session);
    // Untimed housekeeping: production would resolve after the outcome; H0 resolves at once.
    let _ = journal.write_resolved();

    let Some(t_insertion) = watch.arrival_since_arm(timing.notification_grace) else {
        return abort(sample, AbortReason::NoInsertionNotification);
    };
    let components = Components {
        t1_insertion_to_manifest_us: micros(t_manifest, t_insertion),
        t2_manifest_to_open_us: micros(t_open, t_manifest),
        t3_open_to_get_info_us: micros(t_info, t_open),
        t4_validation_us: micros(t_validated, t_info),
        t5_durable_replace_us: micros(t_synced, t_validated),
        t6_sync_to_would_dispatch_us: micros(t_ready, t_synced),
    };
    sample.outcome = SampleOutcome::Measured {
        components,
        total_us: components.total_us(),
    };
    sample
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn label() -> ManifestLabel {
        ManifestLabel {
            vendor_id: 0x1050,
            product_id: 0x0407,
            manufacturer: "Vendor".into(),
            product: "Model".into(),
        }
    }

    fn info() -> InfoSnapshot {
        InfoSnapshot {
            aaguid: "00".repeat(16),
            versions: vec!["FIDO_2_0".into()],
            extensions: vec![],
            options: vec![("clientPin".into(), true)],
            firmware_version: Some(1),
            max_msg_size: 1200,
            transports_for_reset: vec![],
            long_touch_for_reset: false,
        }
    }

    #[derive(Default)]
    struct FakeDevice {
        manifests: VecDeque<usize>,
        info: Option<InfoSnapshot>,
        open_error: Option<i32>,
        opened: u32,
        closed: u32,
        log: Vec<&'static str>,
    }

    impl ReadOnlyDevice for FakeDevice {
        type Token = ();
        type Session = ();
        fn manifest(&mut self) -> Result<Manifest<()>, i32> {
            self.log.push("manifest");
            let count = self.manifests.pop_front().unwrap_or(0);
            Ok(Manifest {
                count,
                single: (count == 1).then(|| (label(), ())),
            })
        }
        fn open(&mut self, _: &()) -> Result<(), i32> {
            self.log.push("open");
            if let Some(code) = self.open_error {
                return Err(code);
            }
            self.opened += 1;
            Ok(())
        }
        fn get_info(&mut self, _: &mut ()) -> Result<InfoSnapshot, i32> {
            self.log.push("get_info");
            self.info.clone().ok_or(-1)
        }
        fn close(&mut self, _: ()) {
            self.log.push("close");
            self.closed += 1;
        }
    }

    struct FakeWatch(Option<Instant>);
    impl InsertionWatch for FakeWatch {
        fn arm(&mut self) {}
        fn arrival_since_arm(&mut self, _: Duration) -> Option<Instant> {
            self.0
        }
    }

    #[derive(Default)]
    struct FakeJournal {
        writes: Vec<String>,
        fail_replace: bool,
    }
    impl ScratchDurability for FakeJournal {
        fn write_pending(&mut self) -> std::io::Result<()> {
            self.writes.push("pending".into());
            Ok(())
        }
        fn dispatch_capable_bytes(&self) -> Vec<u8> {
            b"dispatch_capable".to_vec()
        }
        fn replace(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            if self.fail_replace {
                return Err(std::io::Error::other("injected"));
            }
            self.writes
                .push(String::from_utf8_lossy(bytes).into_owned());
            Ok(())
        }
        fn write_resolved(&mut self) -> std::io::Result<()> {
            self.writes.push("resolved".into());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeExecutor(Vec<Vec<u8>>);
    impl WouldDispatch for FakeExecutor {
        fn deliver(&mut self, frame: &[u8]) -> std::io::Result<Instant> {
            self.0.push(frame.to_vec());
            Ok(Instant::now())
        }
    }

    fn timing() -> Timing {
        Timing {
            insertion_timeout: Duration::from_millis(200),
            poll_pause: Duration::from_millis(1),
            notification_grace: Duration::ZERO,
        }
    }

    fn run(
        device: &mut FakeDevice,
        journal: &mut FakeJournal,
        executor: &mut FakeExecutor,
        baseline: &mut Option<Baseline>,
        insertion: Option<Instant>,
    ) -> HardwareSample {
        let mut watch = FakeWatch(insertion);
        measure_once(1, device, &mut watch, journal, executor, baseline, timing())
    }

    #[test]
    fn happy_path_measures_all_components_in_order() {
        let inserted = Instant::now();
        let mut device = FakeDevice {
            manifests: VecDeque::from([0, 0, 1]),
            info: Some(info()),
            ..FakeDevice::default()
        };
        let (mut journal, mut executor, mut baseline) = Default::default();
        let sample = run(
            &mut device,
            &mut journal,
            &mut executor,
            &mut baseline,
            Some(inserted),
        );
        let SampleOutcome::Measured {
            components,
            total_us,
        } = sample.outcome
        else {
            panic!("expected a measured sample: {sample:?}");
        };
        assert_eq!(total_us, components.total_us());
        assert!(components.values()[1..].iter().all(|v| *v >= 0));
        assert!(components.t1_insertion_to_manifest_us >= 0);
        assert_eq!(sample.manifest_polls, 3);
        assert_eq!(
            device.log,
            [
                "manifest", "manifest", "manifest", "open", "get_info", "close"
            ]
        );
        assert_eq!(journal.writes, ["dispatch_capable", "resolved"]);
        assert_eq!(executor.0.len(), 1);
        let frame = String::from_utf8_lossy(&executor.0[0]).into_owned();
        assert!(frame.contains("h0_would_dispatch_marker"));
        assert!(baseline.is_some());
        assert_eq!(
            sample.device.map(|d| (d.vendor_id, d.aaguid.len())),
            Some((0x1050, 32))
        );
    }

    #[test]
    fn second_device_aborts_before_open() {
        let mut device = FakeDevice {
            manifests: VecDeque::from([0, 2]),
            info: Some(info()),
            ..FakeDevice::default()
        };
        let (mut journal, mut executor, mut baseline) = Default::default();
        let sample = run(
            &mut device,
            &mut journal,
            &mut executor,
            &mut baseline,
            Some(Instant::now()),
        );
        assert_eq!(
            sample.outcome,
            SampleOutcome::Aborted {
                reason: AbortReason::MultipleDevices { count: 2 }
            }
        );
        assert_eq!(device.opened, 0);
        assert!(journal.writes.is_empty() && executor.0.is_empty());
    }

    #[test]
    fn timeout_without_candidate_never_opens() {
        let mut device = FakeDevice::default();
        let (mut journal, mut executor, mut baseline) = Default::default();
        let sample = run(
            &mut device,
            &mut journal,
            &mut executor,
            &mut baseline,
            None,
        );
        assert_eq!(
            sample.outcome,
            SampleOutcome::Aborted {
                reason: AbortReason::InsertionTimeout
            }
        );
        assert_eq!(device.opened, 0);
        assert!(device.log.iter().all(|step| *step == "manifest"));
    }

    #[test]
    fn snapshot_mismatch_aborts_before_durable_write_and_closes() {
        let mut changed = info();
        changed.firmware_version = Some(2);
        let mut device = FakeDevice {
            manifests: VecDeque::from([1]),
            info: Some(changed),
            ..FakeDevice::default()
        };
        let mut baseline = Some(Baseline {
            manifest: label(),
            info: info(),
        });
        let (mut journal, mut executor) = Default::default();
        let sample = run(
            &mut device,
            &mut journal,
            &mut executor,
            &mut baseline,
            Some(Instant::now()),
        );
        assert_eq!(
            sample.outcome,
            SampleOutcome::Aborted {
                reason: AbortReason::SnapshotMismatch {
                    field: "firmware_version".into()
                }
            }
        );
        assert_eq!(device.closed, 1);
        assert!(journal.writes.is_empty() && executor.0.is_empty());
    }

    #[test]
    fn product_string_mismatch_aborts_before_durable_write_and_closes() {
        let mut device = FakeDevice {
            manifests: VecDeque::from([1]),
            info: Some(info()),
            ..FakeDevice::default()
        };
        // Same VID/PID and GetInfo; only the candidate's product string differs from the baseline.
        let base_label = ManifestLabel {
            product: "Other Model".into(),
            ..label()
        };
        let mut baseline = Some(Baseline {
            manifest: base_label.clone(),
            info: info(),
        });
        let (mut journal, mut executor) = Default::default();
        let sample = run(
            &mut device,
            &mut journal,
            &mut executor,
            &mut baseline,
            Some(Instant::now()),
        );
        assert_eq!(
            sample.outcome,
            SampleOutcome::Aborted {
                reason: AbortReason::SnapshotMismatch {
                    field: "product".into()
                }
            }
        );
        assert_eq!((device.opened, device.closed), (1, 1));
        assert_eq!(device.log, ["manifest", "open", "get_info", "close"]);
        assert!(journal.writes.is_empty() && executor.0.is_empty());
        assert_eq!(baseline.map(|b| b.manifest), Some(base_label));
    }

    #[test]
    fn durability_failure_aborts_before_would_dispatch() {
        let mut device = FakeDevice {
            manifests: VecDeque::from([1]),
            info: Some(info()),
            ..FakeDevice::default()
        };
        let mut journal = FakeJournal {
            fail_replace: true,
            ..FakeJournal::default()
        };
        let (mut executor, mut baseline) = Default::default();
        let sample = run(
            &mut device,
            &mut journal,
            &mut executor,
            &mut baseline,
            Some(Instant::now()),
        );
        assert_eq!(
            sample.outcome,
            SampleOutcome::Aborted {
                reason: AbortReason::DurabilityFailed
            }
        );
        assert!(executor.0.is_empty());
        assert_eq!(device.closed, 1);
    }

    #[test]
    fn open_failure_is_recorded_without_close() {
        let mut device = FakeDevice {
            manifests: VecDeque::from([1]),
            open_error: Some(-7),
            ..FakeDevice::default()
        };
        let (mut journal, mut executor, mut baseline) = Default::default();
        let sample = run(
            &mut device,
            &mut journal,
            &mut executor,
            &mut baseline,
            Some(Instant::now()),
        );
        assert_eq!(
            sample.outcome,
            SampleOutcome::Aborted {
                reason: AbortReason::OpenFailed { code: -7 }
            }
        );
        assert_eq!(device.closed, 0);
    }

    #[test]
    fn missing_notification_invalidates_an_otherwise_complete_pass() {
        let mut device = FakeDevice {
            manifests: VecDeque::from([1]),
            info: Some(info()),
            ..FakeDevice::default()
        };
        let (mut journal, mut executor, mut baseline) = Default::default();
        let sample = run(
            &mut device,
            &mut journal,
            &mut executor,
            &mut baseline,
            None,
        );
        assert_eq!(
            sample.outcome,
            SampleOutcome::Aborted {
                reason: AbortReason::NoInsertionNotification
            }
        );
        assert_eq!(device.closed, 1);
    }

    #[test]
    fn notification_after_manifest_yields_negative_t1() {
        let mut device = FakeDevice {
            manifests: VecDeque::from([1]),
            info: Some(info()),
            ..FakeDevice::default()
        };
        let (mut journal, mut executor, mut baseline) = Default::default();
        let late = Instant::now() + Duration::from_millis(50);
        let sample = run(
            &mut device,
            &mut journal,
            &mut executor,
            &mut baseline,
            Some(late),
        );
        let SampleOutcome::Measured { components, .. } = sample.outcome else {
            panic!("expected a measured sample");
        };
        assert!(components.t1_insertion_to_manifest_us < 0);
    }

    #[test]
    fn mismatch_comparison_covers_every_field() {
        let base = info();
        assert_eq!(snapshot_mismatch(&base, &base), None);
        let mut other = info();
        other.aaguid = "11".repeat(16);
        assert_eq!(snapshot_mismatch(&base, &other), Some("aaguid"));
        let mut other = info();
        other.versions.push("FIDO_2_1".into());
        assert_eq!(snapshot_mismatch(&base, &other), Some("versions"));
        let mut other = info();
        other.extensions.push("credProtect".into());
        assert_eq!(snapshot_mismatch(&base, &other), Some("extensions"));
        let mut other = info();
        other.max_msg_size = 1;
        assert_eq!(snapshot_mismatch(&base, &other), Some("max_msg_size"));
        let mut other = info();
        other.transports_for_reset.push("usb".into());
        assert_eq!(
            snapshot_mismatch(&base, &other),
            Some("transports_for_reset")
        );
        let mut other = info();
        other.long_touch_for_reset = true;
        assert_eq!(
            snapshot_mismatch(&base, &other),
            Some("long_touch_for_reset")
        );
        let mut other = info();
        other.options[0].1 = false;
        assert_eq!(snapshot_mismatch(&base, &other), Some("options"));
    }
}
