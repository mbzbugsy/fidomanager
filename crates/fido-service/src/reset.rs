//! M6.1 FIDO2 Reset authority foundation (ADR-011).
//!
//! Pure, non-dispatching ceremony types. Nothing here can authorize a Reset: there is no dispatch
//! permit, journal operation, worker request, native call or renderer surface. The ceremony
//! typestate `ResetIntent → ResetCeremonyGrant → ArmedCeremony → AwaitingReinsertion →
//! InsertedCandidate → CandidateValidated` stops at [`CandidateValidated`], which has no
//! transition. M6.2 adds the durable `DispatchCapable` step and the one permit it may mint.
//!
//! Time is only ever the caller's authority-owned [`MonotonicMillis`]; no wall clock and no
//! `Instant::now()` is read here. Phase durations are policy parameters, not constants, because
//! the Reset timing windows are not final until CTAP PS §6.6 is verified (ADR-011).

use crate::{MonotonicMillis, RegisteredDeviceTarget, WorkerGeneration};
use fido_core::WorkflowId;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const RESET_INTENT_VERSION: u8 = 1;

/// Phase durations of one Reset ceremony, in milliseconds. Every phase deadline is additionally
/// capped by the ceremony expiry. All values must be non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetCeremonyPolicy {
    /// From intent creation to native approval.
    pub approval_ms: u64,
    /// From approval to the end of the whole ceremony.
    pub ceremony_ms: u64,
    /// From arming to observing zero connected devices.
    pub disconnect_ms: u64,
    /// From observing zero devices to the candidate's first insertion observation.
    pub reinsertion_ms: u64,
    /// From the candidate's first insertion observation to the end of validation. The future
    /// dispatch permit expires at `min(ceremony expiry, first_seen + runtime budget)`.
    pub runtime_budget_ms: u64,
}

impl ResetCeremonyPolicy {
    pub fn validate(self) -> Result<Self, ResetError> {
        let durations = [
            self.approval_ms,
            self.ceremony_ms,
            self.disconnect_ms,
            self.reinsertion_ms,
            self.runtime_budget_ms,
        ];
        if durations.contains(&0) {
            return Err(ResetError::InvalidPolicy);
        }
        Ok(self)
    }
}

/// Mismatch-only safety evidence (ADR-011 Decision 5). Any difference aborts the ceremony; a
/// match proves nothing about physical identity and never authorizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetDeviceEvidence {
    pub vendor_id: u16,
    pub product_id: u16,
    pub product: String,
    pub aaguid: [u8; 16],
}

/// Opaque per-enumeration native key (on macOS the `ioreg://` registry entry ID, which changes on
/// every re-enumeration). Compared only to require that a re-enumeration happened; never identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetNativeKey(pub u64);

/// One connected device in a manifest observation. An observation lists every connected device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetSeenDevice {
    pub key: ResetNativeKey,
    pub vendor_id: u16,
    pub product_id: u16,
    pub product: String,
}

/// Facts read by a fresh worker after the Reset call. Evidence only (ADR-011 Decision 7): it never
/// upgrades `OutcomeUnknown`, never changes the journal and never authorizes. A key that reappears
/// empty is `ConsistentWithReset`, not success; it cannot be shown to be the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostResetObservation {
    NotObserved,
    ConsistentWithReset,
    Inconsistent,
    Ambiguous,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ResetError {
    #[error("reset ceremony policy durations must be non-zero")]
    InvalidPolicy,
    #[error("reset ceremony deadline is not representable")]
    DeadlineOverflow,
    #[error("exactly one eligible security key must be connected")]
    NotExactlyOneDevice,
    #[error("reset ceremony evidence differs from the approved security key")]
    EvidenceMismatch,
    #[error("reset target changed before approval")]
    TargetChanged,
    #[error("reset ceremony lifecycle epoch changed")]
    LifecycleChanged,
    #[error("reset ceremony phase deadline expired")]
    Expired,
    #[error("reset ceremony observation time went backwards")]
    ClockRegression,
    #[error("a reconnect was observed without the required disconnect")]
    NoDisconnectObserved,
    #[error("the reset candidate vanished or was replaced before validation")]
    CandidateVanished,
}

/// The device a Reset intent is built for, taken from the live registry under the sensitive gate.
pub(crate) struct ResetSubject {
    pub(crate) workflow: WorkflowId,
    pub(crate) target: RegisteredDeviceTarget,
    pub(crate) worker: WorkerGeneration,
    pub(crate) evidence: ResetDeviceEvidence,
}

/// Backend-owned immutable description of one Reset ceremony, consumed by approval.
///
/// No public constructor, no Clone, no serde, no Debug and no Display.
///
/// ```compile_fail
/// fn replay(i: &fido_service::reset::ResetIntent) {
///     let _copy = (*i).clone();
/// }
/// ```
///
/// ```compile_fail
/// fn serialize(i: &fido_service::reset::ResetIntent) {
///     let _ = serde_json::to_string(i);
/// }
/// ```
///
/// ```compile_fail
/// fn forge(i: fido_service::reset::ResetIntent) -> fido_service::reset::ResetCeremonyGrant {
///     i.into()
/// }
/// ```
pub struct ResetIntent {
    subject: ResetSubject,
    policy: ResetCeremonyPolicy,
    nonce: [u8; 16],
    lifecycle_epoch: u64,
    created_at: MonotonicMillis,
    expires_at: MonotonicMillis,
}

impl ResetIntent {
    /// Exactly one eligible device must be connected when the ceremony starts (Decision 2).
    /// The nonce is injected for deterministic tests; the M6.2 caller must draw it from
    /// `getrandom` for every ceremony, as the PIN and deletion intents do.
    pub(crate) fn new(
        subject: ResetSubject,
        policy: ResetCeremonyPolicy,
        nonce: [u8; 16],
        lifecycle_epoch: u64,
        eligible_devices: usize,
        now: MonotonicMillis,
    ) -> Result<Self, ResetError> {
        let policy = policy.validate()?;
        if eligible_devices != 1 {
            return Err(ResetError::NotExactlyOneDevice);
        }
        Ok(Self {
            subject,
            policy,
            nonce,
            lifecycle_epoch,
            created_at: now,
            expires_at: after(now, policy.approval_ms)?,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical()).into()
    }

    /// Fixed, versioned, big-endian, length-delimited encoding with its own domain tag. No native
    /// path, secret or renderer value is included. Any field change requires a version change.
    fn canonical(&self) -> Vec<u8> {
        let mut out = b"FidoManager reset intent\0".to_vec();
        out.push(RESET_INTENT_VERSION);
        out.extend(self.nonce);
        out.extend(self.subject.workflow.as_raw().to_be_bytes());
        out.extend(self.subject.target.worker_device_id.0.to_be_bytes());
        out.extend(self.subject.target.device_generation.0.to_be_bytes());
        out.extend(self.subject.worker.0.to_be_bytes());
        let evidence = &self.subject.evidence;
        out.extend(evidence.vendor_id.to_be_bytes());
        out.extend(evidence.product_id.to_be_bytes());
        out.extend(evidence.aaguid);
        let product = evidence.product.as_bytes();
        out.extend(
            u64::try_from(product.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        out.extend(product);
        for duration in [
            self.policy.approval_ms,
            self.policy.ceremony_ms,
            self.policy.disconnect_ms,
            self.policy.reinsertion_ms,
            self.policy.runtime_budget_ms,
        ] {
            out.extend(duration.to_be_bytes());
        }
        out.extend(self.created_at.as_millis().to_be_bytes());
        out.extend(self.expires_at.as_millis().to_be_bytes());
        out.extend(self.lifecycle_epoch.to_be_bytes());
        out
    }

    /// Consumes the intent after native approval. The registry target must be unchanged and
    /// exactly one eligible device must still be connected (Decision 2).
    pub(crate) fn approve_at(
        self,
        current: RegisteredDeviceTarget,
        eligible_devices: usize,
        lifecycle_epoch: u64,
        now: MonotonicMillis,
    ) -> Result<ResetCeremonyGrant, ResetError> {
        if lifecycle_epoch != self.lifecycle_epoch {
            return Err(ResetError::LifecycleChanged);
        }
        if now < self.created_at {
            return Err(ResetError::ClockRegression);
        }
        if now >= self.expires_at {
            return Err(ResetError::Expired);
        }
        if current != self.subject.target {
            return Err(ResetError::TargetChanged);
        }
        if eligible_devices != 1 {
            return Err(ResetError::NotExactlyOneDevice);
        }
        let digest = self.digest();
        Ok(ResetCeremonyGrant {
            ceremony: Ceremony {
                digest,
                evidence: self.subject.evidence,
                policy: self.policy,
                lifecycle_epoch: self.lifecycle_epoch,
                expires_at: after(now, self.policy.ceremony_ms)?,
                last_seen: now,
            },
        })
    }
}

/// One approved Reset ceremony. It can arm and wait, never dispatch.
///
/// ```compile_fail
/// fn replay(g: &fido_service::reset::ResetCeremonyGrant) {
///     let _copy = (*g).clone();
/// }
/// ```
///
/// ```compile_fail
/// fn serialize(g: &fido_service::reset::ResetCeremonyGrant) {
///     let _ = serde_json::to_string(g);
/// }
/// ```
pub struct ResetCeremonyGrant {
    ceremony: Ceremony,
}

impl ResetCeremonyGrant {
    /// Arms the ceremony on the single connected, evidence-consistent device. M6.2 writes the
    /// durable Pending record before calling this; it is never written after validation.
    pub(crate) fn arm_at(
        mut self,
        lifecycle_epoch: u64,
        connected: &[ResetSeenDevice],
        now: MonotonicMillis,
    ) -> Result<ArmedCeremony, ResetError> {
        let expires_at = self.ceremony.expires_at;
        self.ceremony.check(lifecycle_epoch, now, expires_at)?;
        let [device] = connected else {
            return Err(ResetError::NotExactlyOneDevice);
        };
        self.ceremony.require_manifest(device)?;
        let deadline = self
            .ceremony
            .phase_deadline(now, self.ceremony.policy.disconnect_ms)?;
        Ok(ArmedCeremony {
            ceremony: self.ceremony,
            armed_key: device.key,
            deadline,
        })
    }
}

/// Armed and waiting for the approved key to be removed.
pub struct ArmedCeremony {
    ceremony: Ceremony,
    armed_key: ResetNativeKey,
    deadline: MonotonicMillis,
}

pub enum Disconnection {
    StillConnected(ArmedCeremony),
    Disconnected(AwaitingReinsertion),
}

impl ArmedCeremony {
    /// 1 → 0: only an observation of zero connected devices advances the ceremony. Any other
    /// device, or a reconnect without an observed disconnect, aborts.
    pub(crate) fn observe_at(
        mut self,
        lifecycle_epoch: u64,
        connected: &[ResetSeenDevice],
        now: MonotonicMillis,
    ) -> Result<Disconnection, ResetError> {
        self.ceremony.check(lifecycle_epoch, now, self.deadline)?;
        match connected {
            [] => {
                let deadline = self
                    .ceremony
                    .phase_deadline(now, self.ceremony.policy.reinsertion_ms)?;
                Ok(Disconnection::Disconnected(AwaitingReinsertion {
                    ceremony: self.ceremony,
                    armed_key: self.armed_key,
                    deadline,
                }))
            }
            [device] if device.key == self.armed_key => {
                self.ceremony.require_manifest(device)?;
                Ok(Disconnection::StillConnected(self))
            }
            [_] => Err(ResetError::NoDisconnectObserved),
            _ => Err(ResetError::NotExactlyOneDevice),
        }
    }
}

/// Zero devices observed; waiting for exactly one candidate.
pub struct AwaitingReinsertion {
    ceremony: Ceremony,
    armed_key: ResetNativeKey,
    deadline: MonotonicMillis,
}

pub enum Reinsertion {
    Waiting(AwaitingReinsertion),
    Inserted(InsertedCandidate),
}

impl AwaitingReinsertion {
    /// 0 → 1: exactly one re-enumerated, manifest-consistent candidate. Its first observation
    /// starts the runtime budget.
    pub(crate) fn observe_at(
        mut self,
        lifecycle_epoch: u64,
        connected: &[ResetSeenDevice],
        now: MonotonicMillis,
    ) -> Result<Reinsertion, ResetError> {
        self.ceremony.check(lifecycle_epoch, now, self.deadline)?;
        match connected {
            [] => Ok(Reinsertion::Waiting(self)),
            [device] => {
                // The same enumeration key means no re-enumeration was proven: fail closed.
                if device.key == self.armed_key {
                    return Err(ResetError::NoDisconnectObserved);
                }
                self.ceremony.require_manifest(device)?;
                let deadline = self
                    .ceremony
                    .phase_deadline(now, self.ceremony.policy.runtime_budget_ms)?;
                Ok(Reinsertion::Inserted(InsertedCandidate {
                    ceremony: self.ceremony,
                    candidate_key: device.key,
                    first_seen: now,
                    deadline,
                }))
            }
            _ => Err(ResetError::NotExactlyOneDevice),
        }
    }
}

/// Exactly one candidate observed; awaiting its fresh open and GetInfo.
pub struct InsertedCandidate {
    ceremony: Ceremony,
    candidate_key: ResetNativeKey,
    first_seen: MonotonicMillis,
    deadline: MonotonicMillis,
}

impl InsertedCandidate {
    /// The candidate must still be the only connected device and its GetInfo AAGUID must match.
    pub(crate) fn validate_at(
        mut self,
        lifecycle_epoch: u64,
        connected: &[ResetSeenDevice],
        aaguid: [u8; 16],
        now: MonotonicMillis,
    ) -> Result<CandidateValidated, ResetError> {
        self.ceremony.check(lifecycle_epoch, now, self.deadline)?;
        let device = match connected {
            [device] if device.key == self.candidate_key => device,
            [] | [_] => return Err(ResetError::CandidateVanished),
            _ => return Err(ResetError::NotExactlyOneDevice),
        };
        self.ceremony.require_manifest(device)?;
        if aaguid != self.ceremony.evidence.aaguid {
            return Err(ResetError::EvidenceMismatch);
        }
        Ok(CandidateValidated {
            digest: self.ceremony.digest,
            lifecycle_epoch: self.ceremony.lifecycle_epoch,
            first_seen: self.first_seen,
            dispatch_deadline: self.deadline,
        })
    }
}

/// Terminal M6.1 state. It carries the inputs the future permit needs but has no transition:
/// minting dispatch authority requires the durable `DispatchCapable` record added in M6.2.
pub struct CandidateValidated {
    digest: [u8; 32],
    lifecycle_epoch: u64,
    first_seen: MonotonicMillis,
    dispatch_deadline: MonotonicMillis,
}

impl CandidateValidated {
    pub(crate) fn intent_digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn lifecycle_epoch(&self) -> u64 {
        self.lifecycle_epoch
    }

    pub(crate) fn first_seen(&self) -> MonotonicMillis {
        self.first_seen
    }

    /// `min(ceremony expiry, first_seen + runtime budget)`.
    pub(crate) fn dispatch_deadline(&self) -> MonotonicMillis {
        self.dispatch_deadline
    }
}

/// State shared by every post-approval phase.
struct Ceremony {
    digest: [u8; 32],
    evidence: ResetDeviceEvidence,
    policy: ResetCeremonyPolicy,
    lifecycle_epoch: u64,
    expires_at: MonotonicMillis,
    last_seen: MonotonicMillis,
}

impl Ceremony {
    /// Fails closed on a lifecycle change, a time regression or a reached deadline.
    fn check(
        &mut self,
        lifecycle_epoch: u64,
        now: MonotonicMillis,
        deadline: MonotonicMillis,
    ) -> Result<(), ResetError> {
        if lifecycle_epoch != self.lifecycle_epoch {
            return Err(ResetError::LifecycleChanged);
        }
        if now < self.last_seen {
            return Err(ResetError::ClockRegression);
        }
        if now >= deadline {
            return Err(ResetError::Expired);
        }
        self.last_seen = now;
        Ok(())
    }

    fn phase_deadline(&self, now: MonotonicMillis, ms: u64) -> Result<MonotonicMillis, ResetError> {
        Ok(after(now, ms)?.min(self.expires_at))
    }

    fn require_manifest(&self, device: &ResetSeenDevice) -> Result<(), ResetError> {
        let evidence = &self.evidence;
        if device.vendor_id != evidence.vendor_id
            || device.product_id != evidence.product_id
            || device.product != evidence.product
        {
            return Err(ResetError::EvidenceMismatch);
        }
        Ok(())
    }
}

fn after(now: MonotonicMillis, ms: u64) -> Result<MonotonicMillis, ResetError> {
    now.as_millis()
        .checked_add(ms)
        .map(MonotonicMillis::from_millis)
        .ok_or(ResetError::DeadlineOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceGeneration, MutationOutcome};
    use fido_auth::reset::ResetCommandOutcome;
    use fido_worker_protocol::WorkerDeviceId;
    use static_assertions::assert_not_impl_any;

    // Reset authority and ceremony state can be neither copied, formatted nor serialized.
    assert_not_impl_any!(
        ResetIntent:
            Clone,
            Copy,
            std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned
    );
    assert_not_impl_any!(
        ResetCeremonyGrant:
            Clone,
            Copy,
            std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned,
            From<ResetIntent>
    );
    assert_not_impl_any!(
        ArmedCeremony:
            Clone,
            Copy,
            std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned
    );
    assert_not_impl_any!(
        AwaitingReinsertion:
            Clone,
            Copy,
            std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned
    );
    assert_not_impl_any!(
        InsertedCandidate:
            Clone,
            Copy,
            std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned
    );
    assert_not_impl_any!(
        CandidateValidated:
            Clone,
            Copy,
            std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned
    );
    // Post-reset observation is evidence only and never becomes an outcome.
    assert_not_impl_any!(ResetCommandOutcome: From<PostResetObservation>);
    assert_not_impl_any!(MutationOutcome: From<PostResetObservation>);

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const EPOCH: u64 = 7;
    const POLICY: ResetCeremonyPolicy = ResetCeremonyPolicy {
        approval_ms: 30_000,
        ceremony_ms: 120_000,
        disconnect_ms: 20_000,
        reinsertion_ms: 20_000,
        runtime_budget_ms: 2_000,
    };

    fn ms(value: u64) -> MonotonicMillis {
        MonotonicMillis::from_millis(value)
    }

    fn target() -> RegisteredDeviceTarget {
        RegisteredDeviceTarget {
            worker_device_id: WorkerDeviceId(3),
            device_generation: DeviceGeneration(4),
        }
    }

    fn evidence() -> ResetDeviceEvidence {
        ResetDeviceEvidence {
            vendor_id: 0x1050,
            product_id: 0x0407,
            product: "YubiKey OTP+FIDO+CCID".into(),
            aaguid: [0xab; 16],
        }
    }

    fn subject() -> ResetSubject {
        ResetSubject {
            workflow: WorkflowId::from_raw(11),
            target: target(),
            worker: WorkerGeneration(5),
            evidence: evidence(),
        }
    }

    fn seen(key: u64) -> ResetSeenDevice {
        let evidence = evidence();
        ResetSeenDevice {
            key: ResetNativeKey(key),
            vendor_id: evidence.vendor_id,
            product_id: evidence.product_id,
            product: evidence.product,
        }
    }

    fn intent_at(now: u64) -> Result<ResetIntent, ResetError> {
        ResetIntent::new(subject(), POLICY, [9; 16], EPOCH, 1, ms(now))
    }

    /// Intent created at 0, approved at 1_000: ceremony expires at 121_000.
    fn grant() -> Result<ResetCeremonyGrant, ResetError> {
        intent_at(0)?.approve_at(target(), 1, EPOCH, ms(1_000))
    }

    /// Armed at 2_000 on key 100: disconnect deadline 22_000.
    fn armed() -> Result<ArmedCeremony, ResetError> {
        grant()?.arm_at(EPOCH, &[seen(100)], ms(2_000))
    }

    /// Disconnected at 3_000: reinsertion deadline 23_000.
    fn awaiting() -> Result<AwaitingReinsertion, ResetError> {
        match armed()?.observe_at(EPOCH, &[], ms(3_000))? {
            Disconnection::Disconnected(awaiting) => Ok(awaiting),
            Disconnection::StillConnected(_) => Err(ResetError::NoDisconnectObserved),
        }
    }

    /// Candidate key 200 first seen at 4_000: runtime deadline 6_000.
    fn inserted() -> Result<InsertedCandidate, ResetError> {
        match awaiting()?.observe_at(EPOCH, &[seen(200)], ms(4_000))? {
            Reinsertion::Inserted(candidate) => Ok(candidate),
            Reinsertion::Waiting(_) => Err(ResetError::CandidateVanished),
        }
    }

    fn validated(at: u64) -> Result<CandidateValidated, ResetError> {
        inserted()?.validate_at(EPOCH, &[seen(200)], evidence().aaguid, ms(at))
    }

    #[test]
    fn intent_digest_is_stable_and_binds_every_dimension() -> TestResult {
        let base = intent_at(0)?;
        assert_eq!(base.digest(), intent_at(0)?.digest());
        assert!(base.canonical().starts_with(b"FidoManager reset intent\0"));

        let mut variants = Vec::new();
        let with = |change: &dyn Fn(&mut ResetSubject)| {
            let mut s = subject();
            change(&mut s);
            ResetIntent::new(s, POLICY, [9; 16], EPOCH, 1, ms(0))
        };
        variants.push(with(&|s| s.workflow = WorkflowId::from_raw(12))?);
        variants.push(with(&|s| s.target.worker_device_id = WorkerDeviceId(4))?);
        variants.push(with(&|s| s.target.device_generation = DeviceGeneration(5))?);
        variants.push(with(&|s| s.worker = WorkerGeneration(6))?);
        variants.push(with(&|s| s.evidence.vendor_id = 0x1051)?);
        variants.push(with(&|s| s.evidence.product_id = 0x0408)?);
        variants.push(with(&|s| s.evidence.product.push('X'))?);
        variants.push(with(&|s| s.evidence.aaguid[15] ^= 1)?);
        variants.push(ResetIntent::new(
            subject(),
            POLICY,
            [8; 16],
            EPOCH,
            1,
            ms(0),
        )?);
        variants.push(ResetIntent::new(
            subject(),
            POLICY,
            [9; 16],
            EPOCH + 1,
            1,
            ms(0),
        )?);
        variants.push(intent_at(1)?);
        for change in [
            |p: &mut ResetCeremonyPolicy| p.approval_ms += 1,
            |p: &mut ResetCeremonyPolicy| p.ceremony_ms += 1,
            |p: &mut ResetCeremonyPolicy| p.disconnect_ms += 1,
            |p: &mut ResetCeremonyPolicy| p.reinsertion_ms += 1,
            |p: &mut ResetCeremonyPolicy| p.runtime_budget_ms += 1,
        ] {
            let mut policy = POLICY;
            change(&mut policy);
            variants.push(ResetIntent::new(
                subject(),
                policy,
                [9; 16],
                EPOCH,
                1,
                ms(0),
            )?);
        }
        let mut digests = vec![base.digest()];
        for variant in &variants {
            let digest = variant.digest();
            assert!(!digests.contains(&digest));
            digests.push(digest);
        }
        Ok(())
    }

    #[test]
    fn reset_canonical_domain_cannot_collide_with_pin_or_deletion_intents() -> TestResult {
        let reset_tag: &[u8] = b"FidoManager reset intent\0";
        let pin_tag: &[u8] = b"FidoManager operation intent\0";
        let delete_tag: &[u8] = b"FidoManager delete credential intent\0";
        // Guard against these literals drifting from the real encoders.
        assert!(include_str!("mutation.rs").contains(r#"b"FidoManager operation intent\0""#));
        assert!(
            include_str!("deletion.rs").contains(r#"b"FidoManager delete credential intent\0""#)
        );
        // NUL-terminated tags that are not prefixes of each other keep the domains disjoint.
        for (a, b) in [
            (reset_tag, pin_tag),
            (reset_tag, delete_tag),
            (pin_tag, delete_tag),
        ] {
            assert!(!a.starts_with(b) && !b.starts_with(a));
        }
        let canonical = intent_at(0)?.canonical();
        assert!(canonical.starts_with(reset_tag));
        assert_eq!(canonical[reset_tag.len()], RESET_INTENT_VERSION);
        Ok(())
    }

    #[test]
    fn intent_requires_valid_policy_one_device_and_representable_expiry() {
        for eligible in [0, 2, 3] {
            assert!(matches!(
                ResetIntent::new(subject(), POLICY, [9; 16], EPOCH, eligible, ms(0)),
                Err(ResetError::NotExactlyOneDevice)
            ));
        }
        for change in [
            |p: &mut ResetCeremonyPolicy| p.approval_ms = 0,
            |p: &mut ResetCeremonyPolicy| p.ceremony_ms = 0,
            |p: &mut ResetCeremonyPolicy| p.disconnect_ms = 0,
            |p: &mut ResetCeremonyPolicy| p.reinsertion_ms = 0,
            |p: &mut ResetCeremonyPolicy| p.runtime_budget_ms = 0,
        ] {
            let mut policy = POLICY;
            change(&mut policy);
            assert_eq!(policy.validate(), Err(ResetError::InvalidPolicy));
            assert!(matches!(
                ResetIntent::new(subject(), policy, [9; 16], EPOCH, 1, ms(0)),
                Err(ResetError::InvalidPolicy)
            ));
        }
        assert!(matches!(
            intent_at(u64::MAX - 1),
            Err(ResetError::DeadlineOverflow)
        ));
    }

    #[test]
    fn approval_is_bounded_by_intent_expiry_epoch_target_and_cardinality() -> TestResult {
        // Valid up to and excluding expires_at (30_000).
        assert!(
            intent_at(0)?
                .approve_at(target(), 1, EPOCH, ms(29_999))
                .is_ok()
        );
        assert!(matches!(
            intent_at(0)?.approve_at(target(), 1, EPOCH, ms(30_000)),
            Err(ResetError::Expired)
        ));
        assert!(matches!(
            intent_at(10)?.approve_at(target(), 1, EPOCH, ms(9)),
            Err(ResetError::ClockRegression)
        ));
        assert!(matches!(
            intent_at(0)?.approve_at(target(), 1, EPOCH + 1, ms(1)),
            Err(ResetError::LifecycleChanged)
        ));
        let mut moved = target();
        moved.device_generation = DeviceGeneration(5);
        assert!(matches!(
            intent_at(0)?.approve_at(moved, 1, EPOCH, ms(1)),
            Err(ResetError::TargetChanged)
        ));
        for eligible in [0, 2] {
            assert!(matches!(
                intent_at(0)?.approve_at(target(), eligible, EPOCH, ms(1)),
                Err(ResetError::NotExactlyOneDevice)
            ));
        }
        // The grant carries the approved intent's digest and its own ceremony expiry.
        let digest = intent_at(0)?.digest();
        let grant = grant()?;
        assert_eq!(grant.ceremony.digest, digest);
        assert_eq!(grant.ceremony.expires_at, ms(121_000));
        Ok(())
    }

    #[test]
    fn one_zero_one_reinsertion_validates_within_the_runtime_budget() -> TestResult {
        let candidate = validated(5_999)?;
        assert_eq!(candidate.intent_digest(), intent_at(0)?.digest());
        assert_eq!(candidate.lifecycle_epoch(), EPOCH);
        assert_eq!(candidate.first_seen(), ms(4_000));
        assert_eq!(candidate.dispatch_deadline(), ms(6_000));
        // The runtime budget is exclusive at its boundary.
        assert!(matches!(validated(6_000), Err(ResetError::Expired)));
        Ok(())
    }

    #[test]
    fn dispatch_deadline_is_capped_by_ceremony_expiry() -> TestResult {
        let policy = ResetCeremonyPolicy {
            ceremony_ms: 4_000,
            ..POLICY
        };
        let grant = ResetIntent::new(subject(), policy, [9; 16], EPOCH, 1, ms(0))?.approve_at(
            target(),
            1,
            EPOCH,
            ms(1_000),
        )?;
        let Disconnection::Disconnected(awaiting) = grant
            .arm_at(EPOCH, &[seen(100)], ms(2_000))?
            .observe_at(EPOCH, &[], ms(3_000))?
        else {
            return Err("disconnect was not observed".into());
        };
        let Reinsertion::Inserted(candidate) =
            awaiting.observe_at(EPOCH, &[seen(200)], ms(4_000))?
        else {
            return Err("candidate was not observed".into());
        };
        // min(ceremony expiry 5_000, first_seen 4_000 + budget 2_000).
        let validated = candidate.validate_at(EPOCH, &[seen(200)], evidence().aaguid, ms(4_500))?;
        assert_eq!(validated.dispatch_deadline(), ms(5_000));
        Ok(())
    }

    #[test]
    fn arming_requires_one_evidence_consistent_device_before_ceremony_expiry() -> TestResult {
        for connected in [vec![], vec![seen(100), seen(101)]] {
            assert!(matches!(
                grant()?.arm_at(EPOCH, &connected, ms(2_000)),
                Err(ResetError::NotExactlyOneDevice)
            ));
        }
        for mismatch in mismatched_manifests(100) {
            assert!(matches!(
                grant()?.arm_at(EPOCH, &[mismatch], ms(2_000)),
                Err(ResetError::EvidenceMismatch)
            ));
        }
        assert!(matches!(
            grant()?.arm_at(EPOCH + 1, &[seen(100)], ms(2_000)),
            Err(ResetError::LifecycleChanged)
        ));
        assert!(matches!(
            grant()?.arm_at(EPOCH, &[seen(100)], ms(999)),
            Err(ResetError::ClockRegression)
        ));
        assert!(grant()?.arm_at(EPOCH, &[seen(100)], ms(120_999)).is_ok());
        assert!(matches!(
            grant()?.arm_at(EPOCH, &[seen(100)], ms(121_000)),
            Err(ResetError::Expired)
        ));
        Ok(())
    }

    #[test]
    fn armed_ceremony_advances_only_on_an_observed_disconnect() -> TestResult {
        assert!(matches!(
            armed()?.observe_at(EPOCH, &[seen(100)], ms(21_999))?,
            Disconnection::StillConnected(_)
        ));
        // A different key without an observed zero-device state is not a reinsertion.
        assert!(matches!(
            armed()?.observe_at(EPOCH, &[seen(200)], ms(2_500)),
            Err(ResetError::NoDisconnectObserved)
        ));
        assert!(matches!(
            armed()?.observe_at(EPOCH, &[seen(100), seen(200)], ms(2_500)),
            Err(ResetError::NotExactlyOneDevice)
        ));
        for mismatch in mismatched_manifests(100) {
            assert!(matches!(
                armed()?.observe_at(EPOCH, &[mismatch], ms(2_500)),
                Err(ResetError::EvidenceMismatch)
            ));
        }
        assert!(matches!(
            armed()?.observe_at(EPOCH, &[], ms(22_000)),
            Err(ResetError::Expired)
        ));
        assert!(matches!(
            armed()?.observe_at(EPOCH + 1, &[], ms(2_500)),
            Err(ResetError::LifecycleChanged)
        ));
        assert!(matches!(
            armed()?.observe_at(EPOCH, &[], ms(1_999)),
            Err(ResetError::ClockRegression)
        ));
        Ok(())
    }

    #[test]
    fn reinsertion_accepts_exactly_one_re_enumerated_consistent_candidate() -> TestResult {
        assert!(matches!(
            awaiting()?.observe_at(EPOCH, &[], ms(22_999))?,
            Reinsertion::Waiting(_)
        ));
        assert!(matches!(
            awaiting()?.observe_at(EPOCH, &[], ms(23_000)),
            Err(ResetError::Expired)
        ));
        // The pre-disconnect enumeration key reappearing proves no re-enumeration.
        assert!(matches!(
            awaiting()?.observe_at(EPOCH, &[seen(100)], ms(4_000)),
            Err(ResetError::NoDisconnectObserved)
        ));
        assert!(matches!(
            awaiting()?.observe_at(EPOCH, &[seen(200), seen(201)], ms(4_000)),
            Err(ResetError::NotExactlyOneDevice)
        ));
        for mismatch in mismatched_manifests(200) {
            assert!(matches!(
                awaiting()?.observe_at(EPOCH, &[mismatch], ms(4_000)),
                Err(ResetError::EvidenceMismatch)
            ));
        }
        assert!(matches!(
            awaiting()?.observe_at(EPOCH + 1, &[seen(200)], ms(4_000)),
            Err(ResetError::LifecycleChanged)
        ));
        assert!(matches!(
            awaiting()?.observe_at(EPOCH, &[seen(200)], ms(2_999)),
            Err(ResetError::ClockRegression)
        ));
        Ok(())
    }

    #[test]
    fn validation_aborts_on_vanished_replaced_second_or_inconsistent_candidate() -> TestResult {
        let aaguid = evidence().aaguid;
        assert!(matches!(
            inserted()?.validate_at(EPOCH, &[], aaguid, ms(4_500)),
            Err(ResetError::CandidateVanished)
        ));
        assert!(matches!(
            inserted()?.validate_at(EPOCH, &[seen(201)], aaguid, ms(4_500)),
            Err(ResetError::CandidateVanished)
        ));
        assert!(matches!(
            inserted()?.validate_at(EPOCH, &[seen(200), seen(201)], aaguid, ms(4_500)),
            Err(ResetError::NotExactlyOneDevice)
        ));
        let mut other = aaguid;
        other[0] ^= 1;
        assert!(matches!(
            inserted()?.validate_at(EPOCH, &[seen(200)], other, ms(4_500)),
            Err(ResetError::EvidenceMismatch)
        ));
        for mismatch in mismatched_manifests(200) {
            assert!(matches!(
                inserted()?.validate_at(EPOCH, &[mismatch], aaguid, ms(4_500)),
                Err(ResetError::EvidenceMismatch)
            ));
        }
        assert!(matches!(
            inserted()?.validate_at(EPOCH + 1, &[seen(200)], aaguid, ms(4_500)),
            Err(ResetError::LifecycleChanged)
        ));
        assert!(matches!(
            inserted()?.validate_at(EPOCH, &[seen(200)], aaguid, ms(3_999)),
            Err(ResetError::ClockRegression)
        ));
        Ok(())
    }

    fn mismatched_manifests(key: u64) -> [ResetSeenDevice; 3] {
        let mut vendor = seen(key);
        vendor.vendor_id ^= 1;
        let mut product_id = seen(key);
        product_id.product_id ^= 1;
        let mut product = seen(key);
        product.product.push('X');
        [vendor, product_id, product]
    }
}
