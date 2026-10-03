//! Backend/worker authentication contracts. This crate has no renderer API.
//! Host cleanup is not authenticator-side revocation or CTAPHID_CANCEL evidence.

use fido_core::{DeviceGeneration, PromptInstanceId, WorkflowId};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, c_char};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_PIN_BYTES: usize = 63;
pub const PROMPT_LIFETIME_SECS: u64 = 30;
pub const AUTH_NATIVE_BUDGET_MS: u64 = 5_000;
pub const AUTH_TRANSACTION_SECS: u64 = 40;

/// No Clone, serde, Debug or Display. All Rust-owned storage is zeroized on drop.
pub struct PinSecret {
    bytes: Zeroizing<Box<[u8]>>,
    len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPin;

impl PinSecret {
    /// Fills a fixed zeroizing allocation directly (e.g. from NSString). Ownership moves only
    /// a pointer; the allocation is never grown/reallocated or copied into Rust channel slots.
    pub fn collect(fill: impl FnOnce(&mut [u8]) -> Option<usize>) -> Result<Self, InvalidPin> {
        let mut bytes = Zeroizing::new(vec![0; 64].into_boxed_slice());
        let len = fill(&mut bytes).ok_or(InvalidPin)?;
        if !(4..=MAX_PIN_BYTES).contains(&len)
            || bytes[..len].contains(&0)
            || std::str::from_utf8(&bytes[..len]).is_err()
        {
            return Err(InvalidPin);
        }
        bytes[len..].zeroize();
        Ok(Self { bytes, len })
    }

    pub fn as_c_str(&self) -> &CStr {
        // SAFETY: validated UTF-8 without embedded NUL; trailing zero is part of owned storage.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.bytes[..=self.len]) }
    }
    pub fn as_ptr(&self) -> *const c_char {
        self.as_c_str().as_ptr()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcquisitionId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionBinding {
    pub worker_generation: u64,
    pub device_generation: DeviceGeneration,
    #[serde(with = "workflow_wire")]
    pub workflow_id: WorkflowId,
    #[serde(with = "prompt_wire")]
    pub prompt_instance_id: PromptInstanceId,
    pub acquisition_id: AcquisitionId,
}

// serde internally-tagged content does not preserve u128. Encode internal prompt/workflow
// identities as exact canonical hex strings, never lossy JSON numbers.
macro_rules! identity_wire {
    ($module:ident, $ty:ident) => {
        mod $module {
            use super::*;
            pub fn serialize<S: serde::Serializer>(id: &$ty, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&format!("{:032x}", id.as_raw()))
            }
            pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<$ty, D::Error> {
                let text = String::deserialize(d)?;
                if text.len() != 32
                    || !text
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(serde::de::Error::custom("invalid internal identity"));
                }
                u128::from_str_radix(&text, 16)
                    .map($ty::from_raw)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
identity_wire!(workflow_wire, WorkflowId);
identity_wire!(prompt_wire, PromptInstanceId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    CredManReadOnly,
    CredMan,
    LegacyUnscoped,
}

impl GrantKind {
    pub const fn permissions(self) -> u32 {
        match self {
            Self::CredManReadOnly => 0x40,
            Self::CredMan | Self::LegacyUnscoped => 0x04,
        }
    }
}

/// Capability selection happens before any PIN is collected. Duplicate security options and
/// contradictory scoped/legacy evidence fail closed; only explicit CTAP 2.0 preview is legacy.
pub fn select_kind<'a>(
    versions: &[String],
    options: impl IntoIterator<Item = (&'a str, bool)>,
) -> Option<GrantKind> {
    let mut seen = std::collections::HashMap::new();
    for (name, enabled) in options {
        if seen.insert(name, enabled).is_some() {
            return None;
        }
    }
    if seen.get("clientPin") != Some(&true) {
        return None;
    }
    let permissions = seen.get("pinUvAuthToken") == Some(&true);
    if !permissions && versions.iter().any(|v| v == "FIDO_2_1") {
        return None;
    }
    let ro = seen.get("perCredMgmtRO") == Some(&true);
    let cm = seen.get("credMgmt") == Some(&true);
    let preview = seen.get("credentialMgmtPreview") == Some(&true);
    if ro && !permissions {
        return None;
    }
    if permissions && (cm || preview) {
        Some(if ro {
            GrantKind::CredManReadOnly
        } else {
            GrantKind::CredMan
        })
    } else if !permissions && !cm && preview && versions.iter().any(|v| v == "FIDO_2_0") {
        Some(GrantKind::LegacyUnscoped)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationStatus {
    Validated,
    WrongPin,
    PinBlocked,
    PinAuthBlocked,
    Unsupported,
    InvalidSecret,
    Cancelled,
    Revoked,
    TimedOut,
    Uncertain,
    CleanupFailed,
    StaleAcquisition,
}

pub const fn classify_acquisition(code: i32) -> AuthenticationStatus {
    match code {
        0 => AuthenticationStatus::Validated,
        0x31 => AuthenticationStatus::WrongPin,
        0x32 => AuthenticationStatus::PinBlocked,
        0x34 => AuthenticationStatus::PinAuthBlocked,
        // Negative host errors and all unknown statuses carry no retry/outcome guarantee.
        _ => AuthenticationStatus::Uncertain,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationEvidence {
    pub binding: AcquisitionBinding,
    pub kind: GrantKind,
    pub status: AuthenticationStatus,
    pub attached_puat_cleared: bool,
}

/// Native-only exact acquisition receipt, neither serialized nor reusable application consent.
pub struct AuthorizationGrant {
    binding: AcquisitionBinding,
    kind: GrantKind,
}

/// Extension point for a single bounded inspection transaction. M2 performs only token validation.
/// It deliberately exposes no CTAP, mutation or reusable-token interface.
pub trait NativeAuthorization {
    fn acquire(&mut self, kind: GrantKind, pin: &PinSecret) -> AuthenticationStatus;
    fn attached(&self) -> bool;
    fn valid_attached(&self) -> bool;
    fn clear(&mut self) -> bool;
}

pub struct AuthorizationTransaction<'a, N: NativeAuthorization> {
    native: &'a mut N,
    binding: AcquisitionBinding,
    kind: GrantKind,
    poisoned: bool,
    finalized: bool,
    attempted: bool,
}

impl<'a, N: NativeAuthorization> AuthorizationTransaction<'a, N> {
    pub fn new(native: &'a mut N, binding: AcquisitionBinding, kind: GrantKind) -> Self {
        Self {
            native,
            binding,
            kind,
            poisoned: false,
            finalized: false,
            attempted: false,
        }
    }
    pub fn acquire(&mut self, pin: PinSecret) -> Result<AuthorizationGrant, AuthenticationStatus> {
        // Ambient token state is never adopted. Unexpected authority is discarded.
        if self.attempted || self.poisoned || self.native.attached() {
            return Err(AuthenticationStatus::StaleAcquisition);
        }
        self.attempted = true;
        let status = self.native.acquire(self.kind, &pin);
        drop(pin);
        if status != AuthenticationStatus::Validated {
            return Err(status);
        }
        if !self.native.valid_attached() {
            return Err(AuthenticationStatus::Uncertain);
        }
        Ok(AuthorizationGrant {
            binding: self.binding,
            kind: self.kind,
        })
    }
    pub fn validate(&mut self, grant: AuthorizationGrant) -> AuthenticationStatus {
        if !self.poisoned
            && grant.binding == self.binding
            && grant.kind == self.kind
            && self.native.valid_attached()
        {
            AuthenticationStatus::Validated
        } else {
            AuthenticationStatus::StaleAcquisition
        }
    }
    pub fn finish(mut self, status: AuthenticationStatus) -> AuthenticationEvidence {
        let cleared = self.native.clear() && !self.native.attached();
        self.poisoned = !cleared;
        self.finalized = true;
        AuthenticationEvidence {
            binding: self.binding,
            kind: self.kind,
            status: if cleared {
                status
            } else {
                AuthenticationStatus::CleanupFailed
            },
            attached_puat_cleared: cleared,
        }
    }
}

impl<N: NativeAuthorization> Drop for AuthorizationTransaction<'_, N> {
    fn drop(&mut self) {
        // Backstop on every early return/unwind. A native object is never reused by the worker.
        if !self.finalized {
            let _ = self.native.clear();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretTransportError;

const SECRET_MAGIC: &[u8; 8] = b"FMPIN002";
const HEADER_LEN: usize = 73;

fn header(binding: AcquisitionBinding, request_id: u64, len: u8) -> [u8; HEADER_LEN] {
    let mut h = [0; HEADER_LEN];
    h[..8].copy_from_slice(SECRET_MAGIC);
    h[8..16].copy_from_slice(&binding.worker_generation.to_be_bytes());
    h[16..24].copy_from_slice(&binding.device_generation.0.to_be_bytes());
    h[24..40].copy_from_slice(&binding.workflow_id.as_raw().to_be_bytes());
    h[40..56].copy_from_slice(&binding.prompt_instance_id.as_raw().to_be_bytes());
    h[56..64].copy_from_slice(&binding.acquisition_id.0.to_be_bytes());
    h[64..72].copy_from_slice(&request_id.to_be_bytes());
    h[72] = len;
    h
}

/// Consumes sender-owned PIN even on partial write. Caller must close the one-use channel.
pub fn send_secret(
    mut output: impl Write,
    binding: AcquisitionBinding,
    request_id: u64,
    pin: PinSecret,
) -> Result<(), SecretTransportError> {
    output
        .write_all(&header(binding, request_id, pin.len as u8))
        .map_err(|_| SecretTransportError)?;
    output
        .write_all(&pin.bytes[..pin.len])
        .map_err(|_| SecretTransportError)?;
    output.flush().map_err(|_| SecretTransportError)
}

/// Reads exactly one bounded frame then EOF. Trailing bytes/replay are rejected, never queued.
pub fn receive_secret(
    mut input: impl Read,
    binding: AcquisitionBinding,
    request_id: u64,
) -> Result<PinSecret, SecretTransportError> {
    let mut h = [0; HEADER_LEN];
    input.read_exact(&mut h).map_err(|_| SecretTransportError)?;
    let len = h[72] as usize;
    if !(4..=MAX_PIN_BYTES).contains(&len) || h != header(binding, request_id, h[72]) {
        return Err(SecretTransportError);
    }
    let pin = PinSecret::collect(|bytes| input.read_exact(&mut bytes[..len]).ok().map(|_| len))
        .map_err(|_| SecretTransportError)?;
    let mut extra = Zeroizing::new([0u8; 1]);
    match input.read(&mut *extra) {
        Ok(0) => Ok(pin),
        _ => Err(SecretTransportError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;
    assert_not_impl_any!(PinSecret: Clone, Copy, std::fmt::Debug, std::fmt::Display, Serialize, serde::de::DeserializeOwned);
    static_assertions::assert_impl_all!(Zeroizing<Box<[u8]>>: zeroize::ZeroizeOnDrop);
    assert_not_impl_any!(AuthorizationGrant: Clone, Copy, Serialize, serde::de::DeserializeOwned);

    fn binding() -> AcquisitionBinding {
        AcquisitionBinding {
            worker_generation: 1,
            device_generation: DeviceGeneration(1),
            workflow_id: WorkflowId::from_raw(1),
            prompt_instance_id: PromptInstanceId::from_raw(1),
            acquisition_id: AcquisitionId(1),
        }
    }
    fn pin() -> PinSecret {
        PinSecret::collect(|b| {
            b[..4].copy_from_slice(b"fake");
            Some(4)
        })
        .unwrap_or_else(|_| panic!("synthetic pin"))
    }

    #[test]
    fn secret_bounds_nul_utf8_and_owned_zeroization() {
        for data in [vec![b'x'; 3], vec![b'x'; 64], vec![0; 4], vec![0xff; 4]] {
            assert!(
                PinSecret::collect(|b| {
                    b[..data.len()].copy_from_slice(&data);
                    Some(data.len())
                })
                .is_err()
            );
        }
        let mut p = pin();
        p.bytes.zeroize();
        assert!(p.bytes.iter().all(|b| *b == 0));
    }
    #[test]
    fn secret_framing_short_oversize_binding_and_replay_fail_closed() {
        let mut bytes = Vec::new();
        assert!(send_secret(&mut bytes, binding(), 7, pin()).is_ok());
        assert!(receive_secret(bytes.as_slice(), binding(), 7).is_ok());
        for n in 0..bytes.len() {
            assert!(receive_secret(&bytes[..n], binding(), 7).is_err());
        }
        assert!(receive_secret(bytes.as_slice(), binding(), 8).is_err());
        let mut wrong = binding();
        wrong.acquisition_id = AcquisitionId(2);
        assert!(receive_secret(bytes.as_slice(), wrong, 7).is_err());
        bytes.push(1);
        assert!(receive_secret(bytes.as_slice(), binding(), 7).is_err());
        bytes[72] = 64;
        assert!(receive_secret(bytes.as_slice(), binding(), 7).is_err());
    }
    struct Fake {
        attached: bool,
        consistent: bool,
        clean: bool,
        status: AuthenticationStatus,
        clears: usize,
    }
    impl NativeAuthorization for Fake {
        fn acquire(&mut self, _: GrantKind, _: &PinSecret) -> AuthenticationStatus {
            self.attached = true;
            self.status
        }
        fn attached(&self) -> bool {
            self.attached
        }
        fn valid_attached(&self) -> bool {
            self.attached && self.consistent
        }
        fn clear(&mut self) -> bool {
            self.clears += 1;
            if self.clean {
                self.attached = false;
            }
            self.clean
        }
    }
    fn fake() -> Fake {
        Fake {
            attached: false,
            consistent: true,
            clean: true,
            status: AuthenticationStatus::Validated,
            clears: 0,
        }
    }
    #[test]
    fn ambient_malformed_and_repeated_acquisition_fail_closed() {
        let mut ambient = fake();
        ambient.attached = true;
        let mut tx = AuthorizationTransaction::new(&mut ambient, binding(), GrantKind::CredMan);
        assert!(matches!(
            tx.acquire(pin()),
            Err(AuthenticationStatus::StaleAcquisition)
        ));
        assert!(
            tx.finish(AuthenticationStatus::StaleAcquisition)
                .attached_puat_cleared
        );

        let mut malformed = fake();
        malformed.consistent = false;
        let mut tx = AuthorizationTransaction::new(&mut malformed, binding(), GrantKind::CredMan);
        assert!(matches!(
            tx.acquire(pin()),
            Err(AuthenticationStatus::Uncertain)
        ));
        assert!(
            tx.finish(AuthenticationStatus::Uncertain)
                .attached_puat_cleared
        );

        let mut native = fake();
        let mut tx = AuthorizationTransaction::new(&mut native, binding(), GrantKind::CredMan);
        let grant = tx.acquire(pin()).unwrap_or_else(|_| panic!("acquire"));
        assert!(matches!(
            tx.acquire(pin()),
            Err(AuthenticationStatus::StaleAcquisition)
        ));
        let status = tx.validate(grant);
        assert_eq!(tx.finish(status).status, AuthenticationStatus::Validated);
    }
    #[test]
    fn exact_acquisition_kind_worker_and_device_generation_are_required() {
        for change in 0..4 {
            let mut n = fake();
            let old = AuthorizationTransaction::new(&mut n, binding(), GrantKind::CredManReadOnly)
                .acquire(pin())
                .unwrap_or_else(|_| panic!("acquire"));
            let mut next = binding();
            let mut kind = GrantKind::CredManReadOnly;
            match change {
                0 => next.acquisition_id = AcquisitionId(2),
                1 => next.worker_generation = 2,
                2 => next.device_generation = DeviceGeneration(2),
                _ => kind = GrantKind::CredMan,
            }
            n.attached = true;
            let mut tx = AuthorizationTransaction::new(&mut n, next, kind);
            assert_eq!(tx.validate(old), AuthenticationStatus::StaleAcquisition);
        }
    }
    #[test]
    fn every_return_clears_authority_and_cleanup_failure_overrides_success() {
        for status in [
            AuthenticationStatus::Validated,
            AuthenticationStatus::WrongPin,
            AuthenticationStatus::PinBlocked,
            AuthenticationStatus::PinAuthBlocked,
            AuthenticationStatus::Uncertain,
        ] {
            let mut n = fake();
            n.status = status;
            let mut tx = AuthorizationTransaction::new(&mut n, binding(), GrantKind::CredMan);
            let result = match tx.acquire(pin()) {
                Ok(g) => tx.validate(g),
                Err(e) => e,
            };
            let evidence = tx.finish(result);
            assert_eq!(evidence.status, status);
            assert!(!n.attached);
            assert!(n.clears > 0);
        }
        let mut n = fake();
        n.clean = false;
        let mut tx = AuthorizationTransaction::new(&mut n, binding(), GrantKind::CredMan);
        let status = match tx.acquire(pin()) {
            Ok(g) => tx.validate(g),
            Err(e) => e,
        };
        assert_eq!(
            tx.finish(status).status,
            AuthenticationStatus::CleanupFailed
        );
    }
    #[test]
    fn capability_policy_preserves_actual_authority() {
        let versions = vec!["FIDO_2_0".into()];
        assert_eq!(
            select_kind(
                &versions,
                [
                    ("clientPin", true),
                    ("credMgmt", true),
                    ("pinUvAuthToken", true)
                ]
            ),
            Some(GrantKind::CredMan)
        );
        assert_eq!(
            select_kind(
                &versions,
                [
                    ("clientPin", true),
                    ("credMgmt", true),
                    ("pinUvAuthToken", true),
                    ("perCredMgmtRO", true)
                ]
            ),
            Some(GrantKind::CredManReadOnly)
        );
        assert_eq!(
            select_kind(
                &versions,
                [("clientPin", true), ("credentialMgmtPreview", true)]
            ),
            Some(GrantKind::LegacyUnscoped)
        );
        assert_eq!(
            select_kind(&versions, [("clientPin", true), ("credMgmt", true)]),
            None
        );
        assert_eq!(
            select_kind(&versions, [("clientPin", true), ("clientPin", false)]),
            None
        );
    }

    #[test]
    fn legacy_preview_refuses_contradictory_ctap21_without_permission_tokens() {
        for versions in [
            vec!["FIDO_2_1".to_owned()],
            vec!["FIDO_2_0".to_owned(), "FIDO_2_1".to_owned()],
            vec![
                "FIDO_2_0".to_owned(),
                "FIDO_2_1_PRE".to_owned(),
                "FIDO_2_1".to_owned(),
            ],
        ] {
            for token_option in [None, Some(("pinUvAuthToken", false))] {
                let mut options = vec![("clientPin", true), ("credentialMgmtPreview", true)];
                options.extend(token_option);
                assert_eq!(select_kind(&versions, options), None);
            }
        }
    }

    #[test]
    fn legacy_preview_and_scoped_ctap21_remain_distinct() {
        for versions in [
            vec!["FIDO_2_0".to_owned()],
            vec!["FIDO_2_0".to_owned(), "FIDO_2_1_PRE".to_owned()],
        ] {
            assert_eq!(
                select_kind(
                    &versions,
                    [("clientPin", true), ("credentialMgmtPreview", true)]
                ),
                Some(GrantKind::LegacyUnscoped)
            );
        }
        assert_eq!(
            select_kind(
                &["FIDO_2_0".to_owned(), "FIDO_2_1".to_owned()],
                [
                    ("clientPin", true),
                    ("credMgmt", true),
                    ("pinUvAuthToken", true)
                ]
            ),
            Some(GrantKind::CredMan)
        );
    }
}
