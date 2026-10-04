//! PIN mutation contracts. Secret ownership and fixed binary transport never use JSON.
use super::{AcquisitionBinding, PinSecret, SecretTransportError};
use fido_core::MutationOutcome;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinOperation {
    SetPin,
    ChangePin,
}
impl PinOperation {
    pub const fn title(self) -> &'static str {
        match self {
            Self::SetPin => "Set PIN",
            Self::ChangePin => "Change PIN",
        }
    }
}
/// Explicit, unique preparation identity plus exact approved intent. No secret fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinMutationBinding {
    pub operation: PinOperation,
    pub session: AcquisitionBinding,
    pub intent_digest: [u8; 32],
}
/// Fixed zeroizing allocations, moved exactly once. Confirmation never leaves native UI.
pub enum PinMutationSecrets {
    Set { new: PinSecret },
    Change { current: PinSecret, new: PinSecret },
}
impl PinMutationSecrets {
    pub fn operation(&self) -> PinOperation {
        match self {
            Self::Set { .. } => PinOperation::SetPin,
            Self::Change { .. } => PinOperation::ChangePin,
        }
    }
    pub fn pins(&self) -> (&PinSecret, Option<&PinSecret>) {
        match self {
            Self::Set { new } => (new, None),
            Self::Change { current, new } => (new, Some(current)),
        }
    }
}
impl Zeroize for PinMutationSecrets {
    fn zeroize(&mut self) {
        match self {
            Self::Set { new } => new.bytes.zeroize(),
            Self::Change { current, new } => {
                current.bytes.zeroize();
                new.bytes.zeroize();
            }
        }
    }
}
impl Drop for PinMutationSecrets {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for PinMutationSecrets {}

/// Duplicate/missing/unsupported capability evidence offers neither operation.
pub fn available_operation<'a>(
    versions: &[String],
    options: impl IntoIterator<Item = (&'a str, bool)>,
) -> Option<PinOperation> {
    if !versions
        .iter()
        .any(|v| matches!(v.as_str(), "FIDO_2_0" | "FIDO_2_1" | "FIDO_2_1_PRE"))
    {
        return None;
    }
    let mut seen = std::collections::BTreeMap::new();
    for (name, enabled) in options {
        if seen.insert(name, enabled).is_some() {
            return None;
        }
    }
    seen.get("clientPin").map(|configured| {
        if *configured {
            PinOperation::ChangePin
        } else {
            PinOperation::SetPin
        }
    })
}
/// ADR-010 exact conservative allowlist; host/transport errors have no phase proof after entry.
pub fn pin_call_outcome(operation: PinOperation, entered: bool, code: i32) -> MutationOutcome {
    if !entered {
        return MutationOutcome::NotDispatched;
    }
    match code {
        0 => MutationOutcome::ConfirmedSuccessful,
        0x02 | 0x14 | 0x33 | 0x37 => MutationOutcome::Rejected,
        0x31 | 0x32 | 0x34 if operation == PinOperation::ChangePin => MutationOutcome::Rejected,
        _ => MutationOutcome::OutcomeUnknown,
    }
}
const HEADER: usize = 107;
fn header(binding: PinMutationBinding, request: u64, current: u8, new: u8) -> [u8; HEADER] {
    let mut h = [0; HEADER];
    h[..8].copy_from_slice(b"FMPIN003");
    h[8] = match binding.operation {
        PinOperation::SetPin => 1,
        PinOperation::ChangePin => 2,
    };
    h[9..17].copy_from_slice(&binding.session.worker_generation.to_be_bytes());
    h[17..25].copy_from_slice(&binding.session.device_generation.0.to_be_bytes());
    h[25..41].copy_from_slice(&binding.session.workflow_id.as_raw().to_be_bytes());
    h[41..57].copy_from_slice(&binding.session.prompt_instance_id.as_raw().to_be_bytes());
    h[57..65].copy_from_slice(&binding.session.acquisition_id.0.to_be_bytes());
    h[65..73].copy_from_slice(&request.to_be_bytes());
    h[73] = current;
    h[74] = new;
    h[75..107].copy_from_slice(&binding.intent_digest);
    h
}
pub fn send_mutation_secret(
    mut output: impl Write,
    binding: PinMutationBinding,
    request: u64,
    secrets: PinMutationSecrets,
) -> Result<(), SecretTransportError> {
    if secrets.operation() != binding.operation {
        return Err(SecretTransportError);
    }
    let (new, current) = secrets.pins();
    output
        .write_all(&header(
            binding,
            request,
            current.map_or(0, |p| p.len as u8),
            new.len as u8,
        ))
        .map_err(|_| SecretTransportError)?;
    if let Some(current) = current {
        output
            .write_all(&current.bytes[..current.len])
            .map_err(|_| SecretTransportError)?;
    }
    output
        .write_all(&new.bytes[..new.len])
        .map_err(|_| SecretTransportError)?;
    output.flush().map_err(|_| SecretTransportError)
}
pub fn receive_mutation_secret(
    mut input: impl Read,
    binding: PinMutationBinding,
    request: u64,
) -> Result<PinMutationSecrets, SecretTransportError> {
    let mut h = [0; HEADER];
    input.read_exact(&mut h).map_err(|_| SecretTransportError)?;
    let new = h[74] as usize;
    let current = h[73] as usize;
    if !(4..=63).contains(&new)
        || match binding.operation {
            PinOperation::SetPin => current != 0,
            PinOperation::ChangePin => !(4..=63).contains(&current),
        }
        || h != header(binding, request, current as u8, new as u8)
    {
        return Err(SecretTransportError);
    }
    let mut collect = |len| {
        PinSecret::collect(|b| input.read_exact(&mut b[..len]).ok().map(|_| len))
            .map_err(|_| SecretTransportError)
    };
    let current = if current > 0 {
        Some(collect(current)?)
    } else {
        None
    };
    let new = collect(new)?;
    if new
        .as_c_str()
        .to_str()
        .map_err(|_| SecretTransportError)?
        .chars()
        .count()
        < 4
    {
        return Err(SecretTransportError);
    }
    let mut extra = Zeroizing::new([0u8; 1]);
    if !matches!(input.read(&mut *extra), Ok(0)) {
        return Err(SecretTransportError);
    }
    Ok(match current {
        Some(current) => PinMutationSecrets::Change { current, new },
        None => PinMutationSecrets::Set { new },
    })
}
/// Recovery policy; permission for passive metadata is not a read-back implementation.
#[derive(Debug, PartialEq, Eq)]
pub struct PinRecoveryPolicy {
    pub passive_client_pin_after_quiescence: bool,
    pub configured_state_proves_exact_pin: bool,
    pub automatic_old_new_probing: bool,
    pub ordinary_retry_consuming_authentication: bool,
    pub verification_requires_recovery_and_visible_retries: bool,
}
impl PinOperation {
    pub const fn recovery_policy(self) -> PinRecoveryPolicy {
        PinRecoveryPolicy {
            passive_client_pin_after_quiescence: matches!(self, Self::SetPin),
            configured_state_proves_exact_pin: false,
            automatic_old_new_probing: false,
            ordinary_retry_consuming_authentication: false,
            verification_requires_recovery_and_visible_retries: true,
        }
    }
}

/// Native outcome is independent of host cleanup and durable journal resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinMutationResult {
    pub outcome: MutationOutcome,
    pub rejection: Option<PinRejection>,
    pub native_closed: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinRejection {
    WrongCurrentPin,
    PinBlocked,
    PinAuthBlocked,
    PinPolicy,
    Parameters,
}
impl PinMutationResult {
    /// Reject contradictory worker evidence rather than showing an unsupported native reason.
    pub fn valid_for(self, operation: PinOperation) -> bool {
        match (self.outcome, self.rejection) {
            (
                MutationOutcome::Rejected,
                Some(
                    PinRejection::WrongCurrentPin
                    | PinRejection::PinBlocked
                    | PinRejection::PinAuthBlocked,
                ),
            ) => operation == PinOperation::ChangePin,
            (
                MutationOutcome::Rejected,
                Some(PinRejection::PinPolicy | PinRejection::Parameters),
            ) => true,
            (MutationOutcome::Rejected, None) => false,
            (_, None) => true,
            (_, Some(_)) => false,
        }
    }
    pub fn from_code(op: PinOperation, entered: bool, code: i32, native_closed: bool) -> Self {
        let outcome = pin_call_outcome(op, entered, code);
        let rejection = if outcome == MutationOutcome::Rejected {
            Some(match code {
                0x31 => PinRejection::WrongCurrentPin,
                0x32 => PinRejection::PinBlocked,
                0x34 => PinRejection::PinAuthBlocked,
                0x37 => PinRejection::PinPolicy,
                _ => PinRejection::Parameters,
            })
        } else {
            None
        };
        Self {
            outcome,
            rejection,
            native_closed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_not_impl_any};
    assert_not_impl_any!(PinMutationSecrets: Clone,Copy,std::fmt::Debug,std::fmt::Display,Serialize,serde::de::DeserializeOwned);
    assert_impl_all!(PinMutationSecrets: Zeroize,ZeroizeOnDrop);
    fn binding(op: PinOperation) -> PinMutationBinding {
        PinMutationBinding {
            operation: op,
            session: super::super::tests::binding(),
            intent_digest: [7; 32],
        }
    }
    fn secrets(op: PinOperation) -> PinMutationSecrets {
        let new = super::super::tests::pin();
        match op {
            PinOperation::SetPin => PinMutationSecrets::Set { new },
            PinOperation::ChangePin => PinMutationSecrets::Change {
                current: super::super::tests::pin(),
                new,
            },
        }
    }
    #[test]
    fn roundtrip_all_fields_truncation_trailing_replay_nul_oversize() {
        for op in [PinOperation::SetPin, PinOperation::ChangePin] {
            let b = binding(op);
            let mut bytes = Vec::new();
            assert!(send_mutation_secret(&mut bytes, b, 4, secrets(op)).is_ok());
            assert!(receive_mutation_secret(bytes.as_slice(), b, 4).is_ok());
            for len in 0..bytes.len() {
                assert!(receive_mutation_secret(&bytes[..len], b, 4).is_err());
            }
            for offset in [0, 7, 8, 9, 17, 25, 41, 57, 65, 73, 74, 75, 106] {
                let mut wrong = bytes.clone();
                wrong[offset] ^= 1;
                assert!(receive_mutation_secret(wrong.as_slice(), b, 4).is_err());
            }
            assert!(receive_mutation_secret(bytes.as_slice(), b, 5).is_err());
            for offset in [73, 74] {
                let mut oversized = bytes.clone();
                oversized[offset] = 64;
                assert!(receive_mutation_secret(oversized.as_slice(), b, 4).is_err());
            }
            let mut invalid_utf8 = bytes.clone();
            invalid_utf8[107] = 255;
            assert!(receive_mutation_secret(invalid_utf8.as_slice(), b, 4).is_err());
            let mut double = bytes.clone();
            double.extend_from_slice(&bytes);
            assert!(receive_mutation_secret(double.as_slice(), b, 4).is_err());
            bytes.push(0);
            assert!(receive_mutation_secret(bytes.as_slice(), b, 4).is_err());
            bytes.pop();
            bytes[107] = 0;
            assert!(receive_mutation_secret(bytes.as_slice(), b, 4).is_err());
        }
    }
    #[test]
    fn secret_zeroization_and_operation_mismatch() {
        let mut s = secrets(PinOperation::ChangePin);
        s.zeroize();
        let (n, c) = s.pins();
        assert!(n.bytes.iter().all(|b| *b == 0));
        assert!(c.is_some_and(|p| p.bytes.iter().all(|b| *b == 0)));
        assert!(send_mutation_secret(Vec::new(), binding(PinOperation::SetPin), 1, s).is_err());
    }
    #[test]
    fn capability_selection_is_explicit() {
        let v = vec!["FIDO_2_1".into()];
        assert_eq!(
            available_operation(&v, [("clientPin", false)]),
            Some(PinOperation::SetPin)
        );
        assert_eq!(
            available_operation(&v, [("clientPin", true)]),
            Some(PinOperation::ChangePin)
        );
        assert_eq!(available_operation(&v, []), None);
        assert_eq!(
            available_operation(&v, [("clientPin", true), ("clientPin", false)]),
            None
        );
        assert_eq!(
            available_operation(&["U2F_V2".into()], [("clientPin", false)]),
            None
        );
    }
    #[test]
    fn result_rejects_contradictory_or_operation_incompatible_reason() {
        for op in [PinOperation::SetPin, PinOperation::ChangePin] {
            for code in -11..=255 {
                let result = PinMutationResult::from_code(op, true, code, false);
                assert!(result.valid_for(op));
                let mut wrong = result;
                wrong.rejection = if result.rejection.is_some() {
                    None
                } else {
                    Some(PinRejection::PinPolicy)
                };
                assert!(!wrong.valid_for(op));
            }
        }
        assert!(
            !PinMutationResult::from_code(PinOperation::ChangePin, true, 0x31, true)
                .valid_for(PinOperation::SetPin)
        );
    }
}
