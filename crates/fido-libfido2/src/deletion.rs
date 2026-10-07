//! Private credential-deletion execution policy shared by the macOS adapter and fixtures.

#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
use crate::NativeDeadline;
use fido_auth::deletion::{DeleteCredentialRejection, DeleteProofResult};
#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
use fido_auth::{PinSecret, deletion::DeleteCredentialResult};
#[cfg(test)]
use fido_core::inventory::MAX_CREDENTIAL_ID_BYTES;
use fido_core::inventory::{DeletionIdentity, OwnedCredential, OwnedInventory, OwnedRp};
use sha2::{Digest, Sha256};

/// Outcome of the data half of the current-session proof, before CTAP status classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofStatus {
    /// Exactly one matching credential on the verified RP; every row well formed.
    Proved,
    /// The enumeration call itself returned this libfido2/CTAP status.
    Ctap(i32),
    /// RP enumerated but the credential ID is not present (or the RP has no credentials).
    Absent,
    /// Duplicate IDs, changed user.id, malformed or out-of-bound rows, or a bad RP binding.
    Mismatch,
}

/// Exact current-RP proof. Reject all malformed rows and duplicate IDs, including unrelated rows.
/// This data check is necessary but grants no standalone native authority.
pub fn classify_current_credentials(
    target: &DeletionIdentity,
    credentials: &[OwnedCredential],
) -> ProofStatus {
    if !target.within_bounds()
        || <[u8; 32]>::from(Sha256::digest(target.rp_text.as_bytes())) != target.rp_hash
        || credentials.len() > fido_core::inventory::MAX_CREDENTIALS
    {
        return ProofStatus::Mismatch;
    }
    if !credentials.iter().any(|c| c.id == target.credential_id) {
        return ProofStatus::Absent;
    }
    let inventory = OwnedInventory {
        metadata_existing: credentials.len() as u64,
        rps: vec![OwnedRp {
            hash: target.rp_hash,
            verified_text: Some(target.rp_text.clone()),
            issue: None,
            credentials: credentials.to_vec(),
        }],
    };
    if inventory.within_bounds()
        && inventory.assess().completeness == fido_core::inventory::Completeness::Complete
        && credentials
            .iter()
            .filter(|c| c.id == target.credential_id)
            .count()
            == 1
        && credentials.iter().any(|c| {
            c.id == target.credential_id
                && target
                    .user_id
                    .as_ref()
                    .is_none_or(|id| c.user_id.as_ref() == Some(id))
        })
    {
        ProofStatus::Proved
    } else {
        ProofStatus::Mismatch
    }
}

pub fn matches_current_credentials(
    target: &DeletionIdentity,
    credentials: &[OwnedCredential],
) -> bool {
    classify_current_credentials(target, credentials) == ProofStatus::Proved
}

impl ProofStatus {
    /// Typed proof result. Every non-proved status is provably pre-delete: the proof step has no
    /// access to the delete call.
    pub fn into_result(self, native_closed: bool) -> DeleteProofResult {
        match self {
            Self::Proved => DeleteProofResult::proved(),
            Self::Ctap(code) => DeleteProofResult::from_proof_code(code, native_closed),
            Self::Absent => DeleteProofResult::rejected(
                DeleteCredentialRejection::CredentialAbsent,
                native_closed,
            ),
            Self::Mismatch => DeleteProofResult::rejected(
                DeleteCredentialRejection::CredentialMismatch,
                native_closed,
            ),
        }
    }
}

#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
pub(crate) trait DeletionNative {
    fn revalidate(&mut self, deadline: &NativeDeadline) -> bool;
    fn prove(
        &mut self,
        target: &DeletionIdentity,
        pin: &PinSecret,
        deadline: &NativeDeadline,
    ) -> ProofStatus;
    fn enter_once(&mut self, credential_id: &[u8], pin: &PinSecret) -> i32;
    fn close(&mut self) -> bool;
}

/// Read-only proof step. It runs before the durable DispatchCapable record and can never reach
/// `enter_once`. Any failure closes the native device and is a provable "nothing was sent".
#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
pub(crate) fn prove(
    native: &mut impl DeletionNative,
    target: &DeletionIdentity,
    pin: &PinSecret,
    deadline: &NativeDeadline,
) -> DeleteProofResult {
    let status = if !target.within_bounds()
        || <[u8; 32]>::from(Sha256::digest(target.rp_text.as_bytes())) != target.rp_hash
    {
        Some(ProofStatus::Mismatch)
    } else if !native.revalidate(deadline) {
        None
    } else {
        match native.prove(target, pin, deadline) {
            ProofStatus::Proved if deadline.remaining().is_zero() => None,
            status => Some(status),
        }
    };
    match status {
        Some(ProofStatus::Proved) => DeleteProofResult::proved(),
        Some(status) => {
            let closed = native.close();
            status.into_result(closed)
        }
        None => DeleteProofResult::not_proved(native.close()),
    }
}

/// The single native deletion. The caller has already proved the exact credential on this same
/// open session and has durably recorded DispatchCapable; no proof, GetInfo or retry-count call
/// is repeated here, so the only remaining uncertainty is uncertainty about a real delete.
#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
pub(crate) fn execute(
    native: &mut impl DeletionNative,
    target: &DeletionIdentity,
    pin: PinSecret,
    deadline: NativeDeadline,
) -> DeleteCredentialResult {
    if !target.within_bounds() || deadline.remaining().is_zero() {
        drop(pin);
        return DeleteCredentialResult::from_code(false, -1, native.close());
    }

    let code = native.enter_once(&target.credential_id, &pin);
    drop(pin);
    DeleteCredentialResult::from_code(true, code, native.close())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_core::MutationOutcome;

    struct Native {
        compatible: bool,
        proof: ProofStatus,
        code: i32,
        calls: usize,
        proofs: usize,
        revalidations: usize,
        closed: bool,
    }

    impl Native {
        fn new(proof: ProofStatus, code: i32) -> Self {
            Self {
                compatible: true,
                proof,
                code,
                calls: 0,
                proofs: 0,
                revalidations: 0,
                closed: true,
            }
        }
    }

    impl DeletionNative for Native {
        fn revalidate(&mut self, deadline: &NativeDeadline) -> bool {
            self.revalidations += 1;
            self.compatible && !deadline.remaining().is_zero()
        }

        fn prove(
            &mut self,
            _: &DeletionIdentity,
            _: &PinSecret,
            _: &NativeDeadline,
        ) -> ProofStatus {
            self.proofs += 1;
            self.proof
        }

        fn enter_once(&mut self, _: &[u8], _: &PinSecret) -> i32 {
            self.calls += 1;
            self.code
        }

        fn close(&mut self) -> bool {
            self.closed
        }
    }

    fn target(credential_id: Vec<u8>) -> DeletionIdentity {
        DeletionIdentity {
            rp_text: "example.com".into(),
            rp_hash: Sha256::digest(b"example.com").into(),
            credential_id,
            user_id: Some(vec![8]),
        }
    }
    fn row() -> OwnedCredential {
        OwnedCredential {
            id: vec![1],
            user_id: Some(vec![8]),
            user_name: None,
            display_name: None,
        }
    }
    #[test]
    fn proof_classifies_absence_ambiguity_changed_user_malformed_and_wrong_rp() {
        let target = target(vec![1]);
        let row = row();
        let status =
            |t: &DeletionIdentity, c: &[OwnedCredential]| classify_current_credentials(t, c);
        assert_eq!(
            status(&target, std::slice::from_ref(&row)),
            ProofStatus::Proved
        );
        assert!(matches_current_credentials(
            &target,
            std::slice::from_ref(&row)
        ));
        assert_eq!(status(&target, &[]), ProofStatus::Absent);
        assert_eq!(
            status(&target, &[row.clone(), row.clone()]),
            ProofStatus::Mismatch
        );
        let mut wrong = row.clone();
        wrong.user_id = Some(vec![9]);
        assert_eq!(status(&target, &[wrong]), ProofStatus::Mismatch);
        let mut wrong = row.clone();
        wrong.id = vec![2];
        assert_eq!(status(&target, &[wrong]), ProofStatus::Absent);
        let mut wrong = row.clone();
        wrong.user_name = Some("bad\n".into());
        assert_eq!(status(&target, &[wrong]), ProofStatus::Mismatch);
        let mut unrelated_malformed = row.clone();
        unrelated_malformed.id = vec![3];
        unrelated_malformed.user_name = Some("bad\n".into());
        assert_eq!(
            status(&target, &[row.clone(), unrelated_malformed]),
            ProofStatus::Mismatch
        );
        let mut target = target;
        target.rp_hash = [0; 32];
        assert_eq!(status(&target, &[row]), ProofStatus::Mismatch);
    }
    fn pin() -> PinSecret {
        PinSecret::collect(|bytes| {
            bytes[..4].copy_from_slice(b"fake");
            Some(4)
        })
        .unwrap_or_else(|_| panic!("synthetic PIN"))
    }
    fn deadline() -> NativeDeadline {
        NativeDeadline::after(std::time::Duration::from_secs(1))
    }

    #[test]
    fn proof_never_reaches_the_native_delete_and_types_every_failure() {
        use fido_auth::deletion::{DeleteCredentialRejection as R, DeleteProofOutcome as O};
        let cases = [
            (ProofStatus::Proved, O::Proved, None),
            (ProofStatus::Absent, O::Rejected, Some(R::CredentialAbsent)),
            (
                ProofStatus::Mismatch,
                O::Rejected,
                Some(R::CredentialMismatch),
            ),
            (ProofStatus::Ctap(0x31), O::Rejected, Some(R::WrongPin)),
            (ProofStatus::Ctap(0x32), O::Rejected, Some(R::PinBlocked)),
            (
                ProofStatus::Ctap(0x34),
                O::Rejected,
                Some(R::PinAuthBlocked),
            ),
            (
                ProofStatus::Ctap(0x2e),
                O::Rejected,
                Some(R::CredentialAbsent),
            ),
            // Transport, timeout and parser failures are never invented into a rejection.
            (ProofStatus::Ctap(-3), O::NotProved, None),
            (ProofStatus::Ctap(-1), O::NotProved, None),
            (ProofStatus::Ctap(0x05), O::NotProved, None),
        ];
        for (status, outcome, rejection) in cases {
            let mut native = Native::new(status, 0);
            let result = prove(&mut native, &target(vec![1]), &pin(), &deadline());
            assert_eq!(result.outcome, outcome, "{status:?}");
            assert_eq!(result.rejection, rejection, "{status:?}");
            assert!(result.valid());
            assert_eq!(native.calls, 0, "proof must never enter the delete");
            assert_eq!(native.proofs, 1);
            // A failed proof closes the device; a successful one keeps it for execute.
            assert_eq!(result.native_closed, outcome != O::Proved);
        }

        // Pre-proof guards: incompatible device, expired budget, bad RP binding, bad bounds.
        for (compatible, budget, hash_ok, id) in [
            (false, 1, true, vec![1]),
            (true, 0, true, vec![1]),
            (true, 1, false, vec![1]),
            (true, 1, true, Vec::new()),
            (true, 1, true, vec![1; MAX_CREDENTIAL_ID_BYTES + 1]),
        ] {
            let mut native = Native::new(ProofStatus::Proved, 0);
            native.compatible = compatible;
            let mut t = target(id);
            if !hash_ok {
                t.rp_hash = [0; 32];
            }
            let result = prove(
                &mut native,
                &t,
                &pin(),
                &NativeDeadline::after(std::time::Duration::from_secs(budget)),
            );
            assert_ne!(
                result.outcome,
                fido_auth::deletion::DeleteProofOutcome::Proved
            );
            assert!(result.valid());
            assert_eq!(native.calls, 0);
        }
    }

    #[test]
    fn exactly_one_native_delete_without_repeating_any_proof() {
        for code in (-11..=255).chain([i32::MIN, -1000, 1000, i32::MAX]) {
            let mut native = Native::new(ProofStatus::Proved, code);
            native.closed = false;
            let result = execute(&mut native, &target(vec![1, 2, 3]), pin(), deadline());
            assert_eq!(
                result.outcome,
                fido_auth::deletion::delete_call_outcome(true, code)
            );
            assert_eq!(native.calls, 1);
            // Execute repeats neither GetInfo/retry revalidation nor the enumeration proof, so
            // nothing after the durable DispatchCapable record can be a provable pre-delete
            // failure of those steps.
            assert_eq!((native.proofs, native.revalidations), (0, 0));
            assert!(!result.native_closed);
        }

        for (credential_id, budget) in [
            (Vec::new(), std::time::Duration::from_secs(1)),
            (
                vec![1; MAX_CREDENTIAL_ID_BYTES + 1],
                std::time::Duration::from_secs(1),
            ),
            (vec![1], std::time::Duration::ZERO),
        ] {
            let mut native = Native::new(ProofStatus::Proved, 0);
            let result = execute(
                &mut native,
                &target(credential_id),
                pin(),
                NativeDeadline::after(budget),
            );
            assert_eq!(native.calls, 0);
            assert_eq!(result.outcome, MutationOutcome::NotDispatched);
            assert!(result.native_closed);
        }
    }
}
