//! Private credential-deletion execution policy shared by the macOS adapter and fixtures.

#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
use crate::NativeDeadline;
#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
use fido_auth::{PinSecret, deletion::DeleteCredentialResult};
#[cfg(test)]
use fido_core::inventory::MAX_CREDENTIAL_ID_BYTES;
use fido_core::inventory::{DeletionIdentity, OwnedCredential, OwnedInventory, OwnedRp};
use sha2::{Digest, Sha256};

/// Exact current-RP proof. Reject all malformed rows and duplicate IDs, including unrelated rows.
/// This data check is necessary but grants no standalone native authority.
pub fn matches_current_credentials(
    target: &DeletionIdentity,
    credentials: &[OwnedCredential],
) -> bool {
    if credentials.is_empty()
        || credentials.len() > fido_core::inventory::MAX_CREDENTIALS
        || !target.within_bounds()
        || <[u8; 32]>::from(Sha256::digest(target.rp_text.as_bytes())) != target.rp_hash
    {
        return false;
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
    inventory.within_bounds()
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
}

#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
pub(crate) trait DeletionNative {
    fn revalidate(&mut self, deadline: &NativeDeadline) -> bool;
    fn prove(
        &mut self,
        target: &DeletionIdentity,
        pin: &PinSecret,
        deadline: &NativeDeadline,
    ) -> bool;
    fn enter_once(&mut self, credential_id: &[u8], pin: &PinSecret) -> i32;
    fn close(&mut self) -> bool;
}

#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
pub(crate) fn execute(
    native: &mut impl DeletionNative,
    target: DeletionIdentity,
    pin: PinSecret,
    deadline: NativeDeadline,
) -> DeleteCredentialResult {
    if !target.within_bounds()
        || <[u8; 32]>::from(Sha256::digest(target.rp_text.as_bytes())) != target.rp_hash
        || !native.revalidate(&deadline)
        || !native.prove(&target, &pin, &deadline)
        || deadline.remaining().is_zero()
    {
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
        proof: bool,
        code: i32,
        calls: usize,
        closed: bool,
    }

    impl DeletionNative for Native {
        fn revalidate(&mut self, deadline: &NativeDeadline) -> bool {
            self.compatible && !deadline.remaining().is_zero()
        }

        fn prove(&mut self, _: &DeletionIdentity, _: &PinSecret, _: &NativeDeadline) -> bool {
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
    #[test]
    fn proof_rejects_absence_ambiguity_changed_user_malformed_and_wrong_rp() {
        let target = target(vec![1]);
        let row = OwnedCredential {
            id: vec![1],
            user_id: Some(vec![8]),
            user_name: None,
            display_name: None,
        };
        assert!(matches_current_credentials(
            &target,
            std::slice::from_ref(&row)
        ));
        assert!(!matches_current_credentials(&target, &[]));
        assert!(!matches_current_credentials(
            &target,
            &[row.clone(), row.clone()]
        ));
        let mut wrong = row.clone();
        wrong.user_id = Some(vec![9]);
        assert!(!matches_current_credentials(&target, &[wrong]));
        let mut wrong = row.clone();
        wrong.id = vec![2];
        assert!(!matches_current_credentials(&target, &[wrong]));
        let mut wrong = row.clone();
        wrong.user_name = Some("bad\n".into());
        assert!(!matches_current_credentials(&target, &[wrong]));
        let mut target = target;
        target.rp_hash = [0; 32];
        assert!(!matches_current_credentials(&target, &[row]));
    }
    fn pin() -> PinSecret {
        PinSecret::collect(|bytes| {
            bytes[..4].copy_from_slice(b"fake");
            Some(4)
        })
        .unwrap_or_else(|_| panic!("synthetic PIN"))
    }

    #[test]
    fn failed_current_session_proof_never_enters_native_delete() {
        let mut native = Native {
            compatible: true,
            proof: false,
            code: 0,
            calls: 0,
            closed: true,
        };
        let result = execute(
            &mut native,
            target(vec![1]),
            pin(),
            NativeDeadline::after(std::time::Duration::from_secs(1)),
        );
        assert_eq!(result.outcome, MutationOutcome::NotDispatched);
        assert_eq!(native.calls, 0);
        assert!(result.native_closed);
    }
    #[test]
    fn exactly_one_native_delete_after_all_preentry_guards() {
        for code in (-11..=255).chain([i32::MIN, -1000, 1000, i32::MAX]) {
            let mut native = Native {
                compatible: true,
                proof: true,
                code,
                calls: 0,
                closed: false,
            };
            let result = execute(
                &mut native,
                target(vec![1, 2, 3]),
                pin(),
                NativeDeadline::after(std::time::Duration::from_secs(1)),
            );
            assert_eq!(
                result.outcome,
                fido_auth::deletion::delete_call_outcome(true, code)
            );
            assert_eq!(native.calls, 1);
            assert!(!result.native_closed);
        }

        for (credential_id, compatible, budget) in [
            (Vec::new(), true, std::time::Duration::from_secs(1)),
            (
                vec![1; MAX_CREDENTIAL_ID_BYTES + 1],
                true,
                std::time::Duration::from_secs(1),
            ),
            (vec![1], false, std::time::Duration::from_secs(1)),
            (vec![1], true, std::time::Duration::ZERO),
        ] {
            let mut native = Native {
                compatible,
                proof: true,
                code: 0,
                calls: 0,
                closed: true,
            };
            let result = execute(
                &mut native,
                target(credential_id),
                pin(),
                NativeDeadline::after(budget),
            );
            assert_eq!(native.calls, 0);
            assert_eq!(result.outcome, MutationOutcome::NotDispatched);
            assert!(result.native_closed);
        }
    }
}
