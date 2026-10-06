//! Private credential-deletion execution policy shared by the macOS adapter and fixtures.

use crate::NativeDeadline;
use fido_auth::{PinSecret, deletion::DeleteCredentialResult};
use fido_core::inventory::MAX_CREDENTIAL_ID_BYTES;

#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
pub(crate) trait DeletionNative {
    fn revalidate(&mut self, deadline: &NativeDeadline) -> bool;
    fn enter_once(&mut self, credential_id: &[u8], pin: &PinSecret) -> i32;
    fn close(&mut self) -> bool;
}

#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
pub(crate) fn execute(
    native: &mut impl DeletionNative,
    credential_id: Vec<u8>,
    pin: PinSecret,
    deadline: NativeDeadline,
) -> DeleteCredentialResult {
    if credential_id.is_empty()
        || credential_id.len() > MAX_CREDENTIAL_ID_BYTES
        || !native.revalidate(&deadline)
    {
        drop(pin);
        return DeleteCredentialResult::from_code(false, -1, native.close());
    }

    let code = native.enter_once(&credential_id, &pin);
    drop(pin);
    DeleteCredentialResult::from_code(true, code, native.close())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_core::MutationOutcome;

    struct Native {
        compatible: bool,
        code: i32,
        calls: usize,
        closed: bool,
    }

    impl DeletionNative for Native {
        fn revalidate(&mut self, deadline: &NativeDeadline) -> bool {
            self.compatible && !deadline.remaining().is_zero()
        }

        fn enter_once(&mut self, _: &[u8], _: &PinSecret) -> i32 {
            self.calls += 1;
            self.code
        }

        fn close(&mut self) -> bool {
            self.closed
        }
    }

    fn pin() -> PinSecret {
        PinSecret::collect(|bytes| {
            bytes[..4].copy_from_slice(b"fake");
            Some(4)
        })
        .unwrap_or_else(|_| panic!("synthetic PIN"))
    }

    #[test]
    fn exactly_one_native_delete_after_all_preentry_guards() {
        for code in (-11..=255).chain([i32::MIN, -1000, 1000, i32::MAX]) {
            let mut native = Native {
                compatible: true,
                code,
                calls: 0,
                closed: false,
            };
            let result = execute(
                &mut native,
                vec![1, 2, 3],
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
                code: 0,
                calls: 0,
                closed: true,
            };
            let result = execute(
                &mut native,
                credential_id,
                pin(),
                NativeDeadline::after(budget),
            );
            assert_eq!(native.calls, 0);
            assert_eq!(result.outcome, MutationOutcome::NotDispatched);
            assert!(result.native_closed);
        }
    }
}
