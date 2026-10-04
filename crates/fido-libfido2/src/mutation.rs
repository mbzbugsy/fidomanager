//! Private execution policy shared by the macOS adapter and deterministic native-call fixtures.
use crate::NativeDeadline;
use fido_auth::mutation::{PinMutationResult, PinMutationSecrets, PinOperation};
#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
pub(crate) trait PinNative {
    fn revalidate(&mut self, operation: PinOperation, deadline: &NativeDeadline) -> bool;
    fn enter_once(&mut self, secrets: &PinMutationSecrets) -> i32;
    fn close(&mut self) -> bool;
}
#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
pub(crate) fn execute(
    native: &mut impl PinNative,
    operation: PinOperation,
    secrets: PinMutationSecrets,
    deadline: NativeDeadline,
) -> PinMutationResult {
    if secrets.operation() != operation || !native.revalidate(operation, &deadline) {
        drop(secrets);
        return PinMutationResult::from_code(operation, false, -1, native.close());
    }
    let code = native.enter_once(&secrets);
    drop(secrets);
    // Cleanup never overwrites the definitive native result; session ownership is consumed by caller.
    PinMutationResult::from_code(operation, true, code, native.close())
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
    impl PinNative for Native {
        fn revalidate(&mut self, _: PinOperation, d: &NativeDeadline) -> bool {
            self.compatible && !d.remaining().is_zero()
        }
        fn enter_once(&mut self, _: &PinMutationSecrets) -> i32 {
            self.calls += 1;
            self.code
        }
        fn close(&mut self) -> bool {
            self.closed
        }
    }
    fn pin() -> fido_auth::PinSecret {
        fido_auth::PinSecret::collect(|b| {
            b[..4].copy_from_slice(b"fake");
            Some(4)
        })
        .unwrap_or_else(|_| panic!("synthetic"))
    }
    #[test]
    fn preentry_gate_and_postentry_classifier_all_statuses_cleanup_separate() {
        for op in [PinOperation::SetPin, PinOperation::ChangePin] {
            for code in (-11..=255).chain([i32::MIN, -1000, 1000, i32::MAX]) {
                let new = pin();
                let secrets = match op {
                    PinOperation::SetPin => PinMutationSecrets::Set { new },
                    PinOperation::ChangePin => PinMutationSecrets::Change {
                        current: pin(),
                        new,
                    },
                };
                let mut native = Native {
                    compatible: true,
                    code,
                    calls: 0,
                    closed: false,
                };
                let result = execute(
                    &mut native,
                    op,
                    secrets,
                    NativeDeadline::after(std::time::Duration::from_secs(1)),
                );
                assert_eq!(
                    result.outcome,
                    fido_auth::mutation::pin_call_outcome(op, true, code)
                );
                assert_eq!(native.calls, 1);
                assert!(!result.native_closed);
            }
        }
        for (compatible, budget) in [
            (false, std::time::Duration::from_secs(1)),
            (true, std::time::Duration::ZERO),
        ] {
            let mut n = Native {
                compatible,
                code: 0,
                calls: 0,
                closed: true,
            };
            let result = execute(
                &mut n,
                PinOperation::SetPin,
                PinMutationSecrets::Set { new: pin() },
                NativeDeadline::after(budget),
            );
            assert_eq!(n.calls, 0);
            assert_eq!(result.outcome, MutationOutcome::NotDispatched);
        }
        let mut n = Native {
            compatible: true,
            code: 0,
            calls: 0,
            closed: true,
        };
        let result = execute(
            &mut n,
            PinOperation::ChangePin,
            PinMutationSecrets::Set { new: pin() },
            NativeDeadline::after(std::time::Duration::from_secs(1)),
        );
        assert_eq!(n.calls, 0);
        assert_eq!(result.outcome, MutationOutcome::NotDispatched);
    }
}
