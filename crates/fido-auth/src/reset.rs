//! M6.1 FIDO2 Reset outcome contract (ADR-011).
//!
//! Pure classification only. No Reset call, binding or worker request exists yet; this module
//! fixes the conservative rule the future single Reset call site must use.

/// Outcome of the one native Reset call and its dispatch phase only (ADR-011 Decision 7).
///
/// Deliberately a separate type from [`fido_core::MutationOutcome`]: no M4/M5 outcome table is
/// reused as Reset evidence (Decision 1). There is no `Rejected` variant. A status may become a
/// rejection only after CTAP PS §6.6 is verified verbatim and sacrificial-hardware runs prove the
/// Reset was not performed; until then such a variant would be unreachable by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetCommandOutcome {
    /// Proven by phase: the native call was never entered.
    NotDispatched,
    /// The native call returned `FIDO_OK`.
    ConfirmedSuccessful,
    /// Every other result after entry, including transport, timeout and every positive status.
    OutcomeUnknown,
}

/// ADR-011 conservative initial rule. Reset safety is never inferred from a CTAP error.
pub const fn reset_call_outcome(entered: bool, code: i32) -> ResetCommandOutcome {
    if !entered {
        return ResetCommandOutcome::NotDispatched;
    }
    match code {
        0 => ResetCommandOutcome::ConfirmedSuccessful,
        _ => ResetCommandOutcome::OutcomeUnknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_core::MutationOutcome;

    // A Reset outcome can neither be produced from nor turned into a PIN/deletion outcome.
    static_assertions::assert_not_impl_any!(ResetCommandOutcome: From<MutationOutcome>);
    static_assertions::assert_not_impl_any!(MutationOutcome: From<ResetCommandOutcome>);

    #[test]
    fn pre_entry_is_not_dispatched_for_every_code() {
        for code in (-11..=255).chain([i32::MIN, -1000, 1000, i32::MAX]) {
            assert_eq!(
                reset_call_outcome(false, code),
                ResetCommandOutcome::NotDispatched,
                "{code:#x}"
            );
        }
    }

    #[test]
    fn only_fido_ok_after_entry_is_confirmed_successful() {
        for code in (-11..=255).chain([i32::MIN, -1000, 1000, i32::MAX]) {
            let expected = if code == 0 {
                ResetCommandOutcome::ConfirmedSuccessful
            } else {
                ResetCommandOutcome::OutcomeUnknown
            };
            assert_eq!(reset_call_outcome(true, code), expected, "{code:#x}");
        }
    }

    #[test]
    fn adr_011_rejection_candidates_stay_unknown() {
        // NOT_ALLOWED, OPERATION_DENIED, USER_ACTION_TIMEOUT, ACTION_TIMEOUT: evaluated, none
        // accepted as proof that the Reset was not performed.
        for code in [0x30, 0x27, 0x2f, 0x3a] {
            assert_eq!(
                reset_call_outcome(true, code),
                ResetCommandOutcome::OutcomeUnknown,
                "{code:#x}"
            );
        }
        // libfido2 negative host errors, FIDO_ERR_TX (-1) through FIDO_ERR_INTERNAL (-9).
        for code in [-1, -2, -3, -4, -5, -6, -7, -8, -9] {
            assert_eq!(
                reset_call_outcome(true, code),
                ResetCommandOutcome::OutcomeUnknown,
                "{code}"
            );
        }
    }
}
