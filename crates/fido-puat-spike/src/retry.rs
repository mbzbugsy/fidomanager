//! Retry-state evidence and conservative interpretation of acquisition failures.
//!
//! What the pinned API can tell us before a PIN is submitted: `fido_dev_get_retry_count()` returns
//! `pinRetries` (clientPin subcommand 0x01, response key 0x03) and `fido_dev_get_uv_retry_count()`
//! returns `uvRetries` (subcommand 0x07, key 0x05). Neither consumes a retry. libfido2's parser
//! reads only those keys: `powerCycleState` (key 0x04) is discarded, so whether the authenticator
//! is currently in the "power cycle required" state cannot be known before an attempt.
//!
//! After an attempt, only two results are definitive evidence that a PIN retry was consumed. Every
//! other failure is "unknown" until the retry count is queried again; this is deliberately more
//! conservative than the CTAP text, which the spike has not yet confirmed on hardware.

/// libfido2 error codes from `fido/err.h` (1.17.0) that this module interprets.
pub mod codes {
    pub const FIDO_ERR_TX: i32 = -1;
    pub const FIDO_ERR_RX: i32 = -2;
    pub const FIDO_ERR_RX_NOT_CBOR: i32 = -3;
    pub const FIDO_ERR_RX_INVALID_CBOR: i32 = -4;
    pub const FIDO_ERR_INVALID_ARGUMENT: i32 = -7;
    pub const FIDO_ERR_INTERNAL: i32 = -9;
    pub const FIDO_ERR_INVALID_PARAMETER: i32 = 0x02;
    pub const FIDO_ERR_TIMEOUT: i32 = 0x05;
    pub const FIDO_ERR_OPERATION_DENIED: i32 = 0x27;
    pub const FIDO_ERR_KEEPALIVE_CANCEL: i32 = 0x2d;
    pub const FIDO_ERR_NO_CREDENTIALS: i32 = 0x2e;
    pub const FIDO_ERR_USER_ACTION_TIMEOUT: i32 = 0x2f;
    pub const FIDO_ERR_NOT_ALLOWED: i32 = 0x30;
    pub const FIDO_ERR_PIN_INVALID: i32 = 0x31;
    pub const FIDO_ERR_PIN_BLOCKED: i32 = 0x32;
    pub const FIDO_ERR_PIN_AUTH_INVALID: i32 = 0x33;
    pub const FIDO_ERR_PIN_AUTH_BLOCKED: i32 = 0x34;
    pub const FIDO_ERR_PIN_NOT_SET: i32 = 0x35;
    pub const FIDO_ERR_PIN_REQUIRED: i32 = 0x36;
    pub const FIDO_ERR_PIN_POLICY_VIOLATION: i32 = 0x37;
    pub const FIDO_ERR_PIN_TOKEN_EXPIRED: i32 = 0x38;
    pub const FIDO_ERR_ACTION_TIMEOUT: i32 = 0x3a;
    pub const FIDO_ERR_UV_BLOCKED: i32 = 0x3c;
    pub const FIDO_ERR_UV_INVALID: i32 = 0x3f;
    pub const FIDO_ERR_UNAUTHORIZED_PERM: i32 = 0x40;
}

use codes::*;

/// Spike threshold for the prominent low-retry warning. A policy constant for M2 to fix.
pub const LOW_RETRY_WARNING_AT_OR_BELOW: u32 = 3;

/// What may be shown and decided before submitting a PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreSubmission {
    /// Retry count reported and comfortably above the warning threshold.
    Proceed { remaining: u32 },
    /// Retry count reported and low: show a prominent warning.
    WarnLowRetries { remaining: u32 },
    /// Exactly one retry reported: require an additional explicit acknowledgement.
    RequireLastRetryAcknowledgement,
    /// Zero reported: the PIN is blocked. Do not submit.
    RefuseBlocked,
    /// The query failed. The count is unknown; never display a guess. M2 policy decides whether
    /// to require acknowledgement or refuse; the spike harness refuses.
    Unknown { query_error: i32 },
}

/// `powerCycleState` is not exposed by `fido_dev_get_retry_count()` in libfido2 1.17.0.
pub const POWER_CYCLE_STATE_EXPOSED: bool = false;

pub fn pre_submission(query: Result<i32, i32>) -> PreSubmission {
    match query {
        Ok(remaining) if remaining <= 0 => PreSubmission::RefuseBlocked,
        Ok(1) => PreSubmission::RequireLastRetryAcknowledgement,
        Ok(remaining) => {
            let remaining = remaining.unsigned_abs();
            if remaining <= LOW_RETRY_WARNING_AT_OR_BELOW {
                PreSubmission::WarnLowRetries { remaining }
            } else {
                PreSubmission::Proceed { remaining }
            }
        }
        Err(query_error) => PreSubmission::Unknown { query_error },
    }
}

/// What a failed acquisition did to the PIN/UV retry counter, as far as the evidence shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryEffect {
    /// libfido2 returned before transmitting anything that carries the PIN (source-backed).
    NotSubmitted,
    /// The authenticator definitively rejected the PIN/UV and decremented the counter.
    Consumed,
    /// Anything else. Re-query the counter; never infer.
    Unknown,
}

/// Conservative classification of a non-`FIDO_OK` return from `fido_dev_get_puat()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionFailure {
    /// `FIDO_ERR_INVALID_ARGUMENT`: rejected inside libfido2 before any transmission (non-FIDO2
    /// device, Windows Hello pseudo-device, or argument copy failure).
    NotSubmitted,
    WrongPin,
    /// Too many consecutive wrong PINs in this power cycle: unplug/replug required.
    PinAuthBlocked,
    /// Retries exhausted: only a reset recovers the authenticator.
    PinBlocked,
    PinNotSet,
    PinRequired,
    PinPolicyViolation,
    UvBlocked,
    UvRejected,
    UvDeniedOrTimedOut,
    /// The authenticator refused the requested permissions or parameters.
    PermissionRejected,
    /// TX/RX failure, timeout, or malformed reply: the PIN may or may not have been processed.
    TransportUncertain,
    Other,
}

impl AcquisitionFailure {
    pub const fn retry_effect(self) -> RetryEffect {
        match self {
            Self::NotSubmitted => RetryEffect::NotSubmitted,
            Self::WrongPin | Self::PinAuthBlocked => RetryEffect::Consumed,
            _ => RetryEffect::Unknown,
        }
    }

    /// Must the application refuse further PIN submissions without user action outside the app?
    pub const fn blocks_further_attempts(self) -> bool {
        matches!(
            self,
            Self::PinAuthBlocked | Self::PinBlocked | Self::UvBlocked
        )
    }
}

pub fn classify_acquisition_error(code: i32) -> AcquisitionFailure {
    match code {
        FIDO_ERR_INVALID_ARGUMENT => AcquisitionFailure::NotSubmitted,
        FIDO_ERR_PIN_INVALID => AcquisitionFailure::WrongPin,
        FIDO_ERR_PIN_AUTH_BLOCKED => AcquisitionFailure::PinAuthBlocked,
        FIDO_ERR_PIN_BLOCKED => AcquisitionFailure::PinBlocked,
        FIDO_ERR_PIN_NOT_SET => AcquisitionFailure::PinNotSet,
        FIDO_ERR_PIN_REQUIRED => AcquisitionFailure::PinRequired,
        FIDO_ERR_PIN_POLICY_VIOLATION => AcquisitionFailure::PinPolicyViolation,
        FIDO_ERR_UV_BLOCKED => AcquisitionFailure::UvBlocked,
        FIDO_ERR_UV_INVALID => AcquisitionFailure::UvRejected,
        FIDO_ERR_OPERATION_DENIED
        | FIDO_ERR_USER_ACTION_TIMEOUT
        | FIDO_ERR_ACTION_TIMEOUT
        | FIDO_ERR_KEEPALIVE_CANCEL => AcquisitionFailure::UvDeniedOrTimedOut,
        FIDO_ERR_UNAUTHORIZED_PERM | FIDO_ERR_NOT_ALLOWED | FIDO_ERR_INVALID_PARAMETER => {
            AcquisitionFailure::PermissionRejected
        }
        FIDO_ERR_TX
        | FIDO_ERR_RX
        | FIDO_ERR_RX_NOT_CBOR
        | FIDO_ERR_RX_INVALID_CBOR
        | FIDO_ERR_TIMEOUT
        | FIDO_ERR_INTERNAL => AcquisitionFailure::TransportUncertain,
        _ => AcquisitionFailure::Other,
    }
}

/// Result of using an attached token for a credential-management read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenUseResult {
    Accepted,
    /// The authenticator no longer accepts this token (regenerated, expired, power-cycled, or
    /// never valid for this command). libfido2 does *not* clear it from the `fido_dev_t`.
    TokenRejected,
    /// The token was accepted for authentication but lacks the permission for this command.
    PermissionRejected,
    /// libfido2 refused before sending: there was no token and no PIN/UV to fall back on.
    NoAuthorizationAvailable,
    Uncertain,
    Other,
}

pub fn classify_token_use(code: i32) -> TokenUseResult {
    match code {
        0 => TokenUseResult::Accepted,
        FIDO_ERR_PIN_AUTH_INVALID | FIDO_ERR_PIN_TOKEN_EXPIRED => TokenUseResult::TokenRejected,
        FIDO_ERR_UNAUTHORIZED_PERM | FIDO_ERR_NOT_ALLOWED => TokenUseResult::PermissionRejected,
        FIDO_ERR_PIN_REQUIRED => TokenUseResult::NoAuthorizationAvailable,
        FIDO_ERR_TX | FIDO_ERR_RX | FIDO_ERR_TIMEOUT | FIDO_ERR_INTERNAL => {
            TokenUseResult::Uncertain
        }
        _ => TokenUseResult::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_submission_thresholds() {
        assert_eq!(
            pre_submission(Ok(8)),
            PreSubmission::Proceed { remaining: 8 }
        );
        assert_eq!(
            pre_submission(Ok(3)),
            PreSubmission::WarnLowRetries { remaining: 3 }
        );
        assert_eq!(
            pre_submission(Ok(2)),
            PreSubmission::WarnLowRetries { remaining: 2 }
        );
        assert_eq!(
            pre_submission(Ok(1)),
            PreSubmission::RequireLastRetryAcknowledgement
        );
        assert_eq!(pre_submission(Ok(0)), PreSubmission::RefuseBlocked);
        assert_eq!(pre_submission(Ok(-1)), PreSubmission::RefuseBlocked);
        assert_eq!(
            pre_submission(Err(FIDO_ERR_RX)),
            PreSubmission::Unknown {
                query_error: FIDO_ERR_RX
            }
        );
    }

    // libfido2 1.17.0 discards powerCycleState; flipping this constant must be a deliberate,
    // evidence-backed change that fails the build of these tests until it is reviewed.
    const _: () = assert!(!POWER_CYCLE_STATE_EXPOSED);

    #[test]
    fn only_invalid_argument_is_not_submitted_and_only_two_codes_prove_consumption() {
        // Sweep every code libfido2 can return (negative library codes and CTAP status bytes).
        for code in -64..=0xff {
            if code == 0 {
                continue;
            }
            let failure = classify_acquisition_error(code);
            match failure.retry_effect() {
                RetryEffect::NotSubmitted => assert_eq!(code, FIDO_ERR_INVALID_ARGUMENT),
                RetryEffect::Consumed => assert!(
                    code == FIDO_ERR_PIN_INVALID || code == FIDO_ERR_PIN_AUTH_BLOCKED,
                    "code {code:#x} must not be treated as proof a retry was consumed"
                ),
                RetryEffect::Unknown => {}
            }
        }
    }

    #[test]
    fn transport_failures_are_uncertain_not_safe() {
        for code in [
            FIDO_ERR_TX,
            FIDO_ERR_RX,
            FIDO_ERR_TIMEOUT,
            FIDO_ERR_INTERNAL,
            FIDO_ERR_RX_INVALID_CBOR,
        ] {
            let failure = classify_acquisition_error(code);
            assert_eq!(failure, AcquisitionFailure::TransportUncertain);
            assert_eq!(failure.retry_effect(), RetryEffect::Unknown);
        }
    }

    #[test]
    fn blocked_states_are_explicit_and_stop_attempts() {
        assert_eq!(
            classify_acquisition_error(FIDO_ERR_PIN_AUTH_BLOCKED),
            AcquisitionFailure::PinAuthBlocked
        );
        assert_eq!(
            classify_acquisition_error(FIDO_ERR_PIN_BLOCKED),
            AcquisitionFailure::PinBlocked
        );
        assert_eq!(
            classify_acquisition_error(FIDO_ERR_UV_BLOCKED),
            AcquisitionFailure::UvBlocked
        );
        for failure in [
            AcquisitionFailure::PinAuthBlocked,
            AcquisitionFailure::PinBlocked,
            AcquisitionFailure::UvBlocked,
        ] {
            assert!(failure.blocks_further_attempts());
        }
        assert!(!AcquisitionFailure::WrongPin.blocks_further_attempts());
    }

    #[test]
    fn unknown_codes_fall_to_other_with_unknown_effect() {
        let failure = classify_acquisition_error(0x7f);
        assert_eq!(failure, AcquisitionFailure::Other);
        assert_eq!(failure.retry_effect(), RetryEffect::Unknown);
    }

    #[test]
    fn token_use_mapping() {
        assert_eq!(classify_token_use(0), TokenUseResult::Accepted);
        assert_eq!(
            classify_token_use(FIDO_ERR_PIN_AUTH_INVALID),
            TokenUseResult::TokenRejected
        );
        assert_eq!(
            classify_token_use(FIDO_ERR_PIN_REQUIRED),
            TokenUseResult::NoAuthorizationAvailable
        );
        assert_eq!(classify_token_use(FIDO_ERR_RX), TokenUseResult::Uncertain);
        assert_eq!(
            classify_token_use(FIDO_ERR_NO_CREDENTIALS),
            TokenUseResult::Other
        );
    }
}
