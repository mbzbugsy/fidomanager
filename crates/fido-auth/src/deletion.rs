//! Credential-deletion authentication and outcome contracts.
//!
//! No renderer types live here. The deletion call is a mutation even when libfido2 has to obtain
//! credential-management authorization internally from the supplied PIN.

use crate::{AcquisitionBinding, GrantKind};
use fido_core::MutationOutcome;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteCredentialBinding {
    pub session: AcquisitionBinding,
    pub intent_digest: [u8; 32],
}

/// Deletion requires the mutating credential-management permission even on authenticators that
/// also advertise per-credential-management read-only permission.
pub fn select_delete_kind<'a>(
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
    let credman = seen.get("credMgmt") == Some(&true);
    let preview = seen.get("credentialMgmtPreview") == Some(&true);

    if !permissions && versions.iter().any(|v| v == "FIDO_2_1") {
        return None;
    }

    if permissions && credman {
        Some(GrantKind::CredMan)
    } else if !permissions && !credman && preview && versions.iter().any(|v| v == "FIDO_2_0") {
        Some(GrantKind::LegacyUnscoped)
    } else {
        None
    }
}

/// Conservative post-entry classifier. Only explicit CTAP rejections prove that this call did not
/// delete the credential. Host/transport/parser failures after entry remain OutcomeUnknown.
pub const fn delete_call_outcome(entered: bool, code: i32) -> MutationOutcome {
    if !entered {
        return MutationOutcome::NotDispatched;
    }
    match code {
        0 => MutationOutcome::ConfirmedSuccessful,
        0x02 | 0x14 | 0x2e | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x40 => {
            MutationOutcome::Rejected
        }
        _ => MutationOutcome::OutcomeUnknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteCredentialRejection {
    Parameters,
    CredentialAbsent,
    WrongPin,
    PinBlocked,
    PinAuthInvalid,
    PinAuthBlocked,
    PinNotSet,
    PinRequired,
    UnauthorizedPermission,
    /// The current-session proof found the RP present but the credential identity ambiguous,
    /// changed or malformed. Never reached the delete call.
    CredentialMismatch,
}

/// Maps an explicit CTAP rejection status to its typed reason. `None` means the status is not an
/// explicit pre-effect rejection and must be treated conservatively by the caller.
const fn rejection_for_code(code: i32) -> Option<DeleteCredentialRejection> {
    Some(match code {
        0x02 | 0x14 => DeleteCredentialRejection::Parameters,
        0x2e => DeleteCredentialRejection::CredentialAbsent,
        0x31 => DeleteCredentialRejection::WrongPin,
        0x32 => DeleteCredentialRejection::PinBlocked,
        0x33 => DeleteCredentialRejection::PinAuthInvalid,
        0x34 => DeleteCredentialRejection::PinAuthBlocked,
        0x35 => DeleteCredentialRejection::PinNotSet,
        0x36 => DeleteCredentialRejection::PinRequired,
        0x40 => DeleteCredentialRejection::UnauthorizedPermission,
        _ => return None,
    })
}

/// Result of the read-only current-session credential proof. It runs BEFORE any durable
/// DispatchCapable record, so every non-`Proved` outcome is a provable "no DeleteCredential was
/// ever sent" and never creates a recovery barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteProofOutcome {
    Proved,
    /// An explicit pre-delete rejection (wrong PIN, credential absent, identity mismatch, ...).
    Rejected,
    /// The proof could not be completed (timeout, transport loss, unsupported device). Nothing
    /// can have been deleted because the delete call is not reachable from the proof step.
    NotProved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteProofResult {
    pub outcome: DeleteProofOutcome,
    pub rejection: Option<DeleteCredentialRejection>,
    pub native_closed: bool,
}

impl DeleteProofResult {
    pub const fn proved() -> Self {
        Self {
            outcome: DeleteProofOutcome::Proved,
            rejection: None,
            native_closed: false,
        }
    }

    pub const fn rejected(rejection: DeleteCredentialRejection, native_closed: bool) -> Self {
        Self {
            outcome: DeleteProofOutcome::Rejected,
            rejection: Some(rejection),
            native_closed,
        }
    }

    pub const fn not_proved(native_closed: bool) -> Self {
        Self {
            outcome: DeleteProofOutcome::NotProved,
            rejection: None,
            native_closed,
        }
    }

    /// Classify a libfido2/CTAP status returned by the proof's enumeration call.
    pub const fn from_proof_code(code: i32, native_closed: bool) -> Self {
        match rejection_for_code(code) {
            Some(rejection) => Self::rejected(rejection, native_closed),
            None => Self::not_proved(native_closed),
        }
    }

    pub fn valid(self) -> bool {
        matches!(
            (self.outcome, self.rejection),
            (DeleteProofOutcome::Proved, None)
                | (DeleteProofOutcome::Rejected, Some(_))
                | (DeleteProofOutcome::NotProved, None)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteCredentialResult {
    pub outcome: MutationOutcome,
    pub rejection: Option<DeleteCredentialRejection>,
    pub native_closed: bool,
}

impl DeleteCredentialResult {
    pub fn from_code(entered: bool, code: i32, native_closed: bool) -> Self {
        let outcome = delete_call_outcome(entered, code);
        let rejection = if outcome == MutationOutcome::Rejected {
            Some(rejection_for_code(code).unwrap_or(DeleteCredentialRejection::Parameters))
        } else {
            None
        };
        Self {
            outcome,
            rejection,
            native_closed,
        }
    }

    pub fn valid(self) -> bool {
        matches!(
            (self.outcome, self.rejection),
            (MutationOutcome::Rejected, Some(_))
                | (MutationOutcome::ConfirmedSuccessful, None)
                | (MutationOutcome::OutcomeUnknown, None)
                | (MutationOutcome::NotDispatched, None)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_results_are_typed_never_invent_a_rejection_and_never_serialize_a_secret() {
        use DeleteCredentialRejection as R;
        for (code, rejection) in [
            (0x31, Some(R::WrongPin)),
            (0x32, Some(R::PinBlocked)),
            (0x33, Some(R::PinAuthInvalid)),
            (0x34, Some(R::PinAuthBlocked)),
            (0x35, Some(R::PinNotSet)),
            (0x36, Some(R::PinRequired)),
            (0x2e, Some(R::CredentialAbsent)),
            (0x40, Some(R::UnauthorizedPermission)),
            (0x02, Some(R::Parameters)),
            // Transport, timeout, parser and unknown statuses are not explicit rejections.
            (-1, None),
            (-2, None),
            (-3, None),
            (0x05, None),
            (0x7f, None),
            (i32::MIN, None),
            (i32::MAX, None),
        ] {
            let result = DeleteProofResult::from_proof_code(code, true);
            assert_eq!(result.rejection, rejection, "{code:#x}");
            assert_eq!(
                result.outcome,
                if rejection.is_some() {
                    DeleteProofOutcome::Rejected
                } else {
                    DeleteProofOutcome::NotProved
                }
            );
            assert!(result.valid());
        }
        assert!(DeleteProofResult::proved().valid());
        assert!(!DeleteProofResult::proved().native_closed);
        // A mismatched outcome/reason pairing is invalid on the wire.
        for invalid in [
            DeleteProofResult {
                outcome: DeleteProofOutcome::Proved,
                rejection: Some(R::WrongPin),
                native_closed: false,
            },
            DeleteProofResult {
                outcome: DeleteProofOutcome::Rejected,
                rejection: None,
                native_closed: true,
            },
            DeleteProofResult {
                outcome: DeleteProofOutcome::NotProved,
                rejection: Some(R::WrongPin),
                native_closed: true,
            },
        ] {
            assert!(!invalid.valid());
        }
        // Only a typed outcome and a reason cross the wire; unknown fields are refused.
        let json = serde_json::to_string(&DeleteProofResult::rejected(R::WrongPin, true));
        assert_eq!(
            json.as_deref().ok(),
            Some(r#"{"outcome":"rejected","rejection":"wrong_pin","native_closed":true}"#)
        );
        assert!(
            serde_json::from_str::<DeleteProofResult>(
                r#"{"outcome":"proved","rejection":null,"native_closed":false,"pin":"x"}"#
            )
            .is_err()
        );
        // The delete-stage classification is unchanged by the shared code table.
        assert_eq!(
            DeleteCredentialResult::from_code(true, 0x2e, true).rejection,
            Some(R::CredentialAbsent)
        );
        assert_eq!(
            DeleteCredentialResult::from_code(true, 0x31, true).rejection,
            Some(R::WrongPin)
        );
    }

    #[test]
    fn deletion_requires_mutating_credman_permission() {
        let v21 = vec!["FIDO_2_1".into()];
        assert_eq!(
            select_delete_kind(
                &v21,
                [
                    ("clientPin", true),
                    ("pinUvAuthToken", true),
                    ("credMgmt", true),
                    ("perCredMgmtRO", true),
                ],
            ),
            Some(GrantKind::CredMan)
        );
        assert_eq!(
            select_delete_kind(
                &v21,
                [
                    ("clientPin", true),
                    ("pinUvAuthToken", true),
                    ("perCredMgmtRO", true),
                ],
            ),
            None
        );
        assert_eq!(
            select_delete_kind(
                &["FIDO_2_0".into()],
                [("clientPin", true), ("credentialMgmtPreview", true)],
            ),
            Some(GrantKind::LegacyUnscoped)
        );
        for versions in [&v21, &vec!["FIDO_2_0".into()]] {
            assert_eq!(
                select_delete_kind(
                    versions,
                    [
                        ("clientPin", true),
                        ("pinUvAuthToken", true),
                        ("credentialMgmtPreview", true)
                    ]
                ),
                None
            );
        }
        assert_eq!(
            select_delete_kind(&v21, [("clientPin", true), ("credMgmt", true)]),
            None
        );
        assert_eq!(
            select_delete_kind(
                &v21,
                [
                    ("clientPin", true),
                    ("clientPin", true),
                    ("pinUvAuthToken", true),
                    ("credMgmt", true),
                ],
            ),
            None
        );
    }

    #[test]
    fn post_entry_outcomes_are_conservative_and_self_consistent() {
        for code in (-11..=255).chain([i32::MIN, -1000, 1000, i32::MAX]) {
            let result = DeleteCredentialResult::from_code(true, code, false);
            assert!(result.valid());
            assert_eq!(result.outcome, delete_call_outcome(true, code));
        }

        let preentry = DeleteCredentialResult::from_code(false, 0, true);
        assert_eq!(preentry.outcome, MutationOutcome::NotDispatched);
        assert_eq!(preentry.rejection, None);

        for code in [0x02, 0x14, 0x2e, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x40] {
            assert_eq!(
                DeleteCredentialResult::from_code(true, code, true).outcome,
                MutationOutcome::Rejected
            );
        }
        for code in [-1, -2, -3, -4, -5, -9, 0x05, 0x06, 0x2f, 0x3a, 0x7f] {
            assert_eq!(
                DeleteCredentialResult::from_code(true, code, true).outcome,
                MutationOutcome::OutcomeUnknown
            );
        }
    }
}
