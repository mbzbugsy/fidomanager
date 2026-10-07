//! Backend-only sensitive-interaction contract. PIN completion never enters renderer DTOs.
//!
//! One controller belongs to one trusted authority. The authority supplies a workflow generation;
//! the controller mints a fresh prompt identity. Native hosts hold the reservation until teardown
//! is proven, then deliver one bound result through an owned Rust channel. Approval is only prompt
//! evidence: it is not an operation permit, and cannot dispatch any FIDO operation.

use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use fido_core::{PromptInstanceId, WorkflowId};
use thiserror::Error;

#[cfg(all(feature = "native-pin", target_os = "macos"))]
pub mod macos_pin;

/// Trusted native completion, delivered only after acknowledged sheet teardown. Never a DTO.
pub struct MutationCompletion {
    pub binding: PromptBinding,
    pub outcome: PromptOutcome,
    pub secrets: Option<fido_auth::mutation::PinMutationSecrets>,
}

/// Deletion recovery cannot submit PIN secrets or masquerade as PIN recovery.
pub struct DeletionRecoveryCompletion {
    pub binding: PromptBinding,
    pub outcome: PromptOutcome,
}

pub struct PinCompletion {
    pub binding: PromptBinding,
    pub outcome: PromptOutcome,
    pub pin: Option<fido_auth::PinSecret>,
}

#[cfg(all(feature = "modality-spike", not(debug_assertions)))]
compile_error!("modality-spike is a non-shipping debug-only prototype");

#[cfg(all(feature = "modality-spike", target_os = "macos"))]
pub mod macos_spike;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptBinding {
    pub workflow_id: WorkflowId,
    pub prompt_instance_id: PromptInstanceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptOutcome {
    Approved(PromptBinding),
    Cancelled(PromptBinding),
    TimedOut(PromptBinding),
    ParentLost(PromptBinding),
    Shutdown(PromptBinding),
    TornDown(PromptBinding),
    /// Controller owner disappeared without native teardown proof. Never release/reuse on this.
    OwnerLost(PromptBinding),
    PresentationFailed(PromptBinding),
}

impl PromptOutcome {
    pub const fn binding(self) -> PromptBinding {
        match self {
            Self::Approved(b)
            | Self::Cancelled(b)
            | Self::TimedOut(b)
            | Self::ParentLost(b)
            | Self::Shutdown(b)
            | Self::TornDown(b)
            | Self::OwnerLost(b)
            | Self::PresentationFailed(b) => b,
        }
    }
}

/// An owned request minted by the controller, never deserialized from renderer input.
#[derive(Debug, Clone)]
pub struct PromptRequest {
    binding: PromptBinding,
    deadline: Instant,
}

impl PromptRequest {
    pub const fn binding(&self) -> PromptBinding {
        self.binding
    }
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PromptError {
    #[error("another sensitive prompt is active; there is no queue")]
    OperationInProgress,
    #[error("native UI authority has shut down")]
    Shutdown,
    #[error("prompt lifetime must be finite, nonzero, and representable")]
    InvalidLifetime,
    #[error("prompt identity space is exhausted")]
    IdentityExhausted,
    #[error("callback does not match the active workflow and prompt")]
    StaleBinding,
    #[error("prompt already has a terminal decision")]
    AlreadyResolved,
}

#[derive(Debug)]
struct ActivePrompt {
    binding: PromptBinding,
    deadline: Instant,
    decision: Option<PromptOutcome>,
    sender: Sender<PromptOutcome>,
}

#[derive(Debug)]
pub struct PromptController {
    next_prompt: u128,
    active: Option<ActivePrompt>,
    shutdown: bool,
}

impl Default for PromptController {
    fn default() -> Self {
        Self {
            next_prompt: 1,
            active: None,
            shutdown: false,
        }
    }
}

impl PromptController {
    pub fn request(
        &mut self,
        workflow_id: WorkflowId,
        now: Instant,
        lifetime: Duration,
    ) -> Result<(PromptRequest, Receiver<PromptOutcome>), PromptError> {
        if self.shutdown {
            return Err(PromptError::Shutdown);
        }
        if self.active.is_some() {
            return Err(PromptError::OperationInProgress);
        }
        let deadline = now
            .checked_add(lifetime)
            .filter(|_| !lifetime.is_zero())
            .ok_or(PromptError::InvalidLifetime)?;
        let prompt_instance_id = PromptInstanceId::from_raw(self.next_prompt);
        self.next_prompt = self
            .next_prompt
            .checked_add(1)
            .ok_or(PromptError::IdentityExhausted)?;
        let binding = PromptBinding {
            workflow_id,
            prompt_instance_id,
        };
        let (sender, receiver) = mpsc::channel();
        self.active = Some(ActivePrompt {
            binding,
            deadline,
            decision: None,
            sender,
        });
        Ok((PromptRequest { binding, deadline }, receiver))
    }

    /// Called only by a trusted native completion. Expired approval becomes timeout even if the
    /// event-loop timer was delayed. A duplicate callback cannot change the first decision.
    pub fn resolve(&mut self, outcome: PromptOutcome, now: Instant) -> Result<(), PromptError> {
        let active = self.match_active(outcome.binding())?;
        if active.decision.is_some() {
            return Err(PromptError::AlreadyResolved);
        }
        active.decision = Some(
            if now >= active.deadline && matches!(outcome, PromptOutcome::Approved(_)) {
                PromptOutcome::TimedOut(active.binding)
            } else {
                outcome
            },
        );
        Ok(())
    }

    /// Backend revocation takes precedence over an approval awaiting teardown. It never converts
    /// another failure to approval. Late native callbacks then fail with AlreadyResolved.
    pub fn revoke(&mut self, outcome: PromptOutcome) -> Result<(), PromptError> {
        if matches!(outcome, PromptOutcome::Approved(_)) {
            return Err(PromptError::AlreadyResolved);
        }
        let active = self.match_active(outcome.binding())?;
        if active.decision.is_none() || matches!(active.decision, Some(PromptOutcome::Approved(_)))
        {
            active.decision = Some(outcome);
        }
        Ok(())
    }

    /// The native host calls this only after the sheet is detached and ordered out. Until then
    /// even a resolved prompt blocks admission. Receiver loss cannot generate approval elsewhere.
    pub fn did_teardown(
        &mut self,
        binding: PromptBinding,
        now: Instant,
    ) -> Result<(), PromptError> {
        let active = self.match_active(binding)?;
        let outcome = match active.decision {
            Some(PromptOutcome::Approved(_)) if now >= active.deadline => {
                PromptOutcome::TimedOut(binding)
            }
            Some(outcome) => outcome,
            None => PromptOutcome::TornDown(binding),
        };
        if let Some(active) = self.active.take() {
            let _ = active.sender.send(outcome);
        }
        Ok(())
    }

    pub fn shutdown(&mut self) {
        self.shutdown = true;
        if let Some(active) = self.active.as_mut() {
            // Shutdown is an unconditional veto, including a decision awaiting native teardown.
            active.decision = Some(PromptOutcome::Shutdown(active.binding));
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }

    fn match_active(&mut self, binding: PromptBinding) -> Result<&mut ActivePrompt, PromptError> {
        self.active
            .as_mut()
            .filter(|active| active.binding == binding)
            .ok_or(PromptError::StaleBinding)
    }
}

impl Drop for PromptController {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            // Owner loss is never successful approval; teardown was not acknowledged.
            let _ = active.sender.send(PromptOutcome::OwnerLost(active.binding));
        }
    }
}

/// Native confirmation is discarded here; only current/new ownership proceeds to the worker.
pub fn confirmed_mutation_secrets(
    operation: fido_auth::mutation::PinOperation,
    current: Option<fido_auth::PinSecret>,
    new: fido_auth::PinSecret,
    confirm: fido_auth::PinSecret,
) -> Option<fido_auth::mutation::PinMutationSecrets> {
    use fido_auth::mutation::{PinMutationSecrets, PinOperation};
    if new.as_c_str() != confirm.as_c_str() {
        return None;
    }
    drop(confirm);
    // CTAP counts Unicode scalar values; the pinned API also requires 4..63 UTF-8 bytes.
    if new.as_c_str().to_str().ok()?.chars().count() < 4 {
        return None;
    }
    match operation {
        PinOperation::SetPin if current.is_none() => Some(PinMutationSecrets::Set { new }),
        PinOperation::ChangePin => Some(PinMutationSecrets::Change {
            current: current?,
            new,
        }),
        _ => None,
    }
}

/// The actual native sheet uses these descriptions and acknowledgement requirements.
pub fn mutation_description(
    operation: fido_auth::mutation::PinOperation,
    target: &str,
    retries: Option<u8>,
) -> String {
    use fido_auth::mutation::PinOperation;
    let change = operation == PinOperation::ChangePin;
    let retry = if change {
        retries.map_or("Retry count unavailable.".into(), |n| {
            format!(
                "PIN retries remaining: {n}.{}",
                if n <= 3 {
                    " Warning: few retries remain."
                } else {
                    ""
                }
            )
        })
    } else {
        String::new()
    };
    format!(
        "Selected key: {target}. {} This is a persistent change. {} {retry} One submission makes one attempt; there is no automatic retry.",
        if change {
            "The PIN on this physical security key will change."
        } else {
            "A PIN will be configured on this physical security key."
        },
        if change {
            "Enter the current PIN and confirm the new PIN."
        } else {
            "Enter and confirm the new PIN."
        }
    )
}
pub fn last_retry_ack_required(
    operation: fido_auth::mutation::PinOperation,
    retries: Option<u8>,
) -> bool {
    operation == fido_auth::mutation::PinOperation::ChangePin && retries == Some(1)
}

/// Shared consequence text for trusted credential-deletion presentations.
pub const DELETION_CONSEQUENCE: &str = "Deleting this credential permanently removes this passkey from the authenticator. You may lose access to the account unless another sign-in method is available. Your website/account is not deleted, and the website is not notified. This deletion cannot be undone.";

/// Detailed, trusted informative text for the native credential-deletion confirmation sheet.
pub fn deletion_description(
    authenticator: &str,
    rp_id: &str,
    user_name: Option<&str>,
    display_name: Option<&str>,
    credential_fingerprint: &str,
    inventory_incomplete: bool,
    retries: Option<u8>,
) -> String {
    let is_non_ascii = !rp_id.is_ascii();
    let account_lines = match (display_name, user_name) {
        (Some(dn), Some(un)) if dn != un => format!("Display Name: {dn}\nUser Name: {un}"),
        (Some(name), _) => format!("Display Name: {name}"),
        (_, Some(name)) => format!("User Name: {name}"),
        (None, None) => "Account: (No username stored)".to_string(),
    };
    let incomplete_warning = if inventory_incomplete {
        "\n\nWarning: other credentials may exist that Fido Manager could not enumerate; only the credential shown in this confirmation is targeted."
    } else {
        ""
    };
    let confusable_warning = if is_non_ascii {
        " (Warning: contains non-ASCII characters; inspect carefully)"
    } else {
        ""
    };
    let retry_text = retries.map_or("PIN retry count unavailable.".to_owned(), |n| {
        if n == 1 {
            "Warning: only 1 PIN retry remains. An incorrect PIN will lock this security key."
                .to_owned()
        } else if n <= 3 {
            format!("Warning: only {n} PIN retries remain.")
        } else {
            format!("PIN retries remaining: {n}.")
        }
    });

    format!(
        "Security key: {authenticator}\n\
         Website / RP: {rp_id}{confusable_warning}\n\
         {account_lines}\n\
         Fingerprint: {credential_fingerprint}\n\n\
         {DELETION_CONSEQUENCE} Fido Manager will not automatically retry an uncertain deletion.{incomplete_warning}\n\n\
         Enter this security key's PIN to confirm deletion. {retry_text} One submission makes one attempt; there is no automatic retry."
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    fn request(c: &mut PromptController, now: Instant) -> (PromptRequest, Receiver<PromptOutcome>) {
        match c.request(WorkflowId::from_raw(7), now, Duration::from_secs(1)) {
            Ok(pair) => pair,
            Err(e) => panic!("test request failed: {e}"),
        }
    }

    fn synthetic_pin(text: &[u8]) -> fido_auth::PinSecret {
        fido_auth::PinSecret::collect(|b| {
            b[..text.len()].copy_from_slice(text);
            Some(text.len())
        })
        .unwrap_or_else(|_| panic!("synthetic"))
    }

    #[test]
    fn mutation_description_and_last_retry_policy_are_exact() {
        use fido_auth::mutation::PinOperation;
        let set = mutation_description(PinOperation::SetPin, "Trusted key A", None);
        let change = mutation_description(PinOperation::ChangePin, "Trusted key B", Some(1));
        assert!(
            set.contains("Trusted key A")
                && set.contains("PIN will be configured")
                && set.contains("persistent change")
                && !set.contains("current PIN")
        );
        assert!(
            change.contains("Trusted key B")
                && change.contains("PIN on this physical security key will change")
                && change.contains("current PIN")
                && change.contains("remaining: 1")
        );
        for op in [PinOperation::SetPin, PinOperation::ChangePin] {
            for retries in [None, Some(0), Some(1), Some(2), Some(8)] {
                assert_eq!(
                    last_retry_ack_required(op, retries),
                    op == PinOperation::ChangePin && retries == Some(1)
                );
            }
        }
    }

    #[test]
    fn deletion_description_and_policy_are_exact() {
        let full = deletion_description(
            "Thetis FIDO2 Key",
            "example.com",
            Some("alice@example.com"),
            Some("Alice Smith"),
            "0123456789abcdef",
            false,
            Some(8),
        );
        assert!(full.contains("Security key: Thetis FIDO2 Key"));
        assert!(full.contains("Website / RP: example.com"));
        assert!(!full.contains("non-ASCII"));
        assert!(full.contains("Display Name: Alice Smith"));
        assert!(full.contains("User Name: alice@example.com"));
        assert!(full.contains("Fingerprint: 0123456789abcdef"));
        assert!(full.contains(DELETION_CONSEQUENCE));
        assert!(full.contains("permanently removes this passkey from the authenticator."));
        assert!(full.contains(
            "You may lose access to the account unless another sign-in method is available."
        ));
        assert!(
            full.contains("Your website/account is not deleted, and the website is not notified.")
        );
        assert!(full.contains("This deletion cannot be undone."));
        assert!(!full.contains("undone from Fido Manager"));
        assert!(full.contains("Fido Manager will not automatically retry an uncertain deletion."));
        assert!(!full.contains("other credentials may exist"));
        assert!(full.contains("PIN retries remaining: 8."));

        // Non-ASCII RP warning
        let non_ascii = deletion_description(
            "Thetis FIDO2 Key",
            "exämple.com",
            None,
            None,
            "0123456789abcdef",
            false,
            Some(3),
        );
        assert!(non_ascii.contains(
            "Website / RP: exämple.com (Warning: contains non-ASCII characters; inspect carefully)"
        ));
        assert!(non_ascii.contains("Account: (No username stored)"));
        assert!(non_ascii.contains("Warning: only 3 PIN retries remain."));

        // Incomplete inventory warning
        let incomplete = deletion_description(
            "Thetis FIDO2 Key",
            "example.com",
            Some("bob"),
            None,
            "0123456789abcdef",
            true,
            Some(1),
        );
        assert!(incomplete.contains("User Name: bob"));
        assert!(incomplete.contains(
            "Warning: other credentials may exist that Fido Manager could not enumerate"
        ));
        assert!(incomplete.contains(
            "Warning: only 1 PIN retry remains. An incorrect PIN will lock this security key."
        ));
    }

    #[test]
    fn mutation_confirmation_is_native_only_exact_and_discards_third_secret() {
        use fido_auth::mutation::PinOperation;
        assert!(
            confirmed_mutation_secrets(
                PinOperation::SetPin,
                None,
                synthetic_pin(b"fake"),
                synthetic_pin(b"fake")
            )
            .is_some()
        );
        assert!(
            confirmed_mutation_secrets(
                PinOperation::ChangePin,
                Some(synthetic_pin(b"fake")),
                synthetic_pin(b"next"),
                synthetic_pin(b"next")
            )
            .is_some()
        );
        assert!(
            confirmed_mutation_secrets(
                PinOperation::SetPin,
                None,
                synthetic_pin(b"fake"),
                synthetic_pin(b"next")
            )
            .is_none()
        );
        assert!(
            confirmed_mutation_secrets(
                PinOperation::ChangePin,
                None,
                synthetic_pin(b"next"),
                synthetic_pin(b"next")
            )
            .is_none()
        );
        assert!(
            confirmed_mutation_secrets(
                PinOperation::SetPin,
                Some(synthetic_pin(b"fake")),
                synthetic_pin(b"next"),
                synthetic_pin(b"next")
            )
            .is_none()
        );
        assert!(
            confirmed_mutation_secrets(
                PinOperation::SetPin,
                None,
                synthetic_pin("éé".as_bytes()),
                synthetic_pin("éé".as_bytes())
            )
            .is_none()
        );
    }
    #[test]
    fn zero_queue_reservation_lasts_until_teardown_and_delivers_once() {
        let now = Instant::now();
        let mut c = PromptController::default();
        let (r, rx) = request(&mut c, now);
        let b = r.binding();
        assert_eq!(c.resolve(PromptOutcome::Approved(b), now), Ok(()));
        assert_eq!(
            c.resolve(PromptOutcome::Cancelled(b), now),
            Err(PromptError::AlreadyResolved)
        );
        assert!(rx.try_recv().is_err());
        assert!(matches!(
            c.request(b.workflow_id, now, Duration::from_secs(1)),
            Err(PromptError::OperationInProgress)
        ));
        assert_eq!(c.did_teardown(b, now), Ok(()));
        assert_eq!(rx.try_recv(), Ok(PromptOutcome::Approved(b)));
        assert!(rx.try_recv().is_err());
        assert_eq!(c.did_teardown(b, now), Err(PromptError::StaleBinding));
    }

    #[test]
    fn wrong_workflow_wrong_prompt_and_late_callback_cannot_approve_successor() {
        let now = Instant::now();
        let mut c = PromptController::default();
        let (r, _) = request(&mut c, now);
        let b = r.binding();
        for bad in [
            PromptBinding {
                workflow_id: WorkflowId::from_raw(8),
                ..b
            },
            PromptBinding {
                prompt_instance_id: PromptInstanceId::from_raw(123),
                ..b
            },
        ] {
            assert_eq!(
                c.resolve(PromptOutcome::Approved(bad), now),
                Err(PromptError::StaleBinding)
            );
            assert_eq!(c.did_teardown(bad, now), Err(PromptError::StaleBinding));
        }
        assert_eq!(c.did_teardown(b, now), Ok(()));
        let (next, rx) = request(&mut c, now);
        assert_ne!(next.binding(), b);
        assert_eq!(
            c.resolve(PromptOutcome::Approved(b), now),
            Err(PromptError::StaleBinding)
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn every_failure_is_bound_and_double_completion_rejected() {
        for make in [
            PromptOutcome::Cancelled,
            PromptOutcome::TimedOut,
            PromptOutcome::ParentLost,
            PromptOutcome::Shutdown,
            PromptOutcome::TornDown,
            PromptOutcome::PresentationFailed,
        ] {
            let now = Instant::now();
            let mut c = PromptController::default();
            let (r, rx) = request(&mut c, now);
            let result = make(r.binding());
            assert_eq!(c.revoke(result), Ok(()));
            assert_eq!(
                c.resolve(PromptOutcome::Approved(r.binding()), now),
                Err(PromptError::AlreadyResolved)
            );
            assert_eq!(c.did_teardown(r.binding(), now), Ok(()));
            assert_eq!(rx.try_recv(), Ok(result));
            assert!(rx.try_recv().is_err());
        }
    }

    #[test]
    fn deadlines_checked_in_callback_and_again_at_teardown() {
        for late_callback in [false, true] {
            let now = Instant::now();
            let mut c = PromptController::default();
            let (r, rx) = request(&mut c, now);
            let later = now + Duration::from_secs(1);
            assert_eq!(
                c.resolve(
                    PromptOutcome::Approved(r.binding()),
                    if late_callback { later } else { now }
                ),
                Ok(())
            );
            assert_eq!(c.did_teardown(r.binding(), later), Ok(()));
            assert_eq!(rx.try_recv(), Ok(PromptOutcome::TimedOut(r.binding())));
        }
    }

    #[test]
    fn revocation_and_shutdown_veto_pending_approval() {
        let now = Instant::now();
        let mut c = PromptController::default();
        let (r, rx) = request(&mut c, now);
        assert_eq!(c.resolve(PromptOutcome::Approved(r.binding()), now), Ok(()));
        assert_eq!(c.revoke(PromptOutcome::ParentLost(r.binding())), Ok(()));
        c.shutdown();
        assert_eq!(c.did_teardown(r.binding(), now), Ok(()));
        assert_eq!(rx.try_recv(), Ok(PromptOutcome::Shutdown(r.binding())));
        assert!(matches!(
            c.request(r.binding().workflow_id, now, Duration::from_secs(1)),
            Err(PromptError::Shutdown)
        ));
    }

    #[test]
    fn owner_loss_and_unacknowledged_teardown_fail_closed() {
        let now = Instant::now();
        let mut c = PromptController::default();
        let (r, rx) = request(&mut c, now);
        assert_eq!(c.resolve(PromptOutcome::Approved(r.binding()), now), Ok(()));
        drop(c);
        assert_eq!(rx.try_recv(), Ok(PromptOutcome::OwnerLost(r.binding())));
        let mut c = PromptController::default();
        let (r, rx) = request(&mut c, now);
        assert_eq!(c.did_teardown(r.binding(), now), Ok(()));
        assert_eq!(rx.try_recv(), Ok(PromptOutcome::TornDown(r.binding())));
    }

    #[test]
    fn zero_lifetime_and_identity_exhaustion_fail_without_admission() {
        let now = Instant::now();
        let mut c = PromptController::default();
        assert!(matches!(
            c.request(WorkflowId::from_raw(1), now, Duration::ZERO),
            Err(PromptError::InvalidLifetime)
        ));
        c.next_prompt = u128::MAX;
        assert!(matches!(
            c.request(WorkflowId::from_raw(1), now, Duration::from_secs(1)),
            Err(PromptError::IdentityExhausted)
        ));
        assert!(!c.is_active());
    }
    #[test]
    fn lost_receiver_does_not_release_native_reservation() {
        let now = Instant::now();
        let mut c = PromptController::default();
        let (r, rx) = request(&mut c, now);
        drop(rx);
        assert!(c.is_active());
        assert_eq!(c.revoke(PromptOutcome::Cancelled(r.binding())), Ok(()));
        assert!(c.is_active());
        assert_eq!(c.did_teardown(r.binding(), now), Ok(()));
        assert!(!c.is_active());
    }

    #[test]
    fn competing_callbacks_accept_exactly_one_decision() {
        let now = Instant::now();
        let mut c = PromptController::default();
        let (r, rx) = request(&mut c, now);
        let b = r.binding();
        let c = std::sync::Arc::new(std::sync::Mutex::new(c));
        let results = std::thread::scope(|scope| {
            let one = scope.spawn(|| {
                c.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .resolve(PromptOutcome::Approved(b), now)
            });
            let two = scope.spawn(|| {
                c.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .resolve(PromptOutcome::Cancelled(b), now)
            });
            [
                one.join()
                    .unwrap_or_else(|_| panic!("callback thread failed")),
                two.join()
                    .unwrap_or_else(|_| panic!("callback thread failed")),
            ]
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(PromptError::AlreadyResolved))
                .count(),
            1
        );
        assert_eq!(
            c.lock()
                .unwrap_or_else(|e| e.into_inner())
                .did_teardown(b, now),
            Ok(())
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(PromptOutcome::Approved(_)) | Ok(PromptOutcome::Cancelled(_))
        ));
        assert!(rx.try_recv().is_err());
    }
}
