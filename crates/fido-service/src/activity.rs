//! Presentation-only credential-inspection activity.
//!
//! Nothing here is an authority. The sensitive-workflow gate, cooldown, recovery barrier and
//! native prompt controller remain the only admission and authorization state; this tracker is
//! never consulted by them and cannot grant, extend or release anything. It only
//!
//! * suppresses a redundant native-menu start while one is already running (the gate would reject
//!   it anyway, so a duplicate never reaches the user as an alarming error),
//! * tells the renderer which connected key is waiting for a PIN or reading credentials, and
//! * carries one short, plain-language outcome per attempt.
//!
//! User-visible text deliberately avoids internal security-model terms.

use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;

use crate::AdmissionError;
use crate::authentication::{AuthenticationResult, Progress, Status};
use crate::inspection::DisplayDeviceHandle;
use fido_core::inventory::InspectionError;

pub const REFRESHED: &str = "Credentials refreshed";
pub const STILL_FINISHING: &str = "Security key operation still finishing. Try again in a moment.";
pub const TOO_MANY_ATTEMPTS: &str =
    "Several attempts ended without a result. Wait a moment before trying again.";
pub const RESTART_NEEDED: &str = "Fido Manager could not confirm the security key was released. Restart Fido Manager before trying again.";
pub const KEY_UNAVAILABLE: &str = "The selected security key is no longer available. Select it again from the Security key menu once it is detected.";
pub const KEY_DISCONNECTED: &str = "The selected security key is no longer connected. Choose a connected key from the Security key menu.";
pub const INVENTORY_UNAVAILABLE: &str =
    "Credential inspection is unavailable right now. The connected keys could not be verified.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityPhase {
    WaitingForPin,
    ReadingCredentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeTone {
    Success,
    Problem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIssue {
    pub device: String,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityNotice {
    pub revision: String,
    pub tone: NoticeTone,
    pub message: &'static str,
}

/// The whole renderer-facing shape. Only display handles (already present in the device list) and
/// fixed text cross; no secret, identity or authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityView {
    pub device: Option<String>,
    pub phase: Option<ActivityPhase>,
    pub issue: Option<DeviceIssue>,
    pub notice: Option<ActivityNotice>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityOutcome {
    Refreshed,
    /// The user dismissed the native prompt. Intentionally silent.
    Cancelled,
    Issue(&'static str),
}

#[derive(Default)]
struct State {
    claimed: bool,
    target: Option<DisplayDeviceHandle>,
    phase: Option<ActivityPhase>,
    issue: Option<(DisplayDeviceHandle, &'static str)>,
    notice: Option<(u64, NoticeTone, &'static str)>,
    revision: u64,
}

#[derive(Default)]
pub struct ActivityTracker {
    state: Mutex<State>,
}

impl ActivityTracker {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Display state only: a poisoned lock holds no authority, so recover and continue.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Claim the single presentation start slot. `None` means a start is already running and this
    /// one must be dropped silently. This never replaces the backend gate: a claimed start still
    /// has to be admitted by it.
    pub fn try_claim(self: &Arc<Self>) -> Option<StartClaim> {
        let mut state = self.lock();
        if state.claimed {
            return None;
        }
        state.claimed = true;
        state.target = None;
        state.phase = None;
        Some(StartClaim {
            tracker: Arc::clone(self),
        })
    }

    pub fn is_busy(&self) -> bool {
        self.lock().claimed
    }

    /// Forget a remembered problem for a key that is no longer connected.
    pub fn retain_connected(&self, connected: &[DisplayDeviceHandle]) {
        let mut state = self.lock();
        if state
            .issue
            .is_some_and(|(device, _)| !connected.contains(&device))
        {
            state.issue = None;
        }
    }

    pub fn view(&self) -> ActivityView {
        let state = self.lock();
        ActivityView {
            device: state.target.map(DisplayDeviceHandle::as_wire),
            phase: state.target.and(state.phase),
            issue: state.issue.map(|(device, message)| DeviceIssue {
                device: device.as_wire(),
                message,
            }),
            notice: state
                .notice
                .map(|(revision, tone, message)| ActivityNotice {
                    revision: revision.to_string(),
                    tone,
                    message,
                }),
        }
    }
}

/// Held for the whole start attempt; dropping it frees the slot even on an early return or panic.
pub struct StartClaim {
    tracker: Arc<ActivityTracker>,
}

impl StartClaim {
    /// The key this attempt is about. Clears that key's previous problem.
    pub fn target(&self, device: DisplayDeviceHandle) {
        let mut state = self.tracker.lock();
        state.target = Some(device);
        if state.issue.is_some_and(|(d, _)| d == device) {
            state.issue = None;
        }
    }

    pub fn progress(&self, progress: Progress) {
        self.tracker.lock().phase = Some(match progress {
            Progress::PinRequested => ActivityPhase::WaitingForPin,
            Progress::PinSubmitted => ActivityPhase::ReadingCredentials,
        });
    }

    /// Record the outcome (problems attach to the targeted key, or become a transient notice when
    /// no key was resolved yet) and free the slot.
    pub fn finish(self, outcome: ActivityOutcome) {
        let mut state = self.tracker.lock();
        let target = state.target;
        match (outcome, target) {
            (ActivityOutcome::Refreshed, _) => {
                state.revision = state.revision.saturating_add(1);
                state.notice = Some((state.revision, NoticeTone::Success, REFRESHED));
            }
            (ActivityOutcome::Cancelled, _) => {}
            (ActivityOutcome::Issue(message), Some(device)) => {
                state.issue = Some((device, message));
            }
            (ActivityOutcome::Issue(message), None) => {
                state.revision = state.revision.saturating_add(1);
                state.notice = Some((state.revision, NoticeTone::Problem, message));
            }
        }
        // Dropping `self` releases the slot after the outcome is visible.
    }
}

impl Drop for StartClaim {
    fn drop(&mut self) {
        let mut state = self.tracker.lock();
        state.claimed = false;
        state.target = None;
        state.phase = None;
    }
}

/// Plain-language wording for an admission refusal. The refusal itself is decided only by the
/// gate; this maps it to text and decides nothing.
pub const fn admission_message(error: AdmissionError) -> &'static str {
    match error {
        AdmissionError::OperationInProgress => STILL_FINISHING,
        AdmissionError::CoolingDown => TOO_MANY_ATTEMPTS,
        AdmissionError::RecoveryBarrier | AdmissionError::WorkflowIdExhausted => RESTART_NEEDED,
    }
}

fn inspection_error_message(error: InspectionError) -> &'static str {
    match error {
        InspectionError::BoundExceeded => {
            "This security key holds more credentials than Fido Manager can show. No inventory was stored."
        }
        InspectionError::Malformed => {
            "The security key returned credential data that could not be read. No inventory was stored."
        }
        InspectionError::CleanupFailed => RESTART_NEEDED,
        InspectionError::Unsupported => {
            "Credential inspection is not available on this security key."
        }
        InspectionError::DeviceAbsent => "The security key was disconnected during inspection.",
        InspectionError::Busy | InspectionError::AccessDenied => {
            "The security key is busy or access was denied. Reconnect it and try again."
        }
        InspectionError::TimedOut => "Credential inspection timed out. Try again.",
        InspectionError::NativeFailure => "Credential inspection failed. No inventory was stored.",
    }
}

/// Map the authority's typed result to presentation. Only categories and booleans are read.
pub fn outcome_for(result: &AuthenticationResult) -> ActivityOutcome {
    if let Some(error) = result.inspection_error {
        return ActivityOutcome::Issue(inspection_error_message(error));
    }
    if !result.worker_quiescent || !result.prompt_torn_down {
        return ActivityOutcome::Issue(RESTART_NEEDED);
    }
    match result.status {
        Status::Validated if result.attached_puat_cleared => ActivityOutcome::Refreshed,
        Status::Cancelled => ActivityOutcome::Cancelled,
        Status::WrongPin => ActivityOutcome::Issue("Incorrect PIN. No retry was made."),
        Status::PinBlocked => ActivityOutcome::Issue("This security key's PIN is blocked."),
        Status::PinAuthBlocked => ActivityOutcome::Issue(
            "PIN entry is temporarily blocked on this security key. Unplug and reconnect it, then try again.",
        ),
        Status::Revoked => ActivityOutcome::Issue("Credential inspection was interrupted."),
        Status::TimedOut => ActivityOutcome::Issue("The PIN prompt timed out. No retry was made."),
        Status::Unsupported => {
            ActivityOutcome::Issue("Credential inspection is not available on this security key.")
        }
        Status::CleanupFailed => ActivityOutcome::Issue(RESTART_NEEDED),
        _ => ActivityOutcome::Issue(
            "Credential inspection could not be completed. No retry was made.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_core::inventory::InspectionError as E;

    fn device(raw: u128) -> DisplayDeviceHandle {
        // The wire form is the only public constructor surface; round-trip it.
        let wire = format!("\"{raw:032x}\"");
        serde_json::from_str(&wire).unwrap_or_else(|_| panic!("display handle wire form"))
    }

    fn result(status: Status) -> AuthenticationResult {
        AuthenticationResult {
            inventory: None,
            inspection_error: None,
            status,
            grant_kind: None,
            attached_puat_cleared: status == Status::Validated,
            worker_quiescent: true,
            prompt_torn_down: true,
        }
    }

    const FORBIDDEN: &[&str] = &[
        "workflow",
        "admission",
        "cooldown",
        "cooling",
        "recovery",
        "barrier",
        "acquisition",
        "binding",
        "puat",
        "worker",
        "authentication",
        "snapshot",
        "quiescen",
        "token",
        "gate",
    ];

    fn every_message() -> Vec<&'static str> {
        let mut all = vec![
            REFRESHED,
            STILL_FINISHING,
            TOO_MANY_ATTEMPTS,
            RESTART_NEEDED,
            KEY_UNAVAILABLE,
            KEY_DISCONNECTED,
            INVENTORY_UNAVAILABLE,
        ];
        for error in [
            AdmissionError::OperationInProgress,
            AdmissionError::CoolingDown,
            AdmissionError::RecoveryBarrier,
            AdmissionError::WorkflowIdExhausted,
        ] {
            all.push(admission_message(error));
        }
        for error in [
            E::Unsupported,
            E::DeviceAbsent,
            E::Busy,
            E::AccessDenied,
            E::TimedOut,
            E::Malformed,
            E::BoundExceeded,
            E::NativeFailure,
            E::CleanupFailed,
        ] {
            all.push(inspection_error_message(error));
        }
        for status in [
            Status::Validated,
            Status::WrongPin,
            Status::PinBlocked,
            Status::PinAuthBlocked,
            Status::Unsupported,
            Status::InvalidSecret,
            Status::Cancelled,
            Status::Revoked,
            Status::TimedOut,
            Status::Uncertain,
            Status::CleanupFailed,
            Status::StaleAcquisition,
        ] {
            if let ActivityOutcome::Issue(message) = outcome_for(&result(status)) {
                all.push(message);
            }
        }
        let mut unproven = result(Status::Validated);
        unproven.worker_quiescent = false;
        if let ActivityOutcome::Issue(message) = outcome_for(&unproven) {
            all.push(message);
        }
        all
    }

    #[test]
    fn a_second_start_is_suppressed_until_the_first_ends() {
        let tracker = Arc::new(ActivityTracker::default());
        let first = tracker.try_claim();
        assert!(first.is_some());
        assert!(tracker.is_busy());
        // Reentrant or duplicate menu events are dropped silently and never reach the gate.
        assert!(tracker.try_claim().is_none());
        assert!(tracker.try_claim().is_none());
        drop(first);
        assert!(!tracker.is_busy());
        assert!(tracker.try_claim().is_some());
    }

    #[test]
    fn dropping_a_claim_without_an_outcome_frees_the_slot_and_state() {
        let tracker = Arc::new(ActivityTracker::default());
        {
            let claim = tracker.try_claim();
            let Some(claim) = claim else {
                panic!("claim");
            };
            claim.target(device(1));
            claim.progress(Progress::PinRequested);
            assert_eq!(tracker.view().phase, Some(ActivityPhase::WaitingForPin));
        }
        let view = tracker.view();
        assert_eq!((view.device, view.phase, view.issue), (None, None, None));
        assert!(tracker.try_claim().is_some());
    }

    #[test]
    fn the_active_key_moves_from_waiting_for_pin_to_reading_credentials() {
        let tracker = Arc::new(ActivityTracker::default());
        let Some(claim) = tracker.try_claim() else {
            panic!("claim");
        };
        // No key resolved yet: nothing is attributed to any card.
        claim.progress(Progress::PinRequested);
        assert_eq!(tracker.view().device, None);
        assert_eq!(tracker.view().phase, None);
        claim.target(device(7));
        assert_eq!(tracker.view().device, Some(device(7).as_wire()));
        assert_eq!(tracker.view().phase, Some(ActivityPhase::WaitingForPin));
        claim.progress(Progress::PinSubmitted);
        assert_eq!(
            tracker.view().phase,
            Some(ActivityPhase::ReadingCredentials)
        );
    }

    #[test]
    fn success_returns_to_normal_with_a_transient_notice_and_no_problem() {
        let tracker = Arc::new(ActivityTracker::default());
        let Some(claim) = tracker.try_claim() else {
            panic!("claim");
        };
        claim.target(device(7));
        claim.progress(Progress::PinSubmitted);
        claim.finish(outcome_for(&result(Status::Validated)));
        let view = tracker.view();
        assert_eq!((view.device, view.phase, view.issue), (None, None, None));
        let notice = view.notice;
        assert_eq!(
            notice.map(|n| (n.tone, n.message)),
            Some((NoticeTone::Success, REFRESHED))
        );
        assert!(!tracker.is_busy());
    }

    #[test]
    fn cancellation_is_quiet() {
        let tracker = Arc::new(ActivityTracker::default());
        let Some(claim) = tracker.try_claim() else {
            panic!("claim");
        };
        claim.target(device(7));
        claim.progress(Progress::PinRequested);
        claim.finish(outcome_for(&result(Status::Cancelled)));
        let view = tracker.view();
        assert_eq!(
            (view.device, view.phase, view.issue, view.notice),
            (None, None, None, None)
        );
    }

    #[test]
    fn a_problem_attaches_to_its_key_until_the_next_attempt_or_disconnect() {
        let tracker = Arc::new(ActivityTracker::default());
        let Some(claim) = tracker.try_claim() else {
            panic!("claim");
        };
        claim.target(device(7));
        claim.finish(outcome_for(&result(Status::WrongPin)));
        let issue = tracker.view().issue;
        assert_eq!(
            issue.as_ref().map(|i| i.device.clone()),
            Some(device(7).as_wire())
        );
        assert_eq!(
            tracker.view().notice,
            None,
            "no global toast for a keyed problem"
        );
        // Another key being present does not clear it; the key leaving does.
        tracker.retain_connected(&[device(7), device(8)]);
        assert!(tracker.view().issue.is_some());
        tracker.retain_connected(&[device(8)]);
        assert!(tracker.view().issue.is_none());
        // A new attempt on the same key clears the previous problem immediately.
        let Some(claim) = tracker.try_claim() else {
            panic!("claim");
        };
        claim.target(device(8));
        claim.finish(outcome_for(&result(Status::PinBlocked)));
        let Some(claim) = tracker.try_claim() else {
            panic!("claim");
        };
        claim.target(device(8));
        assert!(tracker.view().issue.is_none());
        drop(claim);
    }

    #[test]
    fn a_problem_before_any_key_is_resolved_is_a_transient_notice() {
        let tracker = Arc::new(ActivityTracker::default());
        let Some(claim) = tracker.try_claim() else {
            panic!("claim");
        };
        claim.finish(ActivityOutcome::Issue(KEY_UNAVAILABLE));
        let view = tracker.view();
        assert_eq!(
            view.notice.map(|n| (n.tone, n.message)),
            Some((NoticeTone::Problem, KEY_UNAVAILABLE))
        );
        assert!(view.issue.is_none());
    }

    #[test]
    fn a_genuine_gate_refusal_uses_plain_wording() {
        assert_eq!(
            admission_message(AdmissionError::OperationInProgress),
            "Security key operation still finishing. Try again in a moment."
        );
        for error in [
            AdmissionError::OperationInProgress,
            AdmissionError::CoolingDown,
            AdmissionError::RecoveryBarrier,
            AdmissionError::WorkflowIdExhausted,
        ] {
            assert!(!admission_message(error).is_empty());
        }
    }

    #[test]
    fn no_user_text_exposes_internal_security_model_terms() {
        for message in every_message() {
            let lower = message.to_lowercase();
            for term in FORBIDDEN {
                assert!(
                    !lower.contains(term),
                    "`{message}` exposes internal term `{term}`"
                );
            }
        }
    }

    #[test]
    fn unproven_cleanup_is_never_reported_as_success_or_quiet() {
        let mut unproven = result(Status::Validated);
        unproven.prompt_torn_down = false;
        assert_eq!(
            outcome_for(&unproven),
            ActivityOutcome::Issue(RESTART_NEEDED)
        );
        let mut cancelled = result(Status::Cancelled);
        cancelled.worker_quiescent = false;
        assert_eq!(
            outcome_for(&cancelled),
            ActivityOutcome::Issue(RESTART_NEEDED)
        );
        let mut failed = result(Status::Validated);
        failed.inspection_error = Some(E::Malformed);
        assert_ne!(outcome_for(&failed), ActivityOutcome::Refreshed);
    }

    #[test]
    fn the_renderer_shape_is_exactly_these_fields() {
        let tracker = Arc::new(ActivityTracker::default());
        let Some(claim) = tracker.try_claim() else {
            panic!("claim");
        };
        claim.target(device(0xab));
        claim.progress(Progress::PinSubmitted);
        let json = serde_json::to_value(tracker.view()).unwrap_or_default();
        assert_eq!(
            json,
            serde_json::json!({
                "device": format!("{:032x}", 0xabu128),
                "phase": "reading_credentials",
                "issue": null,
                "notice": null,
            })
        );
        drop(claim);
    }
}
