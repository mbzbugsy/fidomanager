//! Non-shipping native-UI feasibility authority. No worker, authentication, or operation permit.

use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use fido_core::{ExecutionQuiescence, RecoveryAdmission, SensitiveWorkflowKind};
use fido_native_ui::{PromptController, PromptOutcome, macos_spike};

use crate::{
    MonotonicClock, SensitiveWorkflowGate, SystemMonotonicClock, WorkflowCompletion,
    WorkflowReleaseEvidence,
};

#[derive(Default)]
struct SpikeAuthority {
    gate: SensitiveWorkflowGate,
    clock: SystemMonotonicClock,
    prompts: Arc<Mutex<PromptController>>,
    result: Option<SpikeResult>,
}

static COMPLETED: Condvar = Condvar::new();

fn authority() -> &'static Mutex<SpikeAuthority> {
    static AUTHORITY: OnceLock<Mutex<SpikeAuthority>> = OnceLock::new();
    AUTHORITY.get_or_init(|| Mutex::new(SpikeAuthority::default()))
}

/// Backend-only startup hook for a fixed placeholder interaction. The admission kind exercises
/// the existing sensitive gate; no credential-inspection transaction is implemented or started.
///
/// # Safety
/// Called on the main AppKit thread, with a live NSWindow from the trusted Tauri registry.
pub unsafe fn start(parent: *mut c_void, timeout: bool) -> Result<(), String> {
    let (admission, request, receiver, controller) = {
        let mut a = authority().lock().map_err(|_| "spike authority poisoned")?;
        let now = a.clock.now();
        let admission = a
            .gate
            .try_begin(SensitiveWorkflowKind::CredentialInspection, now)
            .map_err(|e| e.to_string())?;
        let lifetime = Duration::from_secs(if timeout { 2 } else { 30 });
        let controller = Arc::clone(&a.prompts);
        let pair = controller
            .lock()
            .map_err(|_| "prompt controller poisoned")?
            .request(admission.workflow_id(), Instant::now(), lifetime);
        let (request, receiver) = match pair {
            Ok(pair) => pair,
            Err(e) => {
                a.gate
                    .finish(&admission, WorkflowCompletion::Rejected, release(), now)
                    .map_err(|e| e.to_string())?;
                return Err(e.to_string());
            }
        };
        // Prove zero queue through the actual authority as well as the headless contract tests.
        assert!(matches!(
            a.gate.try_begin(SensitiveWorkflowKind::Recovery, now),
            Err(crate::AdmissionError::OperationInProgress)
        ));
        (admission, request, receiver, controller)
    };
    let binding = request.binding();
    // SAFETY: forwarded live NSWindow contract; the host retains it immediately on main thread.
    let presentation = unsafe { macos_spike::present(parent, request, Arc::clone(&controller)) };
    if presentation.is_err() {
        if let Ok(mut c) = controller.lock() {
            let _ = c.revoke(PromptOutcome::PresentationFailed(binding));
            let _ = c.did_teardown(binding, Instant::now());
        }
    }
    // Native completion crosses into Rust authority asynchronously. No Tauri event/DTO/channel
    // reaches the renderer. Nothing here treats an Approved result as a production permit.
    std::thread::spawn(move || {
        if let Ok(outcome) = receiver.recv() {
            assert_eq!(outcome.binding(), binding);
            let completion = match outcome {
                PromptOutcome::Approved(_) => WorkflowCompletion::Succeeded,
                PromptOutcome::TimedOut(_) => WorkflowCompletion::TimedOut,
                _ => WorkflowCompletion::Cancelled,
            };
            if let Ok(mut a) = authority().lock() {
                let now = a.clock.now();
                a.result = Some(match outcome {
                    PromptOutcome::Approved(_) => SpikeResult::Approved,
                    PromptOutcome::Cancelled(_) => SpikeResult::Cancelled,
                    PromptOutcome::TimedOut(_) => SpikeResult::TimedOut,
                    PromptOutcome::ParentLost(_) => SpikeResult::ParentLost,
                    PromptOutcome::Shutdown(_) => SpikeResult::Shutdown,
                    PromptOutcome::TornDown(_) => SpikeResult::TornDown,
                    PromptOutcome::OwnerLost(_) => SpikeResult::OwnerLost,
                    PromptOutcome::PresentationFailed(_) => SpikeResult::PresentationFailed,
                });
                let released = !matches!(outcome, PromptOutcome::OwnerLost(_))
                    && a.gate
                        .finish(&admission, completion, release(), now)
                        .is_ok();
                COMPLETED.notify_all();
                eprintln!(
                    "[native-ui-spike] Rust authority result={outcome:?} workflow_released={released} second_result={:?}",
                    receiver.try_recv()
                );
            }
        }
    });
    presentation.map_err(str::to_owned)
}

fn release() -> WorkflowReleaseEvidence {
    // This harness has no native FIDO execution or recovery incident. UI teardown was proven by
    // the host before the receiver obtained its result.
    WorkflowReleaseEvidence {
        execution_quiescence: ExecutionQuiescence::Quiescent,
        recovery_admission: RecoveryAdmission::Open,
    }
}

pub fn cancel() {
    macos_spike::cancel();
}
pub fn teardown() {
    macos_spike::teardown();
}
pub fn shutdown() {
    if let Ok(a) = authority().lock() {
        if let Ok(mut c) = a.prompts.lock() {
            c.shutdown();
        }
    }
    macos_spike::shutdown();
    // AppKit teardown has already run on main. Wait only for the Rust receiver acknowledgement,
    // never for UI work or a nested event loop. This prevents normal app exit racing the receiver.
    if let Ok(a) = authority().lock() {
        if let Ok((a, _)) = COMPLETED.wait_timeout_while(a, Duration::from_millis(500), |a| {
            a.gate.is_active() && a.result.is_none()
        }) {
            if a.gate.is_active() {
                eprintln!(
                    "[native-ui-spike] shutdown acknowledgement unavailable; reservation remains fail-closed"
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpikeResult {
    Approved,
    Cancelled,
    TimedOut,
    ParentLost,
    Shutdown,
    TornDown,
    OwnerLost,
    PresentationFailed,
}

pub fn result() -> Option<SpikeResult> {
    authority().lock().ok().and_then(|a| a.result)
}
pub fn exercise_native_button(continue_spike: bool) {
    macos_spike::exercise_native_button(continue_spike);
}
