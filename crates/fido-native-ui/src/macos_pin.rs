//! Production AppKit PIN sheet. Main-thread objects never cross into service/worker threads.
//! NSString/AppKit input copies cannot be promised zeroized; Rust copies use fixed zeroize storage.
use crate::{PinCompletion, PromptBinding, PromptController, PromptOutcome, PromptRequest};
use block2::RcBlock;
use objc2::{MainThreadMarker, MainThreadOnly, rc::Retained, runtime::ProtocolObject};
use objc2_app_kit::{
    NSAlert, NSAlertSecondButtonReturn, NSApplication, NSButton, NSButtonType,
    NSControlStateValueOn, NSModalResponse, NSModalResponseCancel, NSSecureTextField, NSView,
    NSWindow, NSWindowWillCloseNotification, NSWorkspace,
    NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{
    NSDistributedNotificationCenter, NSNotification, NSNotificationCenter, NSObjectProtocol,
    NSPoint, NSRect, NSRunLoop, NSRunLoopCommonModes, NSSize, NSString, NSTimer,
    NSUTF8StringEncoding,
};
use std::{
    cell::RefCell,
    ffi::c_void,
    ptr::NonNull,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::Sender,
    },
    time::Instant,
};

use fido_auth::mutation::{PinMutationSecrets, PinOperation};
#[derive(Clone, Copy)]
enum Purpose {
    Inspection,
    Mutation(PinOperation),
    Recovery(PinOperation),
}
enum Reply {
    Inspection(Sender<PinCompletion>),
    Mutation(Sender<crate::MutationCompletion>),
}

pub type Controller = Arc<Mutex<PromptController>>;
struct Sheet {
    binding: PromptBinding,
    deadline: Instant,
    parent: Retained<NSWindow>,
    alert: Retained<NSAlert>,
    approve: Retained<NSButton>,
    input: Retained<NSSecureTextField>,
    last_retry_ack: Option<Retained<NSButton>>,
    controller: Controller,
    reply: Option<Reply>,
    purpose: Purpose,
    new_input: Option<Retained<NSSecureTextField>>,
    confirm_input: Option<Retained<NSSecureTextField>>,
    secrets: Option<PinMutationSecrets>,
    decision: Option<PromptOutcome>,
    pin: Option<fido_auth::PinSecret>,
    timer: Retained<NSTimer>,
    close_observer: Retained<ProtocolObject<dyn NSObjectProtocol>>,
    epoch: Arc<AtomicU64>,
    expected_epoch: u64,
    approve_after: Instant,
}
impl Drop for Sheet {
    fn drop(&mut self) {
        self.timer.invalidate();
        // SAFETY: token owned by this main-thread sheet; removed before release.
        unsafe {
            NSNotificationCenter::defaultCenter().removeObserver(self.close_observer.as_ref())
        };
        self.input.setStringValue(&NSString::from_str(""));
        for field in [&self.new_input, &self.confirm_input].into_iter().flatten() {
            field.setStringValue(&NSString::from_str(""));
        }
    }
}
type Observer = (
    Retained<NSNotificationCenter>,
    Retained<ProtocolObject<dyn NSObjectProtocol>>,
);
thread_local! {
    static ACTIVE: RefCell<Option<Sheet>> = const { RefCell::new(None) };
    static LIFECYCLE: RefCell<Vec<Observer>> = const { RefCell::new(Vec::new()) };
}

/// Register for the whole application lifetime, including the gap after PIN sheet teardown.
pub fn install_lifecycle(epoch: Arc<AtomicU64>) -> Result<(), &'static str> {
    let mtm = MainThreadMarker::new().ok_or("main thread required")?;
    let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
    let distributed = NSDistributedNotificationCenter::defaultCenter();
    for (center, name) in [
        (workspace.clone(), unsafe {
            NSWorkspaceWillSleepNotification
        }),
        (workspace, unsafe {
            NSWorkspaceSessionDidResignActiveNotification
        }),
        (
            Retained::into_super(distributed),
            &NSString::from_str("com.apple.screenIsLocked"),
        ),
    ] {
        let epoch = Arc::clone(&epoch);
        let callback = RcBlock::new(move |_: NonNull<NSNotification>| {
            // This callback touches no AppKit state and can safely run on the posting thread.
            epoch.fetch_add(1, Ordering::SeqCst);
        });
        // SAFETY: notification token and center retained for application lifetime. Only atomic
        // revocation is captured; native presentation remains on the main thread.
        let token = unsafe {
            center.addObserverForName_object_queue_usingBlock(Some(name), None, None, &callback)
        };
        LIFECYCLE.with(|observers| observers.borrow_mut().push((center, token)));
    }
    let _ = NSApplication::sharedApplication(mtm);
    Ok(())
}

/// # Safety
/// Parent is a live NSWindow from the trusted Tauri main-window registry, retained on main thread.
pub unsafe fn present(
    parent: *mut c_void,
    request: PromptRequest,
    controller: Controller,
    reply: Sender<PinCompletion>,
    retries: Option<u8>,
    revocation: (Arc<AtomicU64>, u64),
    target_label: &str,
) -> Result<(), &'static str> {
    // SAFETY: the trusted caller's main-window contract is forwarded unchanged.
    unsafe {
        present_sheet(
            parent,
            request,
            controller,
            Reply::Inspection(reply),
            retries,
            revocation,
            (target_label, Purpose::Inspection),
        )
    }
}
/// # Safety
/// Parent must be the live trusted main NSWindow, called on AppKit's main thread.
pub unsafe fn present_mutation(
    parent: *mut c_void,
    request: PromptRequest,
    controller: Controller,
    reply: Sender<crate::MutationCompletion>,
    operation_and_retries: (PinOperation, Option<u8>),
    revocation: (Arc<AtomicU64>, u64),
    target_label: &str,
) -> Result<(), &'static str> {
    // SAFETY: forwarded trusted NSWindow contract; no renderer target or operation input.
    unsafe {
        present_sheet(
            parent,
            request,
            controller,
            Reply::Mutation(reply),
            operation_and_retries.1,
            revocation,
            (target_label, Purpose::Mutation(operation_and_retries.0)),
        )
    }
}
/// # Safety
/// Parent must be the live trusted main NSWindow, called on AppKit's main thread.
pub unsafe fn present_recovery(
    parent: *mut c_void,
    request: PromptRequest,
    controller: Controller,
    reply: Sender<crate::MutationCompletion>,
    operation: PinOperation,
    revocation: (Arc<AtomicU64>, u64),
    evidence: &str,
) -> Result<(), &'static str> {
    // SAFETY: forwarded trusted NSWindow contract; this sheet collects no secret or probe.
    unsafe {
        present_sheet(
            parent,
            request,
            controller,
            Reply::Mutation(reply),
            None,
            revocation,
            (evidence, Purpose::Recovery(operation)),
        )
    }
}
unsafe fn present_sheet(
    parent: *mut c_void,
    request: PromptRequest,
    controller: Controller,
    reply: Reply,
    retries: Option<u8>,
    revocation: (Arc<AtomicU64>, u64),
    description: (&str, Purpose),
) -> Result<(), &'static str> {
    let (target_label, purpose) = description;
    let (epoch, expected_epoch) = revocation;
    let mtm = MainThreadMarker::new().ok_or("AppKit presentation requires main thread")?;
    if ACTIVE.with(|a| a.borrow().is_some()) {
        return Err("prompt in progress");
    }
    if parent.is_null() || epoch.load(Ordering::SeqCst) != expected_epoch {
        return Err("authority revoked");
    }
    // SAFETY: caller guarantees the live main-window pointer.
    let parent =
        unsafe { Retained::<NSWindow>::retain(parent.cast()) }.ok_or("parent unavailable")?;
    if !parent.isVisible()
        || parent.isMiniaturized()
        || !NSApplication::sharedApplication(mtm).isActive()
        || parent.attachedSheet().is_some()
    {
        return Err("visible foreground parent required");
    }
    let binding = request.binding();
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str(match purpose {
        Purpose::Inspection => "Authenticate security key",
        Purpose::Mutation(op) => op.title(),
        Purpose::Recovery(_) => "Acknowledge uncertain PIN operation",
    }));
    let retry_text = retries.map_or("Retry count unavailable.".to_owned(), |n| {
        if n <= 3 {
            format!("Warning: only {n} PIN retries remain.")
        } else {
            format!("PIN retries remaining: {n}.")
        }
    });
    let text = match purpose {
        Purpose::Inspection => format!(
            "Selected key: {target_label}. Inspect stored credentials and passkeys. This read-only operation will not change credentials. Enter this key's PIN. {retry_text} One submission makes one attempt; there is no automatic retry."
        ),
        Purpose::Mutation(op) => crate::mutation_description(op, target_label, retries),
        Purpose::Recovery(op) => format!(
            "The previous {} result could not be confirmed. {} {} Acknowledging allows future security key operations but preserves the uncertain historical result. This does not confirm success or failure and makes no PIN attempt.",
            op.title(),
            if op == PinOperation::ChangePin {
                "Fido Manager cannot determine whether the old or new PIN is active without consuming an authentication attempt. Neither PIN will be tested."
            } else {
                "A configured PIN does not prove the exact PIN value. The proposed PIN will not be tested."
            },
            target_label
        ),
    };
    alert.setInformativeText(&NSString::from_str(&text));
    let cancel = alert.addButtonWithTitle(&NSString::from_str("Cancel"));
    cancel.setKeyEquivalent(&NSString::from_str("\r"));
    let approve = alert.addButtonWithTitle(&NSString::from_str(match purpose {
        Purpose::Inspection => "Authenticate",
        Purpose::Mutation(op) => op.title(),
        Purpose::Recovery(_) => "Acknowledge uncertainty",
    }));
    approve.setKeyEquivalent(&NSString::from_str(""));
    approve.setEnabled(matches!(purpose, Purpose::Inspection));
    let input = NSSecureTextField::initWithFrame(
        NSSecureTextField::alloc(mtm),
        NSRect::new(NSPoint::new(0., 0.), NSSize::new(300., 26.)),
    );
    input.setPlaceholderString(Some(&NSString::from_str("Security key PIN")));
    let last_retry_ack = if match purpose {
        Purpose::Inspection => retries == Some(1),
        Purpose::Mutation(op) => crate::last_retry_ack_required(op, retries),
        Purpose::Recovery(_) => true,
    } {
        let button = NSButton::new(mtm);
        button.setButtonType(NSButtonType::Switch);
        button.setTitle(&NSString::from_str(
            if matches!(purpose, Purpose::Recovery(_)) {
                "I acknowledge the PIN result is unknown"
            } else {
                "I understand this is the last PIN retry"
            },
        ));
        button.setFrame(NSRect::new(NSPoint::new(0., 30.), NSSize::new(340., 26.)));
        Some(button)
    } else {
        None
    };
    let mutation = matches!(purpose, Purpose::Mutation(_));
    let field = |placeholder: &str, y: f64| {
        let field = NSSecureTextField::initWithFrame(
            NSSecureTextField::alloc(mtm),
            NSRect::new(NSPoint::new(0., y), NSSize::new(340., 26.)),
        );
        field.setPlaceholderString(Some(&NSString::from_str(placeholder)));
        field
    };
    let new_input = mutation.then(|| field("New PIN", 30.));
    let confirm_input = mutation.then(|| field("Confirm new PIN", 60.));
    let accessory = NSView::initWithFrame(
        NSView::alloc(mtm),
        NSRect::new(
            NSPoint::new(0., 0.),
            NSSize::new(340., if mutation { 120. } else { 60. }),
        ),
    );
    if !matches!(purpose, Purpose::Recovery(_)) {
        input.setPlaceholderString(Some(&NSString::from_str(
            if matches!(purpose, Purpose::Mutation(PinOperation::ChangePin)) {
                "Current PIN"
            } else {
                "Security key PIN"
            },
        )));
        if !matches!(purpose, Purpose::Mutation(PinOperation::SetPin)) {
            accessory.addSubview(&input);
        }
        for field in [&new_input, &confirm_input].into_iter().flatten() {
            accessory.addSubview(field);
        }
        if let Some(button) = &last_retry_ack {
            button.setFrame(NSRect::new(
                NSPoint::new(0., if mutation { 90. } else { 30. }),
                NSSize::new(340., 26.),
            ));
            accessory.addSubview(button);
        }
    }
    if matches!(purpose, Purpose::Recovery(_)) {
        if let Some(button) = &last_retry_ack {
            accessory.addSubview(button);
        }
    }
    alert.setAccessoryView(Some(&accessory));
    alert.layout();
    alert.window().makeFirstResponder(Some(&cancel));
    let tick = RcBlock::new(move |_: NonNull<NSTimer>| {
        poll(binding);
    });
    // SAFETY: registered only on the main AppKit run loop; callback contains no native pointer.
    let timer = unsafe { NSTimer::timerWithTimeInterval_repeats_block(0.025, true, &tick) };
    // SAFETY: timer and mode are valid, and registration runs on the main AppKit thread.
    unsafe { NSRunLoop::mainRunLoop().addTimer_forMode(&timer, NSRunLoopCommonModes) };
    let closed = RcBlock::new(move |_: NonNull<NSNotification>| {
        dismiss(binding, PromptOutcome::ParentLost(binding));
    });
    // SAFETY: exact retained parent object filter; notification is posted on AppKit main thread.
    let close_observer = unsafe {
        NSNotificationCenter::defaultCenter().addObserverForName_object_queue_usingBlock(
            Some(NSWindowWillCloseNotification),
            Some(&parent),
            None,
            &closed,
        )
    };
    ACTIVE.with(|a| {
        *a.borrow_mut() = Some(Sheet {
            binding,
            deadline: request.deadline(),
            parent: parent.clone(),
            alert: alert.clone(),
            approve,
            input,
            last_retry_ack,
            controller,
            reply: Some(reply),
            purpose,
            new_input,
            confirm_input,
            secrets: None,
            decision: None,
            pin: None,
            timer,
            close_observer,
            epoch,
            expected_epoch,
            approve_after: Instant::now() + std::time::Duration::from_millis(500),
        })
    });
    let completion = RcBlock::new(move |response: NSModalResponse| {
        complete(binding, Some(response));
    });
    alert.beginSheetModalForWindow_completionHandler(&parent, Some(&completion));
    let associated = alert
        .window()
        .sheetParent()
        .is_some_and(|w| std::ptr::eq(&*w, &*parent));
    let attached = parent
        .attachedSheet()
        .is_some_and(|w| std::ptr::eq(&*w, &*alert.window()));
    let default_cancel = alert.window().defaultButtonCell().is_some_and(|cell| {
        cancel.cell().is_some_and(|cancel_cell| {
            std::ptr::from_ref(&*cell).cast::<c_void>()
                == std::ptr::from_ref(&*cancel_cell).cast::<c_void>()
        })
    });
    eprintln!(
        "[authentication] prompt main=true secure_control={} window_modal={} default_cancel={default_cancel}",
        !matches!(purpose, Purpose::Recovery(_)),
        associated && attached
    );
    if !associated || !attached || !default_cancel {
        dismiss(binding, PromptOutcome::PresentationFailed(binding));
    }
    Ok(())
}

fn snapshot(binding: PromptBinding) -> Option<(Retained<NSWindow>, Retained<NSAlert>)> {
    ACTIVE.with(|a| {
        a.borrow()
            .as_ref()
            .filter(|s| s.binding == binding)
            .map(|s| (s.parent.clone(), s.alert.clone()))
    })
}
fn poll(binding: PromptBinding) {
    if MainThreadMarker::new().is_none() {
        return;
    }
    let outcome = ACTIVE.with(|a| {
        a.borrow()
            .as_ref()
            .filter(|s| s.binding == binding)
            .and_then(|s| {
                if s.epoch.load(Ordering::SeqCst) != s.expected_epoch {
                    Some(PromptOutcome::Shutdown(binding))
                } else if Instant::now() >= s.deadline {
                    Some(PromptOutcome::TimedOut(binding))
                } else if !s.parent.isVisible() {
                    Some(PromptOutcome::ParentLost(binding))
                } else {
                    if Instant::now() >= s.approve_after {
                        s.approve.setEnabled(true);
                    }
                    None
                }
            })
    });
    if let Some(outcome) = outcome {
        dismiss(binding, outcome);
    } else {
        complete(binding, None);
    }
}
fn dismiss(binding: PromptBinding, outcome: PromptOutcome) {
    if MainThreadMarker::new().is_none() {
        return;
    }
    ACTIVE.with(|a| {
        if let Some(s) = a.borrow_mut().as_mut().filter(|s| s.binding == binding) {
            s.decision = Some(outcome);
            s.pin = None;
            s.secrets = None;
            if let Ok(mut c) = s.controller.lock() {
                let _ = c.revoke(outcome);
            }
        }
    });
    if let Some((parent, alert)) = snapshot(binding) {
        let window = alert.window();
        if window.sheetParent().is_some() {
            parent.endSheet_returnCode(&window, NSModalResponseCancel);
        }
        complete(binding, None);
    }
}
fn complete(binding: PromptBinding, response: Option<NSModalResponse>) {
    if MainThreadMarker::new().is_none() {
        return;
    }
    if let Some(response) = response {
        ACTIVE.with(|a| {
            if let Some(s) = a
                .borrow_mut()
                .as_mut()
                .filter(|s| s.binding == binding && s.decision.is_none())
            {
                let outcome = if s.epoch.load(Ordering::SeqCst) != s.expected_epoch {
                    PromptOutcome::Shutdown(binding)
                } else if !s.parent.isVisible() {
                    PromptOutcome::ParentLost(binding)
                } else if Instant::now() >= s.deadline {
                    PromptOutcome::TimedOut(binding)
                } else if (!matches!(s.purpose, Purpose::Inspection)
                    && Instant::now() < s.approve_after)
                    || response != NSAlertSecondButtonReturn
                    || s.last_retry_ack
                        .as_ref()
                        .is_some_and(|button| button.state() != NSControlStateValueOn)
                {
                    PromptOutcome::Cancelled(binding)
                } else {
                    let approved = match s.purpose {
                        Purpose::Inspection => {
                            s.pin = collect_field(&s.input);
                            s.pin.is_some()
                        }
                        Purpose::Recovery(_) => true,
                        Purpose::Mutation(op) => {
                            s.secrets = s
                                .new_input
                                .as_ref()
                                .and_then(collect_field)
                                .zip(s.confirm_input.as_ref().and_then(collect_field))
                                .and_then(|(new, confirm)| {
                                    crate::confirmed_mutation_secrets(
                                        op,
                                        if op == PinOperation::ChangePin {
                                            collect_field(&s.input)
                                        } else {
                                            None
                                        },
                                        new,
                                        confirm,
                                    )
                                });
                            s.secrets.is_some()
                        }
                    };
                    if approved {
                        PromptOutcome::Approved(binding)
                    } else {
                        PromptOutcome::Cancelled(binding)
                    }
                };
                s.input.setStringValue(&NSString::from_str(""));
                for field in [&s.new_input, &s.confirm_input].into_iter().flatten() {
                    field.setStringValue(&NSString::from_str(""));
                }
                s.decision = Some(outcome);
                if let Ok(mut c) = s.controller.lock() {
                    let _ = c.resolve(outcome, Instant::now());
                }
            }
        });
    }
    let decided = ACTIVE.with(|a| {
        a.borrow()
            .as_ref()
            .filter(|s| s.binding == binding)
            .is_some_and(|s| s.decision.is_some())
    });
    if !decided {
        return;
    }
    let Some((parent, alert)) = snapshot(binding) else {
        return;
    };
    let window = alert.window();
    window.orderOut(None);
    if window.isVisible()
        || window.sheetParent().is_some()
        || parent
            .attachedSheet()
            .is_some_and(|w| std::ptr::eq(&*w, &*window))
    {
        return;
    }
    let removed = ACTIVE.with(|a| a.borrow_mut().take());
    if let Some(mut s) = removed {
        let mut outcome = s.decision.unwrap_or(PromptOutcome::TornDown(binding));
        if Instant::now() >= s.deadline && matches!(outcome, PromptOutcome::Approved(_)) {
            outcome = PromptOutcome::TimedOut(binding);
        }
        if s.epoch.load(Ordering::SeqCst) != s.expected_epoch {
            outcome = PromptOutcome::Shutdown(binding);
        }
        if !matches!(outcome, PromptOutcome::Approved(_)) {
            s.pin = None;
            s.secrets = None;
        }
        let pin = s.pin.take();
        let secrets = s.secrets.take();
        let reply = s.reply.take();
        let controller = Arc::clone(&s.controller);
        drop(s); // Invalidate timer, remove observer, clear native control BEFORE acknowledgement.
        eprintln!("[authentication] prompt_teardown main=true detached=true");
        if let Ok(mut c) = controller.lock() {
            if !matches!(outcome, PromptOutcome::Approved(_)) {
                let _ = c.revoke(outcome);
            }
            let _ = c.did_teardown(binding, Instant::now());
        }
        if let Some(reply) = reply {
            match reply {
                Reply::Inspection(reply) => {
                    let _ = reply.send(PinCompletion {
                        binding,
                        outcome,
                        pin,
                    });
                }
                Reply::Mutation(reply) => {
                    let _ = reply.send(crate::MutationCompletion {
                        binding,
                        outcome,
                        secrets,
                    });
                }
            }
        }
    }
}
fn collect_field(field: &Retained<NSSecureTextField>) -> Option<fido_auth::PinSecret> {
    let value = field.stringValue();
    let len = value.lengthOfBytesUsingEncoding(NSUTF8StringEncoding);
    fido_auth::PinSecret::collect(|bytes| {
        if len > fido_auth::MAX_PIN_BYTES {
            return None;
        }
        // SAFETY: fixed bounded writable allocation; no intermediate Rust String or logging.
        unsafe {
            value.getCString_maxLength_encoding(
                NonNull::new(bytes.as_mut_ptr().cast())?,
                bytes.len(),
                NSUTF8StringEncoding,
            )
        }
        .then_some(len)
    })
    .ok()
}
pub fn shutdown() {
    let binding = ACTIVE.with(|a| a.borrow().as_ref().map(|s| s.binding));
    if let Some(binding) = binding {
        dismiss(binding, PromptOutcome::Shutdown(binding));
    }
}
