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

pub type Controller = Arc<Mutex<PromptController>>;
struct Sheet {
    binding: PromptBinding,
    deadline: Instant,
    parent: Retained<NSWindow>,
    alert: Retained<NSAlert>,
    input: Retained<NSSecureTextField>,
    last_retry_ack: Option<Retained<NSButton>>,
    controller: Controller,
    reply: Option<Sender<PinCompletion>>,
    decision: Option<PromptOutcome>,
    pin: Option<fido_auth::PinSecret>,
    timer: Retained<NSTimer>,
    close_observer: Retained<ProtocolObject<dyn NSObjectProtocol>>,
    epoch: Arc<AtomicU64>,
    expected_epoch: u64,
}
impl Drop for Sheet {
    fn drop(&mut self) {
        self.timer.invalidate();
        // SAFETY: token owned by this main-thread sheet; removed before release.
        unsafe {
            NSNotificationCenter::defaultCenter().removeObserver(self.close_observer.as_ref())
        };
        self.input.setStringValue(&NSString::from_str(""));
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
    alert.setMessageText(&NSString::from_str("Authenticate security key"));
    let retry_text = retries.map_or("Retry count unavailable.".to_owned(), |n| {
        if n <= 3 {
            format!("Warning: only {n} PIN retries remain.")
        } else {
            format!("PIN retries remaining: {n}.")
        }
    });
    alert.setInformativeText(&NSString::from_str(&format!(
        "Selected key: {target_label}. Inspect stored credentials and passkeys. This read-only operation will not change credentials. Enter this key's PIN. {retry_text} One submission makes one attempt; there is no automatic retry."
    )));
    let cancel = alert.addButtonWithTitle(&NSString::from_str("Cancel"));
    cancel.setKeyEquivalent(&NSString::from_str("\r"));
    alert
        .addButtonWithTitle(&NSString::from_str("Authenticate"))
        .setKeyEquivalent(&NSString::from_str(""));
    let input = NSSecureTextField::initWithFrame(
        NSSecureTextField::alloc(mtm),
        NSRect::new(NSPoint::new(0., 0.), NSSize::new(300., 26.)),
    );
    input.setPlaceholderString(Some(&NSString::from_str("Security key PIN")));
    let last_retry_ack = if retries == Some(1) {
        let button = NSButton::new(mtm);
        button.setButtonType(NSButtonType::Switch);
        button.setTitle(&NSString::from_str(
            "I understand this is the last PIN retry",
        ));
        button.setFrame(NSRect::new(NSPoint::new(0., 30.), NSSize::new(340., 26.)));
        Some(button)
    } else {
        None
    };
    let accessory = NSView::initWithFrame(
        NSView::alloc(mtm),
        NSRect::new(
            NSPoint::new(0., 0.),
            NSSize::new(340., if last_retry_ack.is_some() { 60. } else { 26. }),
        ),
    );
    accessory.addSubview(&input);
    if let Some(button) = &last_retry_ack {
        accessory.addSubview(button);
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
            input,
            last_retry_ack,
            controller,
            reply: Some(reply),
            decision: None,
            pin: None,
            timer,
            close_observer,
            epoch,
            expected_epoch,
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
        "[authentication] prompt main=true secure_control=true window_modal={} default_cancel={default_cancel}",
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
                } else if response != NSAlertSecondButtonReturn
                    || s.last_retry_ack
                        .as_ref()
                        .is_some_and(|button| button.state() != NSControlStateValueOn)
                {
                    PromptOutcome::Cancelled(binding)
                } else {
                    let value = s.input.stringValue();
                    let len = value.lengthOfBytesUsingEncoding(NSUTF8StringEncoding);
                    s.pin = fido_auth::PinSecret::collect(|bytes| {
                        if len > fido_auth::MAX_PIN_BYTES {
                            return None;
                        }
                        // SAFETY: fixed writable 64-byte storage; NSString cannot write beyond it.
                        unsafe {
                            value.getCString_maxLength_encoding(
                                NonNull::new(bytes.as_mut_ptr().cast())?,
                                bytes.len(),
                                NSUTF8StringEncoding,
                            )
                        }
                        .then_some(len)
                    })
                    .ok();
                    if s.pin.is_some() {
                        PromptOutcome::Approved(binding)
                    } else {
                        PromptOutcome::Cancelled(binding)
                    }
                };
                s.input.setStringValue(&NSString::from_str(""));
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
        }
        let completion = PinCompletion {
            binding,
            outcome,
            pin: s.pin.take(),
        };
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
            let _ = reply.send(completion);
        }
    }
}
pub fn shutdown() {
    let binding = ACTIVE.with(|a| a.borrow().as_ref().map(|s| s.binding));
    if let Some(binding) = binding {
        dismiss(binding, PromptOutcome::Shutdown(binding));
    }
}
