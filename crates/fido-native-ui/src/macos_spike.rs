//! Debug-only AppKit sheet host. Fixed non-secret content; no input widget or PIN pathway.
//! All AppKit objects stay on the main thread; timer/notification blocks capture only a binding.

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use block2::RcBlock;
use objc2::{MainThreadMarker, rc::Retained, runtime::ProtocolObject};
use objc2_app_kit::{
    NSAlert, NSAlertSecondButtonReturn, NSApplication, NSApplicationWillTerminateNotification,
    NSModalResponse, NSModalResponseCancel, NSWindow, NSWindowWillCloseNotification,
};
use objc2_foundation::{
    NSNotification, NSNotificationCenter, NSObjectProtocol, NSRunLoop, NSRunLoopCommonModes,
    NSString, NSTimer,
};

use crate::{PromptBinding, PromptController, PromptOutcome, PromptRequest};

type Controller = Arc<Mutex<PromptController>>;

struct Sheet {
    binding: PromptBinding,
    deadline: Instant,
    parent: Retained<NSWindow>,
    alert: Retained<NSAlert>,
    controller: Controller,
    timer: Retained<NSTimer>,
    observers: Vec<Retained<ProtocolObject<dyn NSObjectProtocol>>>,
    closing: bool,
    tick_seen: bool,
}

impl Drop for Sheet {
    fn drop(&mut self) {
        self.timer.invalidate();
        let center = NSNotificationCenter::defaultCenter();
        for observer in &self.observers {
            // SAFETY: these tokens were registered by this host; destruction is on main thread.
            unsafe { center.removeObserver((**observer).as_ref()) };
        }
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<Sheet>> = const { RefCell::new(None) };
}

fn on_main() -> MainThreadMarker {
    match MainThreadMarker::new() {
        Some(mtm) => mtm,
        None => panic!("AppKit spike callback ran outside the main thread"),
    }
}

/// Present on the AppKit main thread with a backend-selected real Tauri NSWindow.
///
/// # Safety
/// `parent` must point to a live NSWindow obtained from the trusted application's window registry.
/// The caller must keep that window alive until this function retains it. No renderer handle is
/// accepted. Replacement is a new window identity, never a retargeting of the active sheet.
pub unsafe fn present(
    parent: *mut c_void,
    request: PromptRequest,
    controller: Controller,
) -> Result<(), &'static str> {
    let mtm = MainThreadMarker::new().ok_or("AppKit presentation requires the main thread")?;
    if ACTIVE.with(|active| active.borrow().is_some()) {
        return Err("one global prompt; no queue");
    }
    if parent.is_null() {
        return Err("missing parent NSWindow");
    }
    // SAFETY: live NSWindow and main-thread access are part of the caller's contract.
    let parent = unsafe { Retained::<NSWindow>::retain(parent.cast()) }.ok_or("missing parent")?;
    if !parent.isVisible()
        || parent.isMiniaturized()
        || !NSApplication::sharedApplication(mtm).isActive()
    {
        return Err("parent must be visible and application foreground");
    }
    if parent.attachedSheet().is_some() {
        return Err("parent already has a sheet; no AppKit queue");
    }
    let binding = request.binding();
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str("FidoManager M1.5 native UI spike"));
    alert.setInformativeText(&NSString::from_str(
        "Non-secret placeholder only. Continue records a native prompt result in Rust; it performs no authenticator operation. Cancel is the default. This sheet expires automatically."
    ));
    let cancel = alert.addButtonWithTitle(&NSString::from_str("Cancel"));
    cancel.setKeyEquivalent(&NSString::from_str("\r"));
    let proceed = alert.addButtonWithTitle(&NSString::from_str("Continue spike"));
    proceed.setKeyEquivalent(&NSString::from_str(""));
    alert.layout();
    alert.window().makeFirstResponder(Some(&cancel));

    let tick = RcBlock::new(move |_: NonNull<NSTimer>| {
        on_main();
        poll(binding);
    });
    // SAFETY: timer is registered exclusively on the main run loop; block captures only Send IDs.
    let timer = unsafe { NSTimer::timerWithTimeInterval_repeats_block(0.05, true, &tick) };
    // Common modes keep timeout active during ordinary AppKit event tracking (no nested loop).
    unsafe { NSRunLoop::currentRunLoop().addTimer_forMode(&timer, NSRunLoopCommonModes) };
    let center = NSNotificationCenter::defaultCenter();
    let closed = RcBlock::new(move |_: NonNull<NSNotification>| {
        on_main();
        dismiss(binding, PromptOutcome::ParentLost(binding));
    });
    let terminating = RcBlock::new(move |_: NonNull<NSNotification>| {
        shutdown();
    });
    // SAFETY: exact NSWindow object filter, synchronous posting on AppKit main thread; blocks are
    // Send (only IDs captured). The tokens are removed on every successful teardown.
    let observers = unsafe {
        vec![
            center.addObserverForName_object_queue_usingBlock(
                Some(NSWindowWillCloseNotification),
                Some(&parent),
                None,
                &closed,
            ),
            center.addObserverForName_object_queue_usingBlock(
                Some(NSApplicationWillTerminateNotification),
                None,
                None,
                &terminating,
            ),
        ]
    };
    ACTIVE.with(|active| {
        *active.borrow_mut() = Some(Sheet {
            binding,
            deadline: request.deadline(),
            parent: parent.clone(),
            alert: alert.clone(),
            controller,
            timer,
            observers,
            closing: false,
            tick_seen: false,
        })
    });
    let completion = RcBlock::new(move |response: NSModalResponse| {
        on_main();
        eprintln!("[native-ui-spike] AppKit completion main=true binding={binding:?}");
        complete(binding, Some(response));
    });
    // Asynchronous sheet API. Returns to Tauri's ordinary event loop immediately.
    alert.beginSheetModalForWindow_completionHandler(&parent, Some(&completion));
    let window = alert.window();
    let attached = parent
        .attachedSheet()
        .is_some_and(|sheet| std::ptr::eq(&*sheet, &*window));
    let associated = window
        .sheetParent()
        .is_some_and(|owner| std::ptr::eq(&*owner, &*parent));
    let default_cancel = window.defaultButtonCell().is_some_and(|cell| {
        cancel.cell().is_some_and(|cancel_cell| {
            std::ptr::from_ref(&*cell).cast::<c_void>()
                == std::ptr::from_ref(&*cancel_cell).cast::<c_void>()
        })
    });
    let approval_focused = window.firstResponder().is_some_and(|responder| {
        std::ptr::from_ref(&*responder).cast::<c_void>()
            == std::ptr::from_ref(&*proceed).cast::<c_void>()
    });
    eprintln!(
        "[native-ui-spike] presented main=true attached={attached} sheet_parent={associated} default_cancel={default_cancel} approval_focused={approval_focused} binding={binding:?}"
    );
    if !attached || !associated || !default_cancel || approval_focused {
        dismiss(binding, PromptOutcome::PresentationFailed(binding));
    }
    Ok(())
}

fn snapshot(binding: PromptBinding) -> Option<(Retained<NSWindow>, Retained<NSAlert>, Controller)> {
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .filter(|s| s.binding == binding)
            .map(|s| (s.parent.clone(), s.alert.clone(), Arc::clone(&s.controller)))
    })
}

fn poll(binding: PromptBinding) {
    ACTIVE.with(|active| {
        if let Some(s) = active.borrow_mut().as_mut().filter(|s| s.binding == binding) {
            if !s.tick_seen {
                s.tick_seen = true;
                eprintln!("[native-ui-spike] ordinary main-run-loop timer progressed while sheet open binding={binding:?}");
            }
        }
    });
    let status = ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .filter(|s| s.binding == binding)
            .map(|s| (s.deadline, s.closing))
    });
    let Some((deadline, closing)) = status else {
        return;
    };
    if closing {
        complete(binding, None);
        return;
    }
    let Some((parent, alert, _)) = snapshot(binding) else {
        return;
    };
    let associated = alert
        .window()
        .sheetParent()
        .is_some_and(|owner| std::ptr::eq(&*owner, &*parent));
    if !parent.isVisible() || !associated {
        dismiss(binding, PromptOutcome::ParentLost(binding));
    } else if Instant::now() >= deadline {
        dismiss(binding, PromptOutcome::TimedOut(binding));
    }
}

fn dismiss(binding: PromptBinding, outcome: PromptOutcome) {
    on_main();
    let Some((parent, alert, controller)) = snapshot(binding) else {
        return;
    };
    if let Ok(mut c) = controller.lock() {
        let _ = c.revoke(outcome);
    }
    ACTIVE.with(|active| {
        if let Some(s) = active.borrow_mut().as_mut() {
            s.closing = true;
        }
    });
    let window = alert.window();
    if window.sheetParent().is_some() {
        parent.endSheet_returnCode(&window, NSModalResponseCancel);
    }
    // endSheet may invoke the completion synchronously. This fallback is idempotent and proves
    // detachment even during shutdown when there may be no later event-loop turn.
    complete(binding, None);
}

fn complete(binding: PromptBinding, response: Option<NSModalResponse>) {
    on_main();
    let Some((parent, alert, controller)) = snapshot(binding) else {
        return;
    };
    let window = alert.window();
    if let Some(response) = response {
        let outcome = if !parent.isVisible() {
            PromptOutcome::ParentLost(binding)
        } else if response == NSAlertSecondButtonReturn {
            PromptOutcome::Approved(binding)
        } else {
            PromptOutcome::Cancelled(binding)
        };
        if let Ok(mut c) = controller.lock() {
            let _ = c.resolve(outcome, Instant::now());
        }
    }
    ACTIVE.with(|active| {
        if let Some(s) = active.borrow_mut().as_mut() {
            s.closing = true;
        }
    });
    window.orderOut(None);
    let detached = !window.isVisible()
        && window.sheetParent().is_none()
        && !parent
            .attachedSheet()
            .is_some_and(|sheet| std::ptr::eq(&*sheet, &*window));
    if !detached {
        return;
    } // Keep reservation and timer alive; never guess quiescence.
    let removed = ACTIVE.with(|active| active.borrow_mut().take());
    drop(removed); // invalidate timer and unregister notifications before delivering to authority.
    if let Ok(mut c) = controller.lock() {
        let _ = c.did_teardown(binding, Instant::now());
    }
    eprintln!("[native-ui-spike] teardown main=true detached=true binding={binding:?}");
}

pub fn cancel() {
    on_main();
    let binding = ACTIVE.with(|active| active.borrow().as_ref().map(|s| s.binding));
    if let Some(b) = binding {
        dismiss(b, PromptOutcome::Cancelled(b));
    }
}

pub fn teardown() {
    on_main();
    let binding = ACTIVE.with(|active| active.borrow().as_ref().map(|s| s.binding));
    if let Some(b) = binding {
        dismiss(b, PromptOutcome::TornDown(b));
    }
}

pub fn shutdown() {
    on_main();
    let item = ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .map(|s| (s.binding, Arc::clone(&s.controller)))
    });
    if let Some((b, controller)) = item {
        if let Ok(mut c) = controller.lock() {
            c.shutdown();
        }
        dismiss(b, PromptOutcome::Shutdown(b));
    }
}

/// Mechanical native-button fixture only. This is neither renderer evidence nor human consent.
pub fn exercise_native_button(continue_spike: bool) {
    on_main();
    let binding = ACTIVE.with(|active| active.borrow().as_ref().map(|s| s.binding));
    if let Some(b) = binding {
        if let Some((_, alert, _)) = snapshot(b) {
            let buttons = alert.buttons();
            let button = buttons.objectAtIndex(usize::from(continue_spike));
            eprintln!("[native-ui-spike] mechanical native button fixture; no production approval");
            // SAFETY: NSAlert owns target/action; fixed non-mutating spike button, on main thread.
            unsafe { button.performClick(None) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_core::WorkflowId;
    use std::time::Duration;

    #[test]
    fn off_main_presentation_fails_before_touching_native_parent() {
        let mut controller = PromptController::default();
        let (request, receiver) = match controller.request(
            WorkflowId::from_raw(1),
            Instant::now(),
            Duration::from_secs(1),
        ) {
            Ok(pair) => pair,
            Err(e) => panic!("request failed: {e}"),
        };
        let controller = Arc::new(Mutex::new(controller));
        let result = std::thread::spawn(move || {
            // SAFETY: thread validation must reject before dereferencing this null parent.
            unsafe { present(std::ptr::null_mut(), request, controller) }
        })
        .join()
        .unwrap_or_else(|_| panic!("test thread failed"));
        assert_eq!(result, Err("AppKit presentation requires the main thread"));
        assert!(matches!(
            receiver.try_recv(),
            Ok(PromptOutcome::OwnerLost(_))
        ));
    }
}
