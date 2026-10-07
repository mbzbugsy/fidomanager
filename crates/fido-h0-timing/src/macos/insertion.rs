//! Insertion clock: IOKit first-match notifications for HID services on the FIDO usage page
//! (0xF1D0), the same services libfido2's manifest lists. Absence and cardinality are decided by
//! the libfido2 manifest, not by this watch.
//!
//! This only *observes* the IORegistry. It never opens a device: no HID manager open, no
//! IOHIDDevice handle and no report I/O, so it cannot contend with libfido2's exclusive (seized)
//! open and cannot send anything to an authenticator. The notification port runs on its own thread
//! and run loop; each callback timestamps immediately and forwards the instant over a channel.

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::measurement::InsertionWatch;

type MachPort = c_uint;
type IoIterator = MachPort;
type KernReturn = c_int;
type Callback = unsafe extern "C" fn(refcon: *mut c_void, iterator: IoIterator);

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IONotificationPortCreate(main_port: MachPort) -> *mut c_void;
    fn IONotificationPortDestroy(port: *mut c_void);
    fn IONotificationPortGetRunLoopSource(port: *mut c_void) -> *mut c_void;
    fn IOServiceMatching(name: *const c_char) -> *mut c_void;
    fn IOServiceAddMatchingNotification(
        port: *mut c_void,
        notification_type: *const c_char,
        matching: *mut c_void,
        callback: Callback,
        refcon: *mut c_void,
        notification: *mut IoIterator,
    ) -> KernReturn;
    fn IOIteratorNext(iterator: IoIterator) -> MachPort;
    fn IOObjectRelease(object: MachPort) -> KernReturn;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFRunLoopDefaultMode: *const c_void;
    fn CFRunLoopGetCurrent() -> *mut c_void;
    fn CFRunLoopAddSource(run_loop: *mut c_void, source: *mut c_void, mode: *const c_void);
    fn CFRunLoopRunInMode(mode: *const c_void, seconds: f64, return_after_source: u8) -> i32;
    fn CFNumberCreate(
        allocator: *const c_void,
        number_type: isize,
        value: *const c_void,
    ) -> *const c_void;
    fn CFStringCreateWithCString(
        allocator: *const c_void,
        text: *const c_char,
        encoding: u32,
    ) -> *const c_void;
    fn CFDictionarySetValue(dictionary: *mut c_void, key: *const c_void, value: *const c_void);
    fn CFRelease(object: *const c_void);
}

const MAIN_PORT_DEFAULT: MachPort = 0;
const KERN_SUCCESS: KernReturn = 0;
const FIRST_MATCH: &std::ffi::CStr = c"IOServiceFirstMatch";
const CF_NUMBER_SINT32: isize = 3;
const CF_STRING_UTF8: u32 = 0x0800_0100;
const FIDO_USAGE_PAGE: i32 = 0xF1D0;

/// Drains an IOKit iterator (which also re-arms the notification) and returns how many services
/// it carried.
///
/// # Safety
/// `iterator` must be a live notification iterator.
unsafe fn drain(iterator: IoIterator) -> usize {
    let mut count = 0;
    loop {
        // SAFETY: live iterator per the contract; every returned object is released at once.
        let object = unsafe { IOIteratorNext(iterator) };
        if object == 0 {
            return count;
        }
        // SAFETY: releases the reference IOIteratorNext returned.
        unsafe { IOObjectRelease(object) };
        count += 1;
    }
}

unsafe extern "C" fn on_arrival(refcon: *mut c_void, iterator: IoIterator) {
    let at = Instant::now();
    // SAFETY: refcon is the sender box owned by the watcher thread for the port's lifetime.
    let sender = unsafe { &*(refcon as *const Sender<Instant>) };
    // SAFETY: IOKit passes the live notification iterator.
    if unsafe { drain(iterator) } > 0 {
        let _ = sender.send(at);
    }
}

/// Builds `{IOProviderClass: IOHIDDevice, PrimaryUsagePage: 0xF1D0}`; the notification call
/// consumes the returned reference.
fn fido_hid_matching() -> Option<*mut c_void> {
    // SAFETY: CoreFoundation/IOKit constructors with constant NUL-terminated inputs; every
    // temporary is released after the dictionary retains it.
    unsafe {
        let matching = IOServiceMatching(c"IOHIDDevice".as_ptr());
        if matching.is_null() {
            return None;
        }
        let key = CFStringCreateWithCString(
            std::ptr::null(),
            c"PrimaryUsagePage".as_ptr(),
            CF_STRING_UTF8,
        );
        let value = CFNumberCreate(
            std::ptr::null(),
            CF_NUMBER_SINT32,
            (&FIDO_USAGE_PAGE as *const i32).cast(),
        );
        if key.is_null() || value.is_null() {
            if !key.is_null() {
                CFRelease(key);
            }
            if !value.is_null() {
                CFRelease(value);
            }
            CFRelease(matching);
            return None;
        }
        CFDictionarySetValue(matching, key, value);
        CFRelease(key);
        CFRelease(value);
        Some(matching)
    }
}

pub struct IoKitInsertionWatch {
    events: Receiver<Instant>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    armed_arrivals: Vec<Instant>,
}

impl IoKitInsertionWatch {
    pub fn start() -> std::io::Result<Self> {
        let (sender, events) = channel();
        let (ready_sender, ready) = channel::<Result<(), String>>();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("h0-insertion-watch".into())
            .spawn(move || {
                // The box stays at a fixed address for the port's lifetime (refcon pointer).
                let sender: Box<Sender<Instant>> = Box::new(sender);
                // SAFETY: notification port on this thread's run loop. Every IOKit object created
                // here is released on this thread before the sender box drops.
                unsafe {
                    let port = IONotificationPortCreate(MAIN_PORT_DEFAULT);
                    if port.is_null() {
                        let _ = ready_sender.send(Err("IONotificationPortCreate failed".into()));
                        return;
                    }
                    let Some(matching) = fido_hid_matching() else {
                        IONotificationPortDestroy(port);
                        let _ = ready_sender.send(Err("matching dictionary failed".into()));
                        return;
                    };
                    let mut iterator: IoIterator = 0;
                    let result = IOServiceAddMatchingNotification(
                        port,
                        FIRST_MATCH.as_ptr(),
                        matching,
                        on_arrival,
                        (&*sender as *const Sender<Instant>).cast_mut().cast(),
                        &mut iterator,
                    );
                    if result != KERN_SUCCESS {
                        IONotificationPortDestroy(port);
                        let _ = ready_sender
                            .send(Err("IOServiceAddMatchingNotification failed".into()));
                        return;
                    }
                    // Draining arms the notification; services already present are not arrivals.
                    drain(iterator);
                    CFRunLoopAddSource(
                        CFRunLoopGetCurrent(),
                        IONotificationPortGetRunLoopSource(port),
                        kCFRunLoopDefaultMode,
                    );
                    let _ = ready_sender.send(Ok(()));
                    while !thread_stop.load(Ordering::Acquire) {
                        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, 1);
                    }
                    IOObjectRelease(iterator);
                    IONotificationPortDestroy(port);
                }
                drop(sender);
            })?;
        ready
            .recv_timeout(Duration::from_secs(5))
            .map_err(std::io::Error::other)?
            .map_err(std::io::Error::other)?;
        Ok(Self {
            events,
            stop,
            thread: Some(thread),
            armed_arrivals: Vec::new(),
        })
    }

    fn pump(&mut self) {
        while let Ok(at) = self.events.try_recv() {
            self.armed_arrivals.push(at);
        }
    }
}

impl InsertionWatch for IoKitInsertionWatch {
    fn arm(&mut self) {
        self.pump();
        self.armed_arrivals.clear();
    }

    fn arrival_since_arm(&mut self, wait: Duration) -> Option<Instant> {
        self.pump();
        if self.armed_arrivals.is_empty() {
            if let Ok(at) = self.events.recv_timeout(wait) {
                self.armed_arrivals.push(at);
                self.pump();
            }
        }
        self.armed_arrivals.iter().min().copied()
    }
}

impl Drop for IoKitInsertionWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
