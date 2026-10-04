//! Exactly one PIN set/change call on a consumed, prepared macOS native object.
use super::{
    CborInfo, Device, FIDO_OK, NativeDeadline, NativeDeviceKey, NativeError, NativeErrorKind,
    extract_device_info, fido_dev_get_cbor_info, fido_dev_open, map_libfido2_error,
};
use fido_auth::mutation::{
    PinMutationResult, PinMutationSecrets, PinOperation, available_operation,
};
use std::{
    ffi::{c_char, c_int, c_void},
    ptr,
};
unsafe extern "C" {
    fn fido_dev_set_pin(
        device: *mut c_void,
        new_pin: *const c_char,
        old_pin: *const c_char,
    ) -> c_int;
    fn fido_dev_get_retry_count(device: *mut c_void, retries: *mut c_int) -> c_int;
    fn fido_dev_supports_pin(device: *const c_void) -> bool;
    fn fido_dev_get_pin_protocol(device: *const c_void) -> u8;
}
struct Session {
    device: Device,
    operation: PinOperation,
    retries: Option<u8>,
}
// SAFETY: unique device ownership moves only to the worker's sole native execution thread.
unsafe impl Send for Session {}
fn eligible(
    device: &mut Device,
    op: PinOperation,
    deadline: &NativeDeadline,
) -> Result<(), NativeError> {
    // SAFETY: these passive accessors inspect flags populated during this object's open/GetInfo.
    // The pinned API selects only PIN protocol 1 or 2; missing/unsupported negotiation is refused.
    if !unsafe { fido_dev_supports_pin(device.ptr) }
        || !matches!(unsafe { fido_dev_get_pin_protocol(device.ptr) }, 1 | 2)
    {
        return Err(NativeError::new(NativeErrorKind::Unsupported, None));
    }
    let info = CborInfo::new()?;
    device.set_timeout(deadline)?;
    // SAFETY: both objects uniquely owned and live for the entire bounded call.
    let code = unsafe { fido_dev_get_cbor_info(device.ptr, info.ptr) };
    if code != FIDO_OK {
        return Err(map_libfido2_error(code, deadline));
    }
    // SAFETY: bounded extraction while the info object is live.
    let info = unsafe { extract_device_info(info.ptr) }?;
    if available_operation(
        &info.versions,
        info.options.iter().map(|o| (o.name.as_str(), o.enabled)),
    ) != Some(op)
    {
        return Err(NativeError::new(NativeErrorKind::Unsupported, None));
    }
    Ok(())
}
pub(super) fn prepare(
    key: &NativeDeviceKey,
    operation: PinOperation,
    deadline: NativeDeadline,
) -> Result<Box<dyn crate::NativePinMutationSession>, NativeError> {
    let path = key.to_cstring()?;
    let mut device = Device::new()?;
    device.set_timeout(&deadline)?;
    // SAFETY: bounded registry path and unique live device; never reopened after preparation.
    let code = unsafe { fido_dev_open(device.ptr, path.as_ptr()) };
    if code != FIDO_OK {
        return Err(map_libfido2_error(code, &deadline));
    }
    device.opened = true;
    eligible(&mut device, operation, &deadline)?;
    let retries = if operation == PinOperation::ChangePin {
        device.set_timeout(&deadline)?;
        let mut retries = 0;
        // SAFETY: getPinRetries supplies no PIN and consumes no authentication attempt.
        let code = unsafe { fido_dev_get_retry_count(device.ptr, &mut retries) };
        if code != FIDO_OK {
            return Err(map_libfido2_error(code, &deadline));
        }
        Some(
            u8::try_from(retries)
                .ok()
                .filter(|n| (1..=8).contains(n))
                .ok_or(NativeError::new(NativeErrorKind::Unsupported, None))?,
        )
    } else {
        None
    };
    Ok(Box::new(Session {
        device,
        operation,
        retries,
    }))
}
impl crate::NativePinMutationSession for Session {
    fn operation(&self) -> PinOperation {
        self.operation
    }
    fn pin_retries(&self) -> Option<u8> {
        self.retries
    }
    fn execute(
        mut self: Box<Self>,
        secrets: PinMutationSecrets,
        deadline: NativeDeadline,
    ) -> PinMutationResult {
        let op = self.operation;
        let result = crate::mutation::execute(&mut *self, op, secrets, deadline);
        drop(self);
        result
    }
}
impl crate::mutation::PinNative for Session {
    fn revalidate(&mut self, op: PinOperation, deadline: &NativeDeadline) -> bool {
        if op != self.operation
            || eligible(&mut self.device, op, deadline).is_err()
            || self.device.set_timeout(deadline).is_err()
        {
            return false;
        }
        if op == PinOperation::ChangePin {
            let mut retries = 0;
            // SAFETY: passive getPinRetries on this same unique native object. A changed retry
            // state invalidates the displayed warning/last-retry acknowledgement; never guess.
            let code = unsafe { fido_dev_get_retry_count(self.device.ptr, &mut retries) };
            if code != FIDO_OK || u8::try_from(retries).ok() != self.retries {
                return false;
            }
        }
        self.device.set_timeout(deadline).is_ok()
    }
    fn enter_once(&mut self, secrets: &PinMutationSecrets) -> i32 {
        let (new, current) = secrets.pins();
        // SAFETY: unique, current native object. Fixed zeroizing C buffers borrowed only for this
        // one high-level call. Pinned 1.17 selects Set PIN with NULL, Change PIN with current PIN.
        unsafe {
            fido_dev_set_pin(
                self.device.ptr,
                new.as_ptr(),
                current.map_or(ptr::null(), |p| p.as_ptr()),
            )
        }
    }
    fn close(&mut self) -> bool {
        self.device.close()
    }
}
