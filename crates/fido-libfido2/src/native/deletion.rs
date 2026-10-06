//! Exactly one resident-credential deletion call on a consumed, prepared macOS native object.

use super::{
    CborInfo, Device, FIDO_OK, NativeDeadline, NativeDeviceKey, NativeError, NativeErrorKind,
    extract_device_info, fido_dev_get_cbor_info, fido_dev_open, map_libfido2_error,
};
use fido_auth::{
    GrantKind, PinSecret,
    deletion::{DeleteCredentialResult, select_delete_kind},
};
use std::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

unsafe extern "C" {
    fn fido_credman_del_dev_rk(
        device: *mut c_void,
        credential_id: *const u8,
        credential_id_len: usize,
        pin: *const c_char,
    ) -> c_int;
    fn fido_dev_get_retry_count(device: *mut c_void, retries: *mut c_int) -> c_int;
    fn fido_dev_supports_permissions(device: *const c_void) -> bool;
}

struct Session {
    device: Device,
    kind: GrantKind,
    retries: u8,
}

// SAFETY: the unique native device is owned by this session and moves only to the worker thread.
unsafe impl Send for Session {}

fn eligible(device: &mut Device, deadline: &NativeDeadline) -> Result<GrantKind, NativeError> {
    let info = CborInfo::new()?;
    device.set_timeout(deadline)?;
    // SAFETY: both objects are uniquely owned and live for the bounded call.
    let code = unsafe { fido_dev_get_cbor_info(device.ptr, info.ptr) };
    if code != FIDO_OK {
        return Err(map_libfido2_error(code, deadline));
    }
    // SAFETY: bounded extraction while the CborInfo object is live.
    let info = unsafe { extract_device_info(info.ptr) }?;
    let kind = select_delete_kind(
        &info.versions,
        info.options
            .iter()
            .map(|option| (option.name.as_str(), option.enabled)),
    )
    .ok_or(NativeError::new(NativeErrorKind::Unsupported, None))?;

    // SAFETY: scalar accessor on the same live device. Full scoped CredMan must really use the
    // permissions path; legacy preview must really be unscoped. Never trust GetInfo alone.
    if unsafe { fido_dev_supports_permissions(device.ptr) } != (kind != GrantKind::LegacyUnscoped) {
        return Err(NativeError::new(NativeErrorKind::Malformed, None));
    }
    Ok(kind)
}

pub(super) fn prepare(
    key: &NativeDeviceKey,
    deadline: NativeDeadline,
) -> Result<Box<dyn crate::NativeCredentialDeletionSession>, NativeError> {
    let path = key.to_cstring()?;
    let mut device = Device::new()?;
    device.set_timeout(&deadline)?;
    // SAFETY: bounded path and unique live device.
    let code = unsafe { fido_dev_open(device.ptr, path.as_ptr()) };
    if code != FIDO_OK {
        return Err(map_libfido2_error(code, &deadline));
    }
    device.opened = true;

    let kind = eligible(&mut device, &deadline)?;
    device.set_timeout(&deadline)?;
    let mut retries = 0;
    // SAFETY: getPinRetries supplies no PIN and consumes no authentication attempt.
    let code = unsafe { fido_dev_get_retry_count(device.ptr, ptr::addr_of_mut!(retries)) };
    if code != FIDO_OK {
        return Err(map_libfido2_error(code, &deadline));
    }
    let retries = u8::try_from(retries)
        .ok()
        .filter(|value| (1..=8).contains(value))
        .ok_or(NativeError::new(NativeErrorKind::Unsupported, None))?;

    Ok(Box::new(Session {
        device,
        kind,
        retries,
    }))
}

impl crate::NativeCredentialDeletionSession for Session {
    fn kind(&self) -> GrantKind {
        self.kind
    }

    fn pin_retries(&self) -> u8 {
        self.retries
    }

    fn execute(
        mut self: Box<Self>,
        credential_id: Vec<u8>,
        pin: PinSecret,
        deadline: NativeDeadline,
    ) -> DeleteCredentialResult {
        let result = crate::deletion::execute(&mut *self, credential_id, pin, deadline);
        drop(self);
        result
    }
}

impl crate::deletion::DeletionNative for Session {
    fn revalidate(&mut self, deadline: &NativeDeadline) -> bool {
        let Ok(kind) = eligible(&mut self.device, deadline) else {
            return false;
        };
        if kind != self.kind || self.device.set_timeout(deadline).is_err() {
            return false;
        }

        let mut retries = 0;
        // SAFETY: passive getPinRetries on the same unique native object. A changed retry state
        // invalidates the native warning context and fails before deletion entry.
        let code = unsafe { fido_dev_get_retry_count(self.device.ptr, ptr::addr_of_mut!(retries)) };
        if code != FIDO_OK || u8::try_from(retries).ok() != Some(self.retries) {
            return false;
        }
        self.device.set_timeout(deadline).is_ok()
    }

    fn enter_once(&mut self, credential_id: &[u8], pin: &PinSecret) -> i32 {
        // SAFETY: exact bounded credential ID and fixed zeroizing PIN buffer are borrowed only for
        // this single high-level libfido2 call. The pinned implementation sends DeleteCredential
        // and waits for its CTAP status under the device timeout.
        unsafe {
            fido_credman_del_dev_rk(
                self.device.ptr,
                credential_id.as_ptr(),
                credential_id.len(),
                pin.as_ptr(),
            )
        }
    }

    fn close(&mut self) -> bool {
        self.device.close()
    }
}
