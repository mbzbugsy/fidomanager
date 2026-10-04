//! macOS-only production PUAT path; linked only in the child worker.
use super::{
    CborInfo, Device, FIDO_OK, NativeDeadline, NativeDeviceKey, NativeError, NativeErrorKind,
    extract_device_info, fido_dev_get_cbor_info, fido_dev_open, map_libfido2_error,
};
use crate::NativeAuthenticationSession;
use fido_auth::{
    AcquisitionBinding, AuthenticationEvidence, AuthenticationStatus, AuthorizationTransaction,
    GrantKind, NativeAuthorization, PinSecret, classify_acquisition, select_kind,
};
use std::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

// macOS resolves these symbols exclusively from the private archive selected by build.rs.
unsafe extern "C" {
    fn fido_dev_supports_permissions(device: *const c_void) -> bool;
    fn fido_dev_get_retry_count(device: *mut c_void, retries: *mut c_int) -> c_int;
    fn fido_dev_get_puat(
        device: *mut c_void,
        permissions: u32,
        rp: *const c_char,
        pin: *const c_char,
    ) -> c_int;
    fn fido_dev_set_puat(device: *mut c_void, bytes: *const u8, len: usize) -> c_int;
    fn fido_dev_puat_len(device: *const c_void) -> usize;
    fn fido_dev_puat_ptr(device: *const c_void) -> *const u8;
}

struct Session {
    device: Device,
    kind: GrantKind,
    retries: Option<u8>,
    deadline: NativeDeadline,
}
// SAFETY: this uniquely owned fido_dev_t can move to the worker engine; no shared pointer or
// concurrent native access is possible. All native calls remain on the worker main thread.
unsafe impl Send for Session {}

pub(super) fn prepare(
    key: &NativeDeviceKey,
    deadline: NativeDeadline,
) -> Result<Box<dyn NativeAuthenticationSession>, NativeError> {
    let path = key.to_cstring()?;
    let mut device = Device::new()?;
    device.set_timeout(&deadline)?;
    // SAFETY: unique live object and bounded NUL-terminated path from worker registry.
    let code = unsafe { fido_dev_open(device.ptr, path.as_ptr()) };
    if code != FIDO_OK {
        return Err(map_libfido2_error(code, &deadline));
    }
    device.opened = true;
    let info = CborInfo::new()?;
    device.set_timeout(&deadline)?;
    // SAFETY: both live native objects are owned in this scope.
    let code = unsafe { fido_dev_get_cbor_info(device.ptr, info.ptr) };
    if code != FIDO_OK {
        return Err(map_libfido2_error(code, &deadline));
    }
    // SAFETY: info remains live through bounded extraction.
    let capabilities = unsafe { extract_device_info(info.ptr) }?;
    let kind = select_kind(
        &capabilities.versions,
        capabilities
            .options
            .iter()
            .map(|o| (o.name.as_str(), o.enabled)),
    )
    .ok_or(NativeError::new(NativeErrorKind::Unsupported, None))?;
    // SAFETY: scalar accessor on live object. Cross-check libfido2's actual fallback decision.
    if unsafe { fido_dev_supports_permissions(device.ptr) } != (kind != GrantKind::LegacyUnscoped) {
        return Err(NativeError::new(NativeErrorKind::Malformed, None));
    }
    device.set_timeout(&deadline)?;
    let mut retries = 0;
    // SAFETY: live device and writable c_int. getPinRetries sends no PIN.
    let code = unsafe { fido_dev_get_retry_count(device.ptr, &mut retries) };
    if code != FIDO_OK {
        return Err(map_libfido2_error(code, &deadline));
    }
    let retries = u8::try_from(retries)
        .ok()
        .filter(|r| *r <= 8)
        .ok_or(NativeError::new(NativeErrorKind::Malformed, None))?;
    if retries == 0 {
        return Err(NativeError::new(NativeErrorKind::Unsupported, None));
    }
    let session = Session {
        device,
        kind,
        retries: Some(retries),
        deadline,
    };
    if session.attached() {
        return Err(NativeError::new(NativeErrorKind::Internal, None));
    }
    Ok(Box::new(session))
}

impl NativeAuthenticationSession for Session {
    fn kind(&self) -> GrantKind {
        self.kind
    }
    fn pin_retries(&self) -> Option<u8> {
        self.retries
    }
    fn inspect(
        mut self: Box<Self>,
        binding: AcquisitionBinding,
        pin: PinSecret,
        deadline: NativeDeadline,
    ) -> crate::inspection::NativeInspection {
        self.deadline = deadline;
        let kind = self.kind;
        let result = crate::inspection::finish_inspection(&mut *self, binding, kind, pin, deadline);
        drop(self); // native free completes before any owned result leaves the adapter
        eprintln!(
            "[inspection] native_freed=true puat_cleared={} device_closed={}",
            result.evidence.attached_puat_cleared, result.evidence.attached_puat_cleared
        );
        result
    }

    fn validate(
        mut self: Box<Self>,
        binding: AcquisitionBinding,
        pin: PinSecret,
        deadline: NativeDeadline,
    ) -> AuthenticationEvidence {
        self.deadline = deadline;
        let kind = self.kind;
        let mut transaction = AuthorizationTransaction::new(&mut *self, binding, kind);
        let status = match transaction.acquire(pin) {
            Ok(grant) => transaction.validate(grant),
            Err(status) => status,
        };
        let evidence = transaction.finish(status);
        // Consuming self closes/frees the old native device BEFORE the caller receives evidence.
        drop(self);
        evidence
    }
}

impl NativeAuthorization for Session {
    fn acquire(&mut self, kind: GrantKind, pin: &PinSecret) -> AuthenticationStatus {
        if kind != self.kind {
            return AuthenticationStatus::StaleAcquisition;
        }
        if self.device.set_timeout(&self.deadline).is_err() {
            return AuthenticationStatus::Uncertain;
        }
        // SAFETY: live unique device; PIN borrows fixed zeroizing C storage for this call only.
        // No RP is requested; scope was selected and cross-checked BEFORE acquisition.
        classify_acquisition(unsafe {
            fido_dev_get_puat(
                self.device.ptr,
                kind.permissions(),
                ptr::null(),
                pin.as_ptr(),
            )
        })
    }
    fn attached(&self) -> bool {
        // SAFETY: accessors read live native state; token bytes are never copied or dereferenced.
        unsafe {
            fido_dev_puat_len(self.device.ptr) != 0 || !fido_dev_puat_ptr(self.device.ptr).is_null()
        }
    }
    fn valid_attached(&self) -> bool {
        // SAFETY: scalar/pointer accessors on a live native object. An inconsistent pointer/length
        // pair is never authorization; token bytes remain opaque and are never dereferenced.
        unsafe {
            fido_dev_puat_len(self.device.ptr) > 0 && !fido_dev_puat_ptr(self.device.ptr).is_null()
        }
    }
    fn clear(&mut self) -> bool {
        // SAFETY: NULL/0 is the reviewed 1.17 clear operation; no CTAP request is sent.
        (unsafe { fido_dev_set_puat(self.device.ptr, ptr::null(), 0) == FIDO_OK })
            && !self.attached()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.attached() {
            let _ = self.clear();
        }
    }
}

impl crate::inspection::ReadOnlyInspection for Session {
    fn read_inventory(
        &mut self,
        deadline: NativeDeadline,
    ) -> Result<fido_core::inventory::OwnedInventory, crate::inspection::InspectionError> {
        eprintln!("[inspection] puat_attached=true read_only_sequence=true");
        super::inspection::read(&mut self.device, &deadline)
    }
    fn close_device(&mut self) -> bool {
        self.device.close()
    }
}
