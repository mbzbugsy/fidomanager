//! Read-only 1.17.0 credential-management surface. No mutation symbols are declared here.
use super::{Device, FIDO_OK, NativeDeadline};
use crate::inspection::{InspectionError, check_aggregate, copy_id, copy_text, rp_from_copied};
use fido_core::inventory::*;
use std::{
    ffi::{CString, c_char, c_int, c_void},
    ptr,
};

// Signatures reviewed against checksum-pinned src/fido/credman.h and src/fido.h.
unsafe extern "C" {
    fn fido_credman_metadata_new() -> *mut c_void;
    fn fido_credman_metadata_free(p: *mut *mut c_void);
    fn fido_credman_rp_new() -> *mut c_void;
    fn fido_credman_rp_free(p: *mut *mut c_void);
    fn fido_credman_rk_new() -> *mut c_void;
    fn fido_credman_rk_free(p: *mut *mut c_void);
    fn fido_credman_get_dev_metadata(d: *mut c_void, m: *mut c_void, pin: *const c_char) -> c_int;
    fn fido_credman_get_dev_rp(d: *mut c_void, r: *mut c_void, pin: *const c_char) -> c_int;
    fn fido_credman_get_dev_rk(
        d: *mut c_void,
        rp: *const c_char,
        r: *mut c_void,
        pin: *const c_char,
    ) -> c_int;
    fn fido_credman_rk_existing(m: *const c_void) -> u64;
    fn fido_credman_rp_count(r: *const c_void) -> usize;
    fn fido_credman_rp_id(r: *const c_void, i: usize) -> *const c_char;
    fn fido_credman_rp_id_hash_ptr(r: *const c_void, i: usize) -> *const u8;
    fn fido_credman_rp_id_hash_len(r: *const c_void, i: usize) -> usize;
    fn fido_credman_rk_count(r: *const c_void) -> usize;
    fn fido_credman_rk(r: *const c_void, i: usize) -> *const c_void;
    fn fido_cred_id_ptr(c: *const c_void) -> *const u8;
    fn fido_cred_id_len(c: *const c_void) -> usize;
    fn fido_cred_user_id_ptr(c: *const c_void) -> *const u8;
    fn fido_cred_user_id_len(c: *const c_void) -> usize;
    fn fido_cred_user_name(c: *const c_void) -> *const c_char;
    fn fido_cred_display_name(c: *const c_void) -> *const c_char;
}
struct Object {
    ptr: *mut c_void,
    free: unsafe extern "C" fn(*mut *mut c_void),
}
impl Object {
    fn new(
        new: unsafe extern "C" fn() -> *mut c_void,
        free: unsafe extern "C" fn(*mut *mut c_void),
    ) -> Result<Self, InspectionError> {
        // SAFETY: only reviewed libfido2 allocators and their matching free functions enter here.
        let ptr = unsafe { new() };
        if ptr.is_null() {
            return Err(InspectionError::NativeFailure);
        }
        Ok(Self { ptr, free })
    }
}
impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: unique object allocated by the matching constructor; never freed earlier.
        unsafe { (self.free)(ptr::addr_of_mut!(self.ptr)) };
    }
}
fn call(
    device: &mut Device,
    deadline: &NativeDeadline,
    f: impl FnOnce(*mut c_void) -> c_int,
) -> Result<(), InspectionError> {
    device
        .set_timeout(deadline)
        .map_err(|_| InspectionError::TimedOut)?;
    let code = f(device.ptr);
    if code == FIDO_OK {
        Ok(())
    } else {
        Err(map_error(code, deadline))
    }
}
fn map_error(code: c_int, deadline: &NativeDeadline) -> InspectionError {
    match super::map_libfido2_error(code, deadline).kind() {
        super::NativeErrorKind::Absent => InspectionError::DeviceAbsent,
        super::NativeErrorKind::Busy => InspectionError::Busy,
        super::NativeErrorKind::AccessDenied => InspectionError::AccessDenied,
        super::NativeErrorKind::TimedOut => InspectionError::TimedOut,
        super::NativeErrorKind::Unsupported => InspectionError::Unsupported,
        super::NativeErrorKind::Malformed => InspectionError::Malformed,
        _ => InspectionError::NativeFailure,
    }
}
// Every FFI pointer below is owned by device or an Object guard for the whole call/extraction.
// Indices follow checked counts; pointer+length pairs are bounded before copying; C strings
// use the single reviewed scanner. NULL PIN always means the previously attached PUAT.
pub(super) fn read(
    device: &mut Device,
    deadline: &NativeDeadline,
) -> Result<OwnedInventory, InspectionError> {
    let metadata = Object::new(fido_credman_metadata_new, fido_credman_metadata_free)?;
    call(device, deadline, |d| unsafe {
        fido_credman_get_dev_metadata(d, metadata.ptr, ptr::null())
    })?;
    eprintln!("[inspection] metadata_read=true");
    let existing = unsafe { fido_credman_rk_existing(metadata.ptr) };
    let rps = Object::new(fido_credman_rp_new, fido_credman_rp_free)?;
    // CTAP NO_CREDENTIALS is an explicit empty RP enumeration; contradictory metadata
    // is retained and assessed Inconsistent, never replaced with zero metadata.
    device
        .set_timeout(deadline)
        .map_err(|_| InspectionError::TimedOut)?;
    let code = unsafe { fido_credman_get_dev_rp(device.ptr, rps.ptr, ptr::null()) };
    if code == 0x2e {
        return Ok(OwnedInventory {
            metadata_existing: existing,
            rps: Vec::new(),
        });
    }
    if code != FIDO_OK {
        return Err(map_error(code, deadline));
    }
    eprintln!("[inspection] rp_enumeration_read=true");
    let count = unsafe { fido_credman_rp_count(rps.ptr) };
    if count > MAX_RPS {
        return Err(InspectionError::BoundExceeded);
    }
    let mut inventory = OwnedInventory {
        metadata_existing: existing,
        rps: Vec::with_capacity(count),
    };
    let mut aggregate = 0;
    for i in 0..count {
        let len = unsafe { fido_credman_rp_id_hash_len(rps.ptr, i) };
        if len != 32 {
            return Err(InspectionError::Malformed);
        }
        let hash = unsafe { copy_id(fido_credman_rp_id_hash_ptr(rps.ptr, i), len, 32) }?;
        let hash = hash.try_into().map_err(|_| InspectionError::Malformed)?;
        let text = unsafe { copy_text(fido_credman_rp_id(rps.ptr, i), MAX_RP_SCAN_BYTES) };
        let mut rp = rp_from_copied(hash, text);
        if let Some(text) = &rp.verified_text {
            let text = CString::new(text.as_bytes()).map_err(|_| InspectionError::Malformed)?;
            let rk = Object::new(fido_credman_rk_new, fido_credman_rk_free)?;
            let mut enumeration_code = FIDO_OK;
            match call(device, deadline, |d| {
                // SAFETY: same live owned device/container; verified text CString lives through call.
                enumeration_code =
                    unsafe { fido_credman_get_dev_rk(d, text.as_ptr(), rk.ptr, ptr::null()) };
                enumeration_code
            }) {
                Ok(()) => {
                    eprintln!("[inspection] credential_enumeration_read=true");
                    let count = unsafe { fido_credman_rk_count(rk.ptr) };
                    aggregate = check_aggregate(aggregate, count)?;
                    for j in 0..count {
                        let c = unsafe { fido_credman_rk(rk.ptr, j) };
                        if c.is_null() {
                            return Err(InspectionError::Malformed);
                        }
                        let id = unsafe {
                            copy_id(
                                fido_cred_id_ptr(c),
                                fido_cred_id_len(c),
                                MAX_CREDENTIAL_ID_BYTES,
                            )
                        }?;
                        let user_id_len = unsafe { fido_cred_user_id_len(c) };
                        let user_id = if user_id_len == 0 {
                            None
                        } else {
                            Some(unsafe {
                                copy_id(fido_cred_user_id_ptr(c), user_id_len, MAX_USER_ID_BYTES)
                            }?)
                        };
                        let user_name =
                            unsafe { copy_text(fido_cred_user_name(c), MAX_USER_TEXT_BYTES + 1) }?;
                        let display_name = unsafe {
                            copy_text(fido_cred_display_name(c), MAX_USER_TEXT_BYTES + 1)
                        }?;
                        rp.credentials.push(OwnedCredential {
                            id,
                            user_id,
                            user_name,
                            display_name,
                        });
                    }
                }
                Err(_) if enumeration_code == 0x2e => {} // RP present but no credentials: Inconsistent
                // Preserve this RP as unread; never copy a partially filled native enumeration.
                Err(
                    InspectionError::NativeFailure
                    | InspectionError::Unsupported
                    | InspectionError::AccessDenied,
                ) => rp.issue = Some(RpIssue::EnumerationFailed),
                Err(e) => return Err(e),
            }
        }
        inventory.rps.push(rp);
    }
    Ok(inventory) // all strings and IDs copied; Object guards free native containers first
}
