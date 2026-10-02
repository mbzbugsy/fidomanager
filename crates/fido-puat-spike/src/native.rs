//! libfido2 >= 1.17.0 implementation for the manual hardware harness.
//!
//! Spike code: it duplicates a little of `fido-libfido2` rather than widening the production
//! adapter before the evidence is in. Rules it keeps:
//! - every native call is preceded by an explicit finite `fido_dev_set_timeout`;
//! - credential-management calls always pass `pin = NULL`, so only an attached token can authorize
//!   them (libfido2 ignores the PIN when a token is attached, and would otherwise acquire a fresh
//!   full-`cm` token per call);
//! - token bytes are never read: only `fido_dev_puat_len` and whether `fido_dev_puat_ptr` is NULL;
//! - RP IDs, RP names and user names returned by the authenticator are never printed, only counts
//!   and booleans; the RP ID hash and text are copied out only to be compared in memory.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;

use crate::contract::{AcquisitionPlan, RpId};
use crate::guard::PuatDevice;
use crate::secret::PinSecret;

pub const FIDO_OK: c_int = 0;
const MAX_DEVICES: usize = 16;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_TEXT_BYTES: usize = 256;
const MAX_ITEMS: usize = 128;
/// Largest RP list the spike will copy; more is reported as an error, never truncated silently.
const MAX_RPS: usize = 512;
/// Hash bytes copied per RP. Anything longer than 32 is malformed, so 65 bytes are enough to keep
/// the "wrong length" verdict without copying an attacker-chosen size.
const MAX_HASH_COPY: usize = 65;
/// Local (non-libfido2) error: the RP list exceeded [`MAX_RPS`].
pub const ERR_LOCAL_TOO_MANY_RPS: c_int = -10;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("native-puat is supported only on macOS and Linux");

#[link(name = "fido2")]
unsafe extern "C" {
    fn fido_init(flags: c_int);
    fn fido_strerr(code: c_int) -> *const c_char;

    fn fido_dev_info_new(count: usize) -> *mut c_void;
    fn fido_dev_info_free(list: *mut *mut c_void, count: usize);
    fn fido_dev_info_manifest(list: *mut c_void, capacity: usize, found: *mut usize) -> c_int;
    fn fido_dev_info_ptr(list: *const c_void, index: usize) -> *const c_void;
    fn fido_dev_info_path(info: *const c_void) -> *const c_char;
    fn fido_dev_info_vendor(info: *const c_void) -> i16;
    fn fido_dev_info_product(info: *const c_void) -> i16;

    fn fido_dev_new() -> *mut c_void;
    fn fido_dev_free(device: *mut *mut c_void);
    fn fido_dev_open(device: *mut c_void, path: *const c_char) -> c_int;
    fn fido_dev_close(device: *mut c_void) -> c_int;
    fn fido_dev_set_timeout(device: *mut c_void, timeout_ms: c_int) -> c_int;
    fn fido_dev_major(device: *const c_void) -> u8;
    fn fido_dev_minor(device: *const c_void) -> u8;
    fn fido_dev_build(device: *const c_void) -> u8;

    fn fido_dev_supports_permissions(device: *const c_void) -> bool;
    fn fido_dev_supports_pin(device: *const c_void) -> bool;
    fn fido_dev_has_pin(device: *const c_void) -> bool;
    fn fido_dev_supports_uv(device: *const c_void) -> bool;
    fn fido_dev_has_uv(device: *const c_void) -> bool;
    fn fido_dev_supports_credman(device: *const c_void) -> bool;

    fn fido_cbor_info_new() -> *mut c_void;
    fn fido_cbor_info_free(info: *mut *mut c_void);
    fn fido_dev_get_cbor_info(device: *mut c_void, info: *mut c_void) -> c_int;
    fn fido_cbor_info_aaguid_ptr(info: *const c_void) -> *const u8;
    fn fido_cbor_info_aaguid_len(info: *const c_void) -> usize;
    fn fido_cbor_info_versions_ptr(info: *const c_void) -> *mut *mut c_char;
    fn fido_cbor_info_versions_len(info: *const c_void) -> usize;
    fn fido_cbor_info_options_name_ptr(info: *const c_void) -> *mut *mut c_char;
    fn fido_cbor_info_options_value_ptr(info: *const c_void) -> *const bool;
    fn fido_cbor_info_options_len(info: *const c_void) -> usize;
    fn fido_cbor_info_protocols_ptr(info: *const c_void) -> *const u8;
    fn fido_cbor_info_protocols_len(info: *const c_void) -> usize;
    fn fido_cbor_info_fwversion(info: *const c_void) -> u64;
    fn fido_cbor_info_minpinlen(info: *const c_void) -> u64;
    fn fido_cbor_info_new_pin_required(info: *const c_void) -> bool;
    fn fido_cbor_info_rk_remaining(info: *const c_void) -> i64;
    fn fido_cbor_info_uv_attempts(info: *const c_void) -> u64;
    fn fido_cbor_info_uv_modality(info: *const c_void) -> u64;

    fn fido_dev_get_retry_count(device: *mut c_void, retries: *mut c_int) -> c_int;
    fn fido_dev_get_uv_retry_count(device: *mut c_void, retries: *mut c_int) -> c_int;

    fn fido_dev_get_puat(
        device: *mut c_void,
        perm: u32,
        rpid: *const c_char,
        pin: *const c_char,
    ) -> c_int;
    fn fido_dev_set_puat(device: *mut c_void, ptr: *const u8, len: usize) -> c_int;
    fn fido_dev_puat_ptr(device: *const c_void) -> *const u8;
    fn fido_dev_puat_len(device: *const c_void) -> usize;

    fn fido_credman_metadata_new() -> *mut c_void;
    fn fido_credman_metadata_free(metadata: *mut *mut c_void);
    fn fido_credman_get_dev_metadata(
        device: *mut c_void,
        metadata: *mut c_void,
        pin: *const c_char,
    ) -> c_int;
    fn fido_credman_rk_existing(metadata: *const c_void) -> u64;
    fn fido_credman_rk_remaining(metadata: *const c_void) -> u64;
    fn fido_credman_rp_new() -> *mut c_void;
    fn fido_credman_rp_free(rp: *mut *mut c_void);
    fn fido_credman_get_dev_rp(device: *mut c_void, rp: *mut c_void, pin: *const c_char) -> c_int;
    fn fido_credman_rp_count(rp: *const c_void) -> usize;
    fn fido_credman_rp_id(rp: *const c_void, index: usize) -> *const c_char;
    fn fido_credman_rp_id_hash_len(rp: *const c_void, index: usize) -> usize;
    fn fido_credman_rp_id_hash_ptr(rp: *const c_void, index: usize) -> *const u8;
    fn fido_credman_rk_new() -> *mut c_void;
    fn fido_credman_rk_free(rk: *mut *mut c_void);
    fn fido_credman_get_dev_rk(
        device: *mut c_void,
        rp_id: *const c_char,
        rk: *mut c_void,
        pin: *const c_char,
    ) -> c_int;
    fn fido_credman_rk_count(rk: *const c_void) -> usize;
    fn fido_credman_del_dev_rk(
        device: *mut c_void,
        cred_id: *const u8,
        cred_id_len: usize,
        pin: *const c_char,
    ) -> c_int;
}

/// Process initialization. Refuses (before calling `fido_init`) if `FIDO_DEBUG` is present in the
/// environment, because libfido2 1.17.0 then enables protocol logging regardless of the flags
/// passed. Must run before this process starts any other thread; the harness's `main` does so.
pub fn init() -> Result<(), crate::environment::LibFido2DebugRequested> {
    crate::environment::require_no_libfido2_debug()?;
    // SAFETY: documented process initialization; takes no pointers. With FIDO_DEBUG absent (just
    // checked) and flags 0, libfido2's logging stays off.
    unsafe { fido_init(0) };
    Ok(())
}

/// `fido_strerr` name for a code, for evidence tables.
pub fn error_name(code: c_int) -> String {
    // SAFETY: fido_strerr returns a static NUL-terminated string for any code.
    let pointer = unsafe { fido_strerr(code) };
    if pointer.is_null() {
        return format!("code {code}");
    }
    // SAFETY: static C string owned by libfido2.
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

pub struct DiscoveredDevice {
    pub path: CString,
    pub vendor_id: u16,
    pub product_id: u16,
}

/// Enumerate HID FIDO devices. `fido_dev_info_manifest` takes no timeout (bounded only by the
/// harness watchdog, as the production worker is bounded by its kill boundary).
pub fn manifest() -> Result<Vec<DiscoveredDevice>, c_int> {
    // SAFETY: allocation checked for NULL; freed below with the same capacity.
    let mut list = unsafe { fido_dev_info_new(MAX_DEVICES) };
    if list.is_null() {
        return Err(-9);
    }
    let mut found = 0usize;
    // SAFETY: list has MAX_DEVICES entries; found is a valid out pointer.
    let result = unsafe { fido_dev_info_manifest(list, MAX_DEVICES, ptr::addr_of_mut!(found)) };
    let mut devices = Vec::new();
    if result == FIDO_OK && found <= MAX_DEVICES {
        for index in 0..found {
            // SAFETY: index < found <= capacity.
            let info = unsafe { fido_dev_info_ptr(list, index) };
            if info.is_null() {
                continue;
            }
            // SAFETY: path pointer is valid while the list lives; bounded copy.
            let path = unsafe { bounded_c_string(fido_dev_info_path(info), MAX_PATH_BYTES) };
            if let Some(path) = path {
                devices.push(DiscoveredDevice {
                    path,
                    // SAFETY: scalar accessors on a live entry.
                    vendor_id: unsafe { fido_dev_info_vendor(info) } as u16,
                    // SAFETY: as above.
                    product_id: unsafe { fido_dev_info_product(info) } as u16,
                });
            }
        }
    }
    // SAFETY: allocated by fido_dev_info_new with MAX_DEVICES.
    unsafe { fido_dev_info_free(ptr::addr_of_mut!(list), MAX_DEVICES) };
    if result != FIDO_OK {
        return Err(result);
    }
    Ok(devices)
}

#[derive(Debug, Default)]
pub struct InfoReport {
    pub ctaphid_version: (u8, u8, u8),
    pub versions: Vec<String>,
    pub options: Vec<(String, bool)>,
    pub pin_protocols: Vec<u8>,
    pub aaguid_hex: Option<String>,
    pub firmware_version: u64,
    pub min_pin_length: u64,
    pub force_pin_change: bool,
    pub rk_remaining: i64,
    pub uv_attempts: u64,
    pub uv_modality: u64,
    pub supports_permissions: bool,
    pub supports_pin: bool,
    pub has_pin: bool,
    pub supports_uv: bool,
    pub has_uv: bool,
    pub supports_credman: bool,
}

/// One RP as libfido2 reported it, copied out of the `fido_credman_rp_t` before it is freed.
/// Holds account metadata: never print or log it.
pub struct OwnedRawRp {
    /// `None` when `fido_credman_rp_id_hash_ptr` was `NULL`. At most 65 bytes are copied.
    pub hash: Option<Vec<u8>>,
    /// `None` when `fido_credman_rp_id` was `NULL` (distinct from an empty string). Scanned up to
    /// `MAX_TEXT_BYTES + 1`; a longer string is returned truncated at that bound, which the
    /// contract then rejects as malformed.
    pub text: Option<Vec<u8>>,
}

/// One `fido_dev_t`. Created fresh for every session; freed (which also wipes any token) on drop.
pub struct LibFido2Device {
    ptr: *mut c_void,
    path: CString,
    opened: bool,
}

impl LibFido2Device {
    /// `fido_dev_new` + `fido_dev_open` with an explicit timeout.
    pub fn open(path: &CStr, timeout_ms: c_int) -> Result<Self, c_int> {
        // SAFETY: allocation checked for NULL.
        let ptr = unsafe { fido_dev_new() };
        if ptr.is_null() {
            return Err(-9);
        }
        let mut device = Self {
            ptr,
            path: path.to_owned(),
            opened: false,
        };
        device.reopen(timeout_ms)?;
        Ok(device)
    }

    fn set_timeout(&mut self, timeout_ms: c_int) -> Result<(), c_int> {
        // SAFETY: live object; timeout is validated by libfido2 (>= -1). Callers pass > 0.
        let result = unsafe { fido_dev_set_timeout(self.ptr, timeout_ms.max(1)) };
        if result != FIDO_OK {
            return Err(result);
        }
        Ok(())
    }

    /// Close the transport but keep the object (and, per libfido2, any attached token).
    /// Experiment-only: the contract never reopens an object.
    pub fn close(&mut self) -> c_int {
        if !self.opened {
            return FIDO_OK;
        }
        self.opened = false;
        // SAFETY: live, opened object.
        unsafe { fido_dev_close(self.ptr) }
    }

    /// Experiment-only: reopen this same object, optionally at a new path (after replug).
    pub fn reopen_at(&mut self, path: &CStr, timeout_ms: c_int) -> Result<(), c_int> {
        self.path = path.to_owned();
        self.reopen(timeout_ms)
    }

    fn reopen(&mut self, timeout_ms: c_int) -> Result<(), c_int> {
        self.close();
        self.set_timeout(timeout_ms)?;
        // SAFETY: path is NUL-terminated and outlives the call; object is live and closed.
        let result = unsafe { fido_dev_open(self.ptr, self.path.as_ptr()) };
        if result != FIDO_OK {
            return Err(result);
        }
        self.opened = true;
        Ok(())
    }

    pub fn token_pointer_is_null(&self) -> bool {
        // SAFETY: live object; only the pointer value is inspected, never dereferenced.
        unsafe { fido_dev_puat_ptr(self.ptr) }.is_null()
    }

    pub fn info(&mut self, timeout_ms: c_int) -> Result<InfoReport, c_int> {
        self.set_timeout(timeout_ms)?;
        // SAFETY: allocation checked for NULL, freed on every path below.
        let mut info = unsafe { fido_cbor_info_new() };
        if info.is_null() {
            return Err(-9);
        }
        // SAFETY: both objects live.
        let result = unsafe { fido_dev_get_cbor_info(self.ptr, info) };
        let report = if result == FIDO_OK {
            // SAFETY: info is a live, populated cbor-info object until freed below.
            Ok(unsafe { self.extract(info) })
        } else {
            Err(result)
        };
        // SAFETY: allocated by fido_cbor_info_new.
        unsafe { fido_cbor_info_free(ptr::addr_of_mut!(info)) };
        report
    }

    unsafe fn extract(&self, info: *const c_void) -> InfoReport {
        let mut report = InfoReport::default();
        // SAFETY (whole function): `info` is live; every array is length-checked and bounded.
        unsafe {
            report.ctaphid_version = (
                fido_dev_major(self.ptr),
                fido_dev_minor(self.ptr),
                fido_dev_build(self.ptr),
            );
            let versions_len = fido_cbor_info_versions_len(info).min(MAX_ITEMS);
            let versions = fido_cbor_info_versions_ptr(info);
            for index in 0..versions_len {
                if let Some(text) = bounded_c_string(*versions.add(index), MAX_TEXT_BYTES) {
                    report.versions.push(text.to_string_lossy().into_owned());
                }
            }
            let options_len = fido_cbor_info_options_len(info).min(MAX_ITEMS);
            let names = fido_cbor_info_options_name_ptr(info);
            let values = fido_cbor_info_options_value_ptr(info);
            if !names.is_null() && !values.is_null() {
                for index in 0..options_len {
                    if let Some(name) = bounded_c_string(*names.add(index), MAX_TEXT_BYTES) {
                        report
                            .options
                            .push((name.to_string_lossy().into_owned(), *values.add(index)));
                    }
                }
            }
            let protocols_len = fido_cbor_info_protocols_len(info).min(MAX_ITEMS);
            let protocols = fido_cbor_info_protocols_ptr(info);
            if !protocols.is_null() {
                report.pin_protocols =
                    std::slice::from_raw_parts(protocols, protocols_len).to_vec();
            }
            if fido_cbor_info_aaguid_len(info) == 16 {
                let aaguid = std::slice::from_raw_parts(fido_cbor_info_aaguid_ptr(info), 16);
                report.aaguid_hex = Some(aaguid.iter().map(|b| format!("{b:02x}")).collect());
            }
            report.firmware_version = fido_cbor_info_fwversion(info);
            report.min_pin_length = fido_cbor_info_minpinlen(info);
            report.force_pin_change = fido_cbor_info_new_pin_required(info);
            report.rk_remaining = fido_cbor_info_rk_remaining(info);
            report.uv_attempts = fido_cbor_info_uv_attempts(info);
            report.uv_modality = fido_cbor_info_uv_modality(info);
            report.supports_permissions = fido_dev_supports_permissions(self.ptr);
            report.supports_pin = fido_dev_supports_pin(self.ptr);
            report.has_pin = fido_dev_has_pin(self.ptr);
            report.supports_uv = fido_dev_supports_uv(self.ptr);
            report.has_uv = fido_dev_has_uv(self.ptr);
            report.supports_credman = fido_dev_supports_credman(self.ptr);
        }
        report
    }

    /// clientPin getPinRetries. Sends no PIN and consumes no retry.
    pub fn pin_retries(&mut self, timeout_ms: c_int) -> Result<c_int, c_int> {
        self.set_timeout(timeout_ms)?;
        let mut retries: c_int = 0;
        // SAFETY: live object, valid out pointer.
        let result = unsafe { fido_dev_get_retry_count(self.ptr, ptr::addr_of_mut!(retries)) };
        if result != FIDO_OK {
            return Err(result);
        }
        Ok(retries)
    }

    /// clientPin getUVRetries. Starts no UV and consumes no attempt.
    pub fn uv_retries(&mut self, timeout_ms: c_int) -> Result<c_int, c_int> {
        self.set_timeout(timeout_ms)?;
        let mut retries: c_int = 0;
        // SAFETY: live object, valid out pointer.
        let result = unsafe { fido_dev_get_uv_retry_count(self.ptr, ptr::addr_of_mut!(retries)) };
        if result != FIDO_OK {
            return Err(result);
        }
        Ok(retries)
    }

    /// authenticatorCredentialManagement getCredsMetadata with `pin = NULL`.
    pub fn credman_metadata(&mut self, timeout_ms: c_int) -> Result<(u64, u64), c_int> {
        self.set_timeout(timeout_ms)?;
        // SAFETY: allocation checked; freed below.
        let mut metadata = unsafe { fido_credman_metadata_new() };
        if metadata.is_null() {
            return Err(-9);
        }
        // SAFETY: live objects; NULL PIN is documented as "use the attached token or UV".
        let result = unsafe { fido_credman_get_dev_metadata(self.ptr, metadata, ptr::null()) };
        let outcome = if result == FIDO_OK {
            // SAFETY: populated metadata object.
            Ok(unsafe {
                (
                    fido_credman_rk_existing(metadata),
                    fido_credman_rk_remaining(metadata),
                )
            })
        } else {
            Err(result)
        };
        // SAFETY: allocated above.
        unsafe { fido_credman_metadata_free(ptr::addr_of_mut!(metadata)) };
        outcome
    }

    /// enumerateRPsBegin/GetNextRP with `pin = NULL`. Returns the count only.
    pub fn credman_rp_count(&mut self, timeout_ms: c_int) -> Result<usize, c_int> {
        self.set_timeout(timeout_ms)?;
        // SAFETY: allocation checked; freed below.
        let mut rp = unsafe { fido_credman_rp_new() };
        if rp.is_null() {
            return Err(-9);
        }
        // SAFETY: live objects; NULL PIN.
        let result = unsafe { fido_credman_get_dev_rp(self.ptr, rp, ptr::null()) };
        // SAFETY: rp is live.
        let outcome = if result == FIDO_OK {
            Ok(unsafe { fido_credman_rp_count(rp) })
        } else {
            Err(result)
        };
        // SAFETY: allocated above.
        unsafe { fido_credman_rp_free(ptr::addr_of_mut!(rp)) };
        outcome
    }

    /// enumerateRPsBegin/GetNextRP with `pin = NULL`, copying each RP's hash and text out for the
    /// identity contract. Fails (rather than truncates) above `MAX_RPS` entries.
    pub fn credman_rp_list(&mut self, timeout_ms: c_int) -> Result<Vec<OwnedRawRp>, c_int> {
        self.set_timeout(timeout_ms)?;
        // SAFETY: allocation checked; freed below.
        let mut rp = unsafe { fido_credman_rp_new() };
        if rp.is_null() {
            return Err(-9);
        }
        // SAFETY: live objects; NULL PIN so only the attached token authorizes.
        let result = unsafe { fido_credman_get_dev_rp(self.ptr, rp, ptr::null()) };
        let outcome = if result == FIDO_OK {
            // SAFETY: populated rp object, live until freed below; everything is copied here.
            unsafe { copy_rp_list(rp) }
        } else {
            Err(result)
        };
        // SAFETY: allocated above.
        unsafe { fido_credman_rp_free(ptr::addr_of_mut!(rp)) };
        outcome
    }

    /// enumerateCredentialsBegin/GetNext for one RP with `pin = NULL`. Returns the count only.
    pub fn credman_rk_count(&mut self, rp: &RpId, timeout_ms: c_int) -> Result<usize, c_int> {
        self.credman_rk_count_for(rp.as_c_str(), timeout_ms)
    }

    /// As [`Self::credman_rk_count`] for RP ID text already verified against the authoritative
    /// hash (libfido2 SHA-256s the text itself; there is no hash-taking entry point).
    pub fn credman_rk_count_for(&mut self, rp: &CStr, timeout_ms: c_int) -> Result<usize, c_int> {
        self.set_timeout(timeout_ms)?;
        // SAFETY: allocation checked; freed below.
        let mut rk = unsafe { fido_credman_rk_new() };
        if rk.is_null() {
            return Err(-9);
        }
        // SAFETY: live objects; RP ID NUL-terminated and validated; NULL PIN.
        let result = unsafe { fido_credman_get_dev_rk(self.ptr, rp.as_ptr(), rk, ptr::null()) };
        // SAFETY: rk is live.
        let outcome = if result == FIDO_OK {
            Ok(unsafe { fido_credman_rk_count(rk) })
        } else {
            Err(result)
        };
        // SAFETY: allocated above.
        unsafe { fido_credman_rk_free(ptr::addr_of_mut!(rk)) };
        outcome
    }

    /// OPT-IN PROBE ONLY. Sends deleteCredential for a random credential ID that cannot exist,
    /// using the attached token. A read-only-enforcing authenticator must refuse on permission
    /// before looking the ID up; `FIDO_ERR_NO_CREDENTIALS` would mean it looked it up anyway.
    pub fn delete_probe(&mut self, random_credential_id: &[u8], timeout_ms: c_int) -> c_int {
        if let Err(code) = self.set_timeout(timeout_ms) {
            return code;
        }
        // SAFETY: live object; slice valid for the call; NULL PIN so only the token authorizes.
        unsafe {
            fido_credman_del_dev_rk(
                self.ptr,
                random_credential_id.as_ptr(),
                random_credential_id.len(),
                ptr::null(),
            )
        }
    }
}

impl PuatDevice for LibFido2Device {
    fn attached_token_len(&self) -> usize {
        // SAFETY: live object; reads only the length.
        unsafe { fido_dev_puat_len(self.ptr) }
    }

    fn acquire_token(
        &mut self,
        plan: &AcquisitionPlan,
        pin: Option<&PinSecret>,
        timeout_ms: i32,
    ) -> Result<(), i32> {
        self.set_timeout(timeout_ms)?;
        let rp = plan.rp().map_or(ptr::null(), |rp| rp.as_c_str().as_ptr());
        let pin = pin.map_or(ptr::null(), PinSecret::as_ptr);
        // SAFETY: live object; rp and pin are NULL or NUL-terminated buffers that outlive the
        // call. libfido2 copies the PIN into its own blobs and freezero()s them before returning.
        let result = unsafe { fido_dev_get_puat(self.ptr, plan.permissions(), rp, pin) };
        if result != FIDO_OK {
            return Err(result);
        }
        Ok(())
    }

    fn clear_token(&mut self) -> Result<(), i32> {
        // SAFETY: live object; NULL/0 is the documented "clear" form (freezero of the token).
        let result = unsafe { fido_dev_set_puat(self.ptr, ptr::null(), 0) };
        if result != FIDO_OK {
            return Err(result);
        }
        Ok(())
    }
}

impl Drop for LibFido2Device {
    fn drop(&mut self) {
        self.close();
        // SAFETY: allocated by fido_dev_new, not yet freed. fido_dev_free also wipes any token.
        unsafe { fido_dev_free(ptr::addr_of_mut!(self.ptr)) };
    }
}

/// Copies every RP out of a populated `fido_credman_rp_t`.
///
/// # Safety
/// `rp` must be a live, populated `fido_credman_rp_t`.
unsafe fn copy_rp_list(rp: *const c_void) -> Result<Vec<OwnedRawRp>, c_int> {
    // SAFETY (whole function): `rp` is live; indices are below `fido_credman_rp_count`, which
    // never exceeds the allocated entries libfido2's accessors bound-check; hash and text are
    // copied with explicit bounds before the object is freed.
    unsafe {
        let count = fido_credman_rp_count(rp);
        if count > MAX_RPS {
            return Err(ERR_LOCAL_TOO_MANY_RPS);
        }
        let mut list = Vec::with_capacity(count);
        for index in 0..count {
            let hash_ptr = fido_credman_rp_id_hash_ptr(rp, index);
            let hash = if hash_ptr.is_null() {
                None
            } else {
                let len = fido_credman_rp_id_hash_len(rp, index).min(MAX_HASH_COPY);
                Some(std::slice::from_raw_parts(hash_ptr, len).to_vec())
            };
            let text = bounded_bytes(fido_credman_rp_id(rp, index), MAX_TEXT_BYTES);
            list.push(OwnedRawRp { hash, text });
        }
        Ok(list)
    }
}

/// Bounded copy of a libfido2-owned C string as bytes: `None` on NULL, `Some(empty)` for an empty
/// string, and `max_bytes + 1` bytes (no terminator seen) for anything longer.
unsafe fn bounded_bytes(pointer: *const c_char, max_bytes: usize) -> Option<Vec<u8>> {
    if pointer.is_null() {
        return None;
    }
    let mut bytes = Vec::new();
    for offset in 0..=max_bytes {
        // SAFETY: libfido2 promises a NUL-terminated string; the scan stops at max_bytes + 1.
        let byte = unsafe { *pointer.cast::<u8>().add(offset) };
        if byte == 0 {
            return Some(bytes);
        }
        bytes.push(byte);
    }
    Some(bytes)
}

/// Bounded copy of a libfido2-owned C string; `None` on NULL, overlong, or empty.
unsafe fn bounded_c_string(pointer: *const c_char, max_bytes: usize) -> Option<CString> {
    if pointer.is_null() {
        return None;
    }
    let mut bytes = Vec::new();
    for offset in 0..=max_bytes {
        // SAFETY: libfido2 promises a NUL-terminated string; the scan stops at max_bytes + 1.
        let byte = unsafe { *pointer.cast::<u8>().add(offset) };
        if byte == 0 {
            return if bytes.is_empty() {
                None
            } else {
                CString::new(bytes).ok()
            };
        }
        bytes.push(byte);
    }
    None
}
