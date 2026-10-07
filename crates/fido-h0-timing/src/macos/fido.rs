//! Read-only libfido2 surface: discovery, open, GetInfo and close.
//!
//! This block is the complete set of libfido2 functions H0 can call. Every one of them either
//! enumerates HID services, opens/closes a session (CTAPHID INIT plus GetInfo inside libfido2),
//! sends GetInfo, or reads already-parsed GetInfo fields from memory. No function here writes an
//! arbitrary command, installs custom I/O or transport callbacks, or changes authenticator state;
//! `tests/no_destructive_capability.rs` fails if any other libfido2 function is declared.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

use crate::measurement::{InfoSnapshot, Manifest, ManifestLabel, ReadOnlyDevice};

unsafe extern "C" {
    fn fido_init(flags: c_int);

    fn fido_dev_info_new(count: usize) -> *mut c_void;
    fn fido_dev_info_free(list: *mut *mut c_void, count: usize);
    fn fido_dev_info_manifest(list: *mut c_void, capacity: usize, found: *mut usize) -> c_int;
    fn fido_dev_info_ptr(list: *const c_void, index: usize) -> *const c_void;
    fn fido_dev_info_path(info: *const c_void) -> *const c_char;
    fn fido_dev_info_vendor(info: *const c_void) -> i16;
    fn fido_dev_info_product(info: *const c_void) -> i16;
    fn fido_dev_info_manufacturer_string(info: *const c_void) -> *const c_char;
    fn fido_dev_info_product_string(info: *const c_void) -> *const c_char;

    fn fido_dev_new() -> *mut c_void;
    fn fido_dev_free(device: *mut *mut c_void);
    fn fido_dev_open(device: *mut c_void, path: *const c_char) -> c_int;
    fn fido_dev_close(device: *mut c_void) -> c_int;
    fn fido_dev_set_timeout(device: *mut c_void, timeout_ms: c_int) -> c_int;

    fn fido_cbor_info_new() -> *mut c_void;
    fn fido_cbor_info_free(info: *mut *mut c_void);
    fn fido_dev_get_cbor_info(device: *mut c_void, info: *mut c_void) -> c_int;
    fn fido_cbor_info_aaguid_ptr(info: *const c_void) -> *const u8;
    fn fido_cbor_info_aaguid_len(info: *const c_void) -> usize;
    fn fido_cbor_info_versions_ptr(info: *const c_void) -> *mut *mut c_char;
    fn fido_cbor_info_versions_len(info: *const c_void) -> usize;
    fn fido_cbor_info_extensions_ptr(info: *const c_void) -> *mut *mut c_char;
    fn fido_cbor_info_extensions_len(info: *const c_void) -> usize;
    fn fido_cbor_info_options_name_ptr(info: *const c_void) -> *mut *mut c_char;
    fn fido_cbor_info_options_value_ptr(info: *const c_void) -> *const bool;
    fn fido_cbor_info_options_len(info: *const c_void) -> usize;
    fn fido_cbor_info_maxmsgsiz(info: *const c_void) -> u64;
    fn fido_cbor_info_fwversion(info: *const c_void) -> u64;
    // CTAP 2.2 GetInfo fields 0x1A / 0x18: parsed values only.
    fn fido_cbor_info_reset_transports_ptr(info: *const c_void) -> *mut *mut c_char;
    fn fido_cbor_info_reset_transports_len(info: *const c_void) -> usize;
    fn fido_cbor_info_long_touch_reset(info: *const c_void) -> bool;
}

const MANIFEST_CAPACITY: usize = 16;
/// Per-call native timeout. GetInfo is answered without user interaction.
const CALL_TIMEOUT_MS: c_int = 3000;
const FIDO_OK: c_int = 0;
const FIDO_ERR_INTERNAL: c_int = -9;

/// Opaque per-sample candidate token: the native path, which never leaves this module and is
/// never written to disk or printed.
pub struct PathToken(CString);

/// An open libfido2 device. Not `Send`: it never leaves the measuring thread. Dropping it closes
/// and frees the native object exactly once, on every path.
pub struct OpenDevice {
    ptr: *mut c_void,
}

impl Drop for OpenDevice {
    fn drop(&mut self) {
        // SAFETY: `ptr` is the open device created by `open`, owned solely by this value.
        unsafe {
            fido_dev_close(self.ptr);
            fido_dev_free(&mut self.ptr);
        }
    }
}

pub struct LibFido2ReadOnly {
    _not_send: std::marker::PhantomData<*mut c_void>,
}

impl LibFido2ReadOnly {
    /// Initializes libfido2 without debug logging. The caller has already refused to run when
    /// `FIDO_DEBUG` is present (libfido2 would enable logging from the environment).
    pub fn initialize() -> Self {
        // SAFETY: documented process initialization; flags 0; no pointers.
        unsafe { fido_init(0) };
        Self {
            _not_send: std::marker::PhantomData,
        }
    }
}

fn owned_string(text: *const c_char) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: libfido2 returns a NUL-terminated string owned by the live list/info object.
    unsafe { CStr::from_ptr(text) }
        .to_string_lossy()
        .into_owned()
}

/// Copies a libfido2 `char **` array of `len` entries.
///
/// # Safety
/// `array` must point to `len` valid NUL-terminated strings (or be null with `len == 0`) owned by a
/// live info object.
unsafe fn string_array(array: *mut *mut c_char, len: usize) -> Vec<String> {
    if array.is_null() {
        return Vec::new();
    }
    // SAFETY: per the function contract.
    (0..len)
        .map(|i| owned_string(unsafe { *array.add(i) }))
        .collect()
}

impl ReadOnlyDevice for LibFido2ReadOnly {
    type Token = PathToken;
    type Session = OpenDevice;

    fn manifest(&mut self) -> Result<Manifest<PathToken>, c_int> {
        // SAFETY: allocation of a manifest list with a fixed capacity.
        let mut list = unsafe { fido_dev_info_new(MANIFEST_CAPACITY) };
        if list.is_null() {
            return Err(FIDO_ERR_INTERNAL);
        }
        let mut found = 0usize;
        // SAFETY: live list of MANIFEST_CAPACITY entries; `found` is a valid out-pointer.
        let result = unsafe { fido_dev_info_manifest(list, MANIFEST_CAPACITY, &mut found) };
        let outcome = if result != FIDO_OK {
            Err(result)
        } else if found == 1 {
            // SAFETY: index 0 < found on a live list.
            let info = unsafe { fido_dev_info_ptr(list, 0) };
            // SAFETY: `info` is a live entry; accessor results are copied before the list is freed.
            let (path, vendor, product, manufacturer, product_name) = unsafe {
                (
                    fido_dev_info_path(info),
                    fido_dev_info_vendor(info),
                    fido_dev_info_product(info),
                    fido_dev_info_manufacturer_string(info),
                    fido_dev_info_product_string(info),
                )
            };
            if path.is_null() {
                Err(FIDO_ERR_INTERNAL)
            } else {
                // SAFETY: non-null NUL-terminated path owned by the live list; copied here.
                let path = unsafe { CStr::from_ptr(path) }.to_owned();
                Ok(Manifest {
                    count: 1,
                    single: Some((
                        ManifestLabel {
                            vendor_id: vendor as u16,
                            product_id: product as u16,
                            manufacturer: owned_string(manufacturer),
                            product: owned_string(product_name),
                        },
                        PathToken(path),
                    )),
                })
            }
        } else {
            Ok(Manifest {
                count: found,
                single: None,
            })
        };
        // SAFETY: frees the list allocated above with the same capacity; nulls our pointer.
        unsafe { fido_dev_info_free(&mut list, MANIFEST_CAPACITY) };
        outcome
    }

    fn open(&mut self, token: &PathToken) -> Result<OpenDevice, c_int> {
        // SAFETY: allocation of a fresh device object.
        let mut device = unsafe { fido_dev_new() };
        if device.is_null() {
            return Err(FIDO_ERR_INTERNAL);
        }
        // SAFETY: live device; positive timeout.
        let mut result = unsafe { fido_dev_set_timeout(device, CALL_TIMEOUT_MS) };
        if result == FIDO_OK {
            // SAFETY: live device and NUL-terminated path owned by the token.
            result = unsafe { fido_dev_open(device, token.0.as_ptr()) };
        }
        if result != FIDO_OK {
            // SAFETY: frees the unopened device and nulls the pointer.
            unsafe { fido_dev_free(&mut device) };
            return Err(result);
        }
        Ok(OpenDevice { ptr: device })
    }

    fn get_info(&mut self, session: &mut OpenDevice) -> Result<InfoSnapshot, c_int> {
        // SAFETY: allocation of a fresh info object.
        let mut info = unsafe { fido_cbor_info_new() };
        if info.is_null() {
            return Err(FIDO_ERR_INTERNAL);
        }
        // SAFETY: open device and live info object.
        let result = unsafe { fido_dev_get_cbor_info(session.ptr, info) };
        let snapshot = if result == FIDO_OK {
            // SAFETY: all accessors read the live, parsed info object; values are copied.
            unsafe {
                let aaguid_ptr = fido_cbor_info_aaguid_ptr(info);
                let aaguid_len = fido_cbor_info_aaguid_len(info);
                let aaguid = if aaguid_ptr.is_null() {
                    String::new()
                } else {
                    std::slice::from_raw_parts(aaguid_ptr, aaguid_len)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect()
                };
                let option_names = string_array(
                    fido_cbor_info_options_name_ptr(info),
                    fido_cbor_info_options_len(info),
                );
                let option_values = fido_cbor_info_options_value_ptr(info);
                let options = option_names
                    .into_iter()
                    .enumerate()
                    .map(|(i, name)| {
                        let value = !option_values.is_null() && *option_values.add(i);
                        (name, value)
                    })
                    .collect();
                let firmware = fido_cbor_info_fwversion(info);
                Ok(InfoSnapshot {
                    aaguid,
                    versions: string_array(
                        fido_cbor_info_versions_ptr(info),
                        fido_cbor_info_versions_len(info),
                    ),
                    extensions: string_array(
                        fido_cbor_info_extensions_ptr(info),
                        fido_cbor_info_extensions_len(info),
                    ),
                    options,
                    firmware_version: (firmware != 0).then_some(firmware),
                    max_msg_size: fido_cbor_info_maxmsgsiz(info),
                    transports_for_reset: string_array(
                        fido_cbor_info_reset_transports_ptr(info),
                        fido_cbor_info_reset_transports_len(info),
                    ),
                    long_touch_for_reset: fido_cbor_info_long_touch_reset(info),
                })
            }
        } else {
            Err(result)
        };
        // SAFETY: frees the info object allocated above and nulls the pointer.
        unsafe { fido_cbor_info_free(&mut info) };
        snapshot
    }

    fn close(&mut self, session: OpenDevice) {
        drop(session);
    }
}
