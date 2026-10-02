//! Controlled safe-adapter boundary for libfido2 discovery/GetInfo.
//!
//! The public API deliberately exposes owned values only. Native paths remain opaque inside the
//! worker and libfido2 pointers never cross this crate boundary.

use std::fmt;

pub const MAX_NATIVE_PATH_BYTES: usize = 4_096;
pub const MAX_NATIVE_DEVICE_TEXT_BYTES: usize = 256;
pub const MAX_NATIVE_STRING_ITEMS: usize = 128;
pub const MAX_NATIVE_DISCOVERED_DEVICES: usize = 65;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeDeviceKey(Vec<u8>);

impl NativeDeviceKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, NativeError> {
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_PATH_BYTES || bytes.contains(&0) {
            return Err(NativeError::new(NativeErrorKind::Malformed, None));
        }
        Ok(Self(bytes))
    }

    #[cfg(feature = "native-libfido2")]
    fn to_cstring(&self) -> Result<std::ffi::CString, NativeError> {
        std::ffi::CString::new(self.0.clone())
            .map_err(|_| NativeError::new(NativeErrorKind::Malformed, None))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDiscoveredDevice {
    pub key: NativeDeviceKey,
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDeviceOption {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDeviceInfo {
    pub aaguid: Option<[u8; 16]>,
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub transports: Vec<String>,
    pub options: Vec<NativeDeviceOption>,
    pub max_message_size: Option<u64>,
    pub firmware_version: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeErrorKind {
    Busy,
    AccessDenied,
    TimedOut,
    Unsupported,
    Absent,
    Unavailable,
    Malformed,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeError {
    kind: NativeErrorKind,
    libfido2_code: Option<i32>,
}

impl NativeError {
    pub const fn new(kind: NativeErrorKind, libfido2_code: Option<i32>) -> Self {
        Self {
            kind,
            libfido2_code,
        }
    }

    pub const fn kind(&self) -> NativeErrorKind {
        self.kind
    }

    pub const fn libfido2_code(&self) -> Option<i32> {
        self.libfido2_code
    }
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.libfido2_code {
            Some(code) => write!(
                formatter,
                "libfido2 discovery error {:?} (code {code})",
                self.kind
            ),
            None => write!(formatter, "libfido2 discovery error {:?}", self.kind),
        }
    }
}

impl std::error::Error for NativeError {}

/// Native discovery surface consumed by the in-process worker.
///
/// Implementations own all native identifiers and must never expose raw paths outside
/// `NativeDeviceKey`.
pub trait NativeDiscoveryBackend: Send {
    fn manifest(&mut self, budget_ms: u64) -> Result<Vec<NativeDiscoveredDevice>, NativeError>;

    fn get_info(
        &mut self,
        key: &NativeDeviceKey,
        budget_ms: u64,
    ) -> Result<NativeDeviceInfo, NativeError>;
}

#[cfg(feature = "native-libfido2")]
mod native {
    use std::ffi::{c_char, c_int, c_void};
    use std::ptr;
    use std::time::{Duration, Instant};

    use super::{
        MAX_NATIVE_DEVICE_TEXT_BYTES, MAX_NATIVE_DISCOVERED_DEVICES, MAX_NATIVE_PATH_BYTES,
        MAX_NATIVE_STRING_ITEMS, NativeDeviceInfo, NativeDeviceKey, NativeDeviceOption,
        NativeDiscoveredDevice, NativeDiscoveryBackend, NativeError, NativeErrorKind,
    };

    const FIDO_OK: c_int = 0;
    const ERROR_NAME_BOUND: usize = 64;

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    compile_error!("native-libfido2 is currently supported only on macOS and Linux");

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
        fn fido_cbor_info_transports_ptr(info: *const c_void) -> *mut *mut c_char;
        fn fido_cbor_info_transports_len(info: *const c_void) -> usize;
        fn fido_cbor_info_options_name_ptr(info: *const c_void) -> *mut *mut c_char;
        fn fido_cbor_info_options_value_ptr(info: *const c_void) -> *const bool;
        fn fido_cbor_info_options_len(info: *const c_void) -> usize;
        fn fido_cbor_info_maxmsgsiz(info: *const c_void) -> u64;
        fn fido_cbor_info_fwversion(info: *const c_void) -> u64;
    }

    #[derive(Debug, Default)]
    pub struct LibFido2Adapter;

    impl LibFido2Adapter {
        pub fn new() -> Self {
            // SAFETY: fido_init takes no pointers and is the documented process initialization
            // entry point. Calling it before libfido2 operations is required by the C API.
            unsafe { fido_init(0) };
            Self
        }
    }

    impl NativeDiscoveryBackend for LibFido2Adapter {
        fn manifest(
            &mut self,
            _budget_ms: u64,
        ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
            let mut list = DevInfoList::new(MAX_NATIVE_DISCOVERED_DEVICES)?;
            let mut found = 0usize;

            // SAFETY: `list.ptr` was allocated by fido_dev_info_new for exactly `list.capacity`
            // entries and `found` is a valid writable size_t pointer.
            let result = unsafe {
                fido_dev_info_manifest(list.ptr, list.capacity, ptr::addr_of_mut!(found))
            };
            if result != FIDO_OK {
                return Err(map_libfido2_error(result, Duration::ZERO, 0));
            }
            if found > list.capacity {
                return Err(NativeError::new(NativeErrorKind::Malformed, None));
            }

            let mut devices = Vec::with_capacity(found);
            for index in 0..found {
                // SAFETY: index is bounded by the `found <= capacity` check above.
                let info = unsafe { fido_dev_info_ptr(list.ptr as *const c_void, index) };
                if info.is_null() {
                    return Err(NativeError::new(NativeErrorKind::Malformed, None));
                }

                // SAFETY: libfido2 guarantees these pointers remain valid until the list is freed.
                let path = unsafe {
                    copy_bounded_c_bytes(fido_dev_info_path(info), MAX_NATIVE_PATH_BYTES)?
                };
                let key = NativeDeviceKey::from_bytes(path)?;

                // Invalid display metadata is dropped rather than allowing malformed native text to
                // cross the safe adapter. Device identity and path remain usable for GetInfo.
                let manufacturer = unsafe {
                    copy_optional_utf8(
                        fido_dev_info_manufacturer_string(info),
                        MAX_NATIVE_DEVICE_TEXT_BYTES,
                    )
                    .ok()
                    .flatten()
                };
                let product = unsafe {
                    copy_optional_utf8(
                        fido_dev_info_product_string(info),
                        MAX_NATIVE_DEVICE_TEXT_BYTES,
                    )
                    .ok()
                    .flatten()
                };

                // C exposes signed int16_t for USB IDs; casting preserves the underlying 16 bits.
                let vendor_id = unsafe { fido_dev_info_vendor(info) } as u16;
                let product_id = unsafe { fido_dev_info_product(info) } as u16;

                devices.push(NativeDiscoveredDevice {
                    key,
                    vendor_id,
                    product_id,
                    manufacturer,
                    product,
                });
            }

            // Avoid accidentally retaining an oversized native allocation after conversion.
            list.release();
            Ok(devices)
        }

        fn get_info(
            &mut self,
            key: &NativeDeviceKey,
            budget_ms: u64,
        ) -> Result<NativeDeviceInfo, NativeError> {
            let timeout_ms = i32::try_from(budget_ms)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| NativeError::new(NativeErrorKind::Internal, None))?;
            let path = key.to_cstring()?;
            let mut device = Device::new()?;

            // SAFETY: device is a live libfido2 object and timeout is a positive c_int.
            let timeout_result = unsafe { fido_dev_set_timeout(device.ptr, timeout_ms) };
            if timeout_result != FIDO_OK {
                return Err(map_libfido2_error(
                    timeout_result,
                    Duration::ZERO,
                    budget_ms,
                ));
            }

            let started = Instant::now();
            // SAFETY: path is NUL-terminated for the duration of the call and device is live.
            let open_result = unsafe { fido_dev_open(device.ptr, path.as_ptr()) };
            if open_result != FIDO_OK {
                return Err(map_libfido2_error(
                    open_result,
                    started.elapsed(),
                    budget_ms,
                ));
            }
            device.opened = true;

            let info = CborInfo::new()?;
            let started = Instant::now();
            // SAFETY: both pointers are live libfido2 objects owned by guards in this scope.
            let info_result = unsafe { fido_dev_get_cbor_info(device.ptr, info.ptr) };
            if info_result != FIDO_OK {
                return Err(map_libfido2_error(
                    info_result,
                    started.elapsed(),
                    budget_ms,
                ));
            }

            // SAFETY: `info.ptr` remains live until `info` is dropped after extraction.
            unsafe { extract_device_info(info.ptr as *const c_void) }
        }
    }

    struct DevInfoList {
        ptr: *mut c_void,
        capacity: usize,
    }

    impl DevInfoList {
        fn new(capacity: usize) -> Result<Self, NativeError> {
            // SAFETY: allocation is delegated to libfido2 and checked for NULL.
            let ptr = unsafe { fido_dev_info_new(capacity) };
            if ptr.is_null() {
                return Err(NativeError::new(NativeErrorKind::Internal, None));
            }
            Ok(Self { ptr, capacity })
        }

        fn release(&mut self) {
            if self.ptr.is_null() {
                return;
            }
            // SAFETY: pointer was allocated by fido_dev_info_new with this capacity.
            unsafe { fido_dev_info_free(ptr::addr_of_mut!(self.ptr), self.capacity) };
        }
    }

    impl Drop for DevInfoList {
        fn drop(&mut self) {
            self.release();
        }
    }

    struct Device {
        ptr: *mut c_void,
        opened: bool,
    }

    impl Device {
        fn new() -> Result<Self, NativeError> {
            // SAFETY: allocation is delegated to libfido2 and checked for NULL.
            let ptr = unsafe { fido_dev_new() };
            if ptr.is_null() {
                return Err(NativeError::new(NativeErrorKind::Internal, None));
            }
            Ok(Self { ptr, opened: false })
        }
    }

    impl Drop for Device {
        fn drop(&mut self) {
            if self.ptr.is_null() {
                return;
            }
            if self.opened {
                // SAFETY: pointer is live and was successfully opened. Drop cannot report close
                // errors, but the call has returned before the worker can claim quiescence.
                let _ = unsafe { fido_dev_close(self.ptr) };
            }
            // SAFETY: pointer was allocated by fido_dev_new and has not been freed.
            unsafe { fido_dev_free(ptr::addr_of_mut!(self.ptr)) };
        }
    }

    struct CborInfo {
        ptr: *mut c_void,
    }

    impl CborInfo {
        fn new() -> Result<Self, NativeError> {
            // SAFETY: allocation is delegated to libfido2 and checked for NULL.
            let ptr = unsafe { fido_cbor_info_new() };
            if ptr.is_null() {
                return Err(NativeError::new(NativeErrorKind::Internal, None));
            }
            Ok(Self { ptr })
        }
    }

    impl Drop for CborInfo {
        fn drop(&mut self) {
            if self.ptr.is_null() {
                return;
            }
            // SAFETY: pointer was allocated by fido_cbor_info_new and has not been freed.
            unsafe { fido_cbor_info_free(ptr::addr_of_mut!(self.ptr)) };
        }
    }

    unsafe fn extract_device_info(info: *const c_void) -> Result<NativeDeviceInfo, NativeError> {
        // SAFETY: caller guarantees a live fido_cbor_info_t pointer for the whole extraction.
        let aaguid_len = unsafe { fido_cbor_info_aaguid_len(info) };
        let aaguid = if aaguid_len == 0 {
            None
        } else {
            if aaguid_len != 16 {
                return Err(NativeError::new(NativeErrorKind::Malformed, None));
            }
            // SAFETY: libfido2 reports exactly 16 bytes and the pointer is valid while info lives.
            let pointer = unsafe { fido_cbor_info_aaguid_ptr(info) };
            if pointer.is_null() {
                return Err(NativeError::new(NativeErrorKind::Malformed, None));
            }
            let mut bytes = [0u8; 16];
            // SAFETY: source points to at least 16 bytes and destination is exactly 16 bytes.
            unsafe { ptr::copy_nonoverlapping(pointer, bytes.as_mut_ptr(), bytes.len()) };
            Some(bytes)
        };

        // Lengths are checked before pointer traversal/allocation amplification.
        let versions = unsafe {
            copy_string_array(
                fido_cbor_info_versions_ptr(info),
                fido_cbor_info_versions_len(info),
            )?
        };
        let extensions = unsafe {
            copy_string_array(
                fido_cbor_info_extensions_ptr(info),
                fido_cbor_info_extensions_len(info),
            )?
        };
        let transports = unsafe {
            copy_string_array(
                fido_cbor_info_transports_ptr(info),
                fido_cbor_info_transports_len(info),
            )?
        };
        let options = unsafe {
            copy_options(
                fido_cbor_info_options_name_ptr(info),
                fido_cbor_info_options_value_ptr(info),
                fido_cbor_info_options_len(info),
            )?
        };

        // SAFETY: scalar accessors only read the live cbor-info object.
        let max_message_size = unsafe { fido_cbor_info_maxmsgsiz(info) };
        // SAFETY: scalar accessor only reads the live cbor-info object.
        let firmware_version = unsafe { fido_cbor_info_fwversion(info) };

        Ok(NativeDeviceInfo {
            aaguid,
            versions,
            extensions,
            transports,
            options,
            max_message_size: (max_message_size != 0).then_some(max_message_size),
            firmware_version: (firmware_version != 0).then_some(firmware_version),
        })
    }

    unsafe fn copy_string_array(
        pointer: *mut *mut c_char,
        length: usize,
    ) -> Result<Vec<String>, NativeError> {
        if length > MAX_NATIVE_STRING_ITEMS {
            return Err(NativeError::new(NativeErrorKind::Malformed, None));
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        if pointer.is_null() {
            return Err(NativeError::new(NativeErrorKind::Malformed, None));
        }

        let mut output = Vec::with_capacity(length);
        for index in 0..length {
            // SAFETY: pointer is non-NULL and libfido2 reports `length` array elements.
            let value = unsafe { *pointer.add(index) };
            // SAFETY: each element is expected to be a NUL-terminated libfido2-owned string.
            output.push(unsafe {
                copy_required_utf8(value as *const c_char, MAX_NATIVE_DEVICE_TEXT_BYTES)?
            });
        }
        Ok(output)
    }

    unsafe fn copy_options(
        names: *mut *mut c_char,
        values: *const bool,
        length: usize,
    ) -> Result<Vec<NativeDeviceOption>, NativeError> {
        if length > MAX_NATIVE_STRING_ITEMS {
            return Err(NativeError::new(NativeErrorKind::Malformed, None));
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        if names.is_null() || values.is_null() {
            return Err(NativeError::new(NativeErrorKind::Malformed, None));
        }

        let mut output = Vec::with_capacity(length);
        for index in 0..length {
            // SAFETY: both arrays are non-NULL and libfido2 reports `length` elements.
            let name_ptr = unsafe { *names.add(index) };
            // SAFETY: name is a libfido2-owned NUL-terminated string.
            let name = unsafe {
                copy_required_utf8(name_ptr as *const c_char, MAX_NATIVE_DEVICE_TEXT_BYTES)?
            };
            // SAFETY: values points to an array with the same reported length as names.
            let enabled = unsafe { *values.add(index) };
            output.push(NativeDeviceOption { name, enabled });
        }
        Ok(output)
    }

    unsafe fn copy_optional_utf8(
        pointer: *const c_char,
        max_bytes: usize,
    ) -> Result<Option<String>, NativeError> {
        if pointer.is_null() {
            return Ok(None);
        }
        // SAFETY: caller provides a libfido2-owned C string pointer.
        let bytes = unsafe { copy_bounded_c_bytes(pointer, max_bytes)? };
        if bytes.is_empty() {
            return Ok(None);
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| NativeError::new(NativeErrorKind::Malformed, None))
    }

    unsafe fn copy_required_utf8(
        pointer: *const c_char,
        max_bytes: usize,
    ) -> Result<String, NativeError> {
        if pointer.is_null() {
            return Err(NativeError::new(NativeErrorKind::Malformed, None));
        }
        // SAFETY: caller provides a libfido2-owned C string pointer.
        let bytes = unsafe { copy_bounded_c_bytes(pointer, max_bytes)? };
        String::from_utf8(bytes).map_err(|_| NativeError::new(NativeErrorKind::Malformed, None))
    }

    unsafe fn copy_bounded_c_bytes(
        pointer: *const c_char,
        max_bytes: usize,
    ) -> Result<Vec<u8>, NativeError> {
        if pointer.is_null() {
            return Err(NativeError::new(NativeErrorKind::Malformed, None));
        }

        let mut bytes = Vec::with_capacity(max_bytes.min(64));
        for offset in 0..=max_bytes {
            // SAFETY: libfido2 promises a valid C string. We deliberately stop after max_bytes +
            // one probe to avoid an unbounded scan/allocation if native data is malformed.
            let value = unsafe { *(pointer.cast::<u8>().add(offset)) };
            if value == 0 {
                return Ok(bytes);
            }
            if offset == max_bytes {
                return Err(NativeError::new(NativeErrorKind::Malformed, None));
            }
            bytes.push(value);
        }
        Err(NativeError::new(NativeErrorKind::Malformed, None))
    }

    fn map_libfido2_error(code: c_int, elapsed: Duration, budget_ms: u64) -> NativeError {
        let name = unsafe {
            copy_required_utf8(fido_strerr(code), ERROR_NAME_BOUND)
                .unwrap_or_else(|_| "FIDO_ERR_UNKNOWN".to_owned())
        };
        let timed_out_by_budget = budget_ms != 0 && elapsed >= Duration::from_millis(budget_ms);
        let kind = match name.as_str() {
            "FIDO_ERR_CHANNEL_BUSY"
            | "FIDO_ERR_PROCESSING"
            | "FIDO_ERR_OPERATION_PENDING"
            | "FIDO_ERR_USER_ACTION_PENDING" => NativeErrorKind::Busy,
            "FIDO_ERR_OPERATION_DENIED" | "FIDO_ERR_NOT_ALLOWED" | "FIDO_ERR_UNAUTHORIZED_PERM" => {
                NativeErrorKind::AccessDenied
            }
            "FIDO_ERR_TIMEOUT" | "FIDO_ERR_USER_ACTION_TIMEOUT" | "FIDO_ERR_ACTION_TIMEOUT" => {
                NativeErrorKind::TimedOut
            }
            "FIDO_ERR_INVALID_COMMAND"
            | "FIDO_ERR_UNSUPPORTED_EXTENSION"
            | "FIDO_ERR_UNSUPPORTED_ALGORITHM"
            | "FIDO_ERR_UNSUPPORTED_OPTION" => NativeErrorKind::Unsupported,
            "FIDO_ERR_NOTFOUND" => NativeErrorKind::Absent,
            "FIDO_ERR_INVALID_CBOR"
            | "FIDO_ERR_RX_NOT_CBOR"
            | "FIDO_ERR_RX_INVALID_CBOR"
            | "FIDO_ERR_CBOR_UNEXPECTED_TYPE" => NativeErrorKind::Malformed,
            "FIDO_ERR_RX" | "FIDO_ERR_TX" if timed_out_by_budget => NativeErrorKind::TimedOut,
            "FIDO_ERR_RX" | "FIDO_ERR_TX" => NativeErrorKind::Unavailable,
            _ => NativeErrorKind::Internal,
        };
        NativeError::new(kind, Some(code))
    }
}

#[cfg(feature = "native-libfido2")]
pub use native::LibFido2Adapter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_device_key_rejects_empty_oversized_and_nul_bytes() {
        assert!(NativeDeviceKey::from_bytes(Vec::new()).is_err());
        assert!(NativeDeviceKey::from_bytes(vec![b'x'; MAX_NATIVE_PATH_BYTES + 1]).is_err());
        assert!(NativeDeviceKey::from_bytes(b"abc\0def".to_vec()).is_err());
    }

    #[test]
    fn native_device_key_accepts_non_utf8_path_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = NativeDeviceKey::from_bytes(vec![0xff, 0xfe, 0x01])?;
        assert_eq!(key, key.clone());
        Ok(())
    }
}
