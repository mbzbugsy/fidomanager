//! Controlled safe adapter for discovery/GetInfo and bounded macOS PUAT authentication.
//!
//! The public API deliberately exposes owned values only. Native paths remain opaque inside the
//! worker and libfido2 pointers never cross this crate boundary.

pub mod deletion;
pub mod inspection;
#[cfg(any(test, all(feature = "native-libfido2", target_os = "macos")))]
mod mutation;

use std::fmt;
use std::time::{Duration, Instant};

pub const MAX_NATIVE_PATH_BYTES: usize = 4_096;
pub const MAX_NATIVE_DEVICE_TEXT_BYTES: usize = 256;
pub const MAX_NATIVE_STRING_ITEMS: usize = 128;
pub const MAX_NATIVE_DISCOVERED_DEVICES: usize = 65;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeDeviceKey(Vec<u8>);

impl NativeDeviceKey {
    /// App-scoped historical display correlation for reviewed macOS IORegistry connections.
    /// Never an addressing/authorization identity; no raw path or registry ID is returned.
    pub fn verification_history_id(&self, scope: &[u8; 32]) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let text = std::str::from_utf8(&self.0)
            .ok()?
            .strip_prefix("ioreg://")?;
        let entry = text.parse::<u64>().ok().filter(|id| *id != 0)?;
        if text != entry.to_string() {
            return None;
        }
        let mut hash = Sha256::new();
        hash.update(b"FidoManager PIN check display history v1");
        hash.update(scope);
        hash.update(entry.to_be_bytes());
        Some(hash.finalize().into())
    }

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

/// The single deadline for one whole worker request.
///
/// The worker creates exactly one `NativeDeadline` when it receives a request. Every native
/// sub-call derives its timeout from [`NativeDeadline::next_call_timeout_ms`], which reports only
/// the time that is *left*. A request that performs several native calls (for example `open` then
/// `get_cbor_info`) therefore cannot spend the full budget twice.
#[derive(Debug, Clone, Copy)]
pub struct NativeDeadline {
    expires_at: Instant,
}

impl NativeDeadline {
    /// Reviewed ceiling for one request. Current production budgets are 1–5 seconds.
    /// Oversized/unrepresentable budgets fail closed as already expired, never as unlimited.
    pub const MAX_BUDGET: Duration = Duration::from_secs(60);

    pub fn after(budget: Duration) -> Self {
        let now = Instant::now();
        let expires_at = if budget <= Self::MAX_BUDGET {
            now.checked_add(budget).unwrap_or(now)
        } else {
            now
        };
        Self { expires_at }
    }

    pub fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    pub fn is_expired(&self) -> bool {
        self.remaining().is_zero()
    }

    /// Timeout to hand the next native sub-call, in whole milliseconds, rounded up so a live
    /// deadline never yields zero (libfido2 treats zero as "return immediately").
    ///
    /// Returns a `TimedOut` error once the deadline has expired so callers stop *before* starting
    /// another native call rather than after it.
    pub fn next_call_timeout_ms(&self) -> Result<i32, NativeError> {
        let remaining = self.remaining();
        if remaining.is_zero() {
            return Err(NativeError::new(NativeErrorKind::TimedOut, None));
        }
        let millis = remaining.as_nanos().div_ceil(1_000_000).max(1);
        Ok(i32::try_from(millis).unwrap_or(i32::MAX))
    }
}

/// Native discovery surface consumed by the worker engine.
///
/// Implementations own all native identifiers and must never expose raw paths outside
/// `NativeDeviceKey`. Every method receives the request's [`NativeDeadline`] and must split the
/// remaining time across its native sub-calls instead of granting each one a fresh budget.
pub trait NativeAuthenticationSession: Send {
    fn kind(&self) -> fido_auth::GrantKind;
    fn pin_retries(&self) -> Option<u8>;
    fn inspect(
        self: Box<Self>,
        binding: fido_auth::AcquisitionBinding,
        pin: fido_auth::PinSecret,
        deadline: NativeDeadline,
    ) -> inspection::NativeInspection;
    fn validate(
        self: Box<Self>,
        binding: fido_auth::AcquisitionBinding,
        pin: fido_auth::PinSecret,
        deadline: NativeDeadline,
    ) -> fido_auth::AuthenticationEvidence;
}

pub trait NativePinMutationSession: Send {
    fn operation(&self) -> fido_auth::mutation::PinOperation;
    fn pin_retries(&self) -> Option<u8>;
    fn execute(
        self: Box<Self>,
        secrets: fido_auth::mutation::PinMutationSecrets,
        deadline: NativeDeadline,
    ) -> fido_auth::mutation::PinMutationResult;
}

pub trait NativeCredentialDeletionSession: Send {
    fn kind(&self) -> fido_auth::GrantKind;
    fn pin_retries(&self) -> u8;
    /// Read-only current-session proof, run BEFORE any durable dispatch record. On success the
    /// session retains the proven identity and the zeroizing PIN for the one `execute`; on any
    /// other outcome the session is closed and the PIN dropped. Never reaches the delete call.
    fn prove(
        &mut self,
        target: &fido_core::inventory::DeletionIdentity,
        pin: fido_auth::PinSecret,
        deadline: NativeDeadline,
    ) -> fido_auth::deletion::DeleteProofResult;
    /// Consumes the proven session for exactly one native delete of the same identity. No proof,
    /// GetInfo or retry-count call is repeated.
    fn execute(
        self: Box<Self>,
        target: fido_core::inventory::DeletionIdentity,
        deadline: NativeDeadline,
    ) -> fido_auth::deletion::DeleteCredentialResult;
}

pub trait NativeDiscoveryBackend: Send {
    fn prepare_pin_mutation(
        &mut self,
        _key: &NativeDeviceKey,
        _operation: fido_auth::mutation::PinOperation,
        _deadline: NativeDeadline,
    ) -> Result<Box<dyn NativePinMutationSession>, NativeError> {
        Err(NativeError::new(NativeErrorKind::Unsupported, None))
    }
    fn prepare_credential_deletion(
        &mut self,
        _key: &NativeDeviceKey,
        _deadline: NativeDeadline,
    ) -> Result<Box<dyn NativeCredentialDeletionSession>, NativeError> {
        Err(NativeError::new(NativeErrorKind::Unsupported, None))
    }
    fn prepare_authentication(
        &mut self,
        _key: &NativeDeviceKey,
        _deadline: NativeDeadline,
    ) -> Result<Box<dyn NativeAuthenticationSession>, NativeError> {
        Err(NativeError::new(NativeErrorKind::Unavailable, None))
    }
    fn manifest(
        &mut self,
        deadline: NativeDeadline,
    ) -> Result<Vec<NativeDiscoveredDevice>, NativeError>;

    fn get_info(
        &mut self,
        key: &NativeDeviceKey,
        deadline: NativeDeadline,
    ) -> Result<NativeDeviceInfo, NativeError>;
}

#[cfg(feature = "native-libfido2")]
mod native {
    use std::ffi::{c_char, c_int, c_void};
    use std::ptr;

    use super::{
        MAX_NATIVE_DEVICE_TEXT_BYTES, MAX_NATIVE_DISCOVERED_DEVICES, MAX_NATIVE_PATH_BYTES,
        MAX_NATIVE_STRING_ITEMS, NativeDeadline, NativeDeviceInfo, NativeDeviceKey,
        NativeDeviceOption, NativeDiscoveredDevice, NativeDiscoveryBackend, NativeError,
        NativeErrorKind,
    };

    #[cfg(target_os = "macos")]
    mod authentication;
    #[cfg(target_os = "macos")]
    mod deletion;
    #[cfg(target_os = "macos")]
    mod inspection;
    #[cfg(target_os = "macos")]
    mod mutation;

    const FIDO_OK: c_int = 0;
    const ERROR_NAME_BOUND: usize = 64;

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    compile_error!("native-libfido2 is currently supported only on macOS and Linux");

    #[cfg_attr(not(target_os = "macos"), link(name = "fido2"))]
    unsafe extern "C" {
        #[cfg(target_os = "macos")]
        fn fidomanager_libfido2_1_17_0_credman_limit() -> u32;
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
            #[cfg(target_os = "macos")]
            // SAFETY: private scalar probe compiled in the same patched credman.c translation
            // unit as the count checks. An unpatched archive cannot resolve this link symbol.
            assert_eq!(unsafe { fidomanager_libfido2_1_17_0_credman_limit() }, 256);
            // SAFETY: fido_init takes no pointers and is the documented process initialization
            // entry point. Calling it before libfido2 operations is required by the C API.
            unsafe { fido_init(0) };
            Self
        }
    }

    impl NativeDiscoveryBackend for LibFido2Adapter {
        #[cfg(target_os = "macos")]
        fn prepare_pin_mutation(
            &mut self,
            key: &NativeDeviceKey,
            operation: fido_auth::mutation::PinOperation,
            deadline: NativeDeadline,
        ) -> Result<Box<dyn super::NativePinMutationSession>, NativeError> {
            mutation::prepare(key, operation, deadline)
        }
        #[cfg(target_os = "macos")]
        fn prepare_credential_deletion(
            &mut self,
            key: &NativeDeviceKey,
            deadline: NativeDeadline,
        ) -> Result<Box<dyn super::NativeCredentialDeletionSession>, NativeError> {
            deletion::prepare(key, deadline)
        }
        #[cfg(target_os = "macos")]
        fn prepare_authentication(
            &mut self,
            key: &NativeDeviceKey,
            deadline: NativeDeadline,
        ) -> Result<Box<dyn super::NativeAuthenticationSession>, NativeError> {
            authentication::prepare(key, deadline)
        }
        fn manifest(
            &mut self,
            deadline: NativeDeadline,
        ) -> Result<Vec<NativeDiscoveredDevice>, NativeError> {
            // Do not start a native call with no time left to spend on it.
            deadline.next_call_timeout_ms()?;

            let mut list = DevInfoList::new(MAX_NATIVE_DISCOVERED_DEVICES)?;
            let mut found = 0usize;

            // SAFETY: `list.ptr` was allocated by fido_dev_info_new for exactly `list.capacity`
            // entries and `found` is a valid writable size_t pointer.
            //
            // `fido_dev_info_manifest` accepts no timeout, so this call is bounded only by the
            // worker-process kill boundary enforced by the service, never by `deadline`.
            let result = unsafe {
                fido_dev_info_manifest(list.ptr, list.capacity, ptr::addr_of_mut!(found))
            };
            if result != FIDO_OK {
                return Err(map_libfido2_error(result, &deadline));
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
            deadline: NativeDeadline,
        ) -> Result<NativeDeviceInfo, NativeError> {
            let path = key.to_cstring()?;
            let mut device = Device::new()?;

            // Each sub-call below is given only the time that is left on the request deadline,
            // re-read immediately before the call, so `open` and `get_cbor_info` share one budget.
            device.set_timeout(&deadline)?;
            // SAFETY: path is NUL-terminated for the duration of the call and device is live.
            let open_result = unsafe { fido_dev_open(device.ptr, path.as_ptr()) };
            if open_result != FIDO_OK {
                return Err(map_libfido2_error(open_result, &deadline));
            }
            device.opened = true;

            let info = CborInfo::new()?;
            device.set_timeout(&deadline)?;
            // SAFETY: both pointers are live libfido2 objects owned by guards in this scope.
            let info_result = unsafe { fido_dev_get_cbor_info(device.ptr, info.ptr) };
            if info_result != FIDO_OK {
                return Err(map_libfido2_error(info_result, &deadline));
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

        #[cfg(target_os = "macos")]
        fn close(&mut self) -> bool {
            if !self.opened {
                return true;
            }
            let ok = unsafe { fido_dev_close(self.ptr) } == FIDO_OK;
            if ok {
                self.opened = false;
            }
            ok
        }

        /// Applies the remaining request time as libfido2's timeout for the *next* native call.
        fn set_timeout(&mut self, deadline: &NativeDeadline) -> Result<(), NativeError> {
            let timeout_ms = deadline.next_call_timeout_ms()?;
            // SAFETY: device is a live libfido2 object and timeout is a positive c_int.
            let result = unsafe { fido_dev_set_timeout(self.ptr, timeout_ms) };
            if result != FIDO_OK {
                return Err(map_libfido2_error(result, deadline));
            }
            Ok(())
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

    fn map_libfido2_error(code: c_int, deadline: &NativeDeadline) -> NativeError {
        let name = unsafe {
            copy_required_utf8(fido_strerr(code), ERROR_NAME_BOUND)
                .unwrap_or_else(|_| "FIDO_ERR_UNKNOWN".to_owned())
        };
        // A transport-level failure that arrives after the request deadline is a timeout, not a
        // vanished device.
        let timed_out_by_budget = deadline.is_expired();
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
    #[test]
    fn display_history_is_app_and_connection_scoped_not_model_identity() {
        let a = super::NativeDeviceKey::from_bytes(b"ioreg://100".to_vec())
            .unwrap_or_else(|_| panic!("fixture"));
        let b = super::NativeDeviceKey::from_bytes(b"ioreg://101".to_vec())
            .unwrap_or_else(|_| panic!("fixture"));
        assert_eq!(
            a.verification_history_id(&[1; 32]),
            a.verification_history_id(&[1; 32])
        );
        assert_ne!(
            a.verification_history_id(&[1; 32]),
            b.verification_history_id(&[1; 32])
        );
        assert_ne!(
            a.verification_history_id(&[1; 32]),
            a.verification_history_id(&[2; 32])
        );
        for key in [
            b"ioreg://0".as_slice(),
            b"ioreg://0100",
            b"/dev/hidraw0",
            b"ioreg://bad",
        ] {
            let key = super::NativeDeviceKey::from_bytes(key.to_vec())
                .unwrap_or_else(|_| panic!("fixture"));
            assert!(key.verification_history_id(&[1; 32]).is_none());
        }
    }
    use super::*;

    #[test]
    fn native_device_key_rejects_empty_oversized_and_nul_bytes() {
        assert!(NativeDeviceKey::from_bytes(Vec::new()).is_err());
        assert!(NativeDeviceKey::from_bytes(vec![b'x'; MAX_NATIVE_PATH_BYTES + 1]).is_err());
        assert!(NativeDeviceKey::from_bytes(b"abc\0def".to_vec()).is_err());
    }

    #[test]
    fn deadline_timeout_shrinks_as_time_is_spent() -> Result<(), Box<dyn std::error::Error>> {
        let deadline = NativeDeadline::after(Duration::from_millis(400));
        let first = deadline.next_call_timeout_ms()?;
        assert!((1..=400).contains(&first));

        std::thread::sleep(Duration::from_millis(150));
        let second = deadline.next_call_timeout_ms()?;
        assert!(
            second <= 400 - 100,
            "second sub-call must only get the remaining time, got {second} ms"
        );
        assert!(second < first);
        Ok(())
    }

    #[test]
    fn expired_deadline_refuses_to_start_another_native_call() {
        let deadline = NativeDeadline::after(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(deadline.is_expired());
        let error = deadline.next_call_timeout_ms().err();
        assert_eq!(
            error.map(|error| error.kind()),
            Some(NativeErrorKind::TimedOut)
        );
    }

    #[test]
    fn live_deadline_never_rounds_down_to_zero() -> Result<(), Box<dyn std::error::Error>> {
        let deadline = NativeDeadline::after(Duration::from_micros(900));
        // Either it already expired (error) or it must report at least 1 ms; never 0.
        if let Ok(timeout) = deadline.next_call_timeout_ms() {
            assert!(timeout >= 1);
        }
        let generous = NativeDeadline::after(Duration::from_secs(5));
        assert!(generous.next_call_timeout_ms()? >= 1);
        Ok(())
    }

    #[test]
    fn invalid_deadline_budgets_fail_closed() {
        for budget in [
            Duration::ZERO,
            NativeDeadline::MAX_BUDGET + Duration::from_nanos(1),
            Duration::MAX,
        ] {
            let deadline = NativeDeadline::after(budget);
            assert!(deadline.is_expired());
            assert_eq!(
                deadline.next_call_timeout_ms().err().map(|e| e.kind()),
                Some(NativeErrorKind::TimedOut)
            );
        }
    }

    #[test]
    fn maximum_reviewed_deadline_is_finite_and_accepted() {
        let deadline = NativeDeadline::after(NativeDeadline::MAX_BUDGET);
        assert!(!deadline.is_expired());
        assert!(deadline.remaining() <= NativeDeadline::MAX_BUDGET);
        assert!(matches!(deadline.next_call_timeout_ms(), Ok(1..=60_000)));
    }

    #[test]
    fn native_device_key_accepts_non_utf8_path_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = NativeDeviceKey::from_bytes(vec![0xff, 0xfe, 0x01])?;
        assert_eq!(key, key.clone());
        Ok(())
    }
}
