//! The one reviewed Security.framework binding (ADR-017 §5.2, macOS only).
//!
//! Every `unsafe` call into Security.framework or CoreFoundation for worker authenticity lives in
//! this file. Everything it hands out is owned Rust data or an opaque owned wrapper; no raw CF
//! object, OSStatus text, certificate or diagnostic structure leaves it, and nothing here is ever
//! serialized toward the renderer.
//!
//! # Ownership
//!
//! CoreFoundation's rules are applied explicitly:
//!
//! * *Create/Copy rule* (`…Create…`, `…Copy…`, and out-parameters of those functions): the caller
//!   receives a +1 reference. It is wrapped in [`Owned`] immediately, which calls `CFRelease`
//!   exactly once on drop. Out-parameters are initialised to null and wrapped even when the call
//!   reports an error, so a partially returned object is never leaked.
//! * *Get rule* (`CFDictionaryGetValue`, the exported key constants): the value is borrowed. It is
//!   only read while its owner is alive, converted to owned Rust data, and never released here.
//!
//! No callback crosses the boundary, so no Rust panic can unwind through a foreign frame.

use std::ffi::c_void;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{self, NonNull};

use crate::os_version::DynamicNetworkPolicy;

type CFTypeRef = *const c_void;
type CFIndex = isize;
type CFTypeID = usize;
type Boolean = u8;
type OSStatus = i32;
type SecCSFlags = u32;

#[repr(C)]
struct CFRange {
    location: CFIndex,
    length: CFIndex,
}

/// Opaque callback tables; only their addresses are passed to `CFDictionaryCreate`.
#[repr(C)]
struct CFDictionaryKeyCallBacks {
    _opaque: [u8; 0],
}
#[repr(C)]
struct CFDictionaryValueCallBacks {
    _opaque: [u8; 0],
}

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_CF_NUMBER_SINT32_TYPE: CFIndex = 3;
const K_CF_NUMBER_SINT64_TYPE: CFIndex = 4;

const K_SEC_CS_DEFAULT_FLAGS: SecCSFlags = 0;
const K_SEC_CS_NO_NETWORK_ACCESS: SecCSFlags = 1 << 29;
// SecStaticCode.h, flags for SecStaticCodeCheckValidity*.
const K_SEC_CS_CHECK_ALL_ARCHITECTURES: SecCSFlags = 1 << 0;
const K_SEC_CS_CHECK_NESTED_CODE: SecCSFlags = 1 << 3;
const K_SEC_CS_STRICT_VALIDATE: SecCSFlags = 1 << 4;
const K_SEC_CS_RESTRICT_SYMLINKS: SecCSFlags = 1 << 7;
// SecCode.h, flags for SecCodeCopySigningInformation.
const K_SEC_CS_SIGNING_INFORMATION: SecCSFlags = 1 << 1;
const K_SEC_CS_DYNAMIC_INFORMATION: SecCSFlags = 1 << 3;

/// `kSecCodeSignatureRuntime` (CSCommon.h): Hardened Runtime.
pub const SIGNATURE_FLAG_RUNTIME: u32 = 0x0001_0000;
/// `kSecCodeStatusValid` (CSCommon.h).
pub const STATUS_VALID: u32 = 0x0000_0001;
/// `kSecCodeStatusKill` (CSCommon.h): invalid pages terminate the process.
pub const STATUS_KILL: u32 = 0x0000_0200;

// OSStatus values from CSCommon.h used only to classify failures.
const ERR_SEC_CS_UNSIGNED: OSStatus = -67062;
const ERR_SEC_CS_SIGNATURE_FAILED: OSStatus = -67061;
const ERR_SEC_CS_REQ_FAILED: OSStatus = -67050;
const ERR_SEC_CS_NO_SUCH_CODE: OSStatus = -67065;
/// `kPOSIXErrorBase + ESRCH`, returned for a pid with no live code (for example a zombie).
const ERR_POSIX_ESRCH: OSStatus = 100_003;

/// Bound on any string converted out of a code-signing dictionary (identifiers, Team IDs and the
/// 64-character record digest are far shorter).
const MAX_STRING_BYTES: usize = 1_024;
/// Bound on a converted `CFData` (a cdhash is 20 bytes).
const MAX_DATA_BYTES: usize = 64;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
    static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;

    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    fn CFStringGetTypeID() -> CFTypeID;
    fn CFDataGetTypeID() -> CFTypeID;
    fn CFNumberGetTypeID() -> CFTypeID;
    fn CFDictionaryGetTypeID() -> CFTypeID;
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: CFTypeRef,
        buffer: *const u8,
        length: CFIndex,
        is_directory: Boolean,
    ) -> CFTypeRef;
    fn CFStringCreateWithBytes(
        allocator: CFTypeRef,
        bytes: *const u8,
        length: CFIndex,
        encoding: u32,
        is_external_representation: Boolean,
    ) -> CFTypeRef;
    fn CFStringGetLength(string: CFTypeRef) -> CFIndex;
    fn CFStringGetBytes(
        string: CFTypeRef,
        range: CFRange,
        encoding: u32,
        loss_byte: u8,
        is_external_representation: Boolean,
        buffer: *mut u8,
        max_buffer_length: CFIndex,
        used_buffer_length: *mut CFIndex,
    ) -> CFIndex;
    fn CFDataGetLength(data: CFTypeRef) -> CFIndex;
    fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
    fn CFNumberCreate(
        allocator: CFTypeRef,
        number_type: CFIndex,
        value: *const c_void,
    ) -> CFTypeRef;
    fn CFNumberGetValue(number: CFTypeRef, number_type: CFIndex, value: *mut c_void) -> Boolean;
    fn CFDictionaryCreate(
        allocator: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        key_callbacks: *const CFDictionaryKeyCallBacks,
        value_callbacks: *const CFDictionaryValueCallBacks,
    ) -> CFTypeRef;
    fn CFDictionaryGetValue(dictionary: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributePid: CFTypeRef;
    static kSecCodeInfoIdentifier: CFTypeRef;
    static kSecCodeInfoTeamIdentifier: CFTypeRef;
    static kSecCodeInfoUnique: CFTypeRef;
    static kSecCodeInfoFlags: CFTypeRef;
    static kSecCodeInfoStatus: CFTypeRef;
    static kSecCodeInfoEntitlements: CFTypeRef;
    static kSecCodeInfoEntitlementsDict: CFTypeRef;
    static kSecCodeInfoPList: CFTypeRef;

    fn SecStaticCodeCreateWithPath(
        path: CFTypeRef,
        flags: SecCSFlags,
        static_code: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecStaticCodeCheckValidityWithErrors(
        static_code: CFTypeRef,
        flags: SecCSFlags,
        requirement: CFTypeRef,
        errors: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCopyGuestWithAttributes(
        host: CFTypeRef,
        attributes: CFTypeRef,
        flags: SecCSFlags,
        guest: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(code: CFTypeRef, flags: SecCSFlags, requirement: CFTypeRef)
    -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: SecCSFlags,
        information: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecRequirementCreateWithString(
        text: CFTypeRef,
        flags: SecCSFlags,
        requirement: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCopySelf(flags: SecCSFlags, code: *mut CFTypeRef) -> OSStatus;
    fn SecCodeCopyStaticCode(
        code: CFTypeRef,
        flags: SecCSFlags,
        static_code: *mut CFTypeRef,
    ) -> OSStatus;
}

/// Typed failure of a code-signing operation. The raw `OSStatus` is kept only for local
/// diagnostics; it is never rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSigningError {
    /// A Rust value could not be represented for the API (path, pid or text).
    InvalidInput,
    /// The code has no signature.
    Unsigned,
    /// The signature or a sealed component is invalid.
    InvalidSignature,
    /// The code is validly signed but does not satisfy the requirement.
    RequirementNotSatisfied,
    /// No such code: the path or pid does not name live code.
    NoSuchCode,
    /// The requirement text failed to compile.
    RequirementSyntax,
    /// A required item was missing or malformed in the signing information.
    MalformedInformation,
    /// Any other Security.framework failure.
    Other(i32),
}

impl CodeSigningError {
    fn from_status(status: OSStatus) -> Self {
        match status {
            ERR_SEC_CS_UNSIGNED => Self::Unsigned,
            ERR_SEC_CS_SIGNATURE_FAILED => Self::InvalidSignature,
            ERR_SEC_CS_REQ_FAILED => Self::RequirementNotSatisfied,
            ERR_SEC_CS_NO_SUCH_CODE | ERR_POSIX_ESRCH => Self::NoSuchCode,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for CodeSigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Category only; the OSStatus stays in `Debug` for local diagnostics.
        f.write_str("code signing validation failed")
    }
}

impl std::error::Error for CodeSigningError {}

type Result<T> = std::result::Result<T, CodeSigningError>;

/// An owned (+1) CoreFoundation reference, released exactly once on drop.
struct Owned(NonNull<c_void>);

impl Owned {
    /// Takes ownership of a reference obtained under the Create/Copy rule. Null yields `None`.
    ///
    /// # Safety
    /// `raw` must be null or a +1 CoreFoundation reference that nothing else will release.
    unsafe fn adopt(raw: CFTypeRef) -> Option<Self> {
        NonNull::new(raw.cast_mut()).map(Self)
    }

    fn as_ptr(&self) -> CFTypeRef {
        self.0.as_ptr().cast_const()
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: `self` holds the single +1 reference it adopted; it is released once.
        unsafe { CFRelease(self.as_ptr()) }
    }
}

/// Runs a Create/Copy function with an out-parameter. The out value is adopted whether or not the
/// call succeeded, so nothing is leaked, and only a successful, non-null result is returned.
fn copy_out(call: impl FnOnce(*mut CFTypeRef) -> OSStatus) -> Result<Owned> {
    let mut out: CFTypeRef = ptr::null();
    let status = call(&mut out);
    // SAFETY: the out-parameter of every function passed here follows the Create/Copy rule.
    let owned = unsafe { Owned::adopt(out) };
    if status != 0 {
        return Err(CodeSigningError::from_status(status));
    }
    owned.ok_or(CodeSigningError::MalformedInformation)
}

fn cf_string(text: &str) -> Result<Owned> {
    let length = CFIndex::try_from(text.len()).map_err(|_| CodeSigningError::InvalidInput)?;
    // SAFETY: `text` is valid UTF-8 for `length` bytes during the call; the result is +1.
    let raw = unsafe {
        CFStringCreateWithBytes(
            ptr::null(),
            text.as_ptr(),
            length,
            K_CF_STRING_ENCODING_UTF8,
            0,
        )
    };
    // SAFETY: Create rule.
    unsafe { Owned::adopt(raw) }.ok_or(CodeSigningError::InvalidInput)
}

fn cf_url_for_path(path: &Path) -> Result<Owned> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(CodeSigningError::InvalidInput);
    }
    let length = CFIndex::try_from(bytes.len()).map_err(|_| CodeSigningError::InvalidInput)?;
    // SAFETY: `bytes` is valid for `length` bytes during the call; the result is +1.
    let raw =
        unsafe { CFURLCreateFromFileSystemRepresentation(ptr::null(), bytes.as_ptr(), length, 0) };
    // SAFETY: Create rule.
    unsafe { Owned::adopt(raw) }.ok_or(CodeSigningError::InvalidInput)
}

fn type_is(value: CFTypeRef, type_id: fn() -> CFTypeID) -> bool {
    // SAFETY: `value` is a live, non-null CF object borrowed from its owner.
    !value.is_null() && unsafe { CFGetTypeID(value) } == type_id()
}

fn string_type_id() -> CFTypeID {
    // SAFETY: no arguments; returns a constant.
    unsafe { CFStringGetTypeID() }
}
fn data_type_id() -> CFTypeID {
    // SAFETY: no arguments; returns a constant.
    unsafe { CFDataGetTypeID() }
}
fn number_type_id() -> CFTypeID {
    // SAFETY: no arguments; returns a constant.
    unsafe { CFNumberGetTypeID() }
}
fn dictionary_type_id() -> CFTypeID {
    // SAFETY: no arguments; returns a constant.
    unsafe { CFDictionaryGetTypeID() }
}

/// Borrowed lookup (Get rule). The returned pointer is valid only while `dictionary` is alive.
fn dictionary_value(dictionary: &Owned, key: CFTypeRef) -> Option<CFTypeRef> {
    // SAFETY: `dictionary` is a live CFDictionary (checked by callers) and `key` a live CF key.
    let value = unsafe { CFDictionaryGetValue(dictionary.as_ptr(), key) };
    (!value.is_null()).then_some(value)
}

/// Converts a borrowed CFString into an owned `String`, bounded and lossless.
fn string_value(value: CFTypeRef) -> Result<String> {
    if !type_is(value, string_type_id) {
        return Err(CodeSigningError::MalformedInformation);
    }
    // SAFETY: `value` is a live CFString.
    let characters = unsafe { CFStringGetLength(value) };
    if characters < 0 || characters as usize > MAX_STRING_BYTES {
        return Err(CodeSigningError::MalformedInformation);
    }
    let mut buffer = vec![0u8; MAX_STRING_BYTES];
    let mut used: CFIndex = 0;
    // SAFETY: `buffer` is writable for `MAX_STRING_BYTES`; `used` receives the byte count. A loss
    // byte of 0 makes the call stop at the first unconvertible character instead of substituting.
    let converted = unsafe {
        CFStringGetBytes(
            value,
            CFRange {
                location: 0,
                length: characters,
            },
            K_CF_STRING_ENCODING_UTF8,
            0,
            0,
            buffer.as_mut_ptr(),
            MAX_STRING_BYTES as CFIndex,
            &mut used,
        )
    };
    if converted != characters || used < 0 || used as usize > MAX_STRING_BYTES {
        return Err(CodeSigningError::MalformedInformation);
    }
    buffer.truncate(used as usize);
    String::from_utf8(buffer).map_err(|_| CodeSigningError::MalformedInformation)
}

/// Copies a borrowed CFData into an owned, bounded `Vec<u8>`.
fn data_value(value: CFTypeRef) -> Result<Vec<u8>> {
    if !type_is(value, data_type_id) {
        return Err(CodeSigningError::MalformedInformation);
    }
    // SAFETY: `value` is a live CFData.
    let length = unsafe { CFDataGetLength(value) };
    if length < 0 || length as usize > MAX_DATA_BYTES {
        return Err(CodeSigningError::MalformedInformation);
    }
    // SAFETY: `value` is a live CFData; its byte pointer is valid for `length` bytes while the
    // owning dictionary is alive, and the bytes are copied before returning.
    let bytes = unsafe { CFDataGetBytePtr(value) };
    if bytes.is_null() && length != 0 {
        return Err(CodeSigningError::MalformedInformation);
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: see above.
    Ok(unsafe { std::slice::from_raw_parts(bytes, length as usize) }.to_vec())
}

fn u32_value(value: CFTypeRef) -> Result<u32> {
    if !type_is(value, number_type_id) {
        return Err(CodeSigningError::MalformedInformation);
    }
    let mut number: i64 = 0;
    // SAFETY: `value` is a live CFNumber and `number` a writable i64 for the SInt64 conversion.
    let exact = unsafe {
        CFNumberGetValue(
            value,
            K_CF_NUMBER_SINT64_TYPE,
            (&raw mut number).cast::<c_void>(),
        )
    };
    if exact == 0 {
        return Err(CodeSigningError::MalformedInformation);
    }
    u32::try_from(number).map_err(|_| CodeSigningError::MalformedInformation)
}

/// Owned, plain-Rust copy of the parts of `SecCodeCopySigningInformation` this project uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningInformation {
    /// `kSecCodeInfoIdentifier`; absent for unsigned code.
    pub identifier: Option<String>,
    /// `kSecCodeInfoTeamIdentifier`; absent for ad-hoc and unsigned code.
    pub team_id: Option<String>,
    /// `kSecCodeInfoUnique`: the code directory hash (cdhash).
    pub cdhash: Option<Vec<u8>>,
    /// `kSecCodeInfoFlags`: the signature's code-signing flags.
    pub signature_flags: Option<u32>,
    /// `kSecCodeInfoStatus`: dynamic status word; only for running code.
    pub dynamic_status: Option<u32>,
    /// Whether any entitlements (`kSecCodeInfoEntitlements` or `…EntitlementsDict`) are present.
    pub has_entitlements: bool,
}

fn signing_information(code: CFTypeRef, flags: SecCSFlags) -> Result<SigningInformation> {
    // SAFETY: `code` is a live SecCode/SecStaticCode; the out-parameter follows the Copy rule.
    let info = copy_out(|out| unsafe { SecCodeCopySigningInformation(code, flags, out) })?;
    if !type_is(info.as_ptr(), dictionary_type_id) {
        return Err(CodeSigningError::MalformedInformation);
    }
    // SAFETY: reading the framework's exported, immutable key constants.
    let (identifier, team, unique, code_flags, status, entitlements, entitlements_dict) = unsafe {
        (
            kSecCodeInfoIdentifier,
            kSecCodeInfoTeamIdentifier,
            kSecCodeInfoUnique,
            kSecCodeInfoFlags,
            kSecCodeInfoStatus,
            kSecCodeInfoEntitlements,
            kSecCodeInfoEntitlementsDict,
        )
    };
    Ok(SigningInformation {
        identifier: dictionary_value(&info, identifier)
            .map(string_value)
            .transpose()?,
        team_id: dictionary_value(&info, team)
            .map(string_value)
            .transpose()?,
        cdhash: dictionary_value(&info, unique)
            .map(data_value)
            .transpose()?,
        signature_flags: dictionary_value(&info, code_flags)
            .map(u32_value)
            .transpose()?,
        dynamic_status: dictionary_value(&info, status).map(u32_value).transpose()?,
        has_entitlements: dictionary_value(&info, entitlements).is_some()
            || dictionary_value(&info, entitlements_dict).is_some(),
    })
}

/// A compiled code requirement (`SecRequirementRef`). Compiled once and kept.
pub struct Requirement(Owned);

// SAFETY: a SecRequirement is an immutable CoreFoundation object after creation; CF reference
// counting is thread-safe, and the wrapper exposes no mutation.
unsafe impl Send for Requirement {}
// SAFETY: as above; shared references only pass the immutable object to validation calls.
unsafe impl Sync for Requirement {}

impl Requirement {
    /// Compiles requirement-language `text` with `SecRequirementCreateWithString`.
    pub fn compile(text: &str) -> Result<Self> {
        let text = cf_string(text)?;
        // SAFETY: `text` is a live CFString; the out-parameter follows the Create rule.
        copy_out(|out| unsafe {
            SecRequirementCreateWithString(text.as_ptr(), K_SEC_CS_DEFAULT_FLAGS, out)
        })
        .map(Self)
        .map_err(|error| match error {
            CodeSigningError::Other(_) => CodeSigningError::RequirementSyntax,
            other => other,
        })
    }
}

impl std::fmt::Debug for Requirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Requirement(<compiled>)")
    }
}

/// Which static validation to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticValidation {
    /// A single executable file (the worker):
    /// `kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSRestrictSymlinks |
    /// kSecCSNoNetworkAccess`.
    SingleFile,
    /// The application bundle at startup (ADR-017 §5.8 S3): the single-file flags plus
    /// `kSecCSCheckNestedCode`.
    BundleWithNestedCode,
}

impl StaticValidation {
    const fn flags(self) -> SecCSFlags {
        let base = K_SEC_CS_STRICT_VALIDATE
            | K_SEC_CS_CHECK_ALL_ARCHITECTURES
            | K_SEC_CS_RESTRICT_SYMLINKS
            | K_SEC_CS_NO_NETWORK_ACCESS;
        match self {
            Self::SingleFile => base,
            Self::BundleWithNestedCode => base | K_SEC_CS_CHECK_NESTED_CODE,
        }
    }
}

/// Flags for dynamic validation. Only the network flag depends on the OS version; the requirement
/// passed alongside never does.
pub const fn dynamic_validation_flags(policy: DynamicNetworkPolicy) -> u32 {
    match policy {
        DynamicNetworkPolicy::DefaultFlags => K_SEC_CS_DEFAULT_FLAGS,
        DynamicNetworkPolicy::NoNetworkAccess => K_SEC_CS_NO_NETWORK_ACCESS,
    }
}

/// On-disk code (`SecStaticCodeRef`).
pub struct StaticCode(Owned);

impl StaticCode {
    /// `SecStaticCodeCreateWithPath`.
    pub fn at_path(path: &Path) -> Result<Self> {
        let url = cf_url_for_path(path)?;
        // SAFETY: `url` is a live CFURL; the out-parameter follows the Create rule.
        copy_out(|out| unsafe {
            SecStaticCodeCreateWithPath(url.as_ptr(), K_SEC_CS_DEFAULT_FLAGS, out)
        })
        .map(Self)
    }

    /// `SecStaticCodeCheckValidityWithErrors` against `requirement`.
    pub fn check_validity(&self, kind: StaticValidation, requirement: &Requirement) -> Result<()> {
        let mut errors: CFTypeRef = ptr::null();
        // SAFETY: both objects are live; `errors` follows the Copy rule and is adopted below.
        let status = unsafe {
            SecStaticCodeCheckValidityWithErrors(
                self.0.as_ptr(),
                kind.flags(),
                requirement.0.as_ptr(),
                &mut errors,
            )
        };
        // SAFETY: the error out-parameter is +1 when set; it is released without inspection.
        drop(unsafe { Owned::adopt(errors) });
        if status == 0 {
            Ok(())
        } else {
            Err(CodeSigningError::from_status(status))
        }
    }

    /// Signing information (`kSecCSSigningInformation`) of the on-disk code.
    pub fn signing_information(&self) -> Result<SigningInformation> {
        signing_information(self.0.as_ptr(), K_SEC_CS_SIGNING_INFORMATION)
    }

    /// A string value from the secured `Info.plist` (`kSecCodeInfoPList`), "as seen by code
    /// signing", not the `CFBundle` view of the file. `Ok(None)` when the key is absent. A plist
    /// that is missing or not a dictionary, or a value that is not a string, is an error.
    ///
    /// Callers must have validated this object first. ADR-017 E16 (a release gate) requires
    /// evidence on a real Developer ID bundle that this returns the *signed* value on macOS
    /// 11.0–11.2 and 11.3 or later.
    pub fn secured_info_plist_string(&self, key: &str) -> Result<Option<String>> {
        // SAFETY: `self` is live; the out-parameter follows the Copy rule.
        let info = copy_out(|out| unsafe {
            SecCodeCopySigningInformation(self.0.as_ptr(), K_SEC_CS_DEFAULT_FLAGS, out)
        })?;
        if !type_is(info.as_ptr(), dictionary_type_id) {
            return Err(CodeSigningError::MalformedInformation);
        }
        // SAFETY: reading the framework's exported, immutable key constant.
        let plist_key = unsafe { kSecCodeInfoPList };
        let plist =
            dictionary_value(&info, plist_key).ok_or(CodeSigningError::MalformedInformation)?;
        if !type_is(plist, dictionary_type_id) {
            return Err(CodeSigningError::MalformedInformation);
        }
        let key = cf_string(key)?;
        // SAFETY: `plist` is a live CFDictionary borrowed from `info`, which outlives this call.
        let value = unsafe { CFDictionaryGetValue(plist, key.as_ptr()) };
        if value.is_null() {
            return Ok(None);
        }
        string_value(value).map(Some)
    }
}

/// Running code (`SecCodeRef`).
pub struct RunningCode(Owned);

impl RunningCode {
    /// `SecCodeCopySelf`: this process.
    pub fn current_process() -> Result<Self> {
        // SAFETY: the out-parameter follows the Copy rule.
        copy_out(|out| unsafe { SecCodeCopySelf(K_SEC_CS_DEFAULT_FLAGS, out) }).map(Self)
    }

    /// `SecCodeCopyGuestWithAttributes(NULL, {kSecGuestAttributePid: pid})`.
    ///
    /// A pid is only a sound name for this process's **own, unreaped** child: until it is reaped
    /// the kernel cannot reuse the pid. Callers must guarantee that.
    pub fn child_process(pid: u32) -> Result<Self> {
        let pid = i32::try_from(pid).map_err(|_| CodeSigningError::InvalidInput)?;
        if pid <= 0 {
            return Err(CodeSigningError::InvalidInput);
        }
        // SAFETY: `pid` is a readable i32 for the SInt32 conversion; the result is +1.
        let number = unsafe {
            Owned::adopt(CFNumberCreate(
                ptr::null(),
                K_CF_NUMBER_SINT32_TYPE,
                (&raw const pid).cast::<c_void>(),
            ))
        }
        .ok_or(CodeSigningError::InvalidInput)?;
        // SAFETY: reading the framework's exported, immutable key constant.
        let keys = [unsafe { kSecGuestAttributePid }];
        let values = [number.as_ptr()];
        // SAFETY: both arrays hold one live CF object each; the CFType callbacks retain them for
        // the dictionary's lifetime. The result is +1.
        let attributes = unsafe {
            Owned::adopt(CFDictionaryCreate(
                ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                1,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            ))
        }
        .ok_or(CodeSigningError::InvalidInput)?;
        // SAFETY: `attributes` is live; a null host means "ask the kernel"; Copy rule out-param.
        copy_out(|out| unsafe {
            SecCodeCopyGuestWithAttributes(
                ptr::null(),
                attributes.as_ptr(),
                K_SEC_CS_DEFAULT_FLAGS,
                out,
            )
        })
        .map(Self)
    }

    /// `SecCodeCheckValidity` (dynamic validation) against `requirement`.
    pub fn check_validity(
        &self,
        network: DynamicNetworkPolicy,
        requirement: &Requirement,
    ) -> Result<()> {
        // SAFETY: both objects are live.
        let status = unsafe {
            SecCodeCheckValidity(
                self.0.as_ptr(),
                dynamic_validation_flags(network),
                requirement.0.as_ptr(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(CodeSigningError::from_status(status))
        }
    }

    /// Signing plus dynamic information (`kSecCSSigningInformation | kSecCSDynamicInformation`).
    pub fn signing_information(&self) -> Result<SigningInformation> {
        signing_information(
            self.0.as_ptr(),
            K_SEC_CS_SIGNING_INFORMATION | K_SEC_CS_DYNAMIC_INFORMATION,
        )
    }

    /// `SecCodeCopyStaticCode`: for an application's main executable, the whole bundle.
    pub fn static_code(&self) -> Result<StaticCode> {
        // SAFETY: `self` is live; the out-parameter follows the Copy rule.
        copy_out(|out| unsafe {
            SecCodeCopyStaticCode(self.0.as_ptr(), K_SEC_CS_DEFAULT_FLAGS, out)
        })
        .map(StaticCode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_requirement_text_is_a_typed_error() {
        assert!(matches!(
            Requirement::compile("this is not a requirement ((("),
            Err(CodeSigningError::RequirementSyntax)
        ));
        assert!(Requirement::compile("anchor apple generic").is_ok());
    }

    #[test]
    fn paths_and_pids_that_cannot_name_code_are_rejected() {
        assert_eq!(
            StaticCode::at_path(Path::new("")).err(),
            Some(CodeSigningError::InvalidInput)
        );
        assert!(StaticCode::at_path(Path::new("/definitely/not/here/fido-worker")).is_err());
        assert_eq!(
            RunningCode::child_process(0).err(),
            Some(CodeSigningError::InvalidInput)
        );
        assert_eq!(
            RunningCode::child_process(u32::MAX).err(),
            Some(CodeSigningError::InvalidInput)
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_test_process_has_readable_signing_information() -> Result<()> {
        // Rust test binaries on Apple silicon carry a linker ad-hoc signature (no Team ID).
        let me = RunningCode::current_process()?;
        let info = me.signing_information()?;
        assert!(info.team_id.is_none());
        assert!(info.dynamic_status.is_some_and(|s| s & STATUS_VALID != 0));
        Ok(())
    }

    #[test]
    fn requirement_strings_with_an_anchor_reject_ad_hoc_code() -> Result<()> {
        let me = RunningCode::current_process()?;
        let developer_id = Requirement::compile(
            "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and \
             certificate leaf[field.1.2.840.113635.100.6.1.13] and \
             certificate leaf[subject.OU] = \"ABCDE12345\"",
        )?;
        assert!(
            me.check_validity(DynamicNetworkPolicy::NoNetworkAccess, &developer_id)
                .is_err()
        );
        Ok(())
    }
}
