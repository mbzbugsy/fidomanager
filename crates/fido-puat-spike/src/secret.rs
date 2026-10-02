//! Secret-bearing buffers for the spike.
//!
//! Production should use the reviewed `zeroize` crate; the spike avoids adding a dependency for
//! one small type. The guarantees are deliberately narrow (see `SECURITY_MODEL.md` section 11):
//! the buffer is overwritten before its allocation is released, it is never reallocated after
//! construction, and nothing here can print, clone, or serialize it. Native-library copies, paging,
//! and crash dumps are outside what any of this can promise.

use std::ffi::{CStr, c_char};
use std::fmt;
use std::sync::atomic::{Ordering, compiler_fence};

/// Longest PIN CTAP allows, in bytes of UTF-8 (the authenticator pads to 64 including the NUL).
pub const MAX_PIN_BYTES: usize = 63;
/// Shortest PIN CTAP allows, in bytes. Authenticators may require more (minPINLength); that is
/// their policy to enforce, not ours to guess.
pub const MIN_PIN_BYTES: usize = 4;

/// Owned bytes that are overwritten with zeros when dropped.
///
/// No `Clone`, `Debug` output of the contents, `Display`, `Serialize`, or `Deref`. The only way to
/// look at the bytes is [`SecretBytes::expose`], which keeps every read site greppable.
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    /// Takes ownership of `bytes`. The vector is never grown afterwards, so its single allocation
    /// is the one that gets wiped.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    fn wipe(&mut self) {
        // Wipe the whole allocation, not only `len`, so spare capacity that once held input (for
        // example a trimmed newline) is cleared too.
        let capacity = self.bytes.capacity();
        let pointer = self.bytes.as_mut_ptr();
        for offset in 0..capacity {
            // SAFETY: `offset < capacity` and the pointer is the start of this vector's live
            // allocation. Volatile writes keep the compiler from eliding stores to memory that is
            // about to be freed.
            unsafe { std::ptr::write_volatile(pointer.add(offset), 0) };
        }
        compiler_fence(Ordering::SeqCst);
        self.bytes.clear();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}

/// Why PIN input was refused. Carries no part of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinInputError {
    Empty,
    TooShort,
    TooLong,
    EmbeddedNul,
    NotUtf8,
}

impl fmt::Display for PinInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Empty => "PIN is empty",
            Self::TooShort => "PIN is shorter than 4 bytes",
            Self::TooLong => "PIN is longer than 63 bytes",
            Self::EmbeddedNul => "PIN contains a NUL byte",
            Self::NotUtf8 => "PIN is not valid UTF-8",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for PinInputError {}

/// An authenticator PIN, already NUL-terminated for the libfido2 boundary.
///
/// Validation happens once, at construction, *before* any C string exists: an embedded NUL would
/// otherwise silently truncate the PIN libfido2 sees. The terminating NUL is part of the same
/// zeroizing allocation, so no `CString` copy is ever made.
pub struct PinSecret {
    nul_terminated: SecretBytes,
}

impl PinSecret {
    /// Validates and takes ownership of `input`. Rejected input is wiped before returning.
    pub fn from_utf8_bytes(input: Vec<u8>) -> Result<Self, PinInputError> {
        let input = SecretBytes::new(input);
        let bytes = input.expose();
        if bytes.is_empty() {
            return Err(PinInputError::Empty);
        }
        if bytes.contains(&0) {
            return Err(PinInputError::EmbeddedNul);
        }
        if bytes.len() > MAX_PIN_BYTES {
            return Err(PinInputError::TooLong);
        }
        if bytes.len() < MIN_PIN_BYTES {
            return Err(PinInputError::TooShort);
        }
        if std::str::from_utf8(bytes).is_err() {
            return Err(PinInputError::NotUtf8);
        }

        // Exact capacity up front: pushing the NUL must not reallocate and leave a stale copy.
        let mut terminated = Vec::with_capacity(bytes.len() + 1);
        terminated.extend_from_slice(bytes);
        terminated.push(0);
        Ok(Self {
            nul_terminated: SecretBytes::new(terminated),
        })
        // `input` is wiped here.
    }

    /// Borrow as a C string for exactly one native call. The pointer is valid while `self` lives.
    pub fn as_c_str(&self) -> &CStr {
        // Construction guarantees exactly one NUL, at the end.
        CStr::from_bytes_with_nul(self.nul_terminated.expose()).unwrap_or(c"")
    }

    pub fn as_ptr(&self) -> *const c_char {
        self.as_c_str().as_ptr()
    }
}

impl fmt::Debug for PinSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinSecret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof that the secret types cannot be cloned or copied: the call below is
    // ambiguous (and fails to compile) as soon as either type implements `Clone`. This is the
    // `assert_not_impl_any!` technique without the dependency.
    trait AmbiguousIfClone<Marker> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    struct CloneMarker;
    impl<T: Clone> AmbiguousIfClone<CloneMarker> for T {}

    trait AmbiguousIfDisplay<Marker> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfDisplay<()> for T {}
    struct DisplayMarker;
    impl<T: ?Sized + fmt::Display> AmbiguousIfDisplay<DisplayMarker> for T {}

    #[test]
    fn secret_types_are_neither_clone_nor_display() {
        <PinSecret as AmbiguousIfClone<_>>::check();
        <SecretBytes as AmbiguousIfClone<_>>::check();
        <PinSecret as AmbiguousIfDisplay<_>>::check();
        <SecretBytes as AmbiguousIfDisplay<_>>::check();
    }

    // Synthetic, obviously-fake values only. No test anywhere contains a real PIN or token.
    const FAKE_PIN: &[u8] = b"not-a-real-pin-7f3a";

    #[test]
    fn debug_output_never_contains_secret_bytes() -> Result<(), PinInputError> {
        let pin = PinSecret::from_utf8_bytes(FAKE_PIN.to_vec())?;
        let rendered = format!("{pin:?} {:?}", SecretBytes::new(FAKE_PIN.to_vec()));
        assert_eq!(rendered, "PinSecret(<redacted>) SecretBytes(<redacted>)");
        assert!(!rendered.contains("not-a-real"));
        // Pretty-printing goes through the same impl.
        assert!(!format!("{pin:#?}").contains("not-a-real"));
        Ok(())
    }

    #[test]
    fn pin_validation_rejects_nul_length_and_utf8_before_any_c_string_exists() {
        assert_eq!(
            PinSecret::from_utf8_bytes(Vec::new()).err(),
            Some(PinInputError::Empty)
        );
        assert_eq!(
            PinSecret::from_utf8_bytes(vec![b'1', b'2', 0, b'3', b'4']).err(),
            Some(PinInputError::EmbeddedNul)
        );
        assert_eq!(
            PinSecret::from_utf8_bytes(b"\0abcd".to_vec()).err(),
            Some(PinInputError::EmbeddedNul)
        );
        assert_eq!(
            PinSecret::from_utf8_bytes(b"123".to_vec()).err(),
            Some(PinInputError::TooShort)
        );
        assert_eq!(
            PinSecret::from_utf8_bytes(vec![b'x'; MAX_PIN_BYTES + 1]).err(),
            Some(PinInputError::TooLong)
        );
        assert_eq!(
            PinSecret::from_utf8_bytes(vec![0xff, 0xfe, 0xfd, 0xfc]).err(),
            Some(PinInputError::NotUtf8)
        );
        assert!(PinSecret::from_utf8_bytes(vec![b'x'; MAX_PIN_BYTES]).is_ok());
    }

    #[test]
    fn pin_error_messages_carry_no_input() {
        let error = PinSecret::from_utf8_bytes(b"ab\0cdefg".to_vec()).err();
        let rendered = format!(
            "{error:?} {}",
            error.map(|e| e.to_string()).unwrap_or_default()
        );
        assert!(!rendered.contains("cdefg"));
    }

    #[test]
    fn c_string_view_is_exactly_the_pin() -> Result<(), PinInputError> {
        let pin = PinSecret::from_utf8_bytes(FAKE_PIN.to_vec())?;
        assert_eq!(pin.as_c_str().to_bytes(), FAKE_PIN);
        Ok(())
    }

    #[test]
    fn wipe_clears_the_whole_allocation() {
        let mut secret = SecretBytes::new(FAKE_PIN.to_vec());
        let capacity = secret.bytes.capacity();
        let pointer = secret.bytes.as_ptr();
        secret.wipe();
        // The allocation is still owned by `secret` (clear keeps capacity), so reading it is sound.
        // SAFETY: pointer/capacity describe the live allocation of `secret.bytes`.
        let after = unsafe { std::slice::from_raw_parts(pointer, capacity) };
        assert!(after.iter().all(|byte| *byte == 0));
        assert!(secret.is_empty());
    }
}
