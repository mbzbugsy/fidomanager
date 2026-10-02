//! Process-environment preconditions for the PIN/PUAT harness.
//!
//! libfido2 1.17.0 `fido_init()` enables its protocol logging when *either* the `FIDO_DEBUG` flag
//! is passed *or* the `FIDO_DEBUG` environment variable is present, whatever its value (`dev.c`:
//! `getenv("FIDO_DEBUG") != NULL`). Passing flags `0` therefore does not guarantee logging is off,
//! and libfido2's debug log can include protocol payloads. The harness checks the variable *before*
//! `fido_init()` and before it starts any thread, and refuses to run. It does not remove the
//! variable: mutating the process environment is unsound once other threads may read it, and
//! silently scrubbing it would hide a misconfigured shell from the user.
//!
//! Scope of the guarantee: with `FIDO_DEBUG` absent at start-up, this process never enables
//! libfido2's logging through `fido_init()`. It does not cover a libfido2 build with logging forced
//! on at compile time, nor a variable set later by this process (it sets none).

use std::ffi::OsStr;
use std::fmt;

/// The variable libfido2's `fido_init()` consults.
pub const LIBFIDO2_DEBUG_VARIABLE: &str = "FIDO_DEBUG";

/// Refusal reason. Carries no environment contents, not even the variable's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibFido2DebugRequested;

impl fmt::Display for LibFido2DebugRequested {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "refusing to run: the {LIBFIDO2_DEBUG_VARIABLE} environment variable is set, which \
             would enable libfido2 protocol logging while a PIN or token is in use; unset it and \
             run again"
        )
    }
}

impl std::error::Error for LibFido2DebugRequested {}

/// Pure decision: `variable` is the variable's value if present. Presence alone (even an empty
/// value) is refused, matching libfido2's own `getenv() != NULL` test.
pub fn check_debug_variable(variable: Option<&OsStr>) -> Result<(), LibFido2DebugRequested> {
    match variable {
        None => Ok(()),
        Some(_) => Err(LibFido2DebugRequested),
    }
}

/// Reads the real process environment (presence only; the value is never inspected or kept).
pub fn require_no_libfido2_debug() -> Result<(), LibFido2DebugRequested> {
    check_debug_variable(std::env::var_os(LIBFIDO2_DEBUG_VARIABLE).as_deref())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn absent_is_accepted() {
        assert_eq!(check_debug_variable(None), Ok(()));
    }

    #[test]
    fn any_presence_is_refused_even_empty_or_falsey() {
        for value in ["", "0", "false", "1", "yes"] {
            assert_eq!(
                check_debug_variable(Some(OsStr::new(value))),
                Err(LibFido2DebugRequested),
                "value {value:?} must be refused: libfido2 tests presence only"
            );
        }
    }

    #[test]
    fn non_utf8_value_is_refused() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let value = OsString::from_vec(vec![0xff, 0xfe]);
            assert_eq!(
                check_debug_variable(Some(value.as_os_str())),
                Err(LibFido2DebugRequested)
            );
        }
    }

    #[test]
    fn the_refusal_message_does_not_echo_the_value() {
        let message = LibFido2DebugRequested.to_string();
        assert!(message.contains(LIBFIDO2_DEBUG_VARIABLE));
        assert_eq!(message, LibFido2DebugRequested.to_string());
        // The type has no field that could carry the value.
        assert_eq!(std::mem::size_of::<LibFido2DebugRequested>(), 0);
    }
}
