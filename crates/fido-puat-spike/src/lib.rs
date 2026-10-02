//! M1.5 libfido2 PUAT / credential-management fit spike. Never shipped.
//!
//! - [`contract`]: decides, from GetInfo evidence, what authorization to request and what a
//!   success actually grants (scoped read-only, scoped `cm`, or legacy unscoped), before libfido2 is
//!   asked.
//! - [`guard`]: explicit acquisition, generation binding, and cleanup of the token libfido2 keeps on
//!   the `fido_dev_t`, on every exit path.
//! - [`retry`]: what retry state can be known before a PIN is submitted and conservative
//!   interpretation of failures after.
//! - [`secret`]: zeroizing, non-printable PIN storage with NUL rejection before the C boundary.
//! - `native` (feature `native-puat`, libfido2 >= 1.17.0): the libfido2 implementation used by the
//!   manual hardware harness `fido-puat-spike`.
//!
//! Findings and the proposed M2 contract are in `docs/spikes/M1.5-libfido2-puat-fit.md`.

pub mod contract;
pub mod guard;
pub mod retry;
pub mod secret;

#[cfg(feature = "native-puat")]
pub mod native;
