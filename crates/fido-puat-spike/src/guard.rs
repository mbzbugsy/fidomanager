//! Explicit acquisition, generation binding, and guaranteed cleanup of the attached PUAT.
//!
//! libfido2 keeps an application-acquired token *inside* the `fido_dev_t` (`dev->puat`) and uses it
//! in preference to any PIN for every token-aware call until something clears it. It is not
//! cleared by `fido_dev_close()`, by a failed later call, or by the authenticator rejecting it; it
//! is cleared only by `fido_dev_set_puat(dev, NULL, 0)`, by the next `fido_dev_get_puat()` (which
//! resets it first), or by `fido_dev_free()`. All three wipe the bytes (`freezero`).
//!
//! The types here make that ambient state explicit:
//! - a [`DeviceSession`] wraps exactly one native object for exactly one [`DeviceGeneration`] and
//!   refuses an object that already carries a token;
//! - [`DeviceSession::acquire`] arms a [`PuatGuard`] *before* the native call, so every exit path
//!   (error, early return, panic) clears the token;
//! - the [`AuthorizationGrant`] it returns is checked against the guard's generation on every use.

use std::fmt;

use fido_core::DeviceGeneration;

use crate::contract::{AcquisitionPlan, AuthorizationGrant, VerificationMethod};
use crate::retry::{AcquisitionFailure, classify_acquisition_error};
use crate::secret::PinSecret;

/// The minimal native surface the guard needs. Implemented over libfido2 by the `native` module
/// and by a deterministic fake in tests. No method exposes token bytes.
pub trait PuatDevice {
    /// Length of the token currently attached to the native object; zero means none.
    fn attached_token_len(&self) -> usize;

    /// `fido_dev_get_puat()`: on success the token is attached to the native object.
    fn acquire_token(
        &mut self,
        plan: &AcquisitionPlan,
        pin: Option<&PinSecret>,
        timeout_ms: i32,
    ) -> Result<(), i32>;

    /// `fido_dev_set_puat(dev, NULL, 0)`.
    fn clear_token(&mut self) -> Result<(), i32>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// The native object already carries a token. A fresh `fido_dev_t` never does, so this means
    /// an object is being reused across sessions/generations.
    TokenOnFreshObject,
    /// Reconnect must produce a strictly newer generation.
    GenerationNotNewer,
}

// Deliberately not `Copy`: matching on an acquisition result then moves the whole value, so
// the guard inside an `Ok` can never outlive the match by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireError {
    /// A token was already attached when acquisition started. It has been cleared; ambient token
    /// presence is never treated as authorization.
    AmbientTokenPresent,
    /// PIN method without a PIN, or a PIN supplied for built-in UV (libfido2 would silently take
    /// the PIN path).
    MethodMismatch,
    /// The native call failed. The guard has already cleared any partial state.
    Native {
        failure: AcquisitionFailure,
        code: i32,
    },
    /// libfido2 reported success but no token is attached.
    NoTokenAttached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// The grant belongs to a different device generation (or a different native object).
    GenerationMismatch {
        grant: DeviceGeneration,
        guard: DeviceGeneration,
    },
    /// The guard no longer holds a token (already released).
    NotAuthorized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupError {
    /// `fido_dev_set_puat` reported failure.
    ClearFailed { code: i32 },
    /// The clear call returned but a token is still attached.
    TokenStillAttached { len: usize },
}

macro_rules! debug_display_error {
    ($($name:ident),*) => {$(
        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(self, formatter)
            }
        }

        impl std::error::Error for $name {}
    )*};
}

debug_display_error!(SessionError, AcquireError, GuardError, CleanupError);

/// One native device object bound to one device generation.
pub struct DeviceSession<D: PuatDevice> {
    device: D,
    generation: DeviceGeneration,
}

impl<D: PuatDevice> DeviceSession<D> {
    /// Wrap a freshly created native object. Refuses an object that already holds a token.
    pub fn open(device: D, generation: DeviceGeneration) -> Result<Self, SessionError> {
        if device.attached_token_len() != 0 {
            return Err(SessionError::TokenOnFreshObject);
        }
        Ok(Self { device, generation })
    }

    pub const fn generation(&self) -> DeviceGeneration {
        self.generation
    }

    /// Replace the native object after a disconnect. Consumes the old session, so its object (and
    /// any authorization state it could still hold) is dropped/freed, never reused.
    pub fn reconnect(
        self,
        device: D,
        generation: DeviceGeneration,
    ) -> Result<Self, (Self, SessionError)> {
        if generation.0 <= self.generation.0 {
            return Err((self, SessionError::GenerationNotNewer));
        }
        let fresh = match Self::open(device, generation) {
            Ok(fresh) => fresh,
            Err(error) => return Err((self, error)),
        };
        drop(self);
        Ok(fresh)
    }

    /// Acquire authorization as one explicit step. The returned guard clears the token when it is
    /// released or dropped, on every path.
    pub fn acquire(
        &mut self,
        plan: &AcquisitionPlan,
        pin: Option<&PinSecret>,
        timeout_ms: i32,
    ) -> Result<(PuatGuard<'_, D>, AuthorizationGrant), AcquireError> {
        match (plan.method(), pin) {
            (VerificationMethod::Pin, Some(_)) | (VerificationMethod::BuiltInUv, None) => {}
            _ => return Err(AcquireError::MethodMismatch),
        }

        let generation = self.generation;
        let ambient = self.device.attached_token_len() != 0;
        // Arm the guard first: if the native call errors, returns early, or unwinds, Drop clears.
        let guard = PuatGuard {
            device: &mut self.device,
            generation,
            released: false,
        };
        if ambient {
            return Err(AcquireError::AmbientTokenPresent);
        }

        if let Err(code) = guard.device.acquire_token(plan, pin, timeout_ms) {
            return Err(AcquireError::Native {
                failure: classify_acquisition_error(code),
                code,
            });
        }
        if guard.device.attached_token_len() == 0 {
            return Err(AcquireError::NoTokenAttached);
        }

        let grant = AuthorizationGrant::new(plan.kind(), plan.method(), generation);
        Ok((guard, grant))
    }

    /// Access for calls that must run *without* any token (GetInfo, retry counts). Refuses while a
    /// token is attached so a "no-authorization" call cannot silently use one.
    pub fn without_token<R>(&mut self, operation: impl FnOnce(&mut D) -> R) -> Option<R> {
        if self.device.attached_token_len() != 0 {
            return None;
        }
        Some(operation(&mut self.device))
    }

    /// Spike-only: direct access for deliberately-unsafe negative-control experiments in the
    /// hardware harness (for example reopening the same object). Never part of the M2 contract.
    pub fn device_for_experiment(&mut self) -> &mut D {
        &mut self.device
    }
}

/// Holds the attached token for one controlled transaction and clears it on every exit path.
pub struct PuatGuard<'s, D: PuatDevice> {
    device: &'s mut D,
    generation: DeviceGeneration,
    released: bool,
}

impl<D: PuatDevice> PuatGuard<'_, D> {
    pub const fn generation(&self) -> DeviceGeneration {
        self.generation
    }

    /// Run one token-authorized native call. The grant must come from this generation.
    pub fn use_token<R>(
        &mut self,
        grant: &AuthorizationGrant,
        operation: impl FnOnce(&mut D) -> R,
    ) -> Result<R, GuardError> {
        if grant.generation() != self.generation {
            return Err(GuardError::GenerationMismatch {
                grant: grant.generation(),
                guard: self.generation,
            });
        }
        if self.released || self.device.attached_token_len() == 0 {
            return Err(GuardError::NotAuthorized);
        }
        Ok(operation(self.device))
    }

    /// Spike-only access for negative-control experiments (close/reopen, replug) that must keep
    /// the token attached while doing something the contract forbids.
    pub fn device_for_experiment(&mut self) -> &mut D {
        self.device
    }

    /// Clear and verify. Prefer this over relying on Drop so a failed clear is reported.
    pub fn release(mut self) -> Result<(), CleanupError> {
        self.released = true;
        clear_and_verify(self.device)
    }
}

impl<D: PuatDevice> Drop for PuatGuard<'_, D> {
    fn drop(&mut self) {
        if !self.released {
            // Best effort on error/early-return/unwind paths. Cannot report; must not panic.
            let _ = clear_and_verify(self.device);
        }
    }
}

fn clear_and_verify<D: PuatDevice>(device: &mut D) -> Result<(), CleanupError> {
    if let Err(code) = device.clear_token() {
        return Err(CleanupError::ClearFailed { code });
    }
    match device.attached_token_len() {
        0 => Ok(()),
        len => Err(CleanupError::TokenStillAttached { len }),
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Arc, Mutex, MutexGuard};

    use super::*;
    use crate::contract::{
        GrantKind, RequestedAuthorization, TokenCapabilities, VerificationMethod, plan,
    };
    use crate::retry::RetryEffect;
    use crate::retry::codes::{FIDO_ERR_PIN_INVALID, FIDO_ERR_RX};

    /// Mirrors the libfido2 1.17.0 semantics the guard relies on: a token lives on the object until
    /// cleared, a failed acquisition leaves it empty (`fido_dev_get_puat` resets first), and the
    /// object never clears it by itself.
    #[derive(Default)]
    struct FakeState {
        attached: usize,
        acquire_calls: usize,
        clear_calls: usize,
        next_acquire: Option<i32>,
        clear_is_noop: bool,
        last_permissions: Option<u32>,
    }

    #[derive(Clone, Default)]
    struct FakeDevice(Arc<Mutex<FakeState>>);

    impl FakeDevice {
        fn state(&self) -> MutexGuard<'_, FakeState> {
            match self.0.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            }
        }
        fn with_ambient_token() -> Self {
            let device = Self::default();
            device.state().attached = 32;
            device
        }
        fn failing_with(code: i32) -> Self {
            let device = Self::default();
            device.state().next_acquire = Some(code);
            device
        }
    }

    impl PuatDevice for FakeDevice {
        fn attached_token_len(&self) -> usize {
            self.state().attached
        }
        fn acquire_token(
            &mut self,
            plan: &AcquisitionPlan,
            _pin: Option<&PinSecret>,
            _timeout_ms: i32,
        ) -> Result<(), i32> {
            let mut state = self.state();
            state.acquire_calls += 1;
            state.attached = 0;
            state.last_permissions = Some(plan.permissions());
            match state.next_acquire.take() {
                Some(code) => Err(code),
                None => {
                    state.attached = 32;
                    Ok(())
                }
            }
        }
        fn clear_token(&mut self) -> Result<(), i32> {
            let mut state = self.state();
            state.clear_calls += 1;
            if !state.clear_is_noop {
                state.attached = 0;
            }
            Ok(())
        }
    }

    fn read_only_plan() -> Result<AcquisitionPlan, Box<dyn std::error::Error>> {
        let capabilities = TokenCapabilities::from_options([
            ("clientPin", true),
            ("pinUvAuthToken", true),
            ("credMgmt", true),
            ("perCredMgmtRO", true),
        ]);
        Ok(plan(
            &capabilities,
            &RequestedAuthorization::CredManReadOnly,
            VerificationMethod::Pin,
        )?)
    }

    fn fake_pin() -> Result<PinSecret, Box<dyn std::error::Error>> {
        Ok(PinSecret::from_utf8_bytes(b"fake-pin-0000".to_vec())?)
    }

    fn session(
        device: &FakeDevice,
        generation: u64,
    ) -> Result<DeviceSession<FakeDevice>, SessionError> {
        DeviceSession::open(device.clone(), DeviceGeneration(generation))
    }

    #[test]
    fn cleanup_on_success() -> Result<(), Box<dyn std::error::Error>> {
        let device = FakeDevice::default();
        let mut session = session(&device, 1)?;
        let pin = fake_pin()?;
        let (mut guard, grant) = session.acquire(&read_only_plan()?, Some(&pin), 1_000)?;
        assert_eq!(grant.kind(), GrantKind::ScopedCredManReadOnly);
        assert_eq!(device.state().last_permissions, Some(0x40));
        assert_eq!(guard.use_token(&grant, |d| d.attached_token_len())?, 32);
        guard.release()?;
        assert_eq!(device.attached_token_len(), 0);
        assert_eq!(device.state().clear_calls, 1);
        Ok(())
    }

    #[test]
    fn cleanup_on_acquisition_error_and_failure_is_classified()
    -> Result<(), Box<dyn std::error::Error>> {
        for (code, effect) in [
            (FIDO_ERR_PIN_INVALID, RetryEffect::Consumed),
            (FIDO_ERR_RX, RetryEffect::Unknown),
        ] {
            let device = FakeDevice::failing_with(code);
            let mut session = session(&device, 1)?;
            let pin = fake_pin()?;
            let outcome = session.acquire(&read_only_plan()?, Some(&pin), 1_000);
            match outcome {
                Err(AcquireError::Native { failure, code: got }) => {
                    assert_eq!(got, code);
                    assert_eq!(failure.retry_effect(), effect);
                }
                other => panic!("expected a native failure, got {:?}", other.map(|(_, g)| g)),
            }
            assert_eq!(device.attached_token_len(), 0);
            assert_eq!(
                device.state().clear_calls,
                1,
                "guard must clear even on failure"
            );
            assert_eq!(
                device.state().acquire_calls,
                1,
                "never retried automatically"
            );
        }
        Ok(())
    }

    #[test]
    fn cleanup_on_early_return() -> Result<(), Box<dyn std::error::Error>> {
        fn transaction(session: &mut DeviceSession<FakeDevice>) -> Result<(), &'static str> {
            let pin = fake_pin().map_err(|_| "pin")?;
            let plan = read_only_plan().map_err(|_| "plan")?;
            let (_guard, _grant) = session
                .acquire(&plan, Some(&pin), 1_000)
                .map_err(|_| "acquire")?;
            Err("enumeration failed half way")?;
            Ok(())
        }
        let device = FakeDevice::default();
        let mut session = session(&device, 1)?;
        assert!(transaction(&mut session).is_err());
        assert_eq!(device.attached_token_len(), 0);
        assert_eq!(device.state().clear_calls, 1);
        Ok(())
    }

    #[test]
    fn cleanup_on_panic_unwind() -> Result<(), Box<dyn std::error::Error>> {
        let device = FakeDevice::default();
        let mut session = session(&device, 1)?;
        let pin = fake_pin()?;
        let plan = read_only_plan()?;
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            let acquired = session.acquire(&plan, Some(&pin), 1_000);
            assert!(acquired.is_ok());
            // A panic message must never carry secrets; this one carries none.
            panic!("simulated parser panic mid-transaction");
        }));
        assert!(unwound.is_err());
        assert_eq!(device.attached_token_len(), 0);
        assert_eq!(device.state().clear_calls, 1);
        Ok(())
    }

    #[test]
    fn ambient_token_is_refused_and_cleared_never_used() -> Result<(), Box<dyn std::error::Error>> {
        let device = FakeDevice::default();
        let mut session = session(&device, 1)?;
        // Something attached a token behind the contract's back (e.g. a reused object).
        device.state().attached = 32;
        let pin = fake_pin()?;
        let outcome = session.acquire(&read_only_plan()?, Some(&pin), 1_000);
        assert_eq!(outcome.err(), Some(AcquireError::AmbientTokenPresent));
        assert_eq!(device.state().acquire_calls, 0);
        assert_eq!(device.attached_token_len(), 0);
        // And calls meant to run without authorization refuse while a token is attached.
        device.state().attached = 32;
        assert!(session.without_token(|_| ()).is_none());
        Ok(())
    }

    #[test]
    fn no_authorization_state_survives_fresh_native_object_construction()
    -> Result<(), Box<dyn std::error::Error>> {
        // A reused object that still carries a token is refused as "fresh".
        assert_eq!(
            DeviceSession::open(FakeDevice::with_ambient_token(), DeviceGeneration(1)).err(),
            Some(SessionError::TokenOnFreshObject)
        );

        let old = FakeDevice::default();
        let mut first = session(&old, 1)?;
        let pin = fake_pin()?;
        let plan = read_only_plan()?;
        let (guard, grant_gen1) = first.acquire(&plan, Some(&pin), 1_000)?;
        guard.release()?;

        let replacement = FakeDevice::default();
        let mut second = match first.reconnect(replacement.clone(), DeviceGeneration(2)) {
            Ok(session) => session,
            Err((_, error)) => panic!("reconnect failed: {error:?}"),
        };
        assert_eq!(second.generation(), DeviceGeneration(2));
        assert_eq!(replacement.attached_token_len(), 0);

        // Authorization from generation 1 cannot be used in a generation-2 transaction.
        let (mut guard, _grant_gen2) = second.acquire(&plan, Some(&pin), 1_000)?;
        assert_eq!(
            guard.use_token(&grant_gen1, |_| ()).err(),
            Some(GuardError::GenerationMismatch {
                grant: DeviceGeneration(1),
                guard: DeviceGeneration(2)
            })
        );
        guard.release()?;
        Ok(())
    }

    #[test]
    fn reconnect_requires_a_newer_generation() -> Result<(), Box<dyn std::error::Error>> {
        let first = session(&FakeDevice::default(), 5)?;
        match first.reconnect(FakeDevice::default(), DeviceGeneration(5)) {
            Err((kept, SessionError::GenerationNotNewer)) => {
                assert_eq!(kept.generation(), DeviceGeneration(5))
            }
            _ => panic!("same generation must be refused"),
        }
        Ok(())
    }

    #[test]
    fn release_reports_a_clear_that_did_not_clear() -> Result<(), Box<dyn std::error::Error>> {
        let device = FakeDevice::default();
        let mut session = session(&device, 1)?;
        let pin = fake_pin()?;
        let (guard, _grant) = session.acquire(&read_only_plan()?, Some(&pin), 1_000)?;
        device.state().clear_is_noop = true;
        assert_eq!(
            guard.release().err(),
            Some(CleanupError::TokenStillAttached { len: 32 })
        );
        Ok(())
    }

    #[test]
    fn method_and_pin_must_agree() -> Result<(), Box<dyn std::error::Error>> {
        let device = FakeDevice::default();
        let mut session = session(&device, 1)?;
        let outcome = session.acquire(&read_only_plan()?, None, 1_000);
        assert_eq!(outcome.err(), Some(AcquireError::MethodMismatch));
        assert_eq!(device.state().acquire_calls, 0);
        Ok(())
    }

    #[test]
    fn released_guard_cannot_be_used_and_drop_does_not_double_clear()
    -> Result<(), Box<dyn std::error::Error>> {
        let device = FakeDevice::default();
        let mut session = session(&device, 1)?;
        let pin = fake_pin()?;
        {
            let (guard, _grant) = session.acquire(&read_only_plan()?, Some(&pin), 1_000)?;
            guard.release()?;
        }
        assert_eq!(device.state().clear_calls, 1);
        Ok(())
    }
}
