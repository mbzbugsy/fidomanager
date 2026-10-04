//! Narrow copying helpers shared by native code and deterministic fixtures.
use fido_core::inventory::*;
use sha2::{Digest, Sha256};
use std::ffi::c_char;

pub use fido_core::inventory::InspectionError;
pub struct NativeInspection {
    pub evidence: fido_auth::AuthenticationEvidence,
    pub inventory: Option<OwnedInventory>,
    pub error: Option<InspectionError>,
}

/// The only M3 C-string scanner. The caller supplies a live native C-string allocation;
/// scan at most limit bytes (including the required terminator), then copy before free.
/// Missing terminator is rejected; no CStr::from_ptr/strlen or lossy decoding is used.
///
/// # Safety
/// Pointer must be NULL or readable up to the first NUL or the scan bound, whichever comes first.
pub unsafe fn copy_text(
    pointer: *const c_char,
    limit: usize,
) -> Result<Option<String>, InspectionError> {
    if pointer.is_null() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    for offset in 0..limit {
        // SAFETY: caller's allocation contract; the bound is checked before each read.
        let byte = unsafe { *pointer.cast::<u8>().add(offset) };
        if byte == 0 {
            return validate_text(&bytes, limit - 1).map(Some);
        }
        bytes.push(byte);
    }
    Err(InspectionError::BoundExceeded)
}
pub fn validate_text(bytes: &[u8], limit: usize) -> Result<String, InspectionError> {
    let text = std::str::from_utf8(bytes).map_err(|_| InspectionError::Malformed)?;
    if !safe_text(text, limit) {
        return Err(InspectionError::Malformed);
    }
    Ok(text.to_owned())
}
pub fn rp_from_copied(hash: [u8; 32], text: Result<Option<String>, InspectionError>) -> OwnedRp {
    let (verified_text, issue) = match text {
        Ok(Some(text)) if <[u8; 32]>::from(Sha256::digest(text.as_bytes())) == hash => {
            (Some(text), None)
        }
        Ok(Some(_)) => (None, Some(RpIssue::TextHashMismatch)),
        Ok(None) => (None, Some(RpIssue::TextUnavailable)),
        Err(_) => (None, Some(RpIssue::TextMalformed)),
    };
    OwnedRp {
        hash,
        verified_text,
        issue,
        credentials: Vec::new(),
    }
}
/// Copy pointer+length values only after validating length. Never retain a native borrow.
///
/// # Safety
/// For a valid nonzero bounded length, pointer must address that many readable bytes.
pub unsafe fn copy_id(
    pointer: *const u8,
    len: usize,
    limit: usize,
) -> Result<Vec<u8>, InspectionError> {
    if len == 0 || pointer.is_null() {
        return Err(InspectionError::Malformed);
    }
    if len > limit {
        return Err(InspectionError::BoundExceeded);
    }
    // SAFETY: validated pair and caller's live native allocation contract.
    Ok(unsafe { std::slice::from_raw_parts(pointer, len) }.to_vec())
}
pub fn check_aggregate(current: usize, next: usize) -> Result<usize, InspectionError> {
    current
        .checked_add(next)
        .filter(|n| *n <= MAX_CREDENTIALS)
        .ok_or(InspectionError::BoundExceeded)
}
/// Named native read sequence; never a generic CTAP interface or reusable token.
pub trait ReadOnlyInspection: fido_auth::NativeAuthorization {
    fn read_inventory(
        &mut self,
        deadline: crate::NativeDeadline,
    ) -> Result<OwnedInventory, InspectionError>;
    fn close_device(&mut self) -> bool;
}
pub fn finish_inspection(
    native: &mut impl ReadOnlyInspection,
    binding: fido_auth::AcquisitionBinding,
    kind: fido_auth::GrantKind,
    pin: fido_auth::PinSecret,
    deadline: crate::NativeDeadline,
) -> NativeInspection {
    use fido_auth::{AuthenticationEvidence, AuthenticationStatus as Status};
    let status = if native.attached() {
        Status::StaleAcquisition
    } else {
        native.acquire(kind, &pin)
    };
    drop(pin);
    let acquired = status == Status::Validated && native.valid_attached();
    let read = if acquired {
        native.read_inventory(deadline)
    } else {
        Err(InspectionError::NativeFailure)
    };
    let cleared = native.clear() && !native.attached();
    let closed = native.close_device();
    let status = if !cleared || !closed {
        Status::CleanupFailed
    } else if status == Status::Validated && (!acquired || read.is_err()) {
        Status::Uncertain
    } else {
        status
    };
    let (inventory, error) = if !cleared || !closed {
        (None, Some(InspectionError::CleanupFailed))
    } else if !acquired {
        (None, None)
    } else {
        match read {
            Ok(i) if i.within_bounds() => (Some(i), None),
            Ok(_) => (None, Some(InspectionError::Malformed)),
            Err(e) => (None, Some(e)),
        }
    };
    NativeInspection {
        evidence: AuthenticationEvidence {
            binding,
            kind,
            status,
            attached_puat_cleared: cleared && closed,
        },
        inventory,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rp_text_cases_and_owned_copies() {
        let hash: [u8; 32] = Sha256::digest(b"example.com").into();
        let mut source = b"example.com\0".to_vec();
        let text = unsafe { copy_text(source.as_ptr().cast(), MAX_RP_SCAN_BYTES) };
        source.fill(0);
        drop(source); // models native free; result owns all bytes
        let rp = rp_from_copied(hash, text);
        assert_eq!(rp.verified_text.as_deref(), Some("example.com"));
        assert_eq!(
            rp_from_copied(hash, Ok(None)).issue,
            Some(RpIssue::TextUnavailable)
        );
        assert_eq!(
            rp_from_copied(hash, Ok(Some("different.com".into()))).issue,
            Some(RpIssue::TextHashMismatch)
        );
        for bytes in [
            vec![b'x'; MAX_RP_TEXT_BYTES + 1],
            vec![255, 0],
            b"bad\n\0".to_vec(),
        ] {
            assert!(unsafe { copy_text(bytes.as_ptr().cast(), MAX_RP_SCAN_BYTES) }.is_err());
        }
        let bytes = vec![b'a'; MAX_USER_TEXT_BYTES + 1];
        assert!(validate_text(&bytes, MAX_USER_TEXT_BYTES).is_err());
        let mut id = vec![1; MAX_CREDENTIAL_ID_BYTES];
        let copy =
            unsafe { copy_id(id.as_ptr(), id.len(), MAX_CREDENTIAL_ID_BYTES) }.unwrap_or_default();
        id.fill(0);
        drop(id);
        assert_eq!(copy, vec![1; MAX_CREDENTIAL_ID_BYTES]);
        assert!(
            unsafe {
                copy_id(
                    std::ptr::dangling(),
                    MAX_CREDENTIAL_ID_BYTES + 1,
                    MAX_CREDENTIAL_ID_BYTES,
                )
            }
            .is_err()
        );
        assert!(check_aggregate(MAX_CREDENTIALS, 1).is_err());
    }
    struct Fake {
        steps: Vec<&'static str>,
        attached: bool,
        clear: bool,
        close: bool,
        fail_read: bool,
    }
    impl fido_auth::NativeAuthorization for Fake {
        fn acquire(
            &mut self,
            _: fido_auth::GrantKind,
            _: &fido_auth::PinSecret,
        ) -> fido_auth::AuthenticationStatus {
            self.steps.push("acquire");
            self.attached = true;
            fido_auth::AuthenticationStatus::Validated
        }
        fn attached(&self) -> bool {
            self.attached
        }
        fn valid_attached(&self) -> bool {
            self.attached
        }
        fn clear(&mut self) -> bool {
            self.steps.push("clear");
            if self.clear {
                self.attached = false;
            }
            self.clear
        }
    }
    impl ReadOnlyInspection for Fake {
        fn read_inventory(
            &mut self,
            _: crate::NativeDeadline,
        ) -> Result<OwnedInventory, InspectionError> {
            self.steps.push("read");
            assert!(self.attached);
            if self.fail_read {
                Err(InspectionError::Malformed)
            } else {
                Ok(OwnedInventory {
                    metadata_existing: 1,
                    rps: vec![OwnedRp {
                        hash: Sha256::digest(b"example.com").into(),
                        verified_text: Some("example.com".into()),
                        issue: None,
                        credentials: vec![OwnedCredential {
                            id: vec![1],
                            user_name: None,
                            display_name: None,
                        }],
                    }],
                })
            }
        }
        fn close_device(&mut self) -> bool {
            self.steps.push("close");
            self.close
        }
    }
    #[test]
    fn native_lifecycle_and_cleanup_poisoning() -> Result<(), Box<dyn std::error::Error>> {
        let binding = fido_auth::AcquisitionBinding {
            worker_generation: 1,
            device_generation: fido_core::DeviceGeneration(1),
            workflow_id: fido_core::WorkflowId::from_raw(1),
            prompt_instance_id: fido_core::PromptInstanceId::from_raw(1),
            acquisition_id: fido_auth::AcquisitionId(1),
        };
        for scenario in 0..5 {
            let mut fake = Fake {
                steps: Vec::new(),
                attached: scenario == 4,
                clear: scenario != 1,
                close: scenario != 2,
                fail_read: scenario == 3,
            };
            let pin = fido_auth::PinSecret::collect(|b| {
                b[..4].copy_from_slice(b"fake");
                Some(4)
            })
            .map_err(|_| "pin")?;
            let result = finish_inspection(
                &mut fake,
                binding,
                fido_auth::GrantKind::CredMan,
                pin,
                crate::NativeDeadline::after(std::time::Duration::from_secs(1)),
            );
            if scenario == 4 {
                assert_eq!(fake.steps, ["clear", "close"]);
            } else {
                assert_eq!(fake.steps, ["acquire", "read", "clear", "close"]);
            }
            assert_eq!(result.inventory.is_some(), scenario == 0);
            if scenario == 0 {
                assert_eq!(
                    result.inventory.ok_or("inventory")?.assess().total,
                    CredentialTotal::Exact(1)
                );
            }
            if scenario == 1 || scenario == 2 {
                assert_eq!(result.error, Some(InspectionError::CleanupFailed));
            }
        }
        Ok(())
    }
}
