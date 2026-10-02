//! Prototype authorization contract: what may be asked of libfido2, decided before it is asked.
//!
//! The central source finding (see `docs/spikes/M1.5-libfido2-puat-fit.md`) is that
//! `fido_dev_get_puat()` in libfido2 1.17.0 *silently ignores* the requested permissions and RP ID
//! when the authenticator does not advertise `pinUvAuthToken`: it falls back to the CTAP 2.0
//! `getPinToken` subcommand and returns `FIDO_OK` with an unscoped token. libfido2 therefore cannot
//! be trusted to refuse a scoped request it cannot honour. This module makes that decision instead,
//! from GetInfo evidence, so a request for read-only authorization can never come back as legacy
//! unscoped authorization.

use std::fmt;

use fido_core::DeviceGeneration;

/// libfido2 `FIDO_PUAT_CREDMAN` (`fido/param.h`): CTAP 2.1 `cm` permission.
pub const FIDO_PUAT_CREDMAN: u32 = 0x04;
/// libfido2 `FIDO_PUAT_CREDMAN_RO` (`fido/param.h`): CTAP 2.2 persistent read-only `pcmr`.
pub const FIDO_PUAT_CREDMAN_RO: u32 = 0x40;

/// Longest RP ID the spike will pass to libfido2 (CTAP limits are authenticator-specific; this is
/// a host-side bound, not a protocol claim).
pub const MAX_RP_ID_BYTES: usize = 253;

/// Tri-state GetInfo option: absent means "not supported", present means supported and the value
/// is the current configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionState {
    Absent,
    Present { enabled: bool },
}

impl OptionState {
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Present { enabled: true })
    }
}

/// The GetInfo evidence this contract reads. Built from the option list as reported; unknown
/// options are ignored here (and preserved elsewhere for diagnostics), never interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenCapabilities {
    /// `clientPin`: absent = no PIN support, false = supported but no PIN set.
    pub client_pin: OptionState,
    /// `uv`: built-in user verification (absent = none, false = supported but not configured).
    pub builtin_uv: OptionState,
    /// `pinUvAuthToken`: CTAP 2.1 permission-scoped tokens. libfido2 keys its 2.0/2.1 switch off
    /// exactly this option (`FIDO_DEV_TOKEN_PERMS`).
    pub permission_tokens: bool,
    /// `credMgmt` (CTAP 2.1) or `credentialMgmtPreview` (2.1-pre).
    pub cred_mgmt: bool,
    /// `perCredMgmtRO` (CTAP 2.2): the authenticator advertises the persistent read-only `pcmr`
    /// permission. libfido2 does not check this before sending `FIDO_PUAT_CREDMAN_RO`.
    pub persistent_cred_mgmt_ro: bool,
}

impl TokenCapabilities {
    pub fn from_options<'a, I>(options: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, bool)>,
    {
        let mut capabilities = Self {
            client_pin: OptionState::Absent,
            builtin_uv: OptionState::Absent,
            permission_tokens: false,
            cred_mgmt: false,
            persistent_cred_mgmt_ro: false,
        };
        for (name, enabled) in options {
            match name {
                "clientPin" => capabilities.client_pin = OptionState::Present { enabled },
                "uv" => capabilities.builtin_uv = OptionState::Present { enabled },
                "pinUvAuthToken" => capabilities.permission_tokens |= enabled,
                "credMgmt" | "credentialMgmtPreview" => capabilities.cred_mgmt |= enabled,
                "perCredMgmtRO" => capabilities.persistent_cred_mgmt_ro |= enabled,
                _ => {}
            }
        }
        capabilities
    }
}

/// A validated relying-party ID for RP-scoped credential-management tokens.
#[derive(Clone, PartialEq, Eq)]
pub struct RpId {
    nul_terminated: Vec<u8>,
}

impl RpId {
    pub fn new(text: &str) -> Result<Self, PlanError> {
        let bytes = text.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_RP_ID_BYTES || bytes.contains(&0) {
            return Err(PlanError::InvalidRpId);
        }
        let mut nul_terminated = Vec::with_capacity(bytes.len() + 1);
        nul_terminated.extend_from_slice(bytes);
        nul_terminated.push(0);
        Ok(Self { nul_terminated })
    }

    pub fn as_c_str(&self) -> &std::ffi::CStr {
        std::ffi::CStr::from_bytes_with_nul(&self.nul_terminated).unwrap_or(c"")
    }
}

impl fmt::Debug for RpId {
    // RP IDs are account metadata: not secret, but kept out of logs by default.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RpId(<{} bytes>)", self.nul_terminated.len() - 1)
    }
}

/// What the application asks for. Each variant is a distinct authority; none is a fallback for
/// another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedAuthorization {
    /// Persistent read-only credential management (`pcmr`). Never RP-scoped (libfido2 documents
    /// the RP ID as ignored for this permission, but would still transmit one; we never pass it).
    CredManReadOnly,
    /// Full credential management (`cm`), optionally RP-scoped. Grants deletion/update authority
    /// at the authenticator; the application must still require its own permit for any mutation.
    CredMan { rp: Option<RpId> },
    /// CTAP 2.0 `getPinToken`: PIN-only, unscoped, all-powerful. Only ever planned when asked for
    /// by name *and* the authenticator has no permission-scoped tokens.
    LegacyUnscoped,
}

/// How the user authenticates to the authenticator for this acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMethod {
    Pin,
    BuiltInUv,
}

/// Why an acquisition was not planned. Planning happens before any native call; none of these
/// consumed a retry or touched the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    PinNotSupported,
    /// The authenticator supports a PIN but none is set. The application never sets one to make
    /// management available.
    PinNotSet,
    BuiltInUvUnavailable,
    CredentialManagementUnsupported,
    /// Read-only requires CTAP 2.1 permission tokens *and* advertised `perCredMgmtRO`.
    ReadOnlyUnavailable,
    /// Scoped `cm` is unavailable because the authenticator lacks permission tokens. Only an
    /// explicit, separately-reviewed `LegacyUnscoped` request can proceed.
    ScopedTokenUnavailable,
    /// `LegacyUnscoped` was requested from an authenticator that has scoped tokens; libfido2 would
    /// send a scoped request anyway, so the label would be false.
    LegacyNotApplicable,
    /// CTAP 2.0 `getPinToken` has no UV variant.
    LegacyIsPinOnly,
    InvalidRpId,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

impl std::error::Error for PlanError {}

/// What will actually be sent and what will actually be granted. Produced only by [`plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionPlan {
    kind: GrantKind,
    method: VerificationMethod,
    permissions: u32,
    rp: Option<RpId>,
}

impl AcquisitionPlan {
    pub const fn kind(&self) -> GrantKind {
        self.kind
    }
    pub const fn method(&self) -> VerificationMethod {
        self.method
    }
    pub const fn permissions(&self) -> u32 {
        self.permissions
    }
    pub fn rp(&self) -> Option<&RpId> {
        self.rp.as_ref()
    }
}

/// The authority a successful acquisition actually confers, as far as the host can know.
///
/// `ScopedCredManReadOnly` means *requested and accepted*: the authenticator issued a token for
/// `pcmr`. Whether it then refuses mutations with that token is a per-device empirical question;
/// this type does not claim enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    ScopedCredManReadOnly,
    ScopedCredMan { rp_scoped: bool },
    LegacyUnscoped,
}

impl GrantKind {
    /// True only for a permission-scoped read-only grant. Legacy is never read-only, whatever was
    /// requested and whatever the caller intends to do with it.
    pub const fn is_scoped_read_only(self) -> bool {
        matches!(self, Self::ScopedCredManReadOnly)
    }

    pub const fn is_permission_scoped(self) -> bool {
        !matches!(self, Self::LegacyUnscoped)
    }
}

/// Decide what to ask libfido2 for, from GetInfo evidence, without touching the device.
pub fn plan(
    capabilities: &TokenCapabilities,
    request: &RequestedAuthorization,
    method: VerificationMethod,
) -> Result<AcquisitionPlan, PlanError> {
    match method {
        VerificationMethod::Pin => match capabilities.client_pin {
            OptionState::Absent => return Err(PlanError::PinNotSupported),
            OptionState::Present { enabled: false } => return Err(PlanError::PinNotSet),
            OptionState::Present { enabled: true } => {}
        },
        VerificationMethod::BuiltInUv => {
            if matches!(request, RequestedAuthorization::LegacyUnscoped) {
                return Err(PlanError::LegacyIsPinOnly);
            }
            // libfido2 only reaches getPinUvAuthTokenUsingUvWithPermissions on the 2.1 path, and
            // only when `uv` is configured (`fido_dev_has_uv`).
            if !capabilities.permission_tokens || !capabilities.builtin_uv.is_enabled() {
                return Err(PlanError::BuiltInUvUnavailable);
            }
        }
    }

    if !capabilities.cred_mgmt {
        return Err(PlanError::CredentialManagementUnsupported);
    }

    match request {
        RequestedAuthorization::CredManReadOnly => {
            if !capabilities.permission_tokens || !capabilities.persistent_cred_mgmt_ro {
                return Err(PlanError::ReadOnlyUnavailable);
            }
            Ok(AcquisitionPlan {
                kind: GrantKind::ScopedCredManReadOnly,
                method,
                permissions: FIDO_PUAT_CREDMAN_RO,
                rp: None,
            })
        }
        RequestedAuthorization::CredMan { rp } => {
            if !capabilities.permission_tokens {
                return Err(PlanError::ScopedTokenUnavailable);
            }
            Ok(AcquisitionPlan {
                kind: GrantKind::ScopedCredMan {
                    rp_scoped: rp.is_some(),
                },
                method,
                permissions: FIDO_PUAT_CREDMAN,
                rp: rp.clone(),
            })
        }
        RequestedAuthorization::LegacyUnscoped => {
            if capabilities.permission_tokens {
                return Err(PlanError::LegacyNotApplicable);
            }
            // libfido2 ignores `perm` on this path; pass `cm` so the call is deterministic and
            // never carries the read-only bit that could suggest a read-only grant.
            Ok(AcquisitionPlan {
                kind: GrantKind::LegacyUnscoped,
                method,
                permissions: FIDO_PUAT_CREDMAN,
                rp: None,
            })
        }
    }
}

/// Proof that an acquisition succeeded on one specific native device object.
///
/// Not `Clone`: one acquisition, one grant. It names the device generation it was obtained on, and
/// every use is checked against the session's current generation. It carries no token bytes (the
/// only host copy stays inside libfido2's `fido_dev_t` until the guard clears it) and it is not an
/// application permit: nothing in this crate converts a grant into approval for a mutation.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizationGrant {
    kind: GrantKind,
    method: VerificationMethod,
    generation: DeviceGeneration,
}

impl AuthorizationGrant {
    pub(crate) const fn new(
        kind: GrantKind,
        method: VerificationMethod,
        generation: DeviceGeneration,
    ) -> Self {
        Self {
            kind,
            method,
            generation,
        }
    }

    pub const fn kind(&self) -> GrantKind {
        self.kind
    }
    pub const fn method(&self) -> VerificationMethod {
        self.method
    }
    pub const fn generation(&self) -> DeviceGeneration {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(options: &[(&str, bool)]) -> TokenCapabilities {
        TokenCapabilities::from_options(options.iter().copied())
    }

    fn ctap22_with_ro() -> TokenCapabilities {
        caps(&[
            ("clientPin", true),
            ("pinUvAuthToken", true),
            ("credMgmt", true),
            ("perCredMgmtRO", true),
        ])
    }

    fn ctap21_without_ro() -> TokenCapabilities {
        caps(&[
            ("clientPin", true),
            ("pinUvAuthToken", true),
            ("credMgmt", true),
        ])
    }

    fn ctap20_preview() -> TokenCapabilities {
        caps(&[("clientPin", true), ("credentialMgmtPreview", true)])
    }

    #[test]
    fn modes_map_to_distinct_permissions_and_grants() -> Result<(), PlanError> {
        let ro = plan(
            &ctap22_with_ro(),
            &RequestedAuthorization::CredManReadOnly,
            VerificationMethod::Pin,
        )?;
        let cm = plan(
            &ctap22_with_ro(),
            &RequestedAuthorization::CredMan { rp: None },
            VerificationMethod::Pin,
        )?;
        let legacy = plan(
            &ctap20_preview(),
            &RequestedAuthorization::LegacyUnscoped,
            VerificationMethod::Pin,
        )?;

        assert_eq!(ro.permissions(), FIDO_PUAT_CREDMAN_RO);
        assert_eq!(ro.kind(), GrantKind::ScopedCredManReadOnly);
        assert!(ro.rp().is_none());
        assert_eq!(cm.permissions(), FIDO_PUAT_CREDMAN);
        assert_eq!(cm.kind(), GrantKind::ScopedCredMan { rp_scoped: false });
        assert_eq!(legacy.kind(), GrantKind::LegacyUnscoped);
        assert_ne!(
            legacy.permissions() & FIDO_PUAT_CREDMAN_RO,
            FIDO_PUAT_CREDMAN_RO
        );

        let kinds = [ro.kind(), cm.kind(), legacy.kind()];
        for (index, kind) in kinds.iter().enumerate() {
            for other in &kinds[index + 1..] {
                assert_ne!(kind, other);
            }
        }
        Ok(())
    }

    #[test]
    fn legacy_cannot_masquerade_as_scoped_read_only() {
        // The exact situation where libfido2 would return FIDO_OK with an unscoped token.
        for request in [
            RequestedAuthorization::CredManReadOnly,
            RequestedAuthorization::CredMan { rp: None },
        ] {
            let outcome = plan(&ctap20_preview(), &request, VerificationMethod::Pin);
            assert!(
                matches!(
                    outcome,
                    Err(PlanError::ReadOnlyUnavailable | PlanError::ScopedTokenUnavailable)
                ),
                "{request:?} must not be planned on a CTAP 2.0 authenticator: {outcome:?}"
            );
        }
        assert!(!GrantKind::LegacyUnscoped.is_scoped_read_only());
        assert!(!GrantKind::LegacyUnscoped.is_permission_scoped());
        assert!(!GrantKind::ScopedCredMan { rp_scoped: true }.is_scoped_read_only());
        assert!(GrantKind::ScopedCredManReadOnly.is_scoped_read_only());
    }

    #[test]
    fn read_only_requires_advertised_pcmr_not_just_ctap21() {
        assert_eq!(
            plan(
                &ctap21_without_ro(),
                &RequestedAuthorization::CredManReadOnly,
                VerificationMethod::Pin
            ),
            Err(PlanError::ReadOnlyUnavailable)
        );
    }

    #[test]
    fn legacy_is_refused_where_scoped_tokens_exist_and_is_pin_only() {
        assert_eq!(
            plan(
                &ctap22_with_ro(),
                &RequestedAuthorization::LegacyUnscoped,
                VerificationMethod::Pin
            ),
            Err(PlanError::LegacyNotApplicable)
        );
        assert_eq!(
            plan(
                &ctap20_preview(),
                &RequestedAuthorization::LegacyUnscoped,
                VerificationMethod::BuiltInUv
            ),
            Err(PlanError::LegacyIsPinOnly)
        );
    }

    #[test]
    fn pin_state_is_respected_and_never_assumed() {
        let no_pin_set = caps(&[
            ("clientPin", false),
            ("pinUvAuthToken", true),
            ("credMgmt", true),
        ]);
        let no_pin_support = caps(&[("pinUvAuthToken", true), ("credMgmt", true)]);
        let request = RequestedAuthorization::CredMan { rp: None };
        assert_eq!(
            plan(&no_pin_set, &request, VerificationMethod::Pin),
            Err(PlanError::PinNotSet)
        );
        assert_eq!(
            plan(&no_pin_support, &request, VerificationMethod::Pin),
            Err(PlanError::PinNotSupported)
        );
    }

    #[test]
    fn built_in_uv_needs_configured_uv_and_scoped_tokens() -> Result<(), PlanError> {
        let request = RequestedAuthorization::CredMan { rp: None };
        let uv_unconfigured = caps(&[("uv", false), ("pinUvAuthToken", true), ("credMgmt", true)]);
        let uv_without_tokens = caps(&[("uv", true), ("credMgmt", true)]);
        let uv_ready = caps(&[("uv", true), ("pinUvAuthToken", true), ("credMgmt", true)]);
        assert_eq!(
            plan(&uv_unconfigured, &request, VerificationMethod::BuiltInUv),
            Err(PlanError::BuiltInUvUnavailable)
        );
        assert_eq!(
            plan(&uv_without_tokens, &request, VerificationMethod::BuiltInUv),
            Err(PlanError::BuiltInUvUnavailable)
        );
        // UV needs no clientPin at all.
        let planned = plan(&uv_ready, &request, VerificationMethod::BuiltInUv)?;
        assert_eq!(planned.method(), VerificationMethod::BuiltInUv);
        Ok(())
    }

    #[test]
    fn rp_scoping_is_carried_only_by_cm() -> Result<(), PlanError> {
        let rp = RpId::new("example.invalid")?;
        let planned = plan(
            &ctap22_with_ro(),
            &RequestedAuthorization::CredMan {
                rp: Some(rp.clone()),
            },
            VerificationMethod::Pin,
        )?;
        assert_eq!(planned.kind(), GrantKind::ScopedCredMan { rp_scoped: true });
        assert_eq!(planned.rp(), Some(&rp));
        assert_eq!(
            planned.rp().map(|r| r.as_c_str().to_bytes()),
            Some(&b"example.invalid"[..])
        );
        Ok(())
    }

    #[test]
    fn rp_id_rejects_nul_empty_and_oversized_and_redacts_debug() {
        assert_eq!(RpId::new("").err(), Some(PlanError::InvalidRpId));
        assert_eq!(RpId::new("a\0b").err(), Some(PlanError::InvalidRpId));
        assert_eq!(
            RpId::new(&"a".repeat(MAX_RP_ID_BYTES + 1)).err(),
            Some(PlanError::InvalidRpId)
        );
        let rendered = format!("{:?}", RpId::new("secret-bank.invalid"));
        assert!(!rendered.contains("secret-bank"));
    }

    #[test]
    fn credential_management_must_be_advertised() {
        let none = caps(&[("clientPin", true), ("pinUvAuthToken", true)]);
        assert_eq!(
            plan(
                &none,
                &RequestedAuthorization::CredMan { rp: None },
                VerificationMethod::Pin
            ),
            Err(PlanError::CredentialManagementUnsupported)
        );
    }

    #[test]
    fn options_reported_false_do_not_enable_anything() {
        let reported_false = caps(&[
            ("clientPin", true),
            ("pinUvAuthToken", false),
            ("credMgmt", false),
            ("perCredMgmtRO", false),
        ]);
        assert!(!reported_false.permission_tokens);
        assert!(!reported_false.cred_mgmt);
        assert!(!reported_false.persistent_cred_mgmt_ro);
    }
}
