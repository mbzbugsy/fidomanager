//! MAS.2: release-specific publisher authentication followed by per-spawn kernel cdhash binding.
//! Production main startup remains blocked independently by G1/G5 and the app's store gate.
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use crate::worker_authenticity::IdentityRejection;
use fido_platform::macos_code_signing::{
    Requirement, RunningCode, SIGNATURE_FLAG_RUNTIME, STATUS_KILL, STATUS_VALID,
    SigningInformation, StaticCode, StaticValidation,
};
use fido_platform::os_version::DynamicNetworkPolicy;

// Conservative initial policy; Apple re-signing semantics remain M5 BLOCKED. Do not expand
// the mask to make an unvalidated Apple output pass. Fixture-only code additionally admits ADHOC.
const SIGNATURE_KILL: u32 = 0x200;
#[cfg(test)]
const SIGNATURE_ADHOC: u32 = 0x2;

struct Policy {
    static_requirement: Requirement,
    static_text: String,
    identifier: String,
    team: Option<String>,
    network: DynamicNetworkPolicy,
    build_id: String,
    allowed_flags: u32,
}

pub(crate) struct MasWorkerVerifier(Arc<Policy>);

/// Non-cloneable and private-field token, produced only AFTER static authentication and fact
/// checks. It owns both C_s and a compiled requirement containing C_s. Arc only binds immutable
/// policy provenance; it never holds or caches a hash from another spawn.
pub(crate) struct MasSpawnToken {
    policy: Arc<Policy>,
    cdhash: [u8; 20],
    dynamic_requirement: Requirement,
}
#[cfg(test)]
impl MasSpawnToken {
    pub(crate) fn authenticated_cdhash(&self) -> &[u8; 20] {
        &self.cdhash
    }
}

impl MasWorkerVerifier {
    pub(crate) fn production() -> Result<Self, IdentityRejection> {
        use fido_platform::build_identity as build;
        if !crate::worker_authenticity::signing_flavors_match()
            || !build::MAS_SIGNING_FLAVOR
            || !cfg!(target_arch = "aarch64")
        {
            return Err(IdentityRejection::StartupRejected);
        }
        let commit = build::RELEASE_SOURCE_COMMIT.ok_or(IdentityRejection::StartupRejected)?;
        let identifier =
            crate::mas_worker_policy::release_identifier(build::RELEASE_VERSION, commit)
                .ok_or(IdentityRejection::StartupRejected)?;
        let text = crate::mas_worker_policy::publisher_requirement(build::RELEASE_VERSION, commit)
            .ok_or(IdentityRejection::StartupRejected)?;
        let team = crate::worker_authenticity::MACOS_RELEASE_TEAM_ID
            .filter(|team| crate::worker_authenticity::is_team_id(team))
            .ok_or(IdentityRejection::StartupRejected)?;
        let network = fido_platform::os_version::current()
            .and_then(DynamicNetworkPolicy::for_version)
            .map_err(|_| IdentityRejection::StartupRejected)?;
        Self::new(
            text,
            identifier,
            Some(team.to_owned()),
            build::WORKER_BUILD_ID.to_owned(),
            network,
            SIGNATURE_FLAG_RUNTIME | SIGNATURE_KILL,
        )
    }

    fn new(
        text: String,
        identifier: String,
        team: Option<String>,
        build_id: String,
        network: DynamicNetworkPolicy,
        allowed_flags: u32,
    ) -> Result<Self, IdentityRejection> {
        let static_requirement =
            Requirement::compile(&text).map_err(|_| IdentityRejection::StaticValidation)?;
        Ok(Self(Arc::new(Policy {
            static_requirement,
            static_text: text,
            identifier,
            team,
            network,
            build_id,
            allowed_flags,
        })))
    }

    // Compiles only in libtest, never a feature, renderer command or production override.
    #[cfg(test)]
    pub(crate) fn ad_hoc_for_test(
        identifier: String,
        network: DynamicNetworkPolicy,
    ) -> Result<Self, IdentityRejection> {
        let text = format!("identifier \"{identifier}\"");
        Self::new(
            text,
            identifier,
            None,
            fido_platform::build_identity::WORKER_BUILD_ID.to_owned(),
            network,
            SIGNATURE_FLAG_RUNTIME | SIGNATURE_KILL | SIGNATURE_ADHOC,
        )
    }

    pub(crate) fn build_id(&self) -> &str {
        &self.0.build_id
    }

    pub(crate) fn check_static(&self, path: &Path) -> Result<MasSpawnToken, IdentityRejection> {
        let mut file = fido_platform::file_once::open_regular_nofollow(path)
            .map_err(|_| IdentityRejection::StaticValidation)?;
        let mut header = [0; 32];
        file.read_exact(&mut header)
            .map_err(|_| IdentityRejection::Architecture)?;
        if !crate::mas_worker_policy::thin_arm64_header(&header) {
            return Err(IdentityRejection::Architecture);
        }
        let code = StaticCode::at_path(path).map_err(|_| IdentityRejection::StaticValidation)?;
        code.check_validity(StaticValidation::SingleFile, &self.0.static_requirement)
            .map_err(|_| IdentityRejection::StaticValidation)?;
        // Read C_s only from the statically authenticated object; a byte scan or unattested
        // signing-information lookup is NEVER the production authority for an expected hash.
        let info = code
            .signing_information()
            .map_err(|_| IdentityRejection::StaticValidation)?;
        self.check_facts(&info)?;
        let cdhash: [u8; 20] = info
            .cdhash
            .as_deref()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(IdentityRejection::Cdhash)?;
        let text = format!(
            "{} and cdhash H\"{}\"",
            self.0.static_text,
            crate::release_identity::lower_hex(&cdhash)
        );
        let dynamic_requirement =
            Requirement::compile(&text).map_err(|_| IdentityRejection::StaticValidation)?;
        Ok(MasSpawnToken {
            policy: Arc::clone(&self.0),
            cdhash,
            dynamic_requirement,
        })
    }

    pub(crate) fn check_running(
        &self,
        pid: u32,
        token: &MasSpawnToken,
    ) -> Result<(), IdentityRejection> {
        if !Arc::ptr_eq(&self.0, &token.policy) {
            return Err(IdentityRejection::DynamicValidation);
        }
        let child =
            RunningCode::child_process(pid).map_err(|_| IdentityRejection::DynamicValidation)?;
        child
            .check_validity(self.0.network, &token.dynamic_requirement)
            .map_err(|_| IdentityRejection::DynamicValidation)?;
        let info = child
            .signing_information()
            .map_err(|_| IdentityRejection::DynamicValidation)?;
        let status = info
            .dynamic_status
            .ok_or(IdentityRejection::DynamicStatus)?;
        if status & (STATUS_VALID | STATUS_KILL) != STATUS_VALID | STATUS_KILL {
            return Err(IdentityRejection::DynamicStatus);
        }
        self.check_facts(&info)?;
        if info.cdhash.as_deref() != Some(&token.cdhash[..]) {
            return Err(IdentityRejection::Cdhash);
        }
        Ok(())
    }

    fn check_facts(&self, info: &SigningInformation) -> Result<(), IdentityRejection> {
        if info.identifier.as_deref() != Some(self.0.identifier.as_str()) {
            return Err(IdentityRejection::Identifier);
        }
        if info.team_id != self.0.team {
            return Err(IdentityRejection::TeamId);
        }
        let flags = info.signature_flags.ok_or(IdentityRejection::Runtime)?;
        if flags & SIGNATURE_FLAG_RUNTIME == 0 || flags & !self.0.allowed_flags != 0 {
            return Err(IdentityRejection::Runtime);
        }
        if !info.exact_inherited_worker_entitlements {
            return Err(IdentityRejection::Entitlements);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_selection_never_falls_back_and_unprovisioned_builds_refuse() {
        use fido_platform::build_identity as build;
        if !crate::worker_authenticity::signing_flavors_match()
            || !build::MAS_SIGNING_FLAVOR
            || build::RELEASE_SOURCE_COMMIT.is_none()
            || !cfg!(target_arch = "aarch64")
        {
            assert!(matches!(
                MasWorkerVerifier::production(),
                Err(IdentityRejection::StartupRejected)
            ));
        } else {
            assert!(MasWorkerVerifier::production().is_ok()); // requirement compilation only
        }
    }
    #[test]
    fn code_directory_team_grants_and_unexpected_flags_are_load_bearing() {
        let verifier = MasWorkerVerifier::ad_hoc_for_test(
            "eu.fidomanager.synthetic".into(),
            DynamicNetworkPolicy::NoNetworkAccess,
        )
        .unwrap_or_else(|_| panic!("test requirement"));
        let mut info = SigningInformation {
            identifier: Some("eu.fidomanager.synthetic".into()),
            team_id: None,
            cdhash: Some(vec![1; 20]),
            signature_flags: Some(SIGNATURE_FLAG_RUNTIME | SIGNATURE_ADHOC),
            dynamic_status: Some(STATUS_VALID | STATUS_KILL),
            has_entitlements: true,
            exact_inherited_worker_entitlements: true,
        };
        assert_eq!(verifier.check_facts(&info), Ok(()));
        info.team_id = Some("OTHERTEAM0X".into());
        assert_eq!(verifier.check_facts(&info), Err(IdentityRejection::TeamId));
        info.team_id = None;
        info.exact_inherited_worker_entitlements = false;
        assert_eq!(
            verifier.check_facts(&info),
            Err(IdentityRejection::Entitlements)
        );
        info.exact_inherited_worker_entitlements = true;
        for flags in [
            SIGNATURE_ADHOC,
            SIGNATURE_FLAG_RUNTIME | SIGNATURE_ADHOC | 0x8,
        ] {
            info.signature_flags = Some(flags);
            assert_eq!(verifier.check_facts(&info), Err(IdentityRejection::Runtime));
        }
    }
}
