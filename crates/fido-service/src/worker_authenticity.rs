//! Worker authenticity policy (ADR-017 §5.1–§5.7).
//!
//! The verification mode is fixed at **compile time**:
//!
//! * without the `macos-release-signing` feature: [`WorkerAuthenticity::UnsignedDevelopment`]
//!   (path/layout checks plus the `ChildHello.build_id` consistency check; M7.1 ad-hoc and local
//!   development builds);
//! * with it: release startup authentication (S1–S8, `release_identity`) runs once in
//!   `ProcessWorkerLauncher::beside_current_exe`, the single construction site. Success yields
//!   [`WorkerAuthenticity::Enforced`]: every spawn is validated statically against the exact
//!   per-release requirement before exec, and dynamically, by pid, against the running child before
//!   any byte is written to it. Failure yields [`WorkerAuthenticity::StartupRejected`]: no worker is
//!   ever spawned in this app session.
//!
//! Nothing at runtime (renderer, environment, arguments, configuration files, `Info.plist` keys
//! other than the signed record digest) can select a weaker mode, a different Team ID, another
//! requirement, another worker path or another expected identity.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Signing identifier of the worker helper tool.
pub(crate) const WORKER_IDENTIFIER: &str = "eu.fidomanager.desktop.fido-worker";
/// Signing identifier of the main application.
pub(crate) const APP_IDENTIFIER: &str = "eu.fidomanager.desktop";

/// The one reviewed Apple Developer Team ID for release enforcement (ADR-017 §5.1).
///
/// **Not provisioned.** No Developer ID identity exists for this project yet, so no Team ID is
/// invented here. While this is `None`:
///
/// * development and M7.1 ad-hoc builds are unaffected;
/// * a debug build of the `macos-release-signing` flavor compiles but release startup
///   authentication fails closed (`TeamIdUnprovisioned`): no worker is ever launched;
/// * an optimized (`--release`) build of the flavor does not compile (assertion below), so a
///   shippable enforcing binary cannot exist with a placeholder.
///
/// Setting it is a reviewed release-configuration change, validated against a real Developer
/// ID-signed worker first (ADR-017 E1). It is never read from the environment, `Info.plist`, the
/// renderer, arguments or the worker.
pub(crate) const MACOS_RELEASE_TEAM_ID: Option<&str> = None;

const _: () = assert!(
    match MACOS_RELEASE_TEAM_ID {
        Some(team) => is_team_id(team),
        None => true,
    },
    "MACOS_RELEASE_TEAM_ID must be exactly 10 characters of A-Z and 0-9"
);

#[cfg(all(feature = "macos-release-signing", not(debug_assertions)))]
const _: () = assert!(
    MACOS_RELEASE_TEAM_ID.is_some(),
    "the macos-release-signing flavor cannot be built optimized until the reviewed Team ID is set"
);

/// Apple Team IDs are 10 characters of `A-Z0-9`.
pub(crate) const fn is_team_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        if !(bytes[index].is_ascii_uppercase() || bytes[index].is_ascii_digit()) {
            return false;
        }
        index += 1;
    }
    true
}

/// ADR-017 §5.1: Apple-anchored Developer ID **Application** leaf issued by the Developer ID CA,
/// a fixed Team ID and a fixed identifier. The Mac App Store branch is deliberately absent.
/// Returns `None` for any input that is not a reviewed constant shape.
pub(crate) fn developer_id_requirement(identifier: &str, team_id: &str) -> Option<String> {
    let identifier_ok = !identifier.is_empty()
        && identifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !identifier_ok || !is_team_id(team_id) {
        return None;
    }
    Some(format!(
        "anchor apple generic and identifier \"{identifier}\" and \
         certificate 1[field.1.2.840.113635.100.6.2.6] and \
         certificate leaf[field.1.2.840.113635.100.6.1.13] and \
         certificate leaf[subject.OU] = \"{team_id}\""
    ))
}

/// `WORKER_EXACT_REQ`: the worker publisher requirement plus the exact per-release cdhash.
pub(crate) fn exact_worker_requirement(team_id: &str, cdhash: &[u8; 20]) -> Option<String> {
    developer_id_requirement(WORKER_IDENTIFIER, team_id).map(|publisher| {
        format!(
            "{publisher} and cdhash H\"{}\"",
            crate::release_identity::lower_hex(cdhash)
        )
    })
}

// ---------------------------------------------------------------------------------------------
// Enforcing-build marker (ADR-017 §5.6)
// ---------------------------------------------------------------------------------------------

const MARKER_TEAM: &str = match MACOS_RELEASE_TEAM_ID {
    Some(team) => team,
    None => "UNPROVISIONED",
};
const MARKER_COMMIT: &str = match fido_platform::build_identity::RELEASE_SOURCE_COMMIT {
    Some(commit) => commit,
    None => "UNPROVISIONED",
};
const MARKER_PARTS: [&str; 7] = [
    "FIDOMANAGER-RELEASE-ENFORCING-MARKER/1;team=",
    MARKER_TEAM,
    ";version=",
    fido_platform::build_identity::RELEASE_VERSION,
    ";commit=",
    MARKER_COMMIT,
    ";end",
];

const fn marker_length() -> usize {
    let mut total = 0;
    let mut part = 0;
    while part < MARKER_PARTS.len() {
        total += MARKER_PARTS[part].len();
        part += 1;
    }
    total
}

pub(crate) const ENFORCING_MARKER_LEN: usize = marker_length();

/// The marker bytes: `FIDOMANAGER-RELEASE-ENFORCING-MARKER/1;team=<TEAM>;version=<X.Y.Z>;
/// commit=<40-hex>;end`. Only the release flavor links them into the binary; the signing driver
/// finds them by byte search and compares them with its pinned Team ID and the tag.
pub(crate) const fn enforcing_marker() -> [u8; ENFORCING_MARKER_LEN] {
    let mut out = [0u8; ENFORCING_MARKER_LEN];
    let mut offset = 0;
    let mut part = 0;
    while part < MARKER_PARTS.len() {
        let bytes = MARKER_PARTS[part].as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            out[offset] = bytes[index];
            offset += 1;
            index += 1;
        }
        part += 1;
    }
    out
}

#[cfg(feature = "macos-release-signing")]
#[used]
static ENFORCING_MARKER: [u8; ENFORCING_MARKER_LEN] = enforcing_marker();

// ---------------------------------------------------------------------------------------------
// Launcher-facing contract
// ---------------------------------------------------------------------------------------------

/// Terminal authenticity latch (ADR-017 §5.7). Set **before** containment of a rejected worker is
/// attempted and never cleared, so no later containment result, error conversion or retry can
/// erase it.
#[derive(Debug, Clone, Default)]
pub(crate) struct IdentityLatch(Arc<AtomicBool>);

impl IdentityLatch {
    pub(crate) fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub(crate) fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Local-diagnostic category of a worker identity rejection. Never sent to the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityRejection {
    /// Release startup authentication failed earlier; no worker may ever be spawned.
    StartupRejected,
    /// Static validation against the exact requirement failed (unsigned, ad-hoc, broken
    /// signature, wrong anchor/leaf/Team ID/identifier, other cdhash).
    StaticValidation,
    /// Dynamic validation of the running child failed, or the child could not be addressed.
    DynamicValidation,
    /// The dynamic status lacks `valid` or `kill`.
    DynamicStatus,
    Identifier,
    TeamId,
    Runtime,
    Entitlements,
    Cdhash,
    FileDigest,
}

/// Result of the post-spawn identity step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildVerification {
    /// Development mode: no code-signing identity is required.
    NotRequired,
    /// The running child was dynamically validated against the exact expected identity.
    Verified,
}

/// What the endpoint asks of the authenticity policy on every spawn.
pub(crate) trait WorkerIdentityCheck {
    /// Whether the ADR-017 §5.3 step 2 release layout is required (`.app/Contents/MacOS`, no
    /// symlink, not group-writable).
    fn enforces_release_layout(&self) -> bool;
    /// Step 3: static validation of exactly the file about to be executed.
    fn verify_before_spawn(&self, path: &Path) -> Result<(), IdentityRejection>;
    /// Step 5: dynamic validation of the running, still unreaped child `pid`.
    fn verify_running_child(&self, pid: u32) -> Result<ChildVerification, IdentityRejection>;
    /// Step 7: the build identity `ChildHello` must report. Backend-owned.
    fn expected_build_id(&self) -> &str;
}

/// The compile-time-selected verification mode (ADR-017 §5.6).
#[derive(Clone)]
pub(crate) enum WorkerAuthenticity {
    /// Development and ad-hoc builds: layout checks and the build-id consistency check only.
    UnsignedDevelopment,
    /// Release enforcement with the startup-authenticated expected worker.
    #[cfg(all(target_os = "macos", any(test, feature = "macos-release-signing")))]
    Enforced(Arc<macos::WorkerCodeVerifier>),
    /// Release startup authentication failed: FIDO functionality stays disabled.
    #[cfg(any(test, feature = "macos-release-signing"))]
    StartupRejected,
}

impl std::fmt::Debug for WorkerAuthenticity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsignedDevelopment => "UnsignedDevelopment",
            #[cfg(all(target_os = "macos", any(test, feature = "macos-release-signing")))]
            Self::Enforced(_) => "Enforced",
            #[cfg(any(test, feature = "macos-release-signing"))]
            Self::StartupRejected => "StartupRejected",
        })
    }
}

impl WorkerIdentityCheck for WorkerAuthenticity {
    fn enforces_release_layout(&self) -> bool {
        !matches!(self, Self::UnsignedDevelopment)
    }

    fn verify_before_spawn(&self, _path: &Path) -> Result<(), IdentityRejection> {
        match self {
            Self::UnsignedDevelopment => Ok(()),
            #[cfg(all(target_os = "macos", any(test, feature = "macos-release-signing")))]
            Self::Enforced(verifier) => verifier.check_static(_path),
            #[cfg(any(test, feature = "macos-release-signing"))]
            Self::StartupRejected => Err(IdentityRejection::StartupRejected),
        }
    }

    fn verify_running_child(&self, _pid: u32) -> Result<ChildVerification, IdentityRejection> {
        match self {
            Self::UnsignedDevelopment => Ok(ChildVerification::NotRequired),
            #[cfg(all(target_os = "macos", any(test, feature = "macos-release-signing")))]
            Self::Enforced(verifier) => verifier
                .check_running(_pid)
                .map(|()| ChildVerification::Verified),
            #[cfg(any(test, feature = "macos-release-signing"))]
            Self::StartupRejected => Err(IdentityRejection::StartupRejected),
        }
    }

    fn expected_build_id(&self) -> &str {
        match self {
            Self::UnsignedDevelopment => fido_platform::build_identity::WORKER_BUILD_ID,
            #[cfg(all(target_os = "macos", any(test, feature = "macos-release-signing")))]
            Self::Enforced(verifier) => verifier.build_id(),
            // Never matches: an empty expectation is rejected by the handshake validation.
            #[cfg(any(test, feature = "macos-release-signing"))]
            Self::StartupRejected => "",
        }
    }
}

/// Release startup (ADR-017 §5.8), run once by the single construction site. Any failure leaves
/// the launcher permanently unable to spawn.
#[cfg(feature = "macos-release-signing")]
pub(crate) fn release_startup() -> WorkerAuthenticity {
    #[cfg(target_os = "macos")]
    {
        std::hint::black_box(&ENFORCING_MARKER);
        match macos::authenticate_release_startup() {
            Ok(verifier) => WorkerAuthenticity::Enforced(Arc::new(verifier)),
            Err(rejection) => {
                // Local diagnostics only; the renderer receives one integrity category.
                eprintln!(
                    "Fido Manager could not verify its own components; FIDO functions are \
                     disabled ({rejection:?})"
                );
                WorkerAuthenticity::StartupRejected
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::hint::black_box(&ENFORCING_MARKER);
        eprintln!("macOS release enforcement is unavailable on this platform; FIDO is disabled");
        WorkerAuthenticity::StartupRejected
    }
}

#[cfg(all(target_os = "macos", any(test, feature = "macos-release-signing")))]
pub(crate) mod macos {
    use std::io;
    use std::path::{Path, PathBuf};

    use fido_platform::macos_code_signing::{
        Requirement, RunningCode, SIGNATURE_FLAG_RUNTIME, STATUS_KILL, STATUS_VALID,
        SigningInformation, StaticCode, StaticValidation,
    };
    use fido_platform::os_version::DynamicNetworkPolicy;
    use sha2::{Digest, Sha256};

    use super::{APP_IDENTIFIER, IdentityRejection, WORKER_IDENTIFIER};
    use crate::release_identity::{
        Architecture, CompiledRelease, MAX_RECORD_BYTES, RECORD_BUNDLE_PATH,
        RECORD_DIGEST_PLIST_KEY, ReleaseStartupEnvironment, ReleaseWorkerIdentity,
        StartupRejection, authenticate_release_worker, digests_equal, parse_record_digest,
    };

    /// Upper bound on the worker file hashed per spawn.
    const MAX_WORKER_BYTES: u64 = 256 * 1024 * 1024;

    /// Validates one exact worker: compiled requirement plus the expected identity facts. Holds
    /// only backend-owned values; nothing here comes from the worker, the renderer or the
    /// environment.
    pub(crate) struct WorkerCodeVerifier {
        requirement: Requirement,
        identifier: String,
        /// Exact match: the signing Team ID must equal this (production: always `Some`).
        team_id: Option<String>,
        cdhash: [u8; 20],
        file_sha256: [u8; 32],
        network: DynamicNetworkPolicy,
        build_id: String,
    }

    impl WorkerCodeVerifier {
        /// The production verifier: `WORKER_EXACT_REQ` and `EXPECTED` from the authenticated
        /// release-worker identity record.
        pub(crate) fn for_release(
            expected: &ReleaseWorkerIdentity,
            network: DynamicNetworkPolicy,
        ) -> Result<Self, StartupRejection> {
            let text = super::exact_worker_requirement(expected.team_id(), expected.cdhash())
                .ok_or(StartupRejection::Requirement)?;
            Ok(Self {
                requirement: Requirement::compile(&text)
                    .map_err(|_| StartupRejection::Requirement)?,
                identifier: expected.identifier().to_owned(),
                team_id: Some(expected.team_id().to_owned()),
                cdhash: *expected.cdhash(),
                file_sha256: *expected.file_sha256(),
                network,
                build_id: expected.build_id().to_owned(),
            })
        }

        /// TEST-ONLY exact policy for ad-hoc code, which has no Apple anchor and no Team ID. It
        /// pins identifier and cdhash, and requires the Team ID to be absent. This is not
        /// Developer ID validation.
        #[cfg(test)]
        pub(crate) fn ad_hoc_for_test(
            identifier: &str,
            cdhash: [u8; 20],
            file_sha256: [u8; 32],
            network: DynamicNetworkPolicy,
        ) -> Result<Self, fido_platform::macos_code_signing::CodeSigningError> {
            let text = format!(
                "identifier \"{identifier}\" and cdhash H\"{}\"",
                crate::release_identity::lower_hex(&cdhash)
            );
            Ok(Self {
                requirement: Requirement::compile(&text)?,
                identifier: identifier.to_owned(),
                team_id: None,
                cdhash,
                file_sha256,
                network,
                build_id: "0.0.0+test".to_owned(),
            })
        }

        pub(crate) fn build_id(&self) -> &str {
            &self.build_id
        }

        /// ADR-017 §5.3 step 3, before exec.
        pub(crate) fn check_static(&self, path: &Path) -> Result<(), IdentityRejection> {
            let code =
                StaticCode::at_path(path).map_err(|_| IdentityRejection::StaticValidation)?;
            code.check_validity(StaticValidation::SingleFile, &self.requirement)
                .map_err(|_| IdentityRejection::StaticValidation)?;
            let info = code
                .signing_information()
                .map_err(|_| IdentityRejection::StaticValidation)?;
            self.check_information(&info)?;
            let digest = file_sha256(path).map_err(|_| IdentityRejection::FileDigest)?;
            if !digests_equal(&digest, &self.file_sha256) {
                return Err(IdentityRejection::FileDigest);
            }
            Ok(())
        }

        /// ADR-017 §5.3 step 5: the running child, addressed by the pid of a child the caller
        /// owns and has not reaped.
        pub(crate) fn check_running(&self, pid: u32) -> Result<(), IdentityRejection> {
            let guest = RunningCode::child_process(pid)
                .map_err(|_| IdentityRejection::DynamicValidation)?;
            guest
                .check_validity(self.network, &self.requirement)
                .map_err(|_| IdentityRejection::DynamicValidation)?;
            let info = guest
                .signing_information()
                .map_err(|_| IdentityRejection::DynamicValidation)?;
            let status = info
                .dynamic_status
                .ok_or(IdentityRejection::DynamicStatus)?;
            if status & STATUS_VALID == 0 || status & STATUS_KILL == 0 {
                return Err(IdentityRejection::DynamicStatus);
            }
            self.check_information(&info)
        }

        fn check_information(&self, info: &SigningInformation) -> Result<(), IdentityRejection> {
            if info.identifier.as_deref() != Some(self.identifier.as_str()) {
                return Err(IdentityRejection::Identifier);
            }
            if info.team_id != self.team_id {
                return Err(IdentityRejection::TeamId);
            }
            if info
                .signature_flags
                .is_none_or(|flags| flags & SIGNATURE_FLAG_RUNTIME == 0)
            {
                return Err(IdentityRejection::Runtime);
            }
            if info.has_entitlements {
                return Err(IdentityRejection::Entitlements);
            }
            if info.cdhash.as_deref() != Some(&self.cdhash[..]) {
                return Err(IdentityRejection::Cdhash);
            }
            Ok(())
        }
    }

    /// SHA-256 of the regular file at `path`, opened without following a final symlink.
    pub(crate) fn file_sha256(path: &Path) -> io::Result<[u8; 32]> {
        let file = fido_platform::file_once::open_regular_nofollow(path)?;
        if file.metadata()?.len() > MAX_WORKER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "worker too large",
            ));
        }
        let mut hasher = Sha256::new();
        io::copy(&mut io::Read::take(file, MAX_WORKER_BYTES + 1), &mut hasher)?;
        Ok(hasher.finalize().into())
    }

    /// The macOS half of S1–S8.
    struct BundleEnvironment {
        app_requirement: Requirement,
        network: DynamicNetworkPolicy,
        record_path: PathBuf,
        worker_path: PathBuf,
        verifier: Option<WorkerCodeVerifier>,
    }

    impl ReleaseStartupEnvironment for BundleEnvironment {
        fn secured_record_digest(&mut self) -> Result<[u8; 32], StartupRejection> {
            let identity = |_| StartupRejection::ApplicationIdentity;
            // S1: this process, dynamically, through the kernel, against APP_REQ.
            let me = RunningCode::current_process().map_err(identity)?;
            me.check_validity(self.network, &self.app_requirement)
                .map_err(identity)?;
            let running = me.signing_information().map_err(identity)?;
            if running
                .signature_flags
                .is_none_or(|flags| flags & SIGNATURE_FLAG_RUNTIME == 0)
                || running.has_entitlements
            {
                return Err(StartupRejection::ApplicationIdentity);
            }
            let running_cdhash = running
                .cdhash
                .ok_or(StartupRejection::ApplicationIdentity)?;
            // S2: the bundle's static code must describe the same main executable.
            let bundle = me.static_code().map_err(identity)?;
            let on_disk = bundle.signing_information().map_err(identity)?;
            if on_disk.cdhash.as_deref() != Some(&running_cdhash[..]) {
                return Err(StartupRejection::ApplicationIdentity);
            }
            // S3: the whole bundle, strictly, including nested code (defence in depth).
            bundle
                .check_validity(
                    StaticValidation::BundleWithNestedCode,
                    &self.app_requirement,
                )
                .map_err(identity)?;
            // The secured Info.plist as seen by code signing on the validated object (E16).
            let digest = bundle
                .secured_info_plist_string(RECORD_DIGEST_PLIST_KEY)
                .map_err(|_| StartupRejection::SecuredDigestMissing)?
                .ok_or(StartupRejection::SecuredDigestMissing)?;
            parse_record_digest(&digest)
        }

        fn read_record_once(&mut self) -> Result<Vec<u8>, StartupRejection> {
            fido_platform::file_once::read_regular_once_bounded(&self.record_path, MAX_RECORD_BYTES)
                .map_err(|_| StartupRejection::RecordUnreadable)
        }

        fn verify_worker_on_disk(
            &mut self,
            expected: &ReleaseWorkerIdentity,
        ) -> Result<(), StartupRejection> {
            let verifier = WorkerCodeVerifier::for_release(expected, self.network)?;
            verifier
                .check_static(&self.worker_path)
                .map_err(|_| StartupRejection::WorkerMismatch)?;
            self.verifier = Some(verifier);
            Ok(())
        }
    }

    /// `(Contents/MacOS, Contents)` of the running `.app`, from the canonical executable path.
    fn bundle_layout() -> Result<(PathBuf, PathBuf), StartupRejection> {
        let executable = std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .map_err(|_| StartupRejection::UnexpectedLayout)?;
        let macos = executable
            .parent()
            .filter(|dir| dir.file_name() == Some("MacOS".as_ref()))
            .ok_or(StartupRejection::UnexpectedLayout)?;
        let contents = macos
            .parent()
            .filter(|dir| dir.file_name() == Some("Contents".as_ref()))
            .ok_or(StartupRejection::UnexpectedLayout)?;
        let is_app = contents
            .parent()
            .and_then(Path::extension)
            .is_some_and(|extension| extension == "app");
        if !is_app {
            return Err(StartupRejection::UnexpectedLayout);
        }
        Ok((macos.to_path_buf(), contents.to_path_buf()))
    }

    /// S1–S8 for this process. Returns the per-spawn verifier for `EXPECTED`.
    pub(crate) fn authenticate_release_startup() -> Result<WorkerCodeVerifier, StartupRejection> {
        let team_id = super::MACOS_RELEASE_TEAM_ID.ok_or(StartupRejection::TeamIdUnprovisioned)?;
        let source_commit = fido_platform::build_identity::RELEASE_SOURCE_COMMIT
            .ok_or(StartupRejection::SourceCommitUnprovisioned)?;
        let architecture = Architecture::native().ok_or(StartupRejection::UnsupportedPlatform)?;
        let network = fido_platform::os_version::current()
            .and_then(DynamicNetworkPolicy::for_version)
            .map_err(|_| StartupRejection::UnsupportedOperatingSystem)?;
        let app_requirement = super::developer_id_requirement(APP_IDENTIFIER, team_id)
            .ok_or(StartupRejection::Requirement)
            .and_then(|text| {
                Requirement::compile(&text).map_err(|_| StartupRejection::Requirement)
            })?;
        let (macos, contents) = bundle_layout()?;
        let bundle = contents
            .parent()
            .ok_or(StartupRejection::UnexpectedLayout)?;
        let mut environment = BundleEnvironment {
            app_requirement,
            network,
            record_path: bundle.join(RECORD_BUNDLE_PATH),
            worker_path: macos.join("fido-worker"),
            verifier: None,
        };
        let compiled = CompiledRelease {
            version: fido_platform::build_identity::RELEASE_VERSION,
            source_commit,
            team_id,
            worker_identifier: WORKER_IDENTIFIER,
            architecture,
        };
        let expected = authenticate_release_worker(&mut environment, &compiled)?;
        let verifier = environment
            .verifier
            .take()
            .ok_or(StartupRejection::WorkerMismatch)?;
        if verifier.build_id() != expected.build_id()
            || verifier.build_id() != fido_platform::build_identity::WORKER_BUILD_ID
        {
            return Err(StartupRejection::Record(
                crate::release_identity::RecordError::BuildId,
            ));
        }
        Ok(verifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TEAM: &str = "TESTONLY01";

    #[test]
    fn team_id_constant_is_unprovisioned_and_never_invented() {
        // Changing this is a reviewed release-configuration step (ADR-017 E1), not a code fix.
        assert_eq!(MACOS_RELEASE_TEAM_ID, None);
    }

    #[test]
    fn team_ids_are_exactly_ten_uppercase_alphanumerics() {
        assert!(is_team_id(TEST_TEAM));
        assert!(is_team_id("A1B2C3D4E5"));
        for bad in [
            "",
            "TESTONLY0",
            "TESTONLY012",
            "testonly01",
            "TESTONLY0!",
            "TEST ONLY1",
        ] {
            assert!(!is_team_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn publisher_requirement_is_developer_id_application_with_fixed_team_and_identifier()
    -> Result<(), &'static str> {
        let text = developer_id_requirement(WORKER_IDENTIFIER, TEST_TEAM).ok_or("requirement")?;
        assert_eq!(
            text,
            "anchor apple generic and identifier \"eu.fidomanager.desktop.fido-worker\" and \
             certificate 1[field.1.2.840.113635.100.6.2.6] and \
             certificate leaf[field.1.2.840.113635.100.6.1.13] and \
             certificate leaf[subject.OU] = \"TESTONLY01\""
        );
        // The Mac App Store leaf (…6.1.9) is not accepted.
        assert!(!text.contains("6.1.9"));
        assert!(!text.contains(" or "));
        Ok(())
    }

    #[test]
    fn exact_requirement_adds_only_the_pinned_cdhash() -> Result<(), &'static str> {
        let publisher =
            developer_id_requirement(WORKER_IDENTIFIER, TEST_TEAM).ok_or("publisher")?;
        let exact = exact_worker_requirement(TEST_TEAM, &[0xab; 20]).ok_or("exact")?;
        assert_eq!(
            exact,
            format!("{publisher} and cdhash H\"{}\"", "ab".repeat(20))
        );
        Ok(())
    }

    #[test]
    fn requirement_inputs_outside_the_reviewed_shape_are_refused() {
        assert!(developer_id_requirement("eu.fidomanager\" or anchor apple", TEST_TEAM).is_none());
        assert!(developer_id_requirement("", TEST_TEAM).is_none());
        assert!(developer_id_requirement(WORKER_IDENTIFIER, "TESTONLY01\" or").is_none());
        assert!(developer_id_requirement(WORKER_IDENTIFIER, "lowercase1").is_none());
        assert!(exact_worker_requirement("short", &[0; 20]).is_none());
    }

    /// ADR-017 §5.2: the OS version selects only the network flag. Requirement and identity
    /// checks are the same objects/strings on both paths.
    #[test]
    fn both_os_flag_paths_use_the_identical_requirement() -> Result<(), Box<dyn std::error::Error>>
    {
        use fido_platform::os_version::{DynamicNetworkPolicy, OsVersionError};
        let old = DynamicNetworkPolicy::for_version_text("11.2")?;
        let new = DynamicNetworkPolicy::for_version_text("11.3")?;
        assert_ne!(old, new);
        // The requirement is built without any OS input at all.
        let on_old = exact_worker_requirement(TEST_TEAM, &[1; 20]);
        let on_new = exact_worker_requirement(TEST_TEAM, &[1; 20]);
        assert!(on_old.is_some());
        assert_eq!(on_old, on_new);
        assert_eq!(
            DynamicNetworkPolicy::for_version_text("eleven"),
            Err(OsVersionError::Malformed)
        );
        #[cfg(target_os = "macos")]
        {
            use fido_platform::macos_code_signing::dynamic_validation_flags;
            assert_eq!(dynamic_validation_flags(old), 0);
            assert_eq!(dynamic_validation_flags(new), 1 << 29);
        }
        Ok(())
    }

    #[test]
    fn enforcing_marker_carries_team_version_and_commit() -> Result<(), std::str::Utf8Error> {
        let marker = enforcing_marker();
        let text = std::str::from_utf8(&marker)?;
        assert_eq!(
            text,
            format!(
                "FIDOMANAGER-RELEASE-ENFORCING-MARKER/1;team=UNPROVISIONED;version={};commit={};end",
                fido_platform::build_identity::RELEASE_VERSION,
                fido_platform::build_identity::RELEASE_SOURCE_COMMIT.unwrap_or("UNPROVISIONED"),
            )
        );
        Ok(())
    }

    #[test]
    fn startup_rejected_mode_never_spawns_and_never_matches_a_build() {
        let mode = WorkerAuthenticity::StartupRejected;
        assert_eq!(
            mode.verify_before_spawn(Path::new("/bin/sh")),
            Err(IdentityRejection::StartupRejected)
        );
        assert_eq!(
            mode.verify_running_child(1),
            Err(IdentityRejection::StartupRejected)
        );
        assert_eq!(mode.expected_build_id(), "");
        assert!(mode.enforces_release_layout());
        let development = WorkerAuthenticity::UnsignedDevelopment;
        assert!(!development.enforces_release_layout());
        assert_eq!(
            development.expected_build_id(),
            fido_platform::build_identity::WORKER_BUILD_ID
        );
    }

    #[test]
    fn latch_is_shared_and_never_clears() {
        let latch = IdentityLatch::default();
        let clone = latch.clone();
        assert!(!clone.is_set());
        latch.set();
        assert!(clone.is_set());
        latch.set();
        assert!(latch.is_set());
    }

    /// ADR-017 §12 step 4(c), at the current M6 boundary. M6.0 merged no Reset dispatch, Reset
    /// journal operation or Reset recovery family (ADR-011), so this proves what exists today:
    /// a worker identity failure cannot admit a `Reset` workflow past an existing uncertain-
    /// mutation barrier, cannot rewrite that durable evidence, and cannot release a `Reset`-class
    /// admission while the rejected worker is not proven stopped.
    mod m6_reset_boundary {
        use crate::authentication::AuthenticationAuthority;
        use crate::recovery::tests::MemoryStorage;
        use crate::{
            AdmissionError, CompletionError, DiscoveryPolicy, DiscoverySupervisor, LaunchError,
            MonotonicMillis, ProcessWorkerLauncher, RestartPolicy, SensitiveWorkflowGate,
            SupervisorError, WorkflowCompletion, WorkflowReleaseEvidence,
        };
        use fido_core::{ExecutionQuiescence, RecoveryAdmission, SensitiveWorkflowKind};

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        #[test]
        fn identity_rejection_cannot_admit_reset_or_erase_uncertain_evidence() -> TestResult {
            for operation in ["change_pin", "set_pin", "delete_credential"] {
                let disk = MemoryStorage::default();
                let record = format!(
                    r#"{{"schema":1,"application":"fidomanager-m4-v1","incident":"0123456789abcdef0123456789abcdef","operation":"{operation}","created_unix_secs":42,"phase":"dispatch_capable","resolution":null}}"#
                )
                .into_bytes();
                disk.0.lock().map_err(|_| "disk")?.bytes = Some(record.clone());
                let authority = AuthenticationAuthority::awaiting_recovery_startup();
                authority
                    .initialize_recovery(Box::new(disk.clone()))
                    .map_err(|_| "journal")?;

                let mut supervisor = DiscoverySupervisor::new(
                    ProcessWorkerLauncher::startup_rejected_for_test(),
                    DiscoveryPolicy::default(),
                    RestartPolicy::default(),
                )?;
                for _ in 0..3 {
                    assert!(matches!(
                        supervisor.refresh(),
                        Err(SupervisorError::WorkerIdentityRejected { .. })
                    ));
                }

                assert_eq!(authority.recovery_admission(), RecoveryAdmission::Barrier);
                let reset = authority.gate.lock().map_err(|_| "gate")?.try_begin(
                    SensitiveWorkflowKind::Reset,
                    MonotonicMillis::from_millis(1),
                );
                assert_eq!(
                    reset.err(),
                    Some(AdmissionError::RecoveryBarrier),
                    "{operation}"
                );
                assert_eq!(
                    disk.0.lock().map_err(|_| "disk")?.bytes.as_deref(),
                    Some(record.as_slice()),
                    "{operation}: the uncertain record is untouched"
                );
            }
            Ok(())
        }

        #[test]
        fn uncontained_identity_rejection_never_releases_a_reset_admission() -> TestResult {
            let mut gate = SensitiveWorkflowGate::default();
            let admission = gate.try_begin(
                SensitiveWorkflowKind::Reset,
                MonotonicMillis::from_millis(0),
            )?;
            let rejection = LaunchError::WorkerIdentityRejected {
                quiescence: ExecutionQuiescence::Active,
            };
            let LaunchError::WorkerIdentityRejected { quiescence } = rejection else {
                return Err("not an identity rejection".into());
            };
            assert_eq!(
                gate.finish(
                    &admission,
                    WorkflowCompletion::Failed,
                    WorkflowReleaseEvidence {
                        execution_quiescence: quiescence,
                        recovery_admission: RecoveryAdmission::Open,
                    },
                    MonotonicMillis::from_millis(1),
                ),
                Err(CompletionError::ExecutionNotQuiescent)
            );
            assert!(gate.is_active());
            assert_eq!(
                gate.try_begin(
                    SensitiveWorkflowKind::Reset,
                    MonotonicMillis::from_millis(2)
                )
                .err(),
                Some(AdmissionError::OperationInProgress)
            );
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    mod macos_ad_hoc {
        //! Credential-free evidence on the current Mac. Ad-hoc signatures are NOT Developer ID:
        //! these prove that the exact cdhash pin is load-bearing and that the static and dynamic
        //! checks are wired, not that the release requirement accepts a real release.
        use std::path::{Path, PathBuf};
        use std::process::{Command, Stdio};

        use fido_platform::macos_code_signing::{RunningCode, StaticCode};
        use fido_platform::os_version::DynamicNetworkPolicy;

        use super::super::macos::{WorkerCodeVerifier, file_sha256};
        use super::super::*;

        type TestResult = Result<(), Box<dyn std::error::Error>>;
        const TEST_IDENTIFIER: &str = "eu.fidomanager.test.cdhash-pin";

        struct Workspace(PathBuf);
        impl Drop for Workspace {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn workspace(name: &str) -> std::io::Result<Workspace> {
            let path =
                std::env::temp_dir().join(format!("fido-adhoc-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path)?;
            Ok(Workspace(path))
        }

        /// Compiles a tiny program that blocks on stdin, then ad-hoc signs it with `identifier`.
        fn build(
            dir: &Path,
            name: &str,
            variant: &str,
            sign: &[&str],
        ) -> Result<PathBuf, Box<dyn std::error::Error>> {
            let source = dir.join(format!("{name}.c"));
            std::fs::write(
                &source,
                format!(
                    "#include <unistd.h>\nstatic const char v[] = \"{variant}\";\n\
                     int main(void) {{ char b; (void)v; while (read(0, &b, 1) > 0) {{}} return 0; }}\n"
                ),
            )?;
            let binary = dir.join(name);
            let status = Command::new("/usr/bin/xcrun")
                .args(["clang", "-O0", "-o"])
                .arg(&binary)
                .arg(&source)
                .status()?;
            if !status.success() {
                return Err("clang failed".into());
            }
            if !sign.is_empty() {
                let status = Command::new("/usr/bin/codesign")
                    .args(["--force", "--sign", "-"])
                    .args(sign)
                    .arg(&binary)
                    .stderr(Stdio::null())
                    .status()?;
                if !status.success() {
                    return Err("codesign failed".into());
                }
            }
            Ok(binary)
        }

        fn cdhash(path: &Path) -> Result<[u8; 20], Box<dyn std::error::Error>> {
            let info = StaticCode::at_path(path)?.signing_information()?;
            let bytes = info.cdhash.ok_or("no cdhash")?;
            Ok(<[u8; 20]>::try_from(bytes.as_slice())?)
        }

        fn network() -> Result<DynamicNetworkPolicy, Box<dyn std::error::Error>> {
            Ok(DynamicNetworkPolicy::for_version(
                fido_platform::os_version::current()?,
            )?)
        }

        fn pinned(path: &Path) -> Result<WorkerCodeVerifier, Box<dyn std::error::Error>> {
            Ok(WorkerCodeVerifier::ad_hoc_for_test(
                TEST_IDENTIFIER,
                cdhash(path)?,
                file_sha256(path)?,
                network()?,
            )?)
        }

        /// Runs `check` against a spawned, owned, unreaped child, then reaps it.
        fn with_child<T>(
            path: &Path,
            check: impl FnOnce(u32) -> T,
        ) -> Result<T, Box<dyn std::error::Error>> {
            let mut child = Command::new(path)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()?;
            let result = check(child.id());
            let _ = child.kill();
            child.wait()?;
            Ok(result)
        }

        /// ADR-017 §12 step 2: two ad-hoc binaries with the SAME identifier; a TEST-ONLY exact
        /// requirement pinning A's cdhash accepts A and rejects B, statically and dynamically.
        #[test]
        fn exact_cdhash_pin_accepts_a_and_rejects_b_with_the_same_identifier() -> TestResult {
            let dir = workspace("pin")?;
            let runtime = ["--identifier", TEST_IDENTIFIER, "--options", "runtime"];
            let a = build(&dir.0, "worker-a", "A", &runtime)?;
            let b = build(&dir.0, "worker-b", "B", &runtime)?;
            assert_ne!(cdhash(&a)?, cdhash(&b)?);
            let identifier_of = |p: &Path| -> Result<Option<String>, Box<dyn std::error::Error>> {
                Ok(StaticCode::at_path(p)?.signing_information()?.identifier)
            };
            assert_eq!(identifier_of(&a)?.as_deref(), Some(TEST_IDENTIFIER));
            assert_eq!(identifier_of(&b)?.as_deref(), Some(TEST_IDENTIFIER));

            let verifier = pinned(&a)?;
            assert_eq!(verifier.check_static(&a), Ok(()));
            assert_eq!(with_child(&a, |pid| verifier.check_running(pid))?, Ok(()));

            assert_eq!(
                verifier.check_static(&b),
                Err(IdentityRejection::StaticValidation)
            );
            assert_eq!(
                with_child(&b, |pid| verifier.check_running(pid))?,
                Err(IdentityRejection::DynamicValidation)
            );
            Ok(())
        }

        #[test]
        fn ad_hoc_and_unsigned_code_never_satisfy_the_developer_id_requirement() -> TestResult {
            let dir = workspace("devid")?;
            let ad_hoc = build(
                &dir.0,
                "fido-worker",
                "adhoc",
                &["--identifier", WORKER_IDENTIFIER, "--options", "runtime"],
            )?;
            let unsigned = build(&dir.0, "unsigned", "unsigned", &[])?;
            let status = Command::new("/usr/bin/codesign")
                .args(["--remove-signature"])
                .arg(&unsigned)
                .status()?;
            assert!(status.success());

            let requirement = fido_platform::macos_code_signing::Requirement::compile(
                &exact_worker_requirement(super::TEST_TEAM, &cdhash(&ad_hoc)?)
                    .ok_or("requirement")?,
            )?;
            for path in [&ad_hoc, &unsigned] {
                let code = StaticCode::at_path(path)?;
                assert!(
                    code.check_validity(
                        fido_platform::macos_code_signing::StaticValidation::SingleFile,
                        &requirement
                    )
                    .is_err()
                );
            }
            let dynamic = with_child(&ad_hoc, |pid| {
                RunningCode::child_process(pid).and_then(|guest| {
                    guest.check_validity(DynamicNetworkPolicy::NoNetworkAccess, &requirement)
                })
            })?;
            assert!(dynamic.is_err());
            Ok(())
        }

        #[test]
        fn identity_facts_beyond_the_requirement_are_enforced() -> TestResult {
            let dir = workspace("facts")?;
            // Same identifier and pinned cdhash, but no Hardened Runtime: rejected on `runtime`.
            let no_runtime = build(
                &dir.0,
                "no-runtime",
                "nr",
                &["--identifier", TEST_IDENTIFIER],
            )?;
            assert_eq!(
                pinned(&no_runtime)?.check_static(&no_runtime),
                Err(IdentityRejection::Runtime)
            );

            // Right code, wrong expected file digest: the pre-exec file tripwire fires.
            let a = build(
                &dir.0,
                "worker",
                "A",
                &["--identifier", TEST_IDENTIFIER, "--options", "runtime"],
            )?;
            let wrong_digest = WorkerCodeVerifier::ad_hoc_for_test(
                TEST_IDENTIFIER,
                cdhash(&a)?,
                [0; 32],
                network()?,
            )?;
            assert_eq!(
                wrong_digest.check_static(&a),
                Err(IdentityRejection::FileDigest)
            );

            // Wrong identifier is refused by the requirement itself.
            let other = build(
                &dir.0,
                "other",
                "A",
                &[
                    "--identifier",
                    "eu.fidomanager.test.other",
                    "--options",
                    "runtime",
                ],
            )?;
            let mismatched = WorkerCodeVerifier::ad_hoc_for_test(
                TEST_IDENTIFIER,
                cdhash(&other)?,
                file_sha256(&other)?,
                network()?,
            )?;
            assert_eq!(
                mismatched.check_static(&other),
                Err(IdentityRejection::StaticValidation)
            );

            // A child that has exited cannot be validated by pid.
            let verifier = pinned(&a)?;
            let mut child = Command::new(&a).stdin(Stdio::null()).spawn()?;
            let pid = child.id();
            while !fido_platform::process::child_exited_unreaped(pid)? {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert_eq!(
                verifier.check_running(pid),
                Err(IdentityRejection::DynamicValidation)
            );
            child.wait()?;
            Ok(())
        }

        #[test]
        fn release_startup_fails_closed_without_a_provisioned_team_id() {
            assert!(matches!(
                super::super::macos::authenticate_release_startup(),
                Err(crate::release_identity::StartupRejection::TeamIdUnprovisioned)
            ));
        }
    }
}
