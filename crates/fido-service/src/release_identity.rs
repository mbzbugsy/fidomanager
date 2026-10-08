//! Release-worker identity record and the startup authentication algorithm (ADR-017 §5.8).
//!
//! ```text
//! S1–S3  validate this app (dynamic + bundle static) and read RID from the SECURED Info.plist
//! S4     open the record O_RDONLY|O_NOFOLLOW, fstat regular, <= 4 KiB, read ONCE into BUF
//! S5     SHA-256(BUF) == RID                       (constant-time comparison)
//! S6     strictly parse THAT SAME BUF; version, commit, Team ID, identifier, path, build id
//! S7     the worker on disk matches the parsed identity (cdhash, file SHA-256, signature)
//! S8     EXPECTED = the immutable value parsed from BUF; the record file is never read again
//! ```
//!
//! The generic algorithm ([`authenticate_release_worker`]) owns the ordering and the single read.
//! The platform steps (S1–S3, S4's file access, S7) come from a [`ReleaseStartupEnvironment`]; the
//! production macOS environment is in `worker_authenticity`. The renderer never sees, parses or
//! influences the record, the digest, the expected identity, or the failure detail.

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// `Info.plist` key holding the SHA-256 of the exact record bytes (64 lowercase hex).
pub(crate) const RECORD_DIGEST_PLIST_KEY: &str = "FidoManagerReleaseWorkerIdentitySHA256";
/// Bundle-relative record path.
pub(crate) const RECORD_BUNDLE_PATH: &str = "Contents/Resources/release-worker-identity.json";
/// Upper bound on the record (ADR-017 §5.8).
pub(crate) const MAX_RECORD_BYTES: usize = 4_096;
pub(crate) const RECORD_SCHEMA: &str = "fidomanager.release-worker-identity/1";
/// The only worker path a record may name.
pub(crate) const RECORD_WORKER_PATH: &str = "Contents/MacOS/fido-worker";
const MAX_VERSION_BYTES: usize = 64;
const MAX_SLICES: usize = 2;

/// Why release startup authentication failed. Local diagnostics only: the renderer receives a
/// single integrity category, never this detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupRejection {
    /// The reviewed Team ID constant is not provisioned in this build.
    TeamIdUnprovisioned,
    /// The release flavor was compiled without its source commit.
    SourceCommitUnprovisioned,
    /// Release enforcement is macOS-only.
    UnsupportedPlatform,
    /// The OS version is unreadable, malformed or below the deployment floor.
    UnsupportedOperatingSystem,
    /// The running executable is not inside the expected `.app/Contents/MacOS` layout.
    UnexpectedLayout,
    /// A requirement failed to compile.
    Requirement,
    /// S1–S3: this application's own code identity did not validate.
    ApplicationIdentity,
    /// S3: the secured `Info.plist` or its digest key is missing or not a string.
    SecuredDigestMissing,
    /// S3: the digest key is not exactly 64 lowercase hex characters.
    SecuredDigestMalformed,
    /// S4: the record could not be opened/read as a regular file of at most 4 KiB.
    RecordUnreadable,
    /// S5: `SHA-256(BUF)` differs from the secured digest.
    RecordDigestMismatch,
    /// S6: the record failed the strict schema or names another release/worker.
    Record(RecordError),
    /// S7: the worker on disk does not match the authenticated record.
    WorkerMismatch,
}

/// Strict-schema failures of the release-worker identity record (S6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordError {
    TooLarge,
    /// Not UTF-8 JSON of the exact schema (unknown, missing, duplicate or mistyped fields).
    Malformed,
    Schema,
    Version,
    SourceCommit,
    WorkerPath,
    Identifier,
    TeamId,
    BuildId,
    /// A digest is not the exact number of lowercase hex characters.
    Digest,
    UnsupportedArchitecture,
    /// The same architecture appears more than once, or there are no/too many slices.
    AmbiguousSlices,
    /// No slice for the architecture this application runs as.
    MissingNativeSlice,
}

/// Mach-O slice architectures a record may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Architecture {
    Arm64,
    X86_64,
}

impl Architecture {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "arm64" => Some(Self::Arm64),
            "x86_64" => Some(Self::X86_64),
            _ => None,
        }
    }

    /// The architecture this process was compiled for.
    pub(crate) const fn native() -> Option<Self> {
        if cfg!(target_arch = "aarch64") {
            Some(Self::Arm64)
        } else if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else {
            None
        }
    }
}

/// Values compiled into this application that the record must name exactly (S6).
pub(crate) struct CompiledRelease<'a> {
    pub(crate) version: &'a str,
    pub(crate) source_commit: &'a str,
    pub(crate) team_id: &'a str,
    pub(crate) worker_identifier: &'a str,
    pub(crate) architecture: Architecture,
}

/// `EXPECTED` (S8): the authenticated identity of the one worker approved for this release.
/// Immutable after construction, never serialized, never sent to the renderer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReleaseWorkerIdentity {
    identifier: String,
    team_id: String,
    build_id: String,
    file_sha256: [u8; 32],
    cdhash: [u8; 20],
}

impl ReleaseWorkerIdentity {
    pub(crate) fn identifier(&self) -> &str {
        &self.identifier
    }
    pub(crate) fn team_id(&self) -> &str {
        &self.team_id
    }
    pub(crate) fn build_id(&self) -> &str {
        &self.build_id
    }
    pub(crate) fn file_sha256(&self) -> &[u8; 32] {
        &self.file_sha256
    }
    /// The cdhash of the slice for the architecture this application runs as.
    pub(crate) fn cdhash(&self) -> &[u8; 20] {
        &self.cdhash
    }

    /// S6: strictly parse `buffer` (already authenticated by S5) against the compiled release.
    pub(crate) fn parse(
        buffer: &[u8],
        compiled: &CompiledRelease<'_>,
    ) -> Result<Self, RecordError> {
        if buffer.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge);
        }
        let wire: RecordWire =
            serde_json::from_slice(buffer).map_err(|_| RecordError::Malformed)?;
        if wire.schema != RECORD_SCHEMA {
            return Err(RecordError::Schema);
        }
        if !well_formed_version(&wire.release.version)
            || !well_formed_version(compiled.version)
            || wire.release.version != compiled.version
        {
            return Err(RecordError::Version);
        }
        if !fido_platform::build_identity::is_lower_hex(&wire.release.source_commit, 40)
            || wire.release.source_commit != compiled.source_commit
        {
            return Err(RecordError::SourceCommit);
        }
        let worker = wire.worker;
        if worker.path != RECORD_WORKER_PATH {
            return Err(RecordError::WorkerPath);
        }
        if worker.identifier != compiled.worker_identifier {
            return Err(RecordError::Identifier);
        }
        if worker.team_id != compiled.team_id {
            return Err(RecordError::TeamId);
        }
        let expected_build_id = format!("{}+{}", compiled.version, compiled.source_commit);
        if worker.build_id != expected_build_id {
            return Err(RecordError::BuildId);
        }
        let file_sha256 = hex_array::<32>(&worker.file_sha256).ok_or(RecordError::Digest)?;

        if worker.slices.is_empty() || worker.slices.len() > MAX_SLICES {
            return Err(RecordError::AmbiguousSlices);
        }
        let mut seen: Vec<Architecture> = Vec::with_capacity(worker.slices.len());
        let mut native = None;
        for slice in &worker.slices {
            let architecture =
                Architecture::parse(&slice.arch).ok_or(RecordError::UnsupportedArchitecture)?;
            if seen.contains(&architecture) {
                return Err(RecordError::AmbiguousSlices);
            }
            seen.push(architecture);
            // Every slice must be well formed, including slices this host does not run.
            let cdhash = hex_array::<20>(&slice.cdhash).ok_or(RecordError::Digest)?;
            hex_array::<32>(&slice.cdhash_sha256).ok_or(RecordError::Digest)?;
            if architecture == compiled.architecture {
                native = Some(cdhash);
            }
        }
        let cdhash = native.ok_or(RecordError::MissingNativeSlice)?;
        Ok(Self {
            identifier: worker.identifier,
            team_id: worker.team_id,
            build_id: worker.build_id,
            file_sha256,
            cdhash,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    schema: String,
    release: ReleaseWire,
    worker: WorkerWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseWire {
    version: String,
    source_commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerWire {
    path: String,
    identifier: String,
    team_id: String,
    build_id: String,
    file_sha256: String,
    slices: Vec<SliceWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SliceWire {
    arch: String,
    cdhash: String,
    cdhash_sha256: String,
}

fn well_formed_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_BYTES
        && version.as_bytes()[0].is_ascii_digit()
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Decodes exactly `2 * N` lowercase hex characters.
pub(crate) fn hex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    if !fido_platform::build_identity::is_lower_hex(text, 2 * N) {
        return None;
    }
    let mut out = [0u8; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out[index] = u8::try_from(high * 16 + low).ok()?;
    }
    Some(out)
}

pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// S3: the secured digest value must be exactly 64 lowercase hex characters.
pub(crate) fn parse_record_digest(text: &str) -> Result<[u8; 32], StartupRejection> {
    hex_array::<32>(text).ok_or(StartupRejection::SecuredDigestMalformed)
}

/// Comparison whose duration does not depend on where the inputs differ.
pub(crate) fn digests_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    std::hint::black_box(difference) == 0
}

/// The platform half of release startup authentication.
pub(crate) trait ReleaseStartupEnvironment {
    /// S1–S3: validate this application and return the digest from its secured `Info.plist`.
    fn secured_record_digest(&mut self) -> Result<[u8; 32], StartupRejection>;
    /// S4: read the record exactly once (no-follow open, `fstat` regular, at most 4 KiB).
    fn read_record_once(&mut self) -> Result<Vec<u8>, StartupRejection>;
    /// S7: the worker on disk matches the authenticated identity.
    fn verify_worker_on_disk(
        &mut self,
        expected: &ReleaseWorkerIdentity,
    ) -> Result<(), StartupRejection>;
}

/// S1–S8. Any failure means no authenticated launcher: FIDO functionality stays disabled.
///
/// The record is read once (S4); S5 authenticates exactly those bytes and S6 parses exactly those
/// bytes. Nothing re-reads the file, so a swap after S4 cannot change `EXPECTED`.
pub(crate) fn authenticate_release_worker(
    environment: &mut impl ReleaseStartupEnvironment,
    compiled: &CompiledRelease<'_>,
) -> Result<ReleaseWorkerIdentity, StartupRejection> {
    let secured_digest = environment.secured_record_digest()?; // S1–S3
    let buffer = environment.read_record_once()?; // S4
    if buffer.len() > MAX_RECORD_BYTES {
        return Err(StartupRejection::RecordUnreadable);
    }
    let actual: [u8; 32] = Sha256::digest(&buffer).into();
    if !digests_equal(&actual, &secured_digest) {
        return Err(StartupRejection::RecordDigestMismatch); // S5
    }
    let expected =
        ReleaseWorkerIdentity::parse(&buffer, compiled).map_err(StartupRejection::Record)?; // S6
    drop(buffer);
    environment.verify_worker_on_disk(&expected)?; // S7
    Ok(expected) // S8
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const TEST_TEAM: &str = "TESTONLY01";
    pub(crate) const TEST_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    pub(crate) const TEST_VERSION: &str = "0.1.0";
    const CDHASH_ARM: &str = "1111111111111111111111111111111111111111";
    const CDHASH_X86: &str = "2222222222222222222222222222222222222222";
    const FULL: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const FILE: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    pub(crate) fn compiled(architecture: Architecture) -> CompiledRelease<'static> {
        CompiledRelease {
            version: TEST_VERSION,
            source_commit: TEST_COMMIT,
            team_id: TEST_TEAM,
            worker_identifier: "eu.fidomanager.desktop.fido-worker",
            architecture,
        }
    }

    pub(crate) fn record() -> serde_json::Value {
        serde_json::json!({
            "schema": RECORD_SCHEMA,
            "release": { "version": TEST_VERSION, "source_commit": TEST_COMMIT },
            "worker": {
                "path": RECORD_WORKER_PATH,
                "identifier": "eu.fidomanager.desktop.fido-worker",
                "team_id": TEST_TEAM,
                "build_id": format!("{TEST_VERSION}+{TEST_COMMIT}"),
                "file_sha256": FILE,
                "slices": [
                    { "arch": "arm64", "cdhash": CDHASH_ARM, "cdhash_sha256": FULL }
                ]
            }
        })
    }

    fn bytes(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap_or_default()
    }

    fn parse(value: &serde_json::Value) -> Result<ReleaseWorkerIdentity, RecordError> {
        ReleaseWorkerIdentity::parse(&bytes(value), &compiled(Architecture::Arm64))
    }

    #[test]
    fn valid_record_yields_the_native_slice_identity() -> Result<(), RecordError> {
        let identity = parse(&record())?;
        assert_eq!(identity.identifier(), "eu.fidomanager.desktop.fido-worker");
        assert_eq!(identity.team_id(), TEST_TEAM);
        assert_eq!(identity.build_id(), format!("{TEST_VERSION}+{TEST_COMMIT}"));
        assert_eq!(identity.cdhash(), &[0x11; 20]);
        assert_eq!(identity.file_sha256(), &[0x44; 32]);

        let mut universal = record();
        universal["worker"]["slices"] = serde_json::json!([
            { "arch": "arm64", "cdhash": CDHASH_ARM, "cdhash_sha256": FULL },
            { "arch": "x86_64", "cdhash": CDHASH_X86, "cdhash_sha256": FULL }
        ]);
        let x86 =
            ReleaseWorkerIdentity::parse(&bytes(&universal), &compiled(Architecture::X86_64))?;
        assert_eq!(x86.cdhash(), &[0x22; 20]);
        Ok(())
    }

    type Mutation = (&'static str, fn(&mut serde_json::Value), RecordError);

    #[test]
    fn every_identity_field_is_bound_to_the_compiled_release() {
        let cases: &[Mutation] = &[
            (
                "schema",
                |r| r["schema"] = "fidomanager.release-worker-identity/2".into(),
                RecordError::Schema,
            ),
            (
                "version",
                |r| r["release"]["version"] = "0.1.1".into(),
                RecordError::Version,
            ),
            (
                "empty version",
                |r| r["release"]["version"] = "".into(),
                RecordError::Version,
            ),
            (
                "commit",
                |r| {
                    r["release"]["source_commit"] =
                        "1123456789abcdef0123456789abcdef01234567".into()
                },
                RecordError::SourceCommit,
            ),
            (
                "upper commit",
                |r| r["release"]["source_commit"] = TEST_COMMIT.to_uppercase().into(),
                RecordError::SourceCommit,
            ),
            (
                "short commit",
                |r| r["release"]["source_commit"] = "0123456".into(),
                RecordError::SourceCommit,
            ),
            (
                "path",
                |r| r["worker"]["path"] = "Contents/Helpers/fido-worker".into(),
                RecordError::WorkerPath,
            ),
            (
                "identifier",
                |r| r["worker"]["identifier"] = "eu.fidomanager.desktop".into(),
                RecordError::Identifier,
            ),
            (
                "team",
                |r| r["worker"]["team_id"] = "OTHERTEAM1".into(),
                RecordError::TeamId,
            ),
            (
                "build id",
                |r| r["worker"]["build_id"] = "0.1.0+development".into(),
                RecordError::BuildId,
            ),
            (
                "file digest",
                |r| r["worker"]["file_sha256"] = "44".into(),
                RecordError::Digest,
            ),
            (
                "upper file digest",
                |r| r["worker"]["file_sha256"] = FILE.replace('4', "A").into(),
                RecordError::Digest,
            ),
            (
                "cdhash",
                |r| r["worker"]["slices"][0]["cdhash"] = "11".into(),
                RecordError::Digest,
            ),
            (
                "cdhash non-hex",
                |r| r["worker"]["slices"][0]["cdhash"] = CDHASH_ARM.replace('1', "g").into(),
                RecordError::Digest,
            ),
            (
                "full cdhash",
                |r| r["worker"]["slices"][0]["cdhash_sha256"] = CDHASH_ARM.into(),
                RecordError::Digest,
            ),
            (
                "arch",
                |r| r["worker"]["slices"][0]["arch"] = "arm64e".into(),
                RecordError::UnsupportedArchitecture,
            ),
            (
                "no slices",
                |r| r["worker"]["slices"] = serde_json::json!([]),
                RecordError::AmbiguousSlices,
            ),
            (
                "duplicate arch",
                |r| {
                    r["worker"]["slices"] = serde_json::json!([
                        { "arch": "arm64", "cdhash": CDHASH_ARM, "cdhash_sha256": FULL },
                        { "arch": "arm64", "cdhash": CDHASH_X86, "cdhash_sha256": FULL }
                    ])
                },
                RecordError::AmbiguousSlices,
            ),
            (
                "no native slice",
                |r| r["worker"]["slices"][0]["arch"] = "x86_64".into(),
                RecordError::MissingNativeSlice,
            ),
            (
                "unknown top-level",
                |r| r["extra"] = true.into(),
                RecordError::Malformed,
            ),
            (
                "unknown worker field",
                |r| r["worker"]["entitlements"] = "".into(),
                RecordError::Malformed,
            ),
            (
                "unknown slice field",
                |r| r["worker"]["slices"][0]["unique"] = "".into(),
                RecordError::Malformed,
            ),
            (
                "missing field",
                |r| {
                    if let Some(worker) = r["worker"].as_object_mut() {
                        worker.remove("build_id");
                    }
                },
                RecordError::Malformed,
            ),
            (
                "wrong type",
                |r| r["worker"]["slices"] = "arm64".into(),
                RecordError::Malformed,
            ),
        ];
        for (name, mutate, expected) in cases {
            let mut value = record();
            mutate(&mut value);
            assert_eq!(parse(&value).err(), Some(*expected), "{name}");
        }
    }

    #[test]
    fn malformed_duplicate_and_oversized_bytes_are_rejected() {
        let compiled = compiled(Architecture::Arm64);
        for raw in [
            &b""[..],
            b"null",
            b"[]",
            b"\xff\xfe",
            b"{\"schema\":\"fidomanager.release-worker-identity/1\"",
        ] {
            assert_eq!(
                ReleaseWorkerIdentity::parse(raw, &compiled).err(),
                Some(RecordError::Malformed)
            );
        }
        // Duplicate keys are ambiguous, never "last one wins".
        let text = String::from_utf8(bytes(&record())).unwrap_or_default();
        let duplicated = text.replacen(
            "\"schema\":",
            "\"schema\":\"fidomanager.release-worker-identity/1\",\"schema\":",
            1,
        );
        assert_eq!(
            ReleaseWorkerIdentity::parse(duplicated.as_bytes(), &compiled).err(),
            Some(RecordError::Malformed)
        );
        let mut padded = bytes(&record());
        padded.resize(MAX_RECORD_BYTES + 1, b' ');
        assert_eq!(
            ReleaseWorkerIdentity::parse(&padded, &compiled).err(),
            Some(RecordError::TooLarge)
        );
        let mut exactly = bytes(&record());
        exactly.resize(MAX_RECORD_BYTES, b' ');
        assert!(ReleaseWorkerIdentity::parse(&exactly, &compiled).is_ok());
    }

    #[test]
    fn secured_digest_must_be_64_lowercase_hex() {
        let good = "ab".repeat(32);
        assert_eq!(parse_record_digest(&good), Ok([0xab; 32]));
        for bad in [
            String::new(),
            "ab".repeat(31),
            "ab".repeat(33),
            "AB".repeat(32),
            format!("{}g", "a".repeat(63)),
            format!(" {}", "a".repeat(63)),
        ] {
            assert_eq!(
                parse_record_digest(&bad),
                Err(StartupRejection::SecuredDigestMalformed),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn digest_comparison_is_exact() {
        assert!(digests_equal(&[7; 32], &[7; 32]));
        let mut other = [7; 32];
        other[31] = 8;
        assert!(!digests_equal(&[7; 32], &other));
        other = [7; 32];
        other[0] = 0;
        assert!(!digests_equal(&[7; 32], &other));
    }

    /// Test environment: S1–S3 return a configured digest, S4 uses the production single-read
    /// file primitive on a real temporary file, and hooks run around S4 and inside S7.
    #[cfg(unix)]
    type FileHook = Option<Box<dyn FnMut(&std::path::Path)>>;

    #[cfg(unix)]
    struct FileEnvironment {
        digest: Result<[u8; 32], StartupRejection>,
        path: std::path::PathBuf,
        before_read: FileHook,
        during_worker_check: FileHook,
        reads: usize,
        worker: Result<(), StartupRejection>,
    }

    #[cfg(unix)]
    impl ReleaseStartupEnvironment for FileEnvironment {
        fn secured_record_digest(&mut self) -> Result<[u8; 32], StartupRejection> {
            self.digest
        }
        fn read_record_once(&mut self) -> Result<Vec<u8>, StartupRejection> {
            if let Some(hook) = self.before_read.as_mut() {
                hook(&self.path);
            }
            self.reads += 1;
            fido_platform::file_once::read_regular_once_bounded(&self.path, MAX_RECORD_BYTES)
                .map_err(|_| StartupRejection::RecordUnreadable)
        }
        fn verify_worker_on_disk(
            &mut self,
            _expected: &ReleaseWorkerIdentity,
        ) -> Result<(), StartupRejection> {
            if let Some(hook) = self.during_worker_check.as_mut() {
                hook(&self.path);
            }
            self.worker
        }
    }

    #[cfg(unix)]
    struct TempRecord(std::path::PathBuf);
    #[cfg(unix)]
    impl Drop for TempRecord {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn environment(name: &str, genuine: &[u8]) -> std::io::Result<(TempRecord, FileEnvironment)> {
        let directory =
            std::env::temp_dir().join(format!("fido-release-record-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory)?;
        let path = directory.join("release-worker-identity.json");
        std::fs::write(&path, genuine)?;
        Ok((
            TempRecord(directory),
            FileEnvironment {
                digest: Ok(Sha256::digest(genuine).into()),
                path,
                before_read: None,
                during_worker_check: None,
                reads: 0,
                worker: Ok(()),
            },
        ))
    }

    fn attacker_record() -> Vec<u8> {
        let mut attacker = record();
        attacker["worker"]["slices"][0]["cdhash"] = CDHASH_X86.into();
        bytes(&attacker)
    }

    #[cfg(unix)]
    #[test]
    fn genuine_record_is_authenticated_and_read_exactly_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let genuine = bytes(&record());
        let (_dir, mut env) = environment("genuine", &genuine)?;
        let identity = authenticate_release_worker(&mut env, &compiled(Architecture::Arm64))
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(identity.cdhash(), &[0x11; 20]);
        assert_eq!(env.reads, 1);
        Ok(())
    }

    /// ADR-017 validation A21, first half: attacker bytes in place for the S4 read are rejected
    /// at S5, even though the genuine file is restored afterwards.
    #[cfg(unix)]
    #[test]
    fn record_swapped_for_the_s4_read_is_rejected_at_s5() -> Result<(), Box<dyn std::error::Error>>
    {
        let genuine = bytes(&record());
        let (_dir, mut env) = environment("swap-s4", &genuine)?;
        let attacker = attacker_record();
        env.before_read = Some(Box::new(move |path| {
            let _ = std::fs::write(path, &attacker);
        }));
        let genuine_again = genuine.clone();
        env.during_worker_check = Some(Box::new(move |path| {
            let _ = std::fs::write(path, &genuine_again);
        }));
        assert_eq!(
            authenticate_release_worker(&mut env, &compiled(Architecture::Arm64)).err(),
            Some(StartupRejection::RecordDigestMismatch)
        );
        assert_eq!(env.reads, 1, "the genuine file is never re-read");
        Ok(())
    }

    /// ADR-017 validation A21, second half: a swap after S5 has no effect on `EXPECTED`.
    #[cfg(unix)]
    #[test]
    fn record_swapped_after_s5_cannot_change_expected() -> Result<(), Box<dyn std::error::Error>> {
        let genuine = bytes(&record());
        let (_dir, mut env) = environment("swap-after", &genuine)?;
        let attacker = attacker_record();
        env.during_worker_check = Some(Box::new(move |path| {
            let _ = std::fs::write(path, &attacker);
        }));
        let identity = authenticate_release_worker(&mut env, &compiled(Architecture::Arm64))
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            identity.cdhash(),
            &[0x11; 20],
            "EXPECTED comes from the authenticated BUF"
        );
        assert_eq!(env.reads, 1);
        assert_eq!(
            std::fs::read(&env.path)?,
            attacker_record(),
            "the swap did happen"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn digest_mismatch_oversize_symlink_and_worker_mismatch_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let genuine = bytes(&record());
        let compiled = compiled(Architecture::Arm64);

        let (_a, mut wrong_digest) = environment("wrong-digest", &genuine)?;
        wrong_digest.digest = Ok([0; 32]);
        assert_eq!(
            authenticate_release_worker(&mut wrong_digest, &compiled).err(),
            Some(StartupRejection::RecordDigestMismatch)
        );

        let mut oversized = genuine.clone();
        oversized.resize(MAX_RECORD_BYTES + 1, b' ');
        let (_b, mut too_big) = environment("oversized", &oversized)?;
        assert_eq!(
            authenticate_release_worker(&mut too_big, &compiled).err(),
            Some(StartupRejection::RecordUnreadable)
        );

        let (dir, mut linked) = environment("symlink", &genuine)?;
        let real = dir.0.join("real.json");
        std::fs::rename(&linked.path, &real)?;
        std::os::unix::fs::symlink(&real, &linked.path)?;
        assert_eq!(
            authenticate_release_worker(&mut linked, &compiled).err(),
            Some(StartupRejection::RecordUnreadable)
        );

        let (_c, mut missing_plist) = environment("no-plist", &genuine)?;
        missing_plist.digest = Err(StartupRejection::SecuredDigestMissing);
        assert_eq!(
            authenticate_release_worker(&mut missing_plist, &compiled).err(),
            Some(StartupRejection::SecuredDigestMissing)
        );
        assert_eq!(missing_plist.reads, 0, "nothing is read before S1–S3 pass");

        let (_d, mut worker) = environment("worker", &genuine)?;
        worker.worker = Err(StartupRejection::WorkerMismatch);
        assert_eq!(
            authenticate_release_worker(&mut worker, &compiled).err(),
            Some(StartupRejection::WorkerMismatch)
        );

        // A record that authenticates (its digest is the secured one) but names another release.
        let mut other_release = record();
        other_release["release"]["version"] = "9.9.9".into();
        other_release["worker"]["build_id"] = format!("9.9.9+{TEST_COMMIT}").into();
        let (_e, mut other) = environment("other-release", &bytes(&other_release))?;
        assert_eq!(
            authenticate_release_worker(&mut other, &compiled).err(),
            Some(StartupRejection::Record(RecordError::Version))
        );
        Ok(())
    }
}
