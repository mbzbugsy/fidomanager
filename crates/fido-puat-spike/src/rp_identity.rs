//! RP identity and enumeration-completeness contract for the M1.5 RP-hash spike (issue #12).
//!
//! Prototype only. It models the rules from the architecture plan (section 21) and the security
//! model (section 22) with the least machinery that can prove them; it is not the M3 credential
//! DTO model and nothing production depends on it.
//!
//! The rules, as types:
//!
//! - The authoritative identity of a relying party is the 32-byte RP ID hash returned by the
//!   authenticator. [`RpIdHash`] can only be built from exactly 32 bytes.
//! - RP ID text is a claim. It becomes [`RpTextState::VerifiedText`] only when
//!   `SHA-256(exact text bytes)` equals the authoritative hash. Absent, malformed or mismatching
//!   text is never turned into an RP ID, never defaults to an empty string, and is not retained.
//! - The only public libfido2 1.17.0 way to continue into credential enumeration takes RP ID
//!   *text* and hashes it itself (`fido_credman_get_dev_rk`). [`RpRecord::continuation`] therefore
//!   offers a continuation only for verified text; every other RP is an explicit blocker, not an
//!   RP with zero credentials.
//! - Duplicate authoritative hashes are kept, flagged, and never merged.
//! - [`assess`] reconciles what was enumerated with the authenticator's own credential count.
//!   `Complete` yields an `Exact` total. `Incomplete` (nothing contradictory, some credentials
//!   unread) yields an `AtLeast` lower bound, which is sound because the enumerated RPs have
//!   distinct hashes and so disjoint credential sets. `Inconsistent` (the observations contradict
//!   each other or the authenticator, so they may double-count) yields `Unknown`: no numeric
//!   claim at all. Nothing ever presents an apparently empty list.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::contract::RpId;

/// Length of an RP ID hash (SHA-256) in CTAP.
pub const RP_ID_HASH_LEN: usize = 32;

/// The authoritative RP ID hash exactly as the authenticator returned it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RpIdHash([u8; RP_ID_HASH_LEN]);

/// Why device-supplied hash bytes cannot be an [`RpIdHash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedHash {
    /// The authenticator response had no RP ID hash at all.
    Absent,
    /// The hash was present but not 32 bytes. The length is the only thing retained.
    WrongLength { len: usize },
}

impl fmt::Display for MalformedHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("RP ID hash absent"),
            Self::WrongLength { len } => write!(formatter, "RP ID hash is {len} bytes, not 32"),
        }
    }
}

impl std::error::Error for MalformedHash {}

impl RpIdHash {
    /// Accepts only exactly 32 bytes; never pads, truncates or guesses.
    pub fn from_device(bytes: Option<&[u8]>) -> Result<Self, MalformedHash> {
        let bytes = bytes.ok_or(MalformedHash::Absent)?;
        let array: [u8; RP_ID_HASH_LEN] = bytes
            .try_into()
            .map_err(|_| MalformedHash::WrongLength { len: bytes.len() })?;
        Ok(Self(array))
    }

    /// SHA-256 of the exact bytes given.
    pub fn of_text_bytes(text: &[u8]) -> Self {
        Self(Sha256::digest(text).into())
    }

    pub const fn as_bytes(&self) -> &[u8; RP_ID_HASH_LEN] {
        &self.0
    }
}

impl fmt::Debug for RpIdHash {
    // Hashes identify the services an account uses; keep them out of logs by default.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RpIdHash(<32 bytes>)")
    }
}

/// RP ID text whose SHA-256 equals the authoritative hash it is stored next to. Only
/// [`RpRecord::from_raw`] can construct one.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedRpId(RpId);

impl VerifiedRpId {
    /// NUL-terminated form for `fido_credman_get_dev_rk`. Its bytes hash to the authoritative
    /// hash, so libfido2's own hashing reproduces exactly the hash the authenticator reported.
    pub fn as_c_str(&self) -> &std::ffi::CStr {
        self.0.as_c_str()
    }
}

impl fmt::Debug for VerifiedRpId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "VerifiedRpId(<{} bytes>)",
            self.0.as_c_str().to_bytes().len()
        )
    }
}

/// What is known about the RP ID text of one RP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpTextState {
    /// Text present and `SHA-256(text) == authoritative hash`.
    VerifiedText(VerifiedRpId),
    /// The authenticator returned no RP ID text (libfido2 returns `NULL`). Not an empty string.
    TextUnavailable,
    /// Text present but its SHA-256 differs from the authoritative hash (truncated, altered,
    /// wrong encoding, ...). The text is discarded: it is not an identity and not a display
    /// fallback.
    TextHashMismatch,
    /// Text present but not usable as an RP ID at all (empty, over-long, or contains NUL), so it
    /// was not even compared.
    TextMalformed,
}

/// One RP as listed by `enumerateRPs`, as handed over by the adapter (copied out of libfido2
/// before `fido_credman_rp_free`).
#[derive(Debug, Clone, Copy, Default)]
pub struct RawRp<'a> {
    /// `fido_credman_rp_id_hash_ptr/len`; `None` when the pointer was `NULL`.
    pub hash: Option<&'a [u8]>,
    /// `fido_credman_rp_id`; `None` when the pointer was `NULL`. Distinct from `Some(b"")`.
    pub text: Option<&'a [u8]>,
}

/// An RP with a well-formed authoritative hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpRecord {
    hash: RpIdHash,
    text: RpTextState,
}

/// Why credential enumeration cannot be continued for an RP through the pinned public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuationBlocker {
    /// The RP has no well-formed authoritative hash, so there is no identity to enumerate.
    MalformedHash,
    /// No RP ID text; libfido2 1.17.0 has no entry point that takes only the hash.
    TextUnavailable,
    /// Text does not hash to the authoritative hash; continuing with it would enumerate a
    /// different RP.
    TextHashMismatch,
    /// Text unusable as an RP ID.
    TextMalformed,
}

/// How enumeration of one RP's credentials may proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Continuation<'a> {
    /// `fido_credman_get_dev_rk(dev, text, ...)`; libfido2 hashes the text to the same value.
    ViaVerifiedText(&'a VerifiedRpId),
    /// No safe public path. Callers must report incomplete / unsupported, never zero credentials.
    Blocked(ContinuationBlocker),
}

impl RpRecord {
    /// Builds a record from one raw RP. Fails only on a malformed authoritative hash.
    pub fn from_raw(raw: &RawRp<'_>) -> Result<Self, MalformedHash> {
        let hash = RpIdHash::from_device(raw.hash)?;
        let text = match raw.text {
            None => RpTextState::TextUnavailable,
            Some(bytes) => match std::str::from_utf8(bytes)
                .ok()
                .and_then(|text| RpId::new(text).ok())
            {
                None => RpTextState::TextMalformed,
                Some(rp_id) => {
                    if RpIdHash::of_text_bytes(bytes) == hash {
                        RpTextState::VerifiedText(VerifiedRpId(rp_id))
                    } else {
                        RpTextState::TextHashMismatch
                    }
                }
            },
        };
        Ok(Self { hash, text })
    }

    pub const fn hash(&self) -> &RpIdHash {
        &self.hash
    }

    pub const fn text(&self) -> &RpTextState {
        &self.text
    }

    pub fn continuation(&self) -> Continuation<'_> {
        match &self.text {
            RpTextState::VerifiedText(rp_id) => Continuation::ViaVerifiedText(rp_id),
            RpTextState::TextUnavailable => {
                Continuation::Blocked(ContinuationBlocker::TextUnavailable)
            }
            RpTextState::TextHashMismatch => {
                Continuation::Blocked(ContinuationBlocker::TextHashMismatch)
            }
            RpTextState::TextMalformed => Continuation::Blocked(ContinuationBlocker::TextMalformed),
        }
    }
}

/// One slot of the RP list, in authenticator order. Position is preserved so credential results
/// can be aligned and no entry is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpEntry {
    Identified(RpRecord),
    /// Listed by the authenticator but without a usable authoritative hash.
    MalformedHash(MalformedHash),
}

impl RpEntry {
    pub fn continuation(&self) -> Continuation<'_> {
        match self {
            Self::Identified(record) => record.continuation(),
            Self::MalformedHash(_) => Continuation::Blocked(ContinuationBlocker::MalformedHash),
        }
    }
}

/// A problem found while building the RP list. Any issue makes the list not-complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpListIssue {
    MalformedHash {
        index: usize,
    },
    /// Two entries report the same authoritative hash. Both are kept; neither is dropped.
    DuplicateHash {
        first: usize,
        duplicate: usize,
    },
}

/// The RP list exactly as enumerated: nothing deduplicated, nothing dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpList {
    entries: Vec<RpEntry>,
    issues: Vec<RpListIssue>,
}

impl RpList {
    pub fn from_raw(raw: &[RawRp<'_>]) -> Self {
        let mut entries = Vec::with_capacity(raw.len());
        let mut issues = Vec::new();
        for (index, rp) in raw.iter().enumerate() {
            match RpRecord::from_raw(rp) {
                Ok(record) => {
                    if let Some(first) = entries.iter().position(|entry| {
                        matches!(entry, RpEntry::Identified(other) if other.hash == record.hash)
                    }) {
                        issues.push(RpListIssue::DuplicateHash {
                            first,
                            duplicate: index,
                        });
                    }
                    entries.push(RpEntry::Identified(record));
                }
                Err(malformed) => {
                    issues.push(RpListIssue::MalformedHash { index });
                    entries.push(RpEntry::MalformedHash(malformed));
                }
            }
        }
        Self { entries, issues }
    }

    pub fn entries(&self) -> &[RpEntry] {
        &self.entries
    }

    pub fn issues(&self) -> &[RpListIssue] {
        &self.issues
    }
}

/// Outcome of enumerating one RP's credentials, as the adapter reports it. Only produced for
/// RPs whose [`Continuation`] was `ViaVerifiedText`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialEnumeration {
    /// `fido_credman_rk_count` after a successful `fido_credman_get_dev_rk`.
    Counted(u64),
    /// libfido2 returned an error code.
    Failed { code: i32 },
    /// Not attempted (always the case for a blocked continuation).
    NotAttempted,
}

/// Why an inspection is not [`Completeness::Complete`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncompleteReason {
    /// An entry in the RP list is malformed.
    MalformedRpHash { index: usize },
    /// RP `index` cannot be continued through the public API.
    ContinuationUnsupported {
        index: usize,
        blocker: ContinuationBlocker,
    },
    /// Enumerating RP `index` failed.
    EnumerationFailed { index: usize, code: i32 },
    /// A continuation was available but not performed.
    EnumerationNotAttempted { index: usize },
    /// The adapter supplied a different number of credential results than RP entries.
    ResultsMisaligned,
    /// The authenticator's credential count could not be read, so nothing can be reconciled.
    MetadataUnavailable,
    /// Fewer credentials were enumerated than the authenticator reports.
    Shortfall { enumerated: u64, reported: u64 },
}

/// Why an inspection contradicts itself (stronger than incomplete: the data cannot be trusted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InconsistentReason {
    /// The same authoritative hash was listed twice.
    DuplicateRpHash { first: usize, duplicate: usize },
    /// A listed RP enumerated zero credentials, which a listed RP cannot have. libfido2 also
    /// reports `FIDO_OK` with zero entries when the credential count is missing from the reply.
    ListedRpWithoutCredentials { index: usize },
    /// More credentials were enumerated than the authenticator reports.
    Surplus { enumerated: u64, reported: u64 },
    /// The enumerated total overflowed `u64`.
    TotalOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    Complete,
    Incomplete,
    Inconsistent,
}

/// What may be claimed about the number of credentials on the authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialTotal {
    /// The inspection is `Complete` and reconciled with the authenticator's own count.
    Exact(u64),
    /// The inspection is `Incomplete` with no contradictory evidence: at least this many
    /// credentials exist, the true number is unknown. Only the successfully enumerated, distinct
    /// RPs contribute, so this is a genuine lower bound.
    AtLeast(u64),
    /// The inspection is `Inconsistent`: the observations contradict each other or the
    /// authenticator (duplicate RP hashes may double-count, a surplus contradicts the reported
    /// count, a sum may have overflowed). No numeric bound is trustworthy.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub completeness: Completeness,
    /// The only credential count that may be shown or reasoned about.
    pub credentials: CredentialTotal,
    /// Sum of the per-RP counts as observed, **for diagnostics only**. It is not a bound of any
    /// kind: for an `Inconsistent` inspection it may double-count, and after an overflow it is
    /// the sum up to the overflow.
    pub observed_enumerated: u64,
    pub incomplete: Vec<IncompleteReason>,
    pub inconsistent: Vec<InconsistentReason>,
}

impl Assessment {
    /// The credential total only when the inspection is complete.
    pub const fn complete_total(&self) -> Option<u64> {
        match (self.completeness, self.credentials) {
            (Completeness::Complete, CredentialTotal::Exact(total)) => Some(total),
            _ => None,
        }
    }
}

/// Reconciles an RP list and per-RP credential results with the authenticator's reported count
/// (`getCredsMetadata.existingResidentCredentialsCount`).
///
/// `credentials` must have one element per entry of `list`. An empty list with a reported count of
/// zero is `Complete(0)`; an empty list with any other (or unknown) count is not.
pub fn assess(
    list: &RpList,
    credentials: &[CredentialEnumeration],
    reported_existing: Option<u64>,
) -> Assessment {
    let mut incomplete = Vec::new();
    let mut inconsistent = Vec::new();

    for issue in list.issues() {
        match *issue {
            RpListIssue::MalformedHash { index } => {
                incomplete.push(IncompleteReason::MalformedRpHash { index });
            }
            RpListIssue::DuplicateHash { first, duplicate } => {
                inconsistent.push(InconsistentReason::DuplicateRpHash { first, duplicate });
            }
        }
    }

    let aligned = credentials.len() == list.entries().len();
    if !aligned {
        incomplete.push(IncompleteReason::ResultsMisaligned);
    }

    let mut enumerated: u64 = 0;
    for (index, entry) in list.entries().iter().enumerate() {
        match entry.continuation() {
            Continuation::Blocked(ContinuationBlocker::MalformedHash) => {
                // Already reported as MalformedRpHash; one reason per fault.
            }
            Continuation::Blocked(blocker) => {
                incomplete.push(IncompleteReason::ContinuationUnsupported { index, blocker });
            }
            Continuation::ViaVerifiedText(_) => {
                match credentials.get(index).copied().filter(|_| aligned) {
                    Some(CredentialEnumeration::Counted(0)) => {
                        inconsistent.push(InconsistentReason::ListedRpWithoutCredentials { index });
                    }
                    Some(CredentialEnumeration::Counted(count)) => {
                        match enumerated.checked_add(count) {
                            Some(sum) => enumerated = sum,
                            None => inconsistent.push(InconsistentReason::TotalOverflow),
                        }
                    }
                    Some(CredentialEnumeration::Failed { code }) => {
                        incomplete.push(IncompleteReason::EnumerationFailed { index, code });
                    }
                    Some(CredentialEnumeration::NotAttempted) => {
                        incomplete.push(IncompleteReason::EnumerationNotAttempted { index });
                    }
                    None => {} // already reported as ResultsMisaligned
                }
            }
        }
    }

    match reported_existing {
        None => incomplete.push(IncompleteReason::MetadataUnavailable),
        Some(reported) if enumerated < reported => {
            incomplete.push(IncompleteReason::Shortfall {
                enumerated,
                reported,
            });
        }
        Some(reported) if enumerated > reported => {
            inconsistent.push(InconsistentReason::Surplus {
                enumerated,
                reported,
            });
        }
        Some(_) => {}
    }

    let completeness = if !inconsistent.is_empty() {
        Completeness::Inconsistent
    } else if !incomplete.is_empty() {
        Completeness::Incomplete
    } else {
        Completeness::Complete
    };
    let credentials = match completeness {
        Completeness::Complete => CredentialTotal::Exact(enumerated),
        Completeness::Incomplete => CredentialTotal::AtLeast(enumerated),
        Completeness::Inconsistent => CredentialTotal::Unknown,
    };
    Assessment {
        completeness,
        credentials,
        observed_enumerated: enumerated,
        incomplete,
        inconsistent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn hash_of(text: &str) -> [u8; 32] {
        *RpIdHash::of_text_bytes(text.as_bytes()).as_bytes()
    }

    fn identified(text: &str) -> Result<RpRecord, Box<dyn std::error::Error>> {
        let hash = hash_of(text);
        Ok(RpRecord::from_raw(&RawRp {
            hash: Some(&hash),
            text: Some(text.as_bytes()),
        })?)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            hex(RpIdHash::of_text_bytes(b"abc").as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(RpIdHash::of_text_bytes(b"localhost").as_bytes()),
            "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763"
        );
    }

    #[test]
    fn hash_that_is_not_32_bytes_is_malformed_and_never_padded() {
        for len in [0, 1, 20, 31, 33, 64] {
            let bytes = vec![0xAB; len];
            assert_eq!(
                RpIdHash::from_device(Some(&bytes)),
                Err(MalformedHash::WrongLength { len }),
                "len {len}"
            );
        }
        assert_eq!(RpIdHash::from_device(None), Err(MalformedHash::Absent));
        assert!(RpIdHash::from_device(Some(&[0u8; 32])).is_ok());
    }

    #[test]
    fn matching_text_and_hash_verify() -> TestResult {
        let record = identified("example.com")?;
        assert!(matches!(record.text(), RpTextState::VerifiedText(_)));
        let Continuation::ViaVerifiedText(rp_id) = record.continuation() else {
            return Err("verified text must allow continuation".into());
        };
        assert_eq!(rp_id.as_c_str().to_bytes(), b"example.com");
        // The text libfido2 would hash is exactly the authoritative hash.
        assert_eq!(
            RpIdHash::of_text_bytes(rp_id.as_c_str().to_bytes()),
            *record.hash()
        );
        Ok(())
    }

    #[test]
    fn mismatching_text_never_verifies_and_is_not_retained() -> TestResult {
        let hash = hash_of("example.com");
        for text in [
            "example.org",
            "Example.com",  // case is part of the exact bytes
            "example.com ", // trailing byte
            "example.co",   // truncated
            "xn--exmple-cua.com",
        ] {
            let record = RpRecord::from_raw(&RawRp {
                hash: Some(&hash),
                text: Some(text.as_bytes()),
            })?;
            assert_eq!(record.text(), &RpTextState::TextHashMismatch, "{text}");
            assert_eq!(
                record.continuation(),
                Continuation::Blocked(ContinuationBlocker::TextHashMismatch)
            );
            assert!(!format!("{record:?}").contains(text));
        }
        Ok(())
    }

    #[test]
    fn text_matching_another_rps_hash_is_a_mismatch_here() -> TestResult {
        // The hash is authoritative: text matching some *other* RP's hash is a mismatch here.
        let other = hash_of("other.example");
        let record = RpRecord::from_raw(&RawRp {
            hash: Some(&other),
            text: Some(b"example.com"),
        })?;
        assert_eq!(record.text(), &RpTextState::TextHashMismatch);
        Ok(())
    }

    #[test]
    fn absent_text_is_unavailable_and_never_an_empty_string() -> TestResult {
        let hash = hash_of("example.com");
        let absent = RpRecord::from_raw(&RawRp {
            hash: Some(&hash),
            text: None,
        })?;
        assert_eq!(absent.text(), &RpTextState::TextUnavailable);
        assert_eq!(
            absent.continuation(),
            Continuation::Blocked(ContinuationBlocker::TextUnavailable)
        );

        // Present-but-empty is a different, malformed state (it is not "absent").
        let empty = RpRecord::from_raw(&RawRp {
            hash: Some(&hash_of("")),
            text: Some(b""),
        })?;
        assert_eq!(empty.text(), &RpTextState::TextMalformed);
        assert!(matches!(
            empty.continuation(),
            Continuation::Blocked(ContinuationBlocker::TextMalformed)
        ));
        Ok(())
    }

    #[test]
    fn unusable_text_is_malformed_even_if_its_bytes_hash_correctly() -> TestResult {
        let invalid_utf8: &[u8] = &[0xFF, 0xFE, b'a'];
        let embedded_nul: &[u8] = b"exa\0mple.com";
        let too_long = "a".repeat(crate::contract::MAX_RP_ID_BYTES + 1);
        for text in [invalid_utf8, embedded_nul, too_long.as_bytes()] {
            let hash = *RpIdHash::of_text_bytes(text).as_bytes();
            let record = RpRecord::from_raw(&RawRp {
                hash: Some(&hash),
                text: Some(text),
            })?;
            assert_eq!(record.text(), &RpTextState::TextMalformed);
            assert!(matches!(
                record.continuation(),
                Continuation::Blocked(ContinuationBlocker::TextMalformed)
            ));
        }
        Ok(())
    }

    #[test]
    fn malformed_hash_makes_the_rp_list_incomplete_and_keeps_its_slot() {
        let good = hash_of("example.com");
        let short = [1u8; 20];
        let list = RpList::from_raw(&[
            RawRp {
                hash: Some(&good),
                text: Some(b"example.com"),
            },
            RawRp {
                hash: Some(&short),
                text: Some(b"example.com"), // text must not rescue a malformed hash
            },
            RawRp {
                hash: None,
                text: Some(b"example.com"),
            },
        ]);
        assert_eq!(list.entries().len(), 3);
        assert_eq!(
            list.issues(),
            &[
                RpListIssue::MalformedHash { index: 1 },
                RpListIssue::MalformedHash { index: 2 }
            ]
        );
        assert!(matches!(
            list.entries()[1],
            RpEntry::MalformedHash(MalformedHash::WrongLength { len: 20 })
        ));
        assert!(matches!(
            list.entries()[2],
            RpEntry::MalformedHash(MalformedHash::Absent)
        ));
        let assessment = assess(
            &list,
            &[
                CredentialEnumeration::Counted(2),
                CredentialEnumeration::NotAttempted,
                CredentialEnumeration::NotAttempted,
            ],
            Some(2),
        );
        assert_eq!(assessment.completeness, Completeness::Incomplete);
        assert_eq!(assessment.complete_total(), None);
        assert_eq!(assessment.credentials, CredentialTotal::AtLeast(2));
    }

    #[test]
    fn duplicate_authoritative_hashes_are_kept_and_flagged_never_deduplicated() {
        let hash = hash_of("example.com");
        let raw = RawRp {
            hash: Some(&hash),
            text: Some(b"example.com"),
        };
        let list = RpList::from_raw(&[raw, raw]);
        assert_eq!(list.entries().len(), 2, "no silent deduplication");
        assert_eq!(
            list.issues(),
            &[RpListIssue::DuplicateHash {
                first: 0,
                duplicate: 1
            }]
        );
        // Even with counts that add up, a duplicate hash is never Complete.
        let assessment = assess(
            &list,
            &[
                CredentialEnumeration::Counted(1),
                CredentialEnumeration::Counted(1),
            ],
            Some(2),
        );
        assert_eq!(assessment.completeness, Completeness::Inconsistent);
        assert_eq!(
            assessment.inconsistent,
            vec![InconsistentReason::DuplicateRpHash {
                first: 0,
                duplicate: 1
            }]
        );
        assert_eq!(assessment.complete_total(), None);
        // The same credentials may have been counted twice: no numeric bound at all.
        assert_eq!(assessment.credentials, CredentialTotal::Unknown);
        assert_eq!(assessment.observed_enumerated, 2, "diagnostic only");
    }

    #[test]
    fn hash_only_rp_is_unsupported_not_zero_credentials() {
        let known = hash_of("example.com");
        let hidden = hash_of("hidden.example");
        let list = RpList::from_raw(&[
            RawRp {
                hash: Some(&known),
                text: Some(b"example.com"),
            },
            RawRp {
                hash: Some(&hidden),
                text: None,
            },
        ]);
        // Enumeration of the second RP cannot be continued, so the adapter has nothing to report.
        let assessment = assess(
            &list,
            &[
                CredentialEnumeration::Counted(1),
                CredentialEnumeration::NotAttempted,
            ],
            Some(3),
        );
        assert_eq!(assessment.completeness, Completeness::Incomplete);
        assert_eq!(assessment.credentials, CredentialTotal::AtLeast(1));
        assert_eq!(assessment.complete_total(), None);
        assert!(
            assessment
                .incomplete
                .contains(&IncompleteReason::ContinuationUnsupported {
                    index: 1,
                    blocker: ContinuationBlocker::TextUnavailable
                })
        );
        assert!(
            assessment
                .incomplete
                .contains(&IncompleteReason::Shortfall {
                    enumerated: 1,
                    reported: 3
                })
        );
    }

    #[test]
    fn a_blocked_rp_stays_incomplete_even_if_the_counts_happen_to_reconcile() {
        // If every credential were somehow accounted for, a blocked RP would still have been
        // unreadable: Complete requires every listed RP to have been enumerated.
        let hash = hash_of("hidden.example");
        let list = RpList::from_raw(&[RawRp {
            hash: Some(&hash),
            text: None,
        }]);
        let assessment = assess(&list, &[CredentialEnumeration::NotAttempted], Some(0));
        assert_eq!(assessment.completeness, Completeness::Incomplete);
        assert_eq!(assessment.complete_total(), None);
    }

    #[test]
    fn counts_that_do_not_reconcile_are_never_complete() {
        let hash = hash_of("example.com");
        let list = RpList::from_raw(&[RawRp {
            hash: Some(&hash),
            text: Some(b"example.com"),
        }]);
        let counted = [CredentialEnumeration::Counted(2)];

        let exact = assess(&list, &counted, Some(2));
        assert_eq!(exact.completeness, Completeness::Complete);
        assert_eq!(exact.complete_total(), Some(2));

        let shortfall = assess(&list, &counted, Some(3));
        assert_eq!(shortfall.completeness, Completeness::Incomplete);
        assert_eq!(shortfall.credentials, CredentialTotal::AtLeast(2));
        assert_eq!(shortfall.complete_total(), None);

        let surplus = assess(&list, &counted, Some(1));
        assert_eq!(surplus.completeness, Completeness::Inconsistent);
        assert_eq!(
            surplus.inconsistent,
            vec![InconsistentReason::Surplus {
                enumerated: 2,
                reported: 1
            }]
        );
        // AtLeast(2) would contradict the authenticator's own count of 1.
        assert_eq!(surplus.credentials, CredentialTotal::Unknown);
        assert_eq!(surplus.complete_total(), None);

        let unknown = assess(&list, &counted, None);
        assert_eq!(unknown.completeness, Completeness::Incomplete);
        assert_eq!(
            unknown.incomplete,
            vec![IncompleteReason::MetadataUnavailable]
        );
    }

    #[test]
    fn empty_rp_list_is_complete_only_when_the_authenticator_reports_zero() {
        let empty = RpList::from_raw(&[]);
        // libfido2 returns FIDO_OK with zero RPs both for "no credentials" (after the device's
        // NO_CREDENTIALS error is mapped by the caller) and when `totalRPs` is missing.
        let zero = assess(&empty, &[], Some(0));
        assert_eq!(zero.completeness, Completeness::Complete);
        assert_eq!(zero.complete_total(), Some(0));

        let contradicted = assess(&empty, &[], Some(4));
        assert_eq!(contradicted.completeness, Completeness::Incomplete);
        assert_eq!(contradicted.complete_total(), None);
        assert_eq!(contradicted.credentials, CredentialTotal::AtLeast(0));

        assert_eq!(
            assess(&empty, &[], None).completeness,
            Completeness::Incomplete
        );
    }

    #[test]
    fn listed_rp_with_zero_credentials_is_inconsistent() {
        let hash = hash_of("example.com");
        let list = RpList::from_raw(&[RawRp {
            hash: Some(&hash),
            text: Some(b"example.com"),
        }]);
        // libfido2 returns FIDO_OK and a zero count if the credential count key is missing.
        let assessment = assess(&list, &[CredentialEnumeration::Counted(0)], Some(0));
        assert_eq!(assessment.completeness, Completeness::Inconsistent);
        assert_eq!(
            assessment.inconsistent,
            vec![InconsistentReason::ListedRpWithoutCredentials { index: 0 }]
        );
        assert_eq!(assessment.complete_total(), None);
        assert_eq!(assessment.credentials, CredentialTotal::Unknown);
    }

    #[test]
    fn failed_enumeration_is_incomplete_with_a_lower_bound() {
        let a = hash_of("a.example");
        let b = hash_of("b.example");
        let list = RpList::from_raw(&[
            RawRp {
                hash: Some(&a),
                text: Some(b"a.example"),
            },
            RawRp {
                hash: Some(&b),
                text: Some(b"b.example"),
            },
        ]);
        let assessment = assess(
            &list,
            &[
                CredentialEnumeration::Counted(1),
                CredentialEnumeration::Failed { code: 0x2e },
            ],
            Some(2),
        );
        assert_eq!(assessment.completeness, Completeness::Incomplete);
        assert_eq!(assessment.credentials, CredentialTotal::AtLeast(1));
        assert!(
            assessment
                .incomplete
                .contains(&IncompleteReason::EnumerationFailed {
                    index: 1,
                    code: 0x2e
                })
        );
    }

    #[test]
    fn misaligned_results_are_incomplete_not_guessed() {
        let hash = hash_of("example.com");
        let list = RpList::from_raw(&[RawRp {
            hash: Some(&hash),
            text: Some(b"example.com"),
        }]);
        let assessment = assess(&list, &[], Some(0));
        assert_eq!(assessment.completeness, Completeness::Incomplete);
        assert!(
            assessment
                .incomplete
                .contains(&IncompleteReason::ResultsMisaligned)
        );
    }

    #[test]
    fn total_overflow_is_inconsistent() {
        let a = hash_of("a.example");
        let b = hash_of("b.example");
        let list = RpList::from_raw(&[
            RawRp {
                hash: Some(&a),
                text: Some(b"a.example"),
            },
            RawRp {
                hash: Some(&b),
                text: Some(b"b.example"),
            },
        ]);
        let assessment = assess(
            &list,
            &[
                CredentialEnumeration::Counted(u64::MAX),
                CredentialEnumeration::Counted(1),
            ],
            Some(u64::MAX),
        );
        assert_eq!(assessment.completeness, Completeness::Inconsistent);
        assert!(
            assessment
                .inconsistent
                .contains(&InconsistentReason::TotalOverflow)
        );
        assert_eq!(assessment.credentials, CredentialTotal::Unknown);
        assert_eq!(assessment.complete_total(), None);
    }

    #[test]
    fn total_claims_follow_completeness_and_inconsistency_wins_over_incomplete() {
        let a = hash_of("a.example");
        let hidden = hash_of("hidden.example");
        let a_rp = RawRp {
            hash: Some(&a),
            text: Some(b"a.example"),
        };
        let hidden_rp = RawRp {
            hash: Some(&hidden),
            text: None,
        };

        // Complete -> Exact.
        let complete = assess(
            &RpList::from_raw(&[a_rp]),
            &[CredentialEnumeration::Counted(3)],
            Some(3),
        );
        assert_eq!(complete.credentials, CredentialTotal::Exact(3));

        // Incomplete with nothing contradictory -> a genuine lower bound.
        let incomplete = assess(
            &RpList::from_raw(&[a_rp, hidden_rp]),
            &[
                CredentialEnumeration::Counted(3),
                CredentialEnumeration::NotAttempted,
            ],
            Some(5),
        );
        assert_eq!(incomplete.completeness, Completeness::Incomplete);
        assert_eq!(incomplete.credentials, CredentialTotal::AtLeast(3));

        // The same incomplete inspection plus a duplicate hash: the lower bound is no longer
        // defensible, so no number is claimed.
        let contradicted = assess(
            &RpList::from_raw(&[a_rp, a_rp, hidden_rp]),
            &[
                CredentialEnumeration::Counted(3),
                CredentialEnumeration::Counted(3),
                CredentialEnumeration::NotAttempted,
            ],
            Some(9),
        );
        assert_eq!(contradicted.completeness, Completeness::Inconsistent);
        assert!(
            !contradicted.incomplete.is_empty(),
            "both kinds are reported"
        );
        assert_eq!(contradicted.credentials, CredentialTotal::Unknown);
        assert_eq!(contradicted.complete_total(), None);
    }

    #[test]
    fn debug_output_never_contains_hash_or_text() -> TestResult {
        let record = identified("secret-service.example")?;
        let rendered = format!("{record:?} {:?}", record.hash());
        assert!(!rendered.contains("secret-service"));
        assert!(!rendered.contains(&hex(record.hash().as_bytes())));
        Ok(())
    }
}
