//! Owned worker inventory. Raw identities stay in trusted code; Debug is deliberately redacted.
use serde::{Deserialize, Serialize};

pub const MAX_RPS: usize = 64;
pub const MAX_CREDENTIALS: usize = 128;
pub const MAX_RP_TEXT_BYTES: usize = 254;
pub const MAX_RP_SCAN_BYTES: usize = MAX_RP_TEXT_BYTES + 1;
pub const MAX_CREDENTIAL_ID_BYTES: usize = 512;
pub const MAX_USER_TEXT_BYTES: usize = 256;
pub const MAX_TOTAL_RP_TEXT_BYTES: usize = MAX_RPS * MAX_RP_TEXT_BYTES;
pub const MAX_TOTAL_ID_BYTES: usize = MAX_CREDENTIALS * MAX_CREDENTIAL_ID_BYTES;
pub const MAX_TOTAL_USER_TEXT_BYTES: usize = MAX_CREDENTIALS * MAX_USER_TEXT_BYTES * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Incomplete,
    Inconsistent,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CredentialTotal {
    Exact(u64),
    AtLeast(u64),
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpIssue {
    TextUnavailable,
    TextMalformed,
    TextHashMismatch,
    EnumerationFailed,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedCredential {
    pub id: Vec<u8>,
    pub user_name: Option<String>,
    pub display_name: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedRp {
    pub hash: [u8; 32],
    pub verified_text: Option<String>,
    pub issue: Option<RpIssue>,
    pub credentials: Vec<OwnedCredential>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedInventory {
    pub metadata_existing: u64,
    pub rps: Vec<OwnedRp>,
}
macro_rules! redacted_debug {
    ($($ty:ty),+) => {$(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($ty), "(<redacted>)"))
        }
    })+};
}
redacted_debug!(OwnedCredential, OwnedRp, OwnedInventory);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub completeness: Completeness,
    pub total: CredentialTotal,
    pub duplicate_rps: bool,
    pub duplicate_credentials: bool,
    pub count_contradiction: bool,
}
pub fn safe_text(text: &str, limit: usize) -> bool {
    !text.is_empty() && text.len() <= limit && !text.chars().any(|c| {
        c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    })
}
impl OwnedInventory {
    /// Independent service-side size/schema validation before any renderer snapshot is stored.
    pub fn within_bounds(&self) -> bool {
        let count: usize = self.rps.iter().map(|r| r.credentials.len()).sum();
        self.rps.len() <= MAX_RPS
            && count <= MAX_CREDENTIALS
            && self.rps.iter().all(|r| {
                r.verified_text
                    .as_ref()
                    .is_none_or(|t| safe_text(t, MAX_RP_TEXT_BYTES))
                    && (r.verified_text.is_some() || r.issue.is_some())
                    && (r.verified_text.is_some() || r.credentials.is_empty())
                    && r.credentials.iter().all(|c| {
                        !c.id.is_empty()
                            && c.id.len() <= MAX_CREDENTIAL_ID_BYTES
                            && [&c.user_name, &c.display_name].iter().all(|t| {
                                t.as_ref().is_none_or(|t| safe_text(t, MAX_USER_TEXT_BYTES))
                            })
                    })
            })
    }
    pub fn assess(&self) -> Assessment {
        let count = self
            .rps
            .iter()
            .map(|r| r.credentials.len() as u64)
            .sum::<u64>();
        let incomplete = self.rps.iter().any(|r| r.issue.is_some());
        let duplicate_rps = self
            .rps
            .iter()
            .enumerate()
            .any(|(i, r)| self.rps[..i].iter().any(|p| p.hash == r.hash));
        let mut ids = std::collections::HashSet::new();
        let duplicate_credentials = self
            .rps
            .iter()
            .flat_map(|r| &r.credentials)
            .any(|c| !ids.insert(&c.id));
        let count_contradiction = count > self.metadata_existing
            || (!incomplete && count != self.metadata_existing)
            || self
                .rps
                .iter()
                .any(|r| r.issue.is_none() && r.credentials.is_empty());
        let completeness = if duplicate_rps || duplicate_credentials || count_contradiction {
            Completeness::Inconsistent
        } else if incomplete {
            Completeness::Incomplete
        } else {
            Completeness::Complete
        };
        Assessment {
            completeness,
            total: match completeness {
                Completeness::Complete => CredentialTotal::Exact(count),
                Completeness::Incomplete => CredentialTotal::AtLeast(count),
                Completeness::Inconsistent => CredentialTotal::Unknown,
            },
            duplicate_rps,
            duplicate_credentials,
            count_contradiction,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionError {
    Unsupported,
    DeviceAbsent,
    Busy,
    AccessDenied,
    TimedOut,
    Malformed,
    BoundExceeded,
    NativeFailure,
    CleanupFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rp(issue: Option<RpIssue>) -> OwnedRp {
        OwnedRp {
            hash: [1; 32],
            verified_text: Some("example.com".into()),
            issue,
            credentials: vec![OwnedCredential {
                id: vec![1],
                user_name: None,
                display_name: None,
            }],
        }
    }
    #[test]
    fn typed_totals_and_duplicates_preserved() {
        let mut i = OwnedInventory {
            metadata_existing: 1,
            rps: vec![rp(None)],
        };
        assert_eq!(i.assess().total, CredentialTotal::Exact(1));
        i.rps[0].issue = Some(RpIssue::EnumerationFailed);
        assert_eq!(i.assess().total, CredentialTotal::AtLeast(1));
        i.rps.push(rp(None));
        i.metadata_existing = 2;
        assert_eq!(i.rps.len(), 2);
        assert_eq!(i.assess().completeness, Completeness::Inconsistent);
        assert_eq!(i.assess().total, CredentialTotal::Unknown); // raw count equality cannot win
        i.rps.pop();
        i.rps[0].issue = None;
        i.metadata_existing = 0;
        assert_eq!(i.assess().total, CredentialTotal::Unknown);
    }
    #[test]
    fn bounds_and_controls() {
        let mut i = OwnedInventory {
            metadata_existing: 1,
            rps: vec![rp(None)],
        };
        assert!(i.within_bounds());
        i.rps[0].credentials[0].id = vec![0; MAX_CREDENTIAL_ID_BYTES + 1];
        assert!(!i.within_bounds());
        assert!(!safe_text("abc\n", MAX_USER_TEXT_BYTES));
        assert!(!safe_text("abc\u{202e}", MAX_USER_TEXT_BYTES));
        i.rps[0].credentials.clear();
        i.rps[0].verified_text = None;
        assert!(!i.within_bounds());
    }
    #[test]
    fn unread_rp_preserves_hash_and_never_becomes_exact_zero() {
        for issue in [
            RpIssue::TextUnavailable,
            RpIssue::TextMalformed,
            RpIssue::TextHashMismatch,
            RpIssue::EnumerationFailed,
        ] {
            let i = OwnedInventory {
                metadata_existing: 4,
                rps: vec![OwnedRp {
                    hash: [7; 32],
                    verified_text: None,
                    issue: Some(issue),
                    credentials: Vec::new(),
                }],
            };
            assert!(i.within_bounds());
            assert_eq!(i.rps[0].hash, [7; 32]);
            assert_eq!(i.assess().completeness, Completeness::Incomplete);
            assert_eq!(i.assess().total, CredentialTotal::AtLeast(0));
        }
        let i = OwnedInventory {
            metadata_existing: 4,
            rps: Vec::new(),
        };
        assert_eq!(i.assess().total, CredentialTotal::Unknown);
        let mut i = OwnedInventory {
            metadata_existing: 0,
            rps: vec![rp(None)],
        };
        i.rps[0].credentials.clear();
        assert_eq!(i.assess().completeness, Completeness::Inconsistent);
    }
}
