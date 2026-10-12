//! MAS.2 release identity policy. It never accepts values from a worker or runtime input.
pub(crate) const WORKER_PREFIX: &str = "eu.fidomanager.desktop.mas.fido-worker";

pub(crate) fn release_identifier(version: &str, commit: &str) -> Option<String> {
    // First-release policy: canonical X.Y.Z, full lowercase source commit, fixed MAS flavor.
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
        || !fido_platform::build_identity::is_lower_hex(commit, 40)
    {
        return None;
    }
    Some(format!("{WORKER_PREFIX}.{version}.{commit}.mas"))
}

pub(crate) fn publisher_requirement(version: &str, commit: &str) -> Option<String> {
    let identifier = release_identifier(version, commit)?;
    // Apple TN3127's Mac App Store leaf. Team is checked independently in CodeDirectory
    // signing information, NOT via the Developer ID certificate subject.OU rule.
    Some(format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[field.1.2.840.113635.100.6.1.9]"
    ))
}

pub(crate) fn thin_arm64_header(header: &[u8]) -> bool {
    header.len() == 32
        && header[..4] == [0xcf, 0xfa, 0xed, 0xfe]
        && header[4..8] == 0x0100_000cu32.to_le_bytes() // CPU_TYPE_ARM64
        && header[8..12] == 0u32.to_le_bytes() // CPU_SUBTYPE_ARM64_ALL, not arm64e
        && header[12..16] == 2u32.to_le_bytes() // MH_EXECUTE
}

#[cfg(test)]
mod tests {
    use super::*;
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    #[test]
    fn release_binds_version_commit_flavor_and_store_publisher_only() {
        let id = release_identifier("0.1.0", COMMIT).unwrap_or_default();
        assert_eq!(
            id,
            format!("eu.fidomanager.desktop.mas.fido-worker.0.1.0.{COMMIT}.mas")
        );
        assert_ne!(release_identifier("0.0.9", COMMIT), Some(id.clone()));
        assert_ne!(
            release_identifier("0.1.0", &"a".repeat(40)),
            Some(id.clone())
        );
        let requirement = publisher_requirement("0.1.0", COMMIT).unwrap_or_default();
        assert!(requirement.contains("anchor apple generic"));
        assert!(requirement.contains(&format!("identifier \"{id}\"")));
        assert!(requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.9]"));
        assert!(!requirement.contains("subject.OU") && !requirement.contains(" or "));
        assert!(!requirement.contains("100.6.1.13"));
        for version in [
            "",
            "01.0.0",
            "1.2",
            "1.2.3.mas",
            "1.2.3\" or anchor apple",
            "1.2.3-beta",
        ] {
            assert!(release_identifier(version, COMMIT).is_none());
        }
        for commit in [
            "development",
            "unprovisioned",
            "ABCDEF0123456789abcdef0123456789abcdef0123",
        ] {
            assert!(release_identifier("0.1.0", commit).is_none());
        }
    }
    #[test]
    fn architecture_rejects_fat_other_slice_arm64e_non_executable_and_truncation() {
        let mut header = [0; 32];
        header[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        header[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        header[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert!(thin_arm64_header(&header));
        for (offset, bytes) in [
            (0, [0xca, 0xfe, 0xba, 0xbe]),
            (0, [0xca, 0xfe, 0xba, 0xbf]),
            (4, 0x0100_0007u32.to_le_bytes()),
            (8, 2u32.to_le_bytes()),
            (12, 6u32.to_le_bytes()),
        ] {
            let mut wrong = header;
            wrong[offset..offset + 4].copy_from_slice(&bytes);
            assert!(!thin_arm64_header(&wrong));
        }
        assert!(!thin_arm64_header(&header[..31]));
    }
}
