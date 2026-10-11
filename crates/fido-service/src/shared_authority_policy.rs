#![cfg(any(
    test,
    all(
        target_os = "macos",
        any(feature = "macos-release-signing", feature = "macos-shared-authority")
    )
))]
//! Maintainer-approved source policy (Issue #38); no credentials or identity derivation.
pub(crate) const GROUP_IDENTIFIER: &str = "7VGK9SN42B.eu.fidomanager.authority";
#[cfg(any(test, feature = "macos-shared-authority"))]
pub(crate) const STORE_IDENTIFIER: &str = "eu.fidomanager.desktop.mas";

#[cfg(test)]
mod tests {
    #[test]
    fn group_uses_the_single_reviewed_release_identity() {
        let team = crate::worker_authenticity::MACOS_RELEASE_TEAM_ID
            .unwrap_or_else(|| panic!("reviewed Team ID"));
        assert_eq!(
            super::GROUP_IDENTIFIER,
            format!("{team}.eu.fidomanager.authority")
        );
        assert_eq!(super::STORE_IDENTIFIER, "eu.fidomanager.desktop.mas");
    }
}
