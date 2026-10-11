//! Trusted Foundation resolver. Never builds a Group Containers path or uses HOME/environment.
use fido_platform::authority_root::AuthorityRoot;
use objc2_foundation::{NSFileManager, NSString};
use std::{io, path::PathBuf};

pub fn resolve(identifier: &str) -> io::Result<AuthorityRoot> {
    let identifier = NSString::from_str(identifier);
    let url = NSFileManager::defaultManager()
        .containerURLForSecurityApplicationGroupIdentifier(&identifier)
        .ok_or_else(|| io::Error::other("App Group URL unavailable"))?;
    if !url.isFileURL() {
        return Err(io::Error::other("App Group URL is not local"));
    }
    let path = url
        .path()
        .ok_or_else(|| io::Error::other("App Group path unavailable"))?;
    AuthorityRoot::open_resolved(&PathBuf::from(path.to_string()))
}
