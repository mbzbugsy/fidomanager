//! Single-open, no-follow reads of files the release startup authenticates (ADR-017 §5.8 S4).
//!
//! The final path component is opened with `O_NOFOLLOW`, so a symlink there fails the open, and
//! the type and size checks use `fstat` on the opened descriptor, so they describe exactly the
//! bytes that are read. The bytes are read once; callers never re-open the path to re-read it.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Opens `path` read-only without following a final symlink and requires a regular file.
pub fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// Reads the whole regular file at `path` exactly once into memory, refusing anything larger than
/// `max_bytes` (both by `fstat` size and by the bytes actually read, in case it grows).
pub fn read_regular_once_bounded(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let file = open_regular_nofollow(path)?;
    let declared = file.metadata()?.len();
    if declared > max_bytes as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    let mut buffer = Vec::with_capacity(max_bytes.min(declared as usize));
    // One byte past the bound proves the file grew beyond it.
    file.take(max_bytes as u64 + 1).read_to_end(&mut buffer)?;
    if buffer.len() > max_bytes {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn dir(name: &str) -> io::Result<Dir> {
        let path =
            std::env::temp_dir().join(format!("fido-file-once-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        Ok(Dir(path))
    }

    #[test]
    fn regular_file_within_bound_is_read() -> io::Result<()> {
        let d = dir("ok")?;
        let file = d.0.join("record.json");
        std::fs::write(&file, b"{}")?;
        assert_eq!(read_regular_once_bounded(&file, 4096)?, b"{}");
        std::fs::write(&file, vec![b'x'; 4096])?;
        assert_eq!(read_regular_once_bounded(&file, 4096)?.len(), 4096);
        Ok(())
    }

    #[test]
    fn oversized_symlink_directory_and_missing_are_rejected() -> io::Result<()> {
        let d = dir("bad")?;
        let file = d.0.join("record.json");
        std::fs::write(&file, vec![b'x'; 4097])?;
        assert!(read_regular_once_bounded(&file, 4096).is_err());

        let target = d.0.join("target.json");
        std::fs::write(&target, b"{}")?;
        let link = d.0.join("link.json");
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(read_regular_once_bounded(&link, 4096).is_err());

        assert!(read_regular_once_bounded(&d.0, 4096).is_err());
        assert!(read_regular_once_bounded(&d.0.join("missing"), 4096).is_err());
        Ok(())
    }
}
