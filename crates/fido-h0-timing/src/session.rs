//! Session directory: the only place H0 writes. Raw samples are JSON Lines so an interrupted
//! session keeps every completed sample and can be resumed.
//!
//! Guard: the directory must be new, empty, or already carry H0's own marker. A directory with
//! any other content (for example the application's real data directory, which holds the real
//! recovery journal) is refused before anything is written.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::environment::EnvironmentInfo;

pub const MARKER: &str = "h0-session.json";
pub const HARDWARE_SAMPLES: &str = "hardware-samples.jsonl";
pub const DURABILITY_SAMPLES: &str = "durability-samples.jsonl";
pub const SCRATCH: &str = "journal-scratch";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMarker {
    pub format: String,
    pub created_unix_secs: u64,
    pub environment: EnvironmentInfo,
}

pub struct Session {
    directory: PathBuf,
    pub marker: SessionMarker,
}

#[derive(Debug)]
pub enum SessionError {
    NotAbsolute,
    ForeignContent,
    Io(std::io::Error),
    Corrupt(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsolute => write!(f, "session directory must be an absolute path"),
            Self::ForeignContent => write!(
                f,
                "session directory is not empty and is not an H0 session; refusing to write there"
            ),
            Self::Io(error) => write!(f, "session I/O failed: {error}"),
            Self::Corrupt(what) => write!(f, "session file is not valid H0 data: {what}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

impl Session {
    pub fn open_or_create(
        directory: &Path,
        collect: impl FnOnce(&Path) -> EnvironmentInfo,
    ) -> Result<Self, SessionError> {
        if !directory.is_absolute() {
            return Err(SessionError::NotAbsolute);
        }
        let marker_path = directory.join(MARKER);
        match fs::symlink_metadata(directory) {
            Ok(meta) if !meta.is_dir() => return Err(SessionError::ForeignContent),
            Ok(_) => {
                if marker_path.is_file() {
                    let text = fs::read_to_string(&marker_path)?;
                    let marker: SessionMarker = serde_json::from_str(&text)
                        .map_err(|error| SessionError::Corrupt(error.to_string()))?;
                    if marker.format != crate::FORMAT {
                        return Err(SessionError::Corrupt("format".into()));
                    }
                    return Ok(Self {
                        directory: directory.to_owned(),
                        marker,
                    });
                }
                if fs::read_dir(directory)?.next().is_some() {
                    return Err(SessionError::ForeignContent);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_dir(directory)?;
            }
            Err(error) => return Err(error.into()),
        }
        let marker = SessionMarker {
            format: crate::FORMAT.into(),
            created_unix_secs: unix_now(),
            environment: collect(directory),
        };
        let text = serde_json::to_string_pretty(&marker)
            .map_err(|error| SessionError::Corrupt(error.to_string()))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path)?;
        file.write_all(text.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(Self {
            directory: directory.to_owned(),
            marker,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Root handed to the production `DurableRecoveryFile`, always inside this session.
    pub fn scratch_root(&self) -> PathBuf {
        self.directory.join(SCRATCH)
    }

    pub fn append<T: Serialize>(&self, name: &str, value: &T) -> Result<(), SessionError> {
        let mut line =
            serde_json::to_vec(value).map_err(|error| SessionError::Corrupt(error.to_string()))?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.directory.join(name))?;
        file.write_all(&line)?;
        file.flush()?;
        Ok(())
    }

    pub fn read_all<T: DeserializeOwned>(&self, name: &str) -> Result<Vec<T>, SessionError> {
        let path = self.directory.join(name);
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut values = Vec::new();
        for (number, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            values.push(serde_json::from_str(&line).map_err(|error| {
                SessionError::Corrupt(format!("{name} line {}: {error}", number + 1))
            })?);
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fido-h0-session-{name}-{}-{}",
            std::process::id(),
            unix_now()
        ))
    }

    fn env(_: &Path) -> EnvironmentInfo {
        crate::environment::collect(&std::env::temp_dir())
    }

    #[test]
    fn creates_resumes_and_appends() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp("resume");
        let session = Session::open_or_create(&dir, env)?;
        session.append(DURABILITY_SAMPLES, &serde_json::json!({"a": 1}))?;
        let again = Session::open_or_create(&dir, |_| -> EnvironmentInfo {
            panic!("an existing session must not be re-described")
        })?;
        assert_eq!(again.marker, session.marker);
        again.append(DURABILITY_SAMPLES, &serde_json::json!({"a": 2}))?;
        let values: Vec<serde_json::Value> = again.read_all(DURABILITY_SAMPLES)?;
        assert_eq!(values.len(), 2);
        assert!(again.scratch_root().starts_with(&dir));
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn refuses_foreign_or_relative_directories() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            Session::open_or_create(Path::new("relative/dir"), env),
            Err(SessionError::NotAbsolute)
        ));
        let dir = temp("foreign");
        fs::create_dir_all(dir.join("fido-authority-recovery-v1"))?;
        fs::write(
            dir.join("fido-authority-recovery-v1/incident.json"),
            b"real",
        )?;
        assert!(matches!(
            Session::open_or_create(&dir, env),
            Err(SessionError::ForeignContent)
        ));
        assert_eq!(
            fs::read(dir.join("fido-authority-recovery-v1/incident.json"))?,
            b"real"
        );
        assert!(!dir.join(MARKER).exists());
        let file = dir.join("plain-file");
        fs::write(&file, b"x")?;
        assert!(matches!(
            Session::open_or_create(&file, env),
            Err(SessionError::ForeignContent)
        ));
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn corrupt_lines_are_reported_not_skipped() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp("corrupt");
        let session = Session::open_or_create(&dir, env)?;
        fs::write(dir.join(HARDWARE_SAMPLES), b"{not json}\n")?;
        let result: Result<Vec<serde_json::Value>, _> = session.read_all(HARDWARE_SAMPLES);
        assert!(matches!(result, Err(SessionError::Corrupt(_))));
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
