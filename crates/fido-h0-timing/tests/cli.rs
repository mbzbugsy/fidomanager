//! End-to-end CLI behaviour that needs no security key.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const BINARY: &str = env!("CARGO_BIN_EXE_fido-h0-timing");

fn temp(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("fido-h0-cli-{name}-{}-{nanos}", std::process::id()))
}

fn run(args: &[&str]) -> std::io::Result<Output> {
    Command::new(BINARY)
        .args(args)
        .env_remove("FIDO_DEBUG")
        .output()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[cfg(unix)]
#[test]
fn durability_session_produces_raw_samples_and_a_report() -> TestResult {
    let dir = temp("durability");
    let session = dir.to_str().ok_or("path")?;
    let output = run(&["durability", "--session", session, "--samples", "5"])?;
    assert!(output.status.success(), "{}", text(&output));
    let raw = fs::read_to_string(dir.join("durability-samples.jsonl"))?;
    assert_eq!(raw.lines().count(), 5);
    assert!(!raw.contains(session), "raw samples must not record paths");

    let output = run(&["report", "--session", session])?;
    assert!(output.status.success(), "{}", text(&output));
    let markdown = fs::read_to_string(dir.join("report.md"))?;
    assert!(markdown.contains("Durability only"));
    assert!(markdown.contains("| t5_durable_replace | 5 |"));
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("report.json"))?)?;
    assert_eq!(json["durability_only"]["count"], 5);
    assert_eq!(json["models"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        json["session"]["environment"]["libfido2_revision"]
            .as_str()
            .map(str::len),
        Some(40)
    );
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn refuses_a_directory_that_is_not_an_h0_session() -> TestResult {
    let dir = temp("foreign");
    fs::create_dir_all(dir.join("fido-authority-recovery-v1"))?;
    fs::write(
        dir.join("fido-authority-recovery-v1/incident.json"),
        b"real",
    )?;
    let output = run(&["durability", "--session", dir.to_str().ok_or("path")?])?;
    assert!(!output.status.success());
    assert!(text(&output).contains("not an H0 session"));
    assert_eq!(
        fs::read(dir.join("fido-authority-recovery-v1/incident.json"))?,
        b"real"
    );
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn refuses_libfido2_debug_logging_before_doing_anything() -> TestResult {
    let dir = temp("debug");
    let output = Command::new(BINARY)
        .args(["durability", "--session", dir.to_str().ok_or("path")?])
        .env("FIDO_DEBUG", "")
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output).contains("refusing to run"));
    assert!(!dir.exists());
    Ok(())
}

#[test]
fn has_no_destructive_or_dry_run_switch() -> TestResult {
    let help = run(&["help"])?;
    assert!(help.status.success());
    let usage = text(&help);
    for absent in ["--dry-run", "--execute", "--live", "--force", "reset "] {
        assert!(!usage.contains(absent), "{absent}");
    }
    for flag in ["--dry-run", "--execute", "--force"] {
        let output = run(&["measure", flag])?;
        assert_eq!(output.status.code(), Some(2), "{flag}");
        assert!(text(&output).contains("unknown option"));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[test]
fn hardware_measurement_is_unavailable_off_macos() -> TestResult {
    let dir = temp("measure");
    let output = run(&["measure", "--session", dir.to_str().ok_or("path")?])?;
    assert!(!output.status.success());
    assert!(text(&output).contains("macOS only"));
    Ok(())
}
