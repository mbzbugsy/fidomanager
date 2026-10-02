//! The harness must refuse to start when `FIDO_DEBUG` is present, before `fido_init()` and before
//! any device or terminal access. No device is needed: every case here exits before the first
//! native call.

use std::process::{Command, Output};

const HARNESS: &str = env!("CARGO_BIN_EXE_fido-puat-spike");
const SENTINEL: &str = "sentinel-debug-value-4e1c";

fn run(debug: Option<&str>) -> Result<Output, std::io::Error> {
    let mut command = Command::new(HARNESS);
    command.env_remove("FIDO_DEBUG");
    if let Some(value) = debug {
        command.env("FIDO_DEBUG", value);
    }
    command.output()
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn refuses_when_fido_debug_is_present_with_any_value() -> Result<(), std::io::Error> {
    for value in ["1", "", SENTINEL] {
        let output = run(Some(value))?;
        let text = combined(&output);
        assert_eq!(output.status.code(), Some(2), "value {value:?}");
        assert!(text.contains("FIDO_DEBUG"), "explains why");
        assert!(text.contains("refusing to run"));
        // Neither the usage text (which would mean it got past the check) nor the value appears.
        assert!(!text.contains("usage:"));
        assert!(
            !text.contains(SENTINEL),
            "the environment value must never be echoed"
        );
    }
    Ok(())
}

#[test]
fn proceeds_past_the_check_when_fido_debug_is_absent() -> Result<(), std::io::Error> {
    // No arguments: reaches the usage error (exit 1), never a device.
    let output = run(None)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(combined(&output).contains("usage:"));
    Ok(())
}
