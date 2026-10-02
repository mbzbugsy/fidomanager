//! The worker closes descriptors it inherited from the service before doing anything else.

mod common;

use std::ffi::c_int;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

use common::{TestResult, fixture_path};

unsafe extern "C" {
    fn dup(fd: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}

fn sweep_report(
    extra_leaked_descriptors: usize,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    // `dup` yields descriptors WITHOUT close-on-exec, which is exactly what a C library inside the
    // service (WebKit, IOKit, ...) can leak into a spawned child.
    let source = File::open("/dev/null")?;
    let mut leaked = Vec::new();
    for _ in 0..extra_leaked_descriptors {
        // SAFETY: duplicating a descriptor this test owns is memory-safe; the copy is closed below.
        let fd = unsafe { dup(source.as_raw_fd()) };
        assert!(fd > 2, "dup failed");
        leaked.push(fd);
    }

    let output = Command::new(fixture_path())
        .arg("--raw=fds")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();

    for fd in leaked {
        // SAFETY: closing a descriptor this test opened above.
        unsafe { close(fd) };
    }

    let output = output?;
    let text = String::from_utf8(output.stdout)?;
    let mut first = None;
    let mut second = None;
    for field in text.split_whitespace() {
        if let Some(value) = field.strip_prefix("first=") {
            first = value.parse::<usize>().ok();
        } else if let Some(value) = field.strip_prefix("second=") {
            second = value.parse::<usize>().ok();
        }
    }
    Ok((
        first.ok_or("no first= in fixture output")?,
        second.ok_or("no second= in fixture output")?,
    ))
}

#[test]
fn inherited_descriptors_are_closed_at_startup_and_nothing_remains() -> TestResult {
    let (clean_first, clean_second) = sweep_report(0)?;
    let (leaky_first, leaky_second) = sweep_report(3)?;

    assert_eq!(clean_second, 0);
    assert_eq!(
        leaky_first,
        clean_first + 3,
        "all three leaked descriptors must be closed by the sweep"
    );
    assert_eq!(
        leaky_second, 0,
        "a second sweep finds nothing left to close"
    );
    Ok(())
}
