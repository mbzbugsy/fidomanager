//! The worker closes descriptors it inherited from the service before doing anything else.

mod common;

use std::ffi::c_int;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

use common::{TestResult, fixture_path};

static FD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    let _guard = FD_TEST_LOCK.lock().map_err(|_| "descriptor test lock")?;
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

#[test]
fn secret_socket_is_not_inherited_by_unrelated_children() -> TestResult {
    let _guard = FD_TEST_LOCK.lock().map_err(|_| "descriptor test lock")?;
    let (before, _) = sweep_report(0)?;
    let mut intended = Command::new(fixture_path());
    let secret = fido_platform::process::secret_channel::attach(&mut intended)?;
    // Both parent endpoint and the child endpoint held inside pre_exec remain alive here. An
    // unrelated spawn must still see exactly the original descriptor inventory.
    let (during, second) = sweep_report(0)?;
    assert_eq!(before, during);
    assert_eq!(second, 0);
    drop(secret);
    drop(intended);
    Ok(())
}

#[test]
fn intended_auth_child_keeps_only_secret_fd_beside_stdio() -> TestResult {
    let _guard = FD_TEST_LOCK.lock().map_err(|_| "descriptor test lock")?;
    use fido_core::ExecutionQuiescence;
    use fido_service::{WorkerEndpoint, WorkerGeneration, WorkerLauncher};
    let source = File::open("/dev/null")?;
    // SAFETY: duplicate our live descriptor without CLOEXEC to model a native-library leak.
    let leak = unsafe { dup(source.as_raw_fd()) };
    assert!(leak > 3);
    let launched = common::launcher(&["--authentication"])?.launch(WorkerGeneration(1));
    // SAFETY: this test uniquely owns the leaked duplicate.
    unsafe { close(leak) };
    let mut endpoint = launched?;
    assert_eq!(endpoint.contain(), ExecutionQuiescence::Quiescent);
    Ok(())
}
