//! A worker must not outlive the service, even when it is blocked inside native code.
//!
//! The service is simulated by re-executing this very test binary as a helper "parent" process
//! (selected by an environment variable) that spawns a real worker and reports its pid. The outer
//! test then SIGKILLs that parent, so nothing gets to run cleanup code, and checks that the worker
//! disappears on its own.

mod common;

use std::ffi::c_int;
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use common::{TestResult, fixture_path, launch, list_request, pid_running, wait_until};
use fido_service::{WorkerEndpoint, WorkerGeneration};
use fido_worker_protocol::{
    ChildHello, MAX_WORKER_HANDSHAKE_FRAME_BYTES, ParentHello, read_message, write_message,
};

const ROLE_VARIABLE: &str = "FIDO_FIXTURE_ORPHAN_ROLE";

unsafe extern "C" {
    fn dup(fd: c_int) -> c_int;
}

/// Not a real test: the body of the helper parent process. A no-op in a normal test run.
#[test]
fn orphan_parent_role() -> TestResult {
    let Ok(role) = std::env::var(ROLE_VARIABLE) else {
        return Ok(());
    };

    match role.as_str() {
        "idle" => {
            let endpoint = launch(&["--script=ok", "--tag=orphan-idle"], 1)?;
            announce(&format!("READY worker={}", endpoint.worker_pid()));
            thread::sleep(Duration::from_secs(120));
        }
        "blocked" => {
            let mut endpoint = launch(&["--script=hang", "--tag=orphan-blocked"], 1)?;
            let pid = endpoint.worker_pid();
            // Park the worker inside its (fake) native call with a request that outlives the test.
            let blocker = thread::spawn(move || {
                let _ = endpoint.exchange(list_request(1, 1, 120_000));
            });
            thread::sleep(Duration::from_millis(500));
            announce(&format!("READY worker={pid}"));
            let _ = blocker.join();
        }
        "pipe-held-open" => {
            // Spawn a worker by hand so a *second* process can keep a copy of the pipe's write
            // end alive: the worker then never sees EOF when this parent dies, and only the
            // parent-pid watchdog can save it.
            let mut child = Command::new(fixture_path())
                .args(["--script=ok", "--tag=orphan-pipe"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;
            let worker = child.id();
            let mut stdin = child.stdin.take().ok_or("no stdin")?;
            let mut stdout = child.stdout.take().ok_or("no stdout")?;

            write_message(
                &mut stdin,
                &ParentHello::new(WorkerGeneration(1), std::process::id()),
                MAX_WORKER_HANDSHAKE_FRAME_BYTES,
            )?;
            let _reply: ChildHello = read_message(&mut stdout, MAX_WORKER_HANDSHAKE_FRAME_BYTES)?;

            // SAFETY: duplicating a descriptor we own; the copy deliberately lacks close-on-exec
            // so the sleeper below inherits it.
            let leaked = unsafe { dup(stdin.as_raw_fd()) };
            assert!(leaked > 2, "dup failed");
            let sleeper = Command::new("sleep").arg("60").spawn()?;

            // Control for the premise of this scenario: with this process's own copy of the pipe
            // closed, only the sleeper's copy keeps the worker's stdin open. If the sleeper had
            // not inherited it, the worker would see EOF and leave right here.
            drop(stdin);
            thread::sleep(Duration::from_millis(400));
            if !pid_running(worker) {
                return Err("worker exited on stdin EOF: the pipe was not held open".into());
            }

            announce(&format!("READY worker={worker} sleeper={}", sleeper.id()));
            thread::sleep(Duration::from_secs(120));
        }
        other => return Err(format!("unknown role {other}").into()),
    }
    Ok(())
}

fn announce(line: &str) {
    println!("{line}");
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

struct Helper {
    child: Child,
    worker_pid: u32,
    sleeper_pid: Option<u32>,
}

impl Helper {
    fn start(role: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "orphan_parent_role",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROLE_VARIABLE, role)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("helper has no stdout")?;
        let mut worker_pid = None;
        let mut sleeper_pid = None;
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            // libtest prints "test name ... " without a newline first, so the marker is not
            // necessarily at the start of the line.
            if let Some(index) = line.find("READY ") {
                for field in line[index + "READY ".len()..].split_whitespace() {
                    if let Some(value) = field.strip_prefix("worker=") {
                        worker_pid = value.parse().ok();
                    } else if let Some(value) = field.strip_prefix("sleeper=") {
                        sleeper_pid = value.parse().ok();
                    }
                }
                break;
            }
        }
        let worker_pid = worker_pid.ok_or("helper never announced a worker")?;
        Ok(Self {
            child,
            worker_pid,
            sleeper_pid,
        })
    }

    /// SIGKILL: the service gets no chance to run any cleanup.
    fn kill_without_cleanup(&mut self) -> TestResult {
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for pid in [Some(self.worker_pid), self.sleeper_pid]
            .into_iter()
            .flatten()
        {
            let _ = Command::new("kill")
                .args(["-9", &pid.to_string()])
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn assert_worker_exits_after_parent_death(role: &str) -> TestResult {
    let mut helper = Helper::start(role)?;
    assert!(
        pid_running(helper.worker_pid),
        "worker should be alive while its parent is"
    );

    helper.kill_without_cleanup()?;

    assert!(
        wait_until(Duration::from_secs(5), || !pid_running(helper.worker_pid)),
        "worker {} outlived its SIGKILLed parent (role {role})",
        helper.worker_pid
    );
    Ok(())
}

#[test]
fn idle_worker_exits_when_the_service_is_killed() -> TestResult {
    assert_worker_exits_after_parent_death("idle")
}

#[test]
fn worker_blocked_in_native_code_exits_when_the_service_is_killed() -> TestResult {
    assert_worker_exits_after_parent_death("blocked")
}

#[test]
fn watchdog_catches_a_dead_parent_even_if_another_process_holds_the_pipe_open() -> TestResult {
    let mut helper = Helper::start("pipe-held-open")?;
    let sleeper = helper.sleeper_pid.ok_or("sleeper pid missing")?;
    assert!(
        pid_running(sleeper),
        "the pipe holder must be alive for this test to mean anything"
    );

    helper.kill_without_cleanup()?;

    // stdin never reaches EOF here (the sleeper still holds the write end), so this exercises the
    // parent-pid watchdog in isolation.
    assert!(
        wait_until(Duration::from_secs(5), || !pid_running(helper.worker_pid)),
        "worker {} survived the death of its parent while the pipe stayed open",
        helper.worker_pid
    );
    assert!(
        pid_running(sleeper),
        "the pipe holder must still have been alive, or EOF (not the watchdog) ended the worker"
    );
    Ok(())
}
