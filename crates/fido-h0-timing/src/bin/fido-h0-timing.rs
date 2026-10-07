//! H0 non-destructive Option A timing tool. See `docs/validation/M6.0-h0-reset-timing.md`.
//!
//! Commands:
//!   durability --session DIR [--samples N]      production journal replace timing, no device
//!   measure    --session DIR [--samples N]      interactive unplug/plug timing (macOS only)
//!   report     --session DIR [policy options]   summary tables + Option A evaluation
//!
//! This binary has no destructive mode and no flag that enables one.

use std::path::PathBuf;
use std::process::ExitCode;

use fido_h0_timing::decision::Policy;
use fido_h0_timing::environment::{LIBFIDO2_DEBUG_VARIABLE, collect, debug_logging_requested};
use fido_h0_timing::sample::{DurabilitySample, HardwareSample};
use fido_h0_timing::session::{DURABILITY_SAMPLES, HARDWARE_SAMPLES, Session};
use fido_h0_timing::{FORMAT, report};

const USAGE: &str = "usage:
  fido-h0-timing durability --session DIR [--samples N]
  fido-h0-timing measure --session DIR [--samples N] [--insert-timeout-secs S]
  fido-h0-timing report --session DIR [--window-ms MS] [--power-up-ms MS] [--poll-ms MS]
                        [--dispatch-ms MS] [--margin-ms MS] [--tail-factor F] [--min-samples N]

DIR must be an absolute path that is new, empty, or an existing H0 session.
This tool only discovers, opens and reads GetInfo. It never sends a destructive command.";

struct Args {
    command: String,
    session: Option<PathBuf>,
    samples: Option<u32>,
    insert_timeout_secs: u64,
    policy: Policy,
}

fn parse() -> Result<Args, String> {
    let mut iter = std::env::args().skip(1);
    let command = iter.next().ok_or("missing command")?;
    let mut args = Args {
        command,
        session: None,
        samples: None,
        insert_timeout_secs: 120,
        policy: Policy::default(),
    };
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().ok_or(format!("{flag} needs a value"));
        let number = |text: String| -> Result<f64, String> {
            text.parse::<f64>()
                .ok()
                .filter(|v| v.is_finite() && *v >= 0.0)
                .ok_or(format!("{flag}: not a non-negative number"))
        };
        match flag.as_str() {
            "--session" => args.session = Some(PathBuf::from(value()?)),
            "--samples" => {
                args.samples = Some(
                    value()?
                        .parse()
                        .ok()
                        .filter(|n| (1..=10_000).contains(n))
                        .ok_or("--samples must be 1..=10000")?,
                )
            }
            "--insert-timeout-secs" => {
                args.insert_timeout_secs = value()?
                    .parse()
                    .ok()
                    .filter(|n| (1..=3600).contains(n))
                    .ok_or("--insert-timeout-secs must be 1..=3600")?
            }
            "--window-ms" => args.policy.vendor_window_ms = number(value()?)?,
            "--power-up-ms" => args.policy.power_up_allowance_ms = number(value()?)?,
            "--poll-ms" => args.policy.poll_allowance_ms = number(value()?)?,
            "--dispatch-ms" => args.policy.dispatch_allowance_ms = number(value()?)?,
            "--margin-ms" => args.policy.fixed_margin_ms = number(value()?)?,
            "--tail-factor" => {
                args.policy.tail_factor = number(value()?)?;
                if args.policy.tail_factor < 1.0 {
                    return Err("--tail-factor must be at least 1".into());
                }
            }
            "--min-samples" => {
                args.policy.min_samples = value()?
                    .parse()
                    .ok()
                    .filter(|n| *n >= 1)
                    .ok_or("--min-samples must be at least 1")?
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(args)
}

fn session(args: &Args) -> Result<Session, String> {
    let dir = args.session.as_ref().ok_or("--session DIR is required")?;
    Session::open_or_create(dir, collect).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn durability(args: &Args) -> Result<(), String> {
    use fido_h0_timing::durability::ScratchJournal;
    use fido_h0_timing::measurement::ScratchDurability;
    let session = session(args)?;
    let mut journal = ScratchJournal::open(&session.scratch_root()).map_err(|e| e.to_string())?;
    journal.write_pending().map_err(|e| e.to_string())?;
    let existing: Vec<DurabilitySample> = session
        .read_all(DURABILITY_SAMPLES)
        .map_err(|e| e.to_string())?;
    let start = u32::try_from(existing.len()).unwrap_or(u32::MAX);
    let samples = args.samples.unwrap_or(200);
    for offset in 0..samples {
        let replace_us = journal
            .timed_dispatch_capable()
            .map_err(|e| e.to_string())?;
        journal.write_resolved().map_err(|e| e.to_string())?;
        journal.write_pending().map_err(|e| e.to_string())?;
        session
            .append(
                DURABILITY_SAMPLES,
                &DurabilitySample {
                    format: FORMAT.into(),
                    index: start.saturating_add(offset).saturating_add(1),
                    replace_us,
                },
            )
            .map_err(|e| e.to_string())?;
    }
    journal.write_resolved().map_err(|e| e.to_string())?;
    println!("H0 STATUS: recorded {samples} durability samples");
    Ok(())
}

#[cfg(not(unix))]
fn durability(_: &Args) -> Result<(), String> {
    Err("durability measurement requires a Unix journal implementation".into())
}

#[cfg(target_os = "macos")]
fn measure(args: &Args) -> Result<(), String> {
    use fido_h0_timing::durability::ScratchJournal;
    use fido_h0_timing::macos::{fido::LibFido2ReadOnly, insertion::IoKitInsertionWatch};
    use fido_h0_timing::measurement::Timing;
    use fido_h0_timing::operator::{Stop, run};
    use fido_h0_timing::would_dispatch::SocketStub;

    let session = session(args)?;
    let existing: Vec<HardwareSample> = session
        .read_all(HARDWARE_SAMPLES)
        .map_err(|e| e.to_string())?;
    let first = u32::try_from(existing.len())
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    let mut journal = ScratchJournal::open(&session.scratch_root()).map_err(|e| e.to_string())?;
    let mut executor = SocketStub::spawn().map_err(|e| e.to_string())?;
    let mut watch = IoKitInsertionWatch::start().map_err(|e| e.to_string())?;
    let mut device = LibFido2ReadOnly::initialize();
    let timing = Timing {
        insertion_timeout: std::time::Duration::from_secs(args.insert_timeout_secs),
        ..Timing::default()
    };
    let stop = run(
        first,
        args.samples.unwrap_or(20),
        &mut device,
        &mut watch,
        &mut journal,
        &mut executor,
        timing,
        |sample| {
            session
                .append(HARDWARE_SAMPLES, sample)
                .map_err(|e| e.to_string())
        },
        |text| println!("{text}"),
    );
    match stop {
        Stop::Completed => Ok(()),
        Stop::UnplugTimeout => Err("timed out waiting for the key to be unplugged".into()),
        Stop::DiscoveryFailed(code) => Err(format!("libfido2 discovery failed ({code})")),
        Stop::Storage(error) => Err(format!("could not record the sample: {error}")),
    }
}

#[cfg(not(target_os = "macos"))]
fn measure(_: &Args) -> Result<(), String> {
    Err("hardware measurement is implemented for macOS only".into())
}

fn report_command(args: &Args) -> Result<(), String> {
    let session = session(args)?;
    let hardware: Vec<HardwareSample> = session
        .read_all(HARDWARE_SAMPLES)
        .map_err(|e| e.to_string())?;
    let durability: Vec<DurabilitySample> = session
        .read_all(DURABILITY_SAMPLES)
        .map_err(|e| e.to_string())?;
    let built = report::build(session.marker.clone(), &hardware, &durability, args.policy);
    let json = serde_json::to_string_pretty(&built).map_err(|e| e.to_string())?;
    let markdown = report::markdown(&built);
    std::fs::write(session.directory().join("report.json"), json).map_err(|e| e.to_string())?;
    std::fs::write(session.directory().join("report.md"), &markdown).map_err(|e| e.to_string())?;
    print!("{markdown}");
    Ok(())
}

fn main() -> ExitCode {
    if debug_logging_requested(std::env::var_os(LIBFIDO2_DEBUG_VARIABLE).as_deref()) {
        eprintln!(
            "refusing to run: {LIBFIDO2_DEBUG_VARIABLE} is set, which would enable libfido2 \
             logging of device paths; unset it and run again"
        );
        return ExitCode::from(2);
    }
    let args = match parse() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match args.command.as_str() {
        "durability" => durability(&args),
        "measure" => measure(&args),
        "report" => report_command(&args),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        other => {
            eprintln!("unknown command {other}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("H0 ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}
