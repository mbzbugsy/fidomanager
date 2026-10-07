//! Interactive operator mode: one physical action, then wait for the tool to observe it.
//!
//! Each instruction is printed as one `H0 ACTION:` line; observations and results are printed as
//! `H0 STATUS:` / `H0 SAMPLE:` lines so a supervising agent (or a person) can follow the session
//! without reading logs. The operator only ever unplugs or plugs in the key. No PIN, no touch, no
//! confirmation of anything on the key is requested.

use std::time::{Duration, Instant};

use crate::measurement::{
    Baseline, InsertionWatch, ReadOnlyDevice, ScratchDurability, Timing, WouldDispatch,
    measure_once,
};
use crate::sample::{HardwareSample, SampleOutcome};

pub enum Stop {
    Completed,
    UnplugTimeout,
    DiscoveryFailed(i32),
    Storage(String),
}

/// Waits until libfido2 lists no eligible device. libfido2 is the authority on what counts as a
/// FIDO device; the notification watch is only the insertion clock.
pub fn wait_absent<D: ReadOnlyDevice>(device: &mut D, timeout: Duration) -> Result<bool, i32> {
    let deadline = Instant::now() + timeout;
    loop {
        let manifest = device.manifest()?;
        if manifest.count == 0 {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn line(sample: &HardwareSample, of: u32) -> String {
    match &sample.outcome {
        SampleOutcome::Measured { total_us, .. } => format!(
            "H0 SAMPLE: {}/{of} measured, total {:.1} ms",
            sample.index,
            *total_us as f64 / 1000.0
        ),
        SampleOutcome::Aborted { reason } => format!(
            "H0 SAMPLE: {}/{of} aborted ({})",
            sample.index,
            serde_json::to_value(reason)
                .ok()
                .and_then(|v| v.get("reason").and_then(|r| r.as_str().map(str::to_owned)))
                .unwrap_or_else(|| "unknown".into())
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run<D, W, J, X>(
    first_index: u32,
    samples: u32,
    device: &mut D,
    watch: &mut W,
    journal: &mut J,
    executor: &mut X,
    timing: Timing,
    mut record: impl FnMut(&HardwareSample) -> Result<(), String>,
    mut say: impl FnMut(&str),
) -> Stop
where
    D: ReadOnlyDevice,
    W: InsertionWatch,
    J: ScratchDurability,
    X: WouldDispatch,
{
    let mut baseline: Option<Baseline> = None;
    let last = first_index.saturating_add(samples).saturating_sub(1);
    for index in first_index..=last {
        match wait_absent(device, Duration::from_millis(0)) {
            Ok(true) => {}
            Ok(false) => {
                say("H0 ACTION: Unplug the security key.");
                match wait_absent(device, timing.insertion_timeout) {
                    Ok(true) => say("H0 STATUS: no security key connected"),
                    Ok(false) => return Stop::UnplugTimeout,
                    Err(code) => return Stop::DiscoveryFailed(code),
                }
            }
            Err(code) => return Stop::DiscoveryFailed(code),
        }
        // Untimed preparation, like production before the unplug: durable Pending, armed clock.
        if let Err(error) = journal.write_pending() {
            return Stop::Storage(error.to_string());
        }
        watch.arm();
        say("H0 ACTION: Plug the security key in. Do not touch it.");
        let sample = measure_once(
            index,
            device,
            watch,
            journal,
            executor,
            &mut baseline,
            timing,
        );
        if let Err(error) = record(&sample) {
            return Stop::Storage(error);
        }
        say(&line(&sample, last));
    }
    say("H0 ACTION: Unplug the security key. Measurement session finished.");
    Stop::Completed
}
