//! Option A acceptance rule (ADR-011 §H0 decision rule).
//!
//! The vendor reset window runs from authenticator power-up to the arrival of the request. The
//! host can only observe from its HID insertion notification, so the budget is
//!
//! ```text
//!   tail_factor × tail_adjusted_max(T1..T6)        measured host path, inflated for unseen tail
//! + power_up_allowance                             power-up → HID notification (not measurable)
//! + poll_allowance                                 production discovery cadence vs H0 tight poll
//! + dispatch_allowance                             frame receipt → first HID report written
//! + fixed_margin                                   clock-start ambiguity, scheduler stalls
//! ≤ vendor_window
//! ```
//!
//! `tail_adjusted_max` is the largest observed total, raised by however much the separate
//! durability-only run's worst replace exceeds the worst replace seen during hardware samples (the
//! durability tail is the component most exposed to unrelated disk activity).
//!
//! A deterministic floor (p95 plus the allowances, no factor, no margin) above the window means
//! Option A is not viable. Anything between is not proven either way: more measurement, or a
//! different design decision, is required.

use serde::Serialize;

use crate::sample::{AbortReason, HardwareSample, SampleOutcome};
use crate::stats::summarize;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Policy {
    /// Strictest supported vendor window. 5000 ms: Yubico, as documented by the pinned libfido2
    /// man pages; CTAP's 10 s displayless window is the protocol maximum, not the strictest.
    pub vendor_window_ms: f64,
    pub power_up_allowance_ms: f64,
    pub poll_allowance_ms: f64,
    pub dispatch_allowance_ms: f64,
    pub fixed_margin_ms: f64,
    pub tail_factor: f64,
    pub min_samples: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            vendor_window_ms: 5000.0,
            power_up_allowance_ms: 1000.0,
            poll_allowance_ms: 100.0,
            dispatch_allowance_ms: 250.0,
            fixed_margin_ms: 1000.0,
            tail_factor: 2.0,
            min_samples: 20,
        }
    }
}

impl Policy {
    fn allowances_ms(&self) -> f64 {
        self.power_up_allowance_ms + self.poll_allowance_ms + self.dispatch_allowance_ms
    }

    /// The largest host path (insertion notification → would-dispatch) Option A can accept.
    pub fn max_acceptable_host_path_ms(&self) -> f64 {
        (self.vendor_window_ms - self.allowances_ms() - self.fixed_margin_ms) / self.tail_factor
    }

    /// Runtime abort budget a production ceremony would enforce, measured from the insertion
    /// notification to the would-dispatch point: over budget ⇒ abort before DispatchCapable.
    pub fn runtime_budget_ms(&self) -> f64 {
        self.vendor_window_ms - self.allowances_ms() - self.fixed_margin_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    OptionAViable,
    OptionANotViable,
    MoreMeasurementRequired,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Evaluation {
    pub verdict: Verdict,
    pub policy: Policy,
    pub valid_samples: usize,
    pub procedural_aborts: usize,
    pub reliability_aborts: usize,
    pub p95_total_ms: Option<f64>,
    pub max_total_ms: Option<f64>,
    pub tail_adjusted_max_ms: Option<f64>,
    pub required_ms: Option<f64>,
    pub floor_ms: Option<f64>,
    pub max_acceptable_host_path_ms: f64,
    pub runtime_budget_ms: f64,
    pub reasons: Vec<String>,
}

fn ms(us: i64) -> f64 {
    us as f64 / 1000.0
}

/// Operator-procedure aborts (key not inserted in time, two keys, missed notification) say
/// nothing about Option A latency. Anything else is a reliability problem on the timed path.
fn procedural(reason: &AbortReason) -> bool {
    matches!(
        reason,
        AbortReason::InsertionTimeout
            | AbortReason::MultipleDevices { .. }
            | AbortReason::NoInsertionNotification
    )
}

pub fn evaluate(
    samples: &[&HardwareSample],
    durability_only_max_us: Option<i64>,
    policy: Policy,
) -> Evaluation {
    let mut totals = Vec::new();
    let mut t5 = Vec::new();
    let (mut procedural_aborts, mut reliability_aborts) = (0, 0);
    for sample in samples {
        match &sample.outcome {
            SampleOutcome::Measured {
                components,
                total_us,
            } => {
                totals.push(*total_us);
                t5.push(components.t5_durable_replace_us);
            }
            SampleOutcome::Aborted { reason } if procedural(reason) => procedural_aborts += 1,
            SampleOutcome::Aborted { .. } => reliability_aborts += 1,
        }
    }
    let mut evaluation = Evaluation {
        verdict: Verdict::MoreMeasurementRequired,
        policy,
        valid_samples: totals.len(),
        procedural_aborts,
        reliability_aborts,
        p95_total_ms: None,
        max_total_ms: None,
        tail_adjusted_max_ms: None,
        required_ms: None,
        floor_ms: None,
        max_acceptable_host_path_ms: policy.max_acceptable_host_path_ms(),
        runtime_budget_ms: policy.runtime_budget_ms(),
        reasons: Vec::new(),
    };
    let (Some(total), Some(t5)) = (summarize(&totals), summarize(&t5)) else {
        evaluation
            .reasons
            .push("no valid hardware samples: no evidence for Option A".into());
        return evaluation;
    };
    let durability_excess = durability_only_max_us
        .map(|worst| (worst - t5.max_us).max(0))
        .unwrap_or(0);
    let tail_adjusted = total.max_us + durability_excess;
    let required =
        policy.tail_factor * ms(tail_adjusted) + policy.allowances_ms() + policy.fixed_margin_ms;
    let floor = ms(total.p95_us) + policy.allowances_ms();
    evaluation.p95_total_ms = Some(ms(total.p95_us));
    evaluation.max_total_ms = Some(ms(total.max_us));
    evaluation.tail_adjusted_max_ms = Some(ms(tail_adjusted));
    evaluation.required_ms = Some(required);
    evaluation.floor_ms = Some(floor);

    if floor > policy.vendor_window_ms {
        evaluation.verdict = Verdict::OptionANotViable;
        evaluation.reasons.push(format!(
            "p95 host path plus allowances ({floor:.1} ms) already exceeds the {:.0} ms window",
            policy.vendor_window_ms
        ));
        return evaluation;
    }
    if totals.len() < policy.min_samples {
        evaluation.reasons.push(format!(
            "{} valid samples; at least {} are required",
            totals.len(),
            policy.min_samples
        ));
    }
    if reliability_aborts > 0 {
        evaluation.reasons.push(format!(
            "{reliability_aborts} sample(s) failed on the timed path; explain them before accepting"
        ));
    }
    if durability_only_max_us.is_none() {
        evaluation
            .reasons
            .push("no durability-only run: the F_FULLFSYNC tail is under-sampled".into());
    }
    if required > policy.vendor_window_ms {
        evaluation.reasons.push(format!(
            "required {required:.1} ms exceeds the {:.0} ms window: margin not demonstrated",
            policy.vendor_window_ms
        ));
    }
    if evaluation.reasons.is_empty() {
        evaluation.verdict = Verdict::OptionAViable;
    }
    evaluation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::Components;

    fn measured(total_us: i64, t5_us: i64) -> HardwareSample {
        let components = Components {
            t1_insertion_to_manifest_us: 0,
            t2_manifest_to_open_us: 0,
            t3_open_to_get_info_us: 0,
            t4_validation_us: total_us - t5_us,
            t5_durable_replace_us: t5_us,
            t6_sync_to_would_dispatch_us: 0,
        };
        HardwareSample {
            format: crate::FORMAT.into(),
            index: 0,
            recorded_unix_secs: 0,
            device: None,
            manifest_polls: 1,
            manifest_call_us: None,
            outcome: SampleOutcome::Measured {
                components,
                total_us,
            },
        }
    }

    fn aborted(reason: AbortReason) -> HardwareSample {
        HardwareSample {
            outcome: SampleOutcome::Aborted { reason },
            ..measured(0, 0)
        }
    }

    fn evaluate_owned(samples: &[HardwareSample], durability: Option<i64>) -> Evaluation {
        let refs: Vec<&HardwareSample> = samples.iter().collect();
        evaluate(&refs, durability, Policy::default())
    }

    #[test]
    fn default_policy_derives_the_documented_limits() {
        let policy = Policy::default();
        // (5000 − 1000 − 100 − 250 − 1000) / 2 = 1325 ms of measured host path.
        assert!((policy.max_acceptable_host_path_ms() - 1325.0).abs() < 1e-9);
        assert!((policy.runtime_budget_ms() - 2650.0).abs() < 1e-9);
    }

    #[test]
    fn fast_complete_evidence_is_viable() {
        let samples: Vec<_> = (0..20)
            .map(|i| measured(300_000 + i * 1000, 50_000))
            .collect();
        let evaluation = evaluate_owned(&samples, Some(80_000));
        assert_eq!(evaluation.verdict, Verdict::OptionAViable, "{evaluation:?}");
        // 319 ms max + 30 ms durability excess = 349 ms; ×2 + 2350 = 3048 ms.
        assert_eq!(evaluation.tail_adjusted_max_ms, Some(349.0));
        assert_eq!(evaluation.required_ms, Some(3048.0));
    }

    #[test]
    fn too_few_samples_or_no_durability_run_needs_more_measurement() {
        let few: Vec<_> = (0..19).map(|_| measured(300_000, 50_000)).collect();
        assert_eq!(
            evaluate_owned(&few, Some(60_000)).verdict,
            Verdict::MoreMeasurementRequired
        );
        let enough: Vec<_> = (0..20).map(|_| measured(300_000, 50_000)).collect();
        assert_eq!(
            evaluate_owned(&enough, None).verdict,
            Verdict::MoreMeasurementRequired
        );
        assert_eq!(
            evaluate_owned(&[], Some(1)).verdict,
            Verdict::MoreMeasurementRequired
        );
    }

    #[test]
    fn marginal_latency_is_not_accepted_without_margin() {
        // 1.5 s max: floor 1.5 + 1.35 = 2.85 s fits, but 2 × 1.5 + 2.35 = 5.35 s does not.
        let samples: Vec<_> = (0..20).map(|_| measured(1_500_000, 100_000)).collect();
        let evaluation = evaluate_owned(&samples, Some(100_000));
        assert_eq!(evaluation.verdict, Verdict::MoreMeasurementRequired);
    }

    #[test]
    fn slow_p95_is_not_viable() {
        let samples: Vec<_> = (0..20).map(|_| measured(4_000_000, 100_000)).collect();
        assert_eq!(
            evaluate_owned(&samples, Some(100_000)).verdict,
            Verdict::OptionANotViable
        );
    }

    #[test]
    fn durability_tail_from_the_separate_run_is_charged() {
        // Hardware path is fast, but a 700 ms F_FULLFSYNC outlier pushes the bound over.
        let samples: Vec<_> = (0..20).map(|_| measured(700_000, 50_000)).collect();
        let fast = evaluate_owned(&samples, Some(50_000));
        assert_eq!(fast.verdict, Verdict::OptionAViable);
        let slow_disk = evaluate_owned(&samples, Some(750_000));
        assert_eq!(slow_disk.verdict, Verdict::MoreMeasurementRequired);
        assert_eq!(slow_disk.tail_adjusted_max_ms, Some(1400.0));
    }

    #[test]
    fn reliability_aborts_block_acceptance_but_procedural_ones_do_not() {
        let mut samples: Vec<_> = (0..20).map(|_| measured(300_000, 50_000)).collect();
        samples.push(aborted(AbortReason::MultipleDevices { count: 2 }));
        samples.push(aborted(AbortReason::InsertionTimeout));
        let evaluation = evaluate_owned(&samples, Some(60_000));
        assert_eq!(evaluation.verdict, Verdict::OptionAViable);
        assert_eq!(evaluation.procedural_aborts, 2);
        samples.push(aborted(AbortReason::DurabilityFailed));
        let evaluation = evaluate_owned(&samples, Some(60_000));
        assert_eq!(evaluation.verdict, Verdict::MoreMeasurementRequired);
        assert_eq!(evaluation.reliability_aborts, 1);
    }
}
