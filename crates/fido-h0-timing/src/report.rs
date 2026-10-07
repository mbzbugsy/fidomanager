//! Aggregation: per model label, min/median/p95/max for each component and the total, plus the
//! Option A evaluation. Model labels group samples for reporting only.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::decision::{Evaluation, Policy, evaluate};
use crate::sample::{
    AbortReason, Components, DeviceLabel, DurabilitySample, HardwareSample, SampleOutcome,
};
use crate::session::SessionMarker;
use crate::stats::{Summary, summarize};

#[derive(Debug, Clone, Serialize)]
pub struct ComponentSummary {
    pub component: &'static str,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelReport {
    pub label: Option<DeviceLabel>,
    pub measured: usize,
    pub aborted: BTreeMap<String, usize>,
    pub components: Vec<ComponentSummary>,
    pub total: Option<Summary>,
    pub manifest_call: Option<Summary>,
    pub evaluation: Evaluation,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub format: &'static str,
    pub session: SessionMarker,
    pub durability_only: Option<Summary>,
    pub models: Vec<ModelReport>,
}

fn abort_key(reason: &AbortReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| {
            value
                .get("reason")
                .and_then(|r| r.as_str().map(str::to_owned))
        })
        .unwrap_or_else(|| "unknown".into())
}

pub fn build(
    session: SessionMarker,
    hardware: &[HardwareSample],
    durability: &[DurabilitySample],
    policy: Policy,
) -> Report {
    let durability_only = summarize(&durability.iter().map(|s| s.replace_us).collect::<Vec<_>>());
    let mut groups: BTreeMap<Option<DeviceLabel>, Vec<&HardwareSample>> = BTreeMap::new();
    for sample in hardware {
        groups
            .entry(sample.device.clone())
            .or_default()
            .push(sample);
    }
    let models = groups
        .into_iter()
        .map(|(label, samples)| {
            let measured: Vec<&Components> = samples
                .iter()
                .filter_map(|s| match &s.outcome {
                    SampleOutcome::Measured { components, .. } => Some(components),
                    SampleOutcome::Aborted { .. } => None,
                })
                .collect();
            let mut aborted = BTreeMap::new();
            for sample in &samples {
                if let SampleOutcome::Aborted { reason } = &sample.outcome {
                    *aborted.entry(abort_key(reason)).or_insert(0) += 1;
                }
            }
            let components = Components::NAMES
                .iter()
                .enumerate()
                .filter_map(|(i, name)| {
                    let values: Vec<i64> = measured.iter().map(|c| c.values()[i]).collect();
                    summarize(&values).map(|summary| ComponentSummary {
                        component: name,
                        summary,
                    })
                })
                .collect();
            let total = summarize(&measured.iter().map(|c| c.total_us()).collect::<Vec<_>>());
            let manifest_call = summarize(
                &samples
                    .iter()
                    .filter(|s| matches!(s.outcome, SampleOutcome::Measured { .. }))
                    .filter_map(|s| s.manifest_call_us)
                    .collect::<Vec<_>>(),
            );
            let evaluation = evaluate(&samples, durability_only.map(|d| d.max_us), policy);
            ModelReport {
                label,
                measured: measured.len(),
                aborted,
                components,
                total,
                manifest_call,
                evaluation,
            }
        })
        .collect();
    Report {
        format: crate::FORMAT,
        session,
        durability_only,
        models,
    }
}

fn ms(us: i64) -> String {
    format!("{:.3}", us as f64 / 1000.0)
}

fn row(name: &str, s: &Summary) -> String {
    format!(
        "| {name} | {} | {} | {} | {} | {} |\n",
        s.count,
        ms(s.min_us),
        ms(s.median_us),
        ms(s.p95_us),
        ms(s.max_us)
    )
}

pub fn markdown(report: &Report) -> String {
    let env = &report.session.environment;
    let mut out = String::from("# H0 Option A timing report\n\n");
    out += &format!(
        "- OS: {} {} ({}), {} {}\n- Scratch filesystem: {}\n- libfido2: `{}`\n- Tool: {} `{}`\n\n",
        env.os,
        env.os_version.as_deref().unwrap_or("?"),
        env.os_build.as_deref().unwrap_or("?"),
        env.hardware_model.as_deref().unwrap_or("?"),
        env.architecture,
        env.scratch_filesystem.as_deref().unwrap_or("?"),
        env.libfido2_revision,
        env.tool_version,
        report.format,
    );
    out += "All values in milliseconds. Nearest-rank percentiles; every value is an observed sample.\n\n";
    if let Some(d) = &report.durability_only {
        out += "## Durability only (production replace, no device)\n\n";
        out += "| component | n | min | median | p95 | max |\n|---|---|---|---|---|---|\n";
        out += &row("t5_durable_replace", d);
        out += "\n";
    }
    for model in &report.models {
        match &model.label {
            Some(l) => {
                out += &format!(
                    "## {} {} (VID {:04x} PID {:04x}, AAGUID {}, firmware {})\n\n",
                    l.manufacturer,
                    l.product,
                    l.vendor_id,
                    l.product_id,
                    l.aaguid,
                    l.firmware_version
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into())
                );
                out += "Model label groups samples only; it is not identity or authority.\n\n";
            }
            None => out += "## Samples aborted before GetInfo (no model label)\n\n",
        }
        out += &format!(
            "Measured: {}. Aborted: {}.\n\n",
            model.measured,
            if model.aborted.is_empty() {
                "none".into()
            } else {
                model
                    .aborted
                    .iter()
                    .map(|(k, v)| format!("{k} ×{v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
        if !model.components.is_empty() {
            out += "| component | n | min | median | p95 | max |\n|---|---|---|---|---|---|\n";
            for c in &model.components {
                out += &row(c.component, &c.summary);
            }
            if let Some(total) = &model.total {
                out += &row("**total T1–T6**", total);
            }
            if let Some(m) = &model.manifest_call {
                out += &row("(manifest call)", m);
            }
            out += "\n";
        }
        let e = &model.evaluation;
        out += &format!(
            "Verdict: **{:?}**. Window {:.0} ms; acceptable host path ≤ {:.1} ms; runtime budget {:.1} ms; required {}.\n",
            e.verdict,
            e.policy.vendor_window_ms,
            e.max_acceptable_host_path_ms,
            e.runtime_budget_ms,
            e.required_ms
                .map(|r| format!("{r:.1} ms"))
                .unwrap_or_else(|| "n/a".into())
        );
        for reason in &e.reasons {
            out += &format!("- {reason}\n");
        }
        out += "\n";
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::collect;

    fn sample(index: u32, total: i64, label: Option<DeviceLabel>) -> HardwareSample {
        HardwareSample {
            format: crate::FORMAT.into(),
            index,
            recorded_unix_secs: 0,
            device: label,
            manifest_polls: 2,
            manifest_call_us: Some(900),
            outcome: SampleOutcome::Measured {
                components: Components {
                    t1_insertion_to_manifest_us: 10_000,
                    t2_manifest_to_open_us: 20_000,
                    t3_open_to_get_info_us: 15_000,
                    t4_validation_us: 100,
                    t5_durable_replace_us: total - 45_200,
                    t6_sync_to_would_dispatch_us: 100,
                },
                total_us: total,
            },
        }
    }

    fn label(product: &str) -> DeviceLabel {
        DeviceLabel {
            vendor_id: 0x1050,
            product_id: 0x0407,
            manufacturer: "Vendor".into(),
            product: product.into(),
            aaguid: "ab".repeat(16),
            firmware_version: Some(5),
        }
    }

    #[test]
    fn groups_by_model_and_renders_every_statistic() {
        let marker = SessionMarker {
            format: crate::FORMAT.into(),
            created_unix_secs: 0,
            environment: collect(&std::env::temp_dir()),
        };
        let mut hardware: Vec<_> = (0..20)
            .map(|i| sample(i, 100_000 + i64::from(i) * 1000, Some(label("A"))))
            .collect();
        hardware.push(sample(20, 200_000, Some(label("B"))));
        hardware.push(HardwareSample {
            device: None,
            outcome: SampleOutcome::Aborted {
                reason: AbortReason::InsertionTimeout,
            },
            ..sample(21, 0, None)
        });
        let durability = vec![DurabilitySample {
            format: crate::FORMAT.into(),
            index: 0,
            replace_us: 60_000,
        }];
        let report = build(marker, &hardware, &durability, Policy::default());
        assert_eq!(report.models.len(), 3);
        let a = report
            .models
            .iter()
            .find(|m| m.label.as_ref().is_some_and(|l| l.product == "A"));
        let Some(a) = a else {
            panic!("model A missing");
        };
        assert_eq!(a.measured, 20);
        assert_eq!(a.components.len(), 6);
        assert_eq!(a.total.map(|t| t.max_us), Some(119_000));
        assert_eq!(
            a.evaluation.verdict,
            crate::decision::Verdict::OptionAViable
        );
        let b = report
            .models
            .iter()
            .find(|m| m.label.as_ref().is_some_and(|l| l.product == "B"));
        assert_eq!(
            b.map(|m| m.evaluation.verdict),
            Some(crate::decision::Verdict::MoreMeasurementRequired)
        );
        let text = markdown(&report);
        for needle in [
            "t1_insertion_to_manifest",
            "t6_sync_to_would_dispatch",
            "**total T1–T6**",
            "| p95 |",
            "OptionAViable",
            "insertion_timeout ×1",
            "Durability only",
        ] {
            assert!(text.contains(needle), "{needle}\n{text}");
        }
    }
}
