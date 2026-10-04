//! Entire production authority/transport/runtime against synthetic native mutation, never HID.
#![cfg(unix)]
mod common;
use common::{TestResult, launcher};
use fido_auth::{
    PinSecret,
    mutation::{PinMutationSecrets, PinOperation},
};
use fido_core::{MutationOutcome, RecoveryAdmission};
use fido_native_ui::{MutationCompletion, PromptOutcome};
use fido_service::{
    DiscoveryPolicy, DiscoverySupervisor, RestartPolicy, authentication::AuthenticationAuthority,
    recovery::JournalStorage,
};
use std::sync::{Arc, Mutex};
use std::time::Instant;
#[derive(Default)]
struct Disk {
    bytes: Option<Vec<u8>>,
    phases: Vec<String>,
    writes: usize,
    fail_at: usize,
    publish_failure: bool,
    revoke_on_dispatch: Option<Arc<std::sync::atomic::AtomicU64>>,
}
#[derive(Clone, Default)]
struct Storage(Arc<Mutex<Disk>>);
impl JournalStorage for Storage {
    fn read(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("disk"))?
            .bytes
            .clone())
    }
    fn replace_durable(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let mut d = self.0.lock().map_err(|_| std::io::Error::other("disk"))?;
        d.writes += 1;
        if d.writes == d.fail_at && !d.publish_failure {
            return Err(std::io::Error::other("write"));
        }
        d.bytes = Some(bytes.to_vec());
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        d.phases.push(
            value["phase"]
                .as_str()
                .ok_or(std::io::Error::other("phase"))?
                .into(),
        );
        if d.writes == d.fail_at {
            return Err(std::io::Error::other("sync"));
        }
        if d.writes == 2 {
            if let Some(epoch) = &d.revoke_on_dispatch {
                epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        Ok(())
    }
}
fn pin() -> Result<PinSecret, &'static str> {
    PinSecret::collect(|b| {
        b[..4].copy_from_slice(b"fake");
        Some(4)
    })
    .map_err(|_| "synthetic PIN")
}
#[test]
fn durable_order_definitive_unknown_preentry_cleanup_and_lost_response() -> TestResult {
    for (args, expected, resolution) in [
        (
            &["--authentication", "--mutation=success"][..],
            MutationOutcome::ConfirmedSuccessful,
            Some("confirmed_successful"),
        ),
        (
            &["--authentication", "--mutation=reject"][..],
            MutationOutcome::Rejected,
            Some("rejected"),
        ),
        (
            &["--authentication", "--mutation=unknown"][..],
            MutationOutcome::OutcomeUnknown,
            None,
        ),
        (
            &["--authentication", "--mutation=hang"][..],
            MutationOutcome::OutcomeUnknown,
            None,
        ),
        (
            &["--authentication", "--mutation=crash"][..],
            MutationOutcome::OutcomeUnknown,
            None,
        ),
        (
            &["--authentication", "--mutation=pre-entry"][..],
            MutationOutcome::OutcomeUnknown,
            None,
        ),
        (
            &["--authentication", "--mutation=cleanup"][..],
            MutationOutcome::ConfirmedSuccessful,
            Some("confirmed_successful"),
        ),
        (
            &["--authentication", "--mutation=prepare-failure"][..],
            MutationOutcome::NotDispatched,
            None,
        ),
    ] {
        for operation in [PinOperation::SetPin, PinOperation::ChangePin] {
            let storage = Storage::default();
            let a = AuthenticationAuthority::default();
            a.initialize_recovery(Box::new(storage.clone()))?;
            let mut s = DiscoverySupervisor::new(
                launcher(args)?,
                DiscoveryPolicy::default(),
                RestartPolicy::default(),
            )?;
            let snapshot = s.refresh()?;
            let handle = snapshot.devices[0].handle;
            let r = a.reserve_pin_intent(&mut s, handle, operation)?;
            let result = a.mutate_pin(&mut s, r, |request, c, tx, op, retries, _, _| {
                assert_eq!(op, operation);
                assert_eq!(
                    retries,
                    if operation == PinOperation::ChangePin {
                        Some(1)
                    } else {
                        None
                    }
                );
                let binding = request.binding();
                let mut c = c.lock().map_err(|_| "controller")?;
                c.resolve(PromptOutcome::Approved(binding), Instant::now())
                    .map_err(|_| "resolve")?;
                c.did_teardown(binding, Instant::now())
                    .map_err(|_| "teardown")?;
                let new = pin()?;
                let secrets = match operation {
                    PinOperation::SetPin => PinMutationSecrets::Set { new },
                    PinOperation::ChangePin => PinMutationSecrets::Change {
                        current: pin()?,
                        new,
                    },
                };
                tx.send(MutationCompletion {
                    binding,
                    outcome: PromptOutcome::Approved(binding),
                    secrets: Some(secrets),
                })
                .map_err(|_| "reply")
            });
            assert_eq!(result.outcome, expected);
            assert!(result.worker_quiescent && result.prompt_torn_down);
            assert!(s.resolve_handle(handle).is_none());
            let d = storage.0.lock().map_err(|_| "disk")?;
            if let Some(resolution) = resolution {
                assert_eq!(d.phases, ["pending", "dispatch_capable", "resolved"]);
                let value: serde_json::Value =
                    serde_json::from_slice(d.bytes.as_ref().ok_or("record")?)?;
                assert_eq!(value["resolution"], resolution);
                assert!(!result.recovery_required);
            } else if expected == MutationOutcome::OutcomeUnknown {
                assert_eq!(d.phases, ["pending", "dispatch_capable"]);
                assert!(result.recovery_required);
            } else {
                assert!(d.phases.is_empty());
            }
            drop(d);
            if result.recovery_required {
                assert!(a.reserve().is_err());
                let restarted = AuthenticationAuthority::default();
                restarted.initialize_recovery(Box::new(storage.clone()))?;
                assert_eq!(restarted.recovery_admission(), RecoveryAdmission::Barrier);
                a.acknowledge_pin_recovery(&mut s, |request, c, tx, op, _, _| {
                    assert_eq!(op, operation);
                    let binding = request.binding();
                    let mut c = c.lock().map_err(|_| "controller")?;
                    c.resolve(PromptOutcome::Approved(binding), Instant::now())
                        .map_err(|_| "resolve")?;
                    c.did_teardown(binding, Instant::now())
                        .map_err(|_| "teardown")?;
                    tx.send(MutationCompletion {
                        binding,
                        outcome: PromptOutcome::Approved(binding),
                        secrets: None,
                    })
                    .map_err(|_| "reply")
                })?;
                let d = storage.0.lock().map_err(|_| "disk")?;
                let value: serde_json::Value =
                    serde_json::from_slice(d.bytes.as_ref().ok_or("record")?)?;
                assert_eq!(value["resolution"], "acknowledged_unknown");
                assert_eq!(a.recovery_admission(), RecoveryAdmission::Open);
            }
        }
    }
    Ok(())
}
#[test]
fn each_durability_failure_zero_dispatch_or_preserved_success_barrier() -> TestResult {
    for fail_at in 1..=3 {
        for publish_failure in [false, true] {
            let storage = Storage::default();
            {
                let mut d = storage.0.lock().map_err(|_| "disk")?;
                d.fail_at = fail_at;
                d.publish_failure = publish_failure;
            }
            let a = AuthenticationAuthority::default();
            a.initialize_recovery(Box::new(storage.clone()))?;
            let mut s = DiscoverySupervisor::new(
                launcher(&["--authentication", "--mutation=success"])?,
                DiscoveryPolicy::default(),
                RestartPolicy::default(),
            )?;
            let handle = s.refresh()?.devices[0].handle;
            let r = a.reserve_pin_intent(&mut s, handle, PinOperation::ChangePin)?;
            let result = a.mutate_pin(&mut s, r, |request, c, tx, _, _, _, _| {
                let binding = request.binding();
                let mut c = c.lock().map_err(|_| "controller")?;
                c.resolve(PromptOutcome::Approved(binding), Instant::now())
                    .map_err(|_| "resolve")?;
                c.did_teardown(binding, Instant::now())
                    .map_err(|_| "teardown")?;
                tx.send(MutationCompletion {
                    binding,
                    outcome: PromptOutcome::Approved(binding),
                    secrets: Some(PinMutationSecrets::Change {
                        current: pin()?,
                        new: pin()?,
                    }),
                })
                .map_err(|_| "reply")
            });
            assert_eq!(
                result.outcome,
                if fail_at == 3 {
                    MutationOutcome::ConfirmedSuccessful
                } else {
                    MutationOutcome::NotDispatched
                }
            );
            assert!(result.worker_quiescent && result.prompt_torn_down && result.recovery_required);
            assert!(a.reserve().is_err());
            assert!(a.recoverable_pin_operation().is_none());
        }
    }
    Ok(())
}
#[test]
fn cancelled_stale_or_revoked_native_result_never_creates_marker() -> TestResult {
    for scenario in 0..4 {
        let storage = Storage::default();
        let a = AuthenticationAuthority::default();
        a.initialize_recovery(Box::new(storage.clone()))?;
        let mut s = DiscoverySupervisor::new(
            launcher(&["--authentication", "--mutation=success"])?,
            DiscoveryPolicy::default(),
            RestartPolicy::default(),
        )?;
        let handle = s.refresh()?.devices[0].handle;
        let r = a.reserve_pin_intent(&mut s, handle, PinOperation::SetPin)?;
        let result = a.mutate_pin(&mut s, r, |request, c, tx, _, _, epoch, _| {
            let binding = request.binding();
            let outcome = if scenario == 0 {
                PromptOutcome::Cancelled(binding)
            } else {
                PromptOutcome::Approved(binding)
            };
            let mut c = c.lock().map_err(|_| "controller")?;
            c.resolve(outcome, Instant::now()).map_err(|_| "resolve")?;
            if scenario != 3 {
                c.did_teardown(binding, Instant::now())
                    .map_err(|_| "teardown")?;
            }
            if scenario == 1 {
                epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            tx.send(MutationCompletion {
                binding: if scenario == 2 {
                    fido_native_ui::PromptBinding {
                        workflow_id: fido_core::WorkflowId::from_raw(99),
                        ..binding
                    }
                } else {
                    binding
                },
                outcome,
                secrets: Some(PinMutationSecrets::Set { new: pin()? }),
            })
            .map_err(|_| "reply")
        });
        assert_eq!(result.outcome, MutationOutcome::NotDispatched);
        assert!(storage.0.lock().map_err(|_| "disk")?.phases.is_empty());
        assert!(result.worker_quiescent);
        assert_eq!(result.prompt_torn_down, scenario != 3);
    }
    Ok(())
}

#[test]
fn revocation_during_dispatch_sync_retains_marker_without_native_execution() -> TestResult {
    for operation in [PinOperation::SetPin, PinOperation::ChangePin] {
        let storage = Storage::default();
        let a = AuthenticationAuthority::default();
        a.initialize_recovery(Box::new(storage.clone()))?;
        let mut s = DiscoverySupervisor::new(
            launcher(&["--authentication", "--mutation=success"])?,
            DiscoveryPolicy::default(),
            RestartPolicy::default(),
        )?;
        let handle = s.refresh()?.devices[0].handle;
        let r = a.reserve_pin_intent(&mut s, handle, operation)?;
        let result = a.mutate_pin(&mut s, r, |request, c, tx, _, _, epoch, _| {
            storage.0.lock().map_err(|_| "disk")?.revoke_on_dispatch = Some(epoch);
            let binding = request.binding();
            let mut c = c.lock().map_err(|_| "controller")?;
            c.resolve(PromptOutcome::Approved(binding), Instant::now())
                .map_err(|_| "resolve")?;
            c.did_teardown(binding, Instant::now())
                .map_err(|_| "teardown")?;
            let new = pin()?;
            let secrets = match operation {
                PinOperation::SetPin => PinMutationSecrets::Set { new },
                PinOperation::ChangePin => PinMutationSecrets::Change {
                    current: pin()?,
                    new,
                },
            };
            tx.send(MutationCompletion {
                binding,
                outcome: PromptOutcome::Approved(binding),
                secrets: Some(secrets),
            })
            .map_err(|_| "reply")
        });
        assert_eq!(result.outcome, MutationOutcome::OutcomeUnknown);
        assert!(result.worker_quiescent && result.prompt_torn_down && result.recovery_required);
        assert_eq!(
            storage.0.lock().map_err(|_| "disk")?.phases,
            ["pending", "dispatch_capable"]
        );
        assert!(a.reserve().is_err());
        assert!(s.resolve_handle(handle).is_none());
    }
    Ok(())
}

#[test]
fn corrupt_storage_has_no_native_acknowledgement_bypass() -> TestResult {
    let storage = Storage::default();
    storage.0.lock().map_err(|_| "disk")?.bytes = Some(b"corrupt".to_vec());
    let a = AuthenticationAuthority::default();
    a.initialize_recovery(Box::new(storage.clone()))?;
    let mut s = DiscoverySupervisor::new(
        launcher(&["--authentication", "--mutation=success"])?,
        DiscoveryPolicy::default(),
        RestartPolicy::default(),
    )?;
    assert!(
        a.acknowledge_pin_recovery(&mut s, |_, _, _, _, _, _| panic!(
            "corrupt storage must not present acknowledgement"
        ))
        .is_err()
    );
    assert_eq!(a.recovery_admission(), RecoveryAdmission::Barrier);
    assert!(a.reserve().is_err());
    assert_eq!(storage.0.lock().map_err(|_| "disk")?.writes, 0);
    Ok(())
}
