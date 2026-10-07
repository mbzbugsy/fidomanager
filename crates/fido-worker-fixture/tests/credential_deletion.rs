//! Production service -> process endpoint -> worker engine, with synthetic native I/O only.
#![cfg(unix)]
mod common;
use common::{TestResult, launcher};
use fido_core::{ExecutionQuiescence, MutationOutcome, RecoveryAdmission};
use fido_native_ui::{PinCompletion, PromptOutcome};
use fido_service::{
    DiscoveryPolicy, DiscoverySupervisor, ProcessWorkerLauncher, RestartPolicy,
    authentication::{AuthenticationAuthority, NativeController},
    deletion::{DeleteCredentialWorkflowResult, DeletionRecoveryCompletion},
    inspection::{ExactCredentialTarget, InspectionStore, InventoryDevice},
    recovery::{JournalStorage, RecoverableOperation},
};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Default)]
struct Disk {
    bytes: Option<Vec<u8>>,
    phases: Vec<String>,
    writes: usize,
    fail_at: usize,
    publish_failure: bool,
    revoke: Option<Arc<AtomicU64>>,
    revoke_at: usize,
    delay_at: usize,
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
        if d.fail_at == d.writes && !d.publish_failure {
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
        if d.fail_at == d.writes {
            return Err(std::io::Error::other("sync"));
        }
        if d.revoke_at == d.writes {
            if let Some(epoch) = &d.revoke {
                epoch.fetch_add(1, Ordering::SeqCst);
            }
        }
        if d.delay_at == d.writes {
            std::thread::sleep(Duration::from_millis(10_100));
        }
        Ok(())
    }
}
fn complete(
    request: fido_native_ui::PromptRequest,
    controller: NativeController,
    reply: std::sync::mpsc::Sender<PinCompletion>,
    cancel: bool,
) -> Result<(), &'static str> {
    let binding = request.binding();
    let outcome = if cancel {
        PromptOutcome::Cancelled(binding)
    } else {
        PromptOutcome::Approved(binding)
    };
    let mut c = controller.lock().map_err(|_| "controller")?;
    c.resolve(outcome, Instant::now()).map_err(|_| "resolve")?;
    c.did_teardown(binding, Instant::now())
        .map_err(|_| "teardown")?;
    let pin = if cancel {
        None
    } else {
        Some(
            fido_auth::PinSecret::collect(|b| {
                b[..4].copy_from_slice(b"fake");
                Some(4)
            })
            .map_err(|_| "pin")?,
        )
    };
    reply
        .send(PinCompletion {
            binding,
            outcome,
            pin,
        })
        .map_err(|_| "reply")
}
struct Harness {
    a: AuthenticationAuthority,
    s: DiscoverySupervisor<ProcessWorkerLauncher>,
    store: InspectionStore,
    device: InventoryDevice,
    storage: Storage,
    log: PathBuf,
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.log);
    }
}
impl Harness {
    fn inspected(mode: &str) -> Result<Self, Box<dyn std::error::Error>> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let log = std::env::temp_dir().join(format!(
            "fido-deletion-{}-{}.log",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let args: &'static [&'static str] = Box::leak(
            vec![
                "--authentication",
                Box::leak(format!("--deletion={mode}").into_boxed_str()),
                Box::leak(format!("--deletion-log={}", log.display()).into_boxed_str()),
            ]
            .into_boxed_slice(),
        );
        let storage = Storage::default();
        let a = AuthenticationAuthority::default();
        a.initialize_recovery(Box::new(storage.clone()))?;
        let mut s = DiscoverySupervisor::new(
            launcher(args)?,
            DiscoveryPolicy::default(),
            RestartPolicy::default(),
        )?;
        let snapshot = s.refresh()?;
        let old_worker = s.status().worker_generation.ok_or("worker")?;
        let old_handle = snapshot.devices[0].handle;
        let mut store = InspectionStore::default();
        let device = store
            .reconcile_connected(&snapshot.devices, old_worker)
            .map_err(|_| "reconcile")?[0];
        let result = a.inspect(&mut s, old_handle, a.reserve()?, |r, c, t, _, _, _| {
            complete(r, c, t, false)
        });
        assert_eq!(result.status, fido_auth::AuthenticationStatus::Validated);
        assert!(result.worker_quiescent && result.prompt_torn_down && result.attached_puat_cleared);
        assert!(s.resolve_handle(old_handle).is_none());
        // The actual production order: N is retired BEFORE its inventory is published.
        store.proven_retirement(old_worker);
        assert_eq!(result.inspection_worker, Some(old_worker));
        store
            .replace(
                device,
                result.inspection_worker.ok_or("provenance")?,
                "Fixture key".into(),
                result.inventory.ok_or("inventory")?,
            )
            .map_err(|_| "publish")?;
        assert!(store.snapshot_for(device).is_none());
        std::thread::sleep(Duration::from_millis(1_020));
        let next = s.refresh()?;
        let current_worker = s.status().worker_generation.ok_or("worker")?;
        assert!(current_worker.0 > old_worker.0);
        assert!(s.resolve_handle(old_handle).is_none());
        assert_eq!(
            store
                .reconcile_connected(&next.devices, current_worker)
                .map_err(|_| "reconcile")?[0],
            device
        );
        assert!(store.snapshot_for(device).is_some());
        Ok(Self {
            a,
            s,
            store,
            device,
            storage,
            log,
        })
    }
    fn target(&self) -> Result<ExactCredentialTarget, &'static str> {
        let snapshot = self.store.snapshot_for(self.device).ok_or("snapshot")?;
        self.store
            .resolve_for_mutation(
                self.device.handle,
                self.device.generation,
                &snapshot.epoch,
                &snapshot.rps[0].credentials[0].handle,
            )
            .ok_or("target")
    }
    fn events(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    }
    fn run(
        &mut self,
        cancel: bool,
    ) -> Result<DeleteCredentialWorkflowResult, Box<dyn std::error::Error>> {
        let target = self.target()?;
        let fingerprint = self.store.snapshot_for(self.device).ok_or("snapshot")?.rps[0]
            .credentials[0]
            .credential_fingerprint
            .clone();
        Ok(self.a.delete_credential(
            &mut self.s,
            &mut self.store,
            target,
            |r, c, t, p, retries, _, _| {
                assert_eq!(p.rp_id(), "example.com");
                assert_eq!(p.user_name(), Some("person@example.com"));
                assert_eq!(p.display_name(), Some("Person"));
                assert_eq!(p.credential_fingerprint(), fingerprint);
                assert!(p.consequence().contains("permanently"));
                assert_eq!(retries, 8);
                complete(r, c, t, cancel)
            },
        )?)
    }
    fn journal(&self) -> serde_json::Value {
        serde_json::from_slice(
            self.storage
                .0
                .lock()
                .unwrap_or_else(|_| panic!("disk"))
                .bytes
                .as_ref()
                .unwrap_or_else(|| panic!("record")),
        )
        .unwrap_or_else(|_| panic!("json"))
    }
}

#[test]
fn production_retirement_current_worker_proof_and_definitive_results() -> TestResult {
    for (mode, outcome, resolution) in [
        (
            "success",
            MutationOutcome::ConfirmedSuccessful,
            "confirmed_successful",
        ),
        ("reject", MutationOutcome::Rejected, "rejected"),
        (
            "cleanup",
            MutationOutcome::ConfirmedSuccessful,
            "confirmed_successful",
        ),
    ] {
        let mut h = Harness::inspected(mode)?;
        let result = h.run(false)?;
        assert_eq!(result.outcome, outcome);
        assert!(result.worker_quiescent && result.prompt_torn_down && !result.recovery_required);
        assert_eq!(h.events(), ["prepared", "proof", "proof-ok", "entered"]);
        assert_eq!(h.journal()["resolution"], resolution);
        assert_eq!(
            h.storage.0.lock().map_err(|_| "disk")?.phases,
            ["pending", "dispatch_capable", "resolved"]
        );
        if outcome == MutationOutcome::ConfirmedSuccessful {
            let next = {
                std::thread::sleep(Duration::from_millis(1_020));
                h.s.refresh()?
            };
            h.store
                .reconcile_connected(
                    &next.devices,
                    h.s.status().worker_generation.ok_or("worker")?,
                )
                .map_err(|_| "reconcile")?;
            assert!(h.store.snapshot_for(h.device).is_none());
        }
        let reservation = h.a.reserve()?;
        assert_eq!(
            h.a.cancel_unpresented(&mut h.s, reservation),
            ExecutionQuiescence::Quiescent
        );
    }
    Ok(())
}
#[test]
fn cancellation_and_prepare_failure_have_no_journal_or_delete_and_release_gate() -> TestResult {
    for (mode, cancel) in [("success", true), ("prepare-failure", false)] {
        let mut h = Harness::inspected(mode)?;
        let r = h.run(cancel)?;
        assert_eq!(r.outcome, MutationOutcome::NotDispatched);
        assert_eq!(r.cancelled, cancel);
        assert!(r.worker_quiescent && r.prompt_torn_down && !r.recovery_required);
        assert!(!h.events().iter().any(|e| e == "proof" || e == "entered"));
        assert_eq!(h.storage.0.lock().map_err(|_| "disk")?.writes, 0);
        let reservation = h.a.reserve()?;
        h.a.cancel_unpresented(&mut h.s, reservation);
    }
    Ok(())
}
/// N1: every provable pre-delete failure happens in the proof step, BEFORE the durable
/// DispatchCapable record. None of them may write a journal record, create a recovery barrier,
/// reach the native delete, or cost the user a second PIN prompt to recover.
#[test]
fn proof_stage_failures_are_typed_clean_and_never_reach_delete_or_a_barrier() -> TestResult {
    use fido_auth::deletion::DeleteCredentialRejection as R;
    for (mode, outcome, rejection) in [
        ("wrong-pin", MutationOutcome::Rejected, Some(R::WrongPin)),
        (
            "pin-blocked",
            MutationOutcome::Rejected,
            Some(R::PinBlocked),
        ),
        (
            "auth-blocked",
            MutationOutcome::Rejected,
            Some(R::PinAuthBlocked),
        ),
        (
            "absent",
            MutationOutcome::Rejected,
            Some(R::CredentialAbsent),
        ),
        (
            "wrong-id",
            MutationOutcome::Rejected,
            Some(R::CredentialAbsent),
        ),
        (
            "ambiguous",
            MutationOutcome::Rejected,
            Some(R::CredentialMismatch),
        ),
        (
            "wrong-user",
            MutationOutcome::Rejected,
            Some(R::CredentialMismatch),
        ),
        (
            "malformed",
            MutationOutcome::Rejected,
            Some(R::CredentialMismatch),
        ),
        ("wrong-device", MutationOutcome::NotDispatched, None),
        ("proof-unavailable", MutationOutcome::NotDispatched, None),
    ] {
        let mut h = Harness::inspected(mode)?;
        let r = h.run(false)?;
        assert_eq!(r.outcome, outcome, "{mode}");
        assert_eq!(r.rejection, rejection, "{mode}");
        assert!(r.worker_quiescent && r.prompt_torn_down, "{mode}");
        assert!(
            !r.recovery_required,
            "{mode}: a proof failure is never a barrier"
        );
        assert!(!r.cancelled, "{mode}");
        assert_eq!(
            h.events(),
            ["prepared", "proof", "proof-rejected"],
            "{mode}"
        );
        // Nothing durable was ever written, so there is nothing to acknowledge.
        assert_eq!(h.storage.0.lock().map_err(|_| "disk")?.writes, 0, "{mode}");
        assert!(h.storage.0.lock().map_err(|_| "disk")?.bytes.is_none());
        assert_eq!(h.a.recoverable_operation(), None, "{mode}");
        assert_eq!(h.a.recovery_admission(), RecoveryAdmission::Open, "{mode}");
        // The gate is free again: the next attempt needs no recovery acknowledgement.
        let reservation = h.a.reserve()?;
        assert_eq!(
            h.a.cancel_unpresented(&mut h.s, reservation),
            ExecutionQuiescence::Quiescent
        );
        // The card is invalidated only when it provably no longer describes the key; otherwise it
        // is republished after the (always retired) worker is replaced.
        std::thread::sleep(Duration::from_millis(1_020));
        let next = h.s.refresh()?;
        h.store
            .reconcile_connected(
                &next.devices,
                h.s.status().worker_generation.ok_or("worker")?,
            )
            .map_err(|_| "reconcile")?;
        assert_eq!(
            h.store.snapshot_for(h.device).is_none(),
            matches!(rejection, Some(R::CredentialAbsent | R::CredentialMismatch)),
            "{mode}"
        );
    }
    Ok(())
}
/// A hang, crash or lost response during the proof is a worker failure before any delete could
/// have been sent. It is NotDispatched without a barrier, and the worker is reaped.
#[test]
fn worker_failure_or_timeout_during_proof_is_not_dispatched_without_barrier() -> TestResult {
    for mode in ["proof-hang", "proof-crash", "proof-lost-response"] {
        let mut h = Harness::inspected(mode)?;
        let r = h.run(false)?;
        assert_eq!(r.outcome, MutationOutcome::NotDispatched, "{mode}");
        assert_eq!(r.rejection, None, "{mode}");
        assert!(r.worker_quiescent && r.prompt_torn_down, "{mode}");
        assert!(!r.recovery_required, "{mode}");
        assert_eq!(h.events(), ["prepared", "proof"], "{mode}");
        assert_eq!(h.storage.0.lock().map_err(|_| "disk")?.writes, 0, "{mode}");
        assert_eq!(h.a.recovery_admission(), RecoveryAdmission::Open, "{mode}");
        assert!(h.a.reserve().is_ok(), "{mode}");
    }
    Ok(())
}
#[test]
fn every_storage_failure_poisoned_no_native_capability_before_durable_dispatch() -> TestResult {
    for fail_at in 1..=3 {
        for publish_failure in [false, true] {
            let mut h = Harness::inspected("success")?;
            {
                let mut d = h.storage.0.lock().map_err(|_| "disk")?;
                d.fail_at = fail_at;
                d.publish_failure = publish_failure;
            }
            let r = h.run(false)?;
            assert_eq!(
                r.outcome,
                if fail_at == 3 {
                    MutationOutcome::ConfirmedSuccessful
                } else {
                    MutationOutcome::NotDispatched
                }
            );
            assert!(r.worker_quiescent && r.prompt_torn_down && r.recovery_required);
            assert_eq!(
                h.events().iter().filter(|e| *e == "entered").count(),
                usize::from(fail_at == 3)
            );
            // The proof always ran first and succeeded, even when the first journal write fails.
            assert_eq!(&h.events()[..3], ["prepared", "proof", "proof-ok"]);
            assert_eq!(
                h.a.recoverable_operation(),
                None,
                "poisoned storage is never acknowledgeable"
            );
            assert!(h.a.reserve().is_err());
        }
    }
    Ok(())
}
#[test]
fn revocation_and_expiry_after_proof_mint_no_native_dispatch() -> TestResult {
    // (revoke_at, delay_at): revoke after the Pending write, after the DispatchCapable write, and
    // an approval that expires after Pending / after DispatchCapable.
    for (revoke_at, delay_at) in [(1, 0), (2, 0), (0, 1), (0, 2)] {
        let mut h = Harness::inspected("success")?;
        {
            let mut d = h.storage.0.lock().map_err(|_| "disk")?;
            d.revoke_at = revoke_at;
            d.revoke = Some(Arc::clone(&h.a.epoch));
            d.delay_at = delay_at;
        }
        let r = h.run(false)?;
        let before_marker = revoke_at == 1 || delay_at == 1;
        assert_eq!(
            r.outcome,
            if before_marker {
                MutationOutcome::NotDispatched
            } else {
                MutationOutcome::OutcomeUnknown
            },
            "{revoke_at}/{delay_at}"
        );
        assert!(r.worker_quiescent && r.prompt_torn_down);
        // The proof ran, but the native delete was never sent.
        assert_eq!(
            h.events(),
            ["prepared", "proof", "proof-ok"],
            "{revoke_at}/{delay_at}"
        );
        assert_eq!(
            r.recovery_required, !before_marker,
            "{revoke_at}/{delay_at}"
        );
        if before_marker {
            // Pending was written and honestly resolved: DispatchCapable never was.
            assert_eq!(
                h.storage.0.lock().map_err(|_| "disk")?.phases,
                ["pending", "resolved"]
            );
            assert_eq!(h.journal()["resolution"], "not_dispatched");
        } else {
            assert_eq!(h.journal()["phase"], "dispatch_capable");
        }
    }
    Ok(())
}
#[test]
fn stale_or_replaced_epoch_fails_before_prepare() -> TestResult {
    for replaced in [false, true] {
        let mut h = Harness::inspected("success")?;
        let target = h.target()?;
        if replaced {
            h.store
                .replace(
                    h.device,
                    h.s.status().worker_generation.ok_or("worker")?,
                    "Fixture key".into(),
                    fido_worker_fixture::inventory(),
                )
                .map_err(|_| "replace")?;
        } else {
            h.store.invalidate(h.device);
        }
        assert!(
            h.a.delete_credential(
                &mut h.s,
                &mut h.store,
                target,
                |_, _, _, _, _, _, _| panic!("stale selection")
            )
            .is_err()
        );
        assert!(h.events().is_empty());
        assert_eq!(h.storage.0.lock().map_err(|_| "disk")?.writes, 0);
        assert!(h.a.reserve().is_ok());
    }
    Ok(())
}
#[test]
fn lost_response_crash_unknown_and_hang_reap_without_retry_then_typed_recovery() -> TestResult {
    for mode in ["lost-response", "crash", "unknown", "hang"] {
        let mut h = Harness::inspected(mode)?;
        let r = h.run(false)?;
        assert_eq!(r.outcome, MutationOutcome::OutcomeUnknown);
        assert!(r.worker_quiescent && r.prompt_torn_down && r.recovery_required);
        assert_eq!(h.events(), ["prepared", "proof", "proof-ok", "entered"]);
        assert_eq!(
            h.a.recoverable_operation(),
            Some(RecoverableOperation::DeleteCredential)
        );
        assert_eq!(h.a.recoverable_pin_operation(), None);
        assert!(
            h.a.acknowledge_pin_recovery(&mut h.s, |_, _, _, _, _, _| panic!(
                "must not present PIN recovery"
            ))
            .is_err()
        );
        assert!(h.a.reserve().is_err());
        let restarted = AuthenticationAuthority::default();
        restarted.initialize_recovery(Box::new(h.storage.clone()))?;
        assert_eq!(restarted.recovery_admission(), RecoveryAdmission::Barrier);
        restarted.acknowledge_deletion_recovery(
            &mut h.s,
            &mut h.store,
            |request, c, tx, p, _, _| {
                assert!(p.created_unix_secs() > 0);
                assert!(p.explanation().contains("may or may not have been deleted"));
                let binding = request.binding();
                let mut c = c.lock().map_err(|_| "controller")?;
                c.resolve(PromptOutcome::Approved(binding), Instant::now())
                    .map_err(|_| "approve")?;
                c.did_teardown(binding, Instant::now())
                    .map_err(|_| "teardown")?;
                tx.send(DeletionRecoveryCompletion {
                    binding,
                    outcome: PromptOutcome::Approved(binding),
                })
                .map_err(|_| "reply")
            },
        )?;
        assert_eq!(h.journal()["resolution"], "acknowledged_unknown");
        assert_eq!(restarted.recovery_admission(), RecoveryAdmission::Open);
        assert!(h.store.snapshot_for(h.device).is_none());
        assert_eq!(
            h.events(),
            ["prepared", "proof", "proof-ok", "entered"],
            "acknowledgement never retries"
        );
    }
    Ok(())
}
#[test]
fn deletion_recovery_requires_native_approval_and_teardown() -> TestResult {
    for scenario in 0..4 {
        let mut h = Harness::inspected("unknown")?;
        h.run(false)?;
        assert!(
            h.a.acknowledge_deletion_recovery(
                &mut h.s,
                &mut h.store,
                |request, c, tx, _, epoch, _| {
                    let binding = request.binding();
                    let outcome = if scenario == 0 {
                        PromptOutcome::Cancelled(binding)
                    } else {
                        PromptOutcome::Approved(binding)
                    };
                    if scenario != 1 {
                        // A forged channel reply is not approval evidence.
                        let mut c = c.lock().map_err(|_| "controller")?;
                        c.resolve(outcome, Instant::now()).map_err(|_| "resolve")?;
                        if scenario != 2 {
                            c.did_teardown(binding, Instant::now())
                                .map_err(|_| "teardown")?;
                        }
                    }
                    if scenario == 3 {
                        epoch.fetch_add(1, Ordering::SeqCst);
                    }
                    tx.send(DeletionRecoveryCompletion { binding, outcome })
                        .map_err(|_| "reply")
                }
            )
            .is_err()
        );
        assert_eq!(h.a.recovery_admission(), RecoveryAdmission::Barrier);
        assert_eq!(h.journal()["phase"], "dispatch_capable");
    }
    Ok(())
}
#[test]
fn serialized_m4_compatibility_pending_restart_and_corrupt_storage() -> TestResult {
    for operation in ["set_pin", "change_pin", "delete_credential"] {
        for phase in ["pending", "dispatch_capable"] {
            let storage = Storage::default();
            storage.0.lock().map_err(|_| "disk")?.bytes = Some(format!(r#"{{"schema":1,"application":"fidomanager-m4-v1","incident":"0123456789abcdef0123456789abcdef","operation":"{operation}","created_unix_secs":42,"phase":"{phase}","resolution":null}}"#).into_bytes());
            let a = AuthenticationAuthority::default();
            a.initialize_recovery(Box::new(storage))?;
            assert_eq!(
                a.recovery_admission(),
                if phase == "pending" {
                    RecoveryAdmission::Open
                } else {
                    RecoveryAdmission::Barrier
                }
            );
            assert_eq!(
                a.recoverable_operation(),
                if phase == "pending" {
                    None
                } else {
                    Some(match operation {
                        "set_pin" => RecoverableOperation::SetPin,
                        "change_pin" => RecoverableOperation::ChangePin,
                        _ => RecoverableOperation::DeleteCredential,
                    })
                }
            );
        }
    }
    // A resolved deletion record (and a resolved M4 record) is no barrier after restart.
    for operation in ["set_pin", "change_pin", "delete_credential"] {
        for resolution in [
            "not_dispatched",
            "rejected",
            "confirmed_successful",
            "acknowledged_unknown",
        ] {
            let storage = Storage::default();
            storage.0.lock().map_err(|_| "disk")?.bytes = Some(format!(r#"{{"schema":1,"application":"fidomanager-m4-v1","incident":"0123456789abcdef0123456789abcdef","operation":"{operation}","created_unix_secs":42,"phase":"resolved","resolution":"{resolution}"}}"#).into_bytes());
            let a = AuthenticationAuthority::default();
            a.initialize_recovery(Box::new(storage))?;
            assert_eq!(a.recovery_admission(), RecoveryAdmission::Open);
            assert_eq!(a.recoverable_operation(), None);
        }
    }
    // Reverse direction: a PIN incident is never acknowledgeable through deletion recovery.
    for operation in ["set_pin", "change_pin"] {
        let mut h = Harness::inspected("success")?;
        let storage = Storage::default();
        storage.0.lock().map_err(|_| "disk")?.bytes = Some(format!(r#"{{"schema":1,"application":"fidomanager-m4-v1","incident":"0123456789abcdef0123456789abcdef","operation":"{operation}","created_unix_secs":42,"phase":"dispatch_capable","resolution":null}}"#).into_bytes());
        let a = AuthenticationAuthority::default();
        a.initialize_recovery(Box::new(storage.clone()))?;
        assert!(
            a.acknowledge_deletion_recovery(&mut h.s, &mut h.store, |_, _, _, _, _, _| panic!(
                "PIN incident must not reach the deletion sheet"
            ))
            .is_err()
        );
        assert_eq!(a.recovery_admission(), RecoveryAdmission::Barrier);
        assert!(a.recoverable_pin_operation().is_some());
    }
    let mut h = Harness::inspected("success")?;
    let storage = Storage::default();
    storage.0.lock().map_err(|_| "disk")?.bytes = Some(b"corrupt".to_vec());
    let a = AuthenticationAuthority::default();
    a.initialize_recovery(Box::new(storage))?;
    assert!(
        a.acknowledge_deletion_recovery(&mut h.s, &mut h.store, |_, _, _, _, _, _| panic!(
            "corrupt storage"
        ))
        .is_err()
    );
    assert_eq!(a.recovery_admission(), RecoveryAdmission::Barrier);
    Ok(())
}
