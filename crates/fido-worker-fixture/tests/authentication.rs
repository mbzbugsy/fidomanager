//! Real process, framing, secret fd and admission lifecycle; synthetic PIN only.
#![cfg(unix)]
mod common;
use common::{TestResult, launcher};
use fido_auth::{AuthenticationStatus as Status, PinSecret};
use fido_native_ui::{PinCompletion, PromptOutcome};
use fido_service::{
    DiscoveryPolicy, DiscoverySupervisor, RestartPolicy, authentication::AuthenticationAuthority,
};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

// Existing M2/M3 fixtures initialize an empty read-only journal. Every write fails: these
// tests can exercise inspection, but this storage can never acknowledge mutation readiness.
fn initialized_authority() -> Result<AuthenticationAuthority, fido_service::recovery::JournalError>
{
    struct InspectionJournal;
    impl fido_service::recovery::JournalStorage for InspectionJournal {
        fn read(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn replace_durable(&mut self, _: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other(
                "inspection fixture cannot acknowledge journal writes",
            ))
        }
    }
    let authority = AuthenticationAuthority::default();
    authority.initialize_recovery(Box::new(InspectionJournal))?;
    Ok(authority)
}

#[test]
fn complete_native_auth_transaction_clears_reaps_and_restarts_fresh() -> TestResult {
    let mut supervisor = DiscoverySupervisor::new(
        launcher(&["--authentication"])?,
        DiscoveryPolicy::default(),
        RestartPolicy::default(),
    )?;
    let authority = initialized_authority()?;
    let mut previous_worker = 0;
    for _ in 0..2 {
        let snapshot = supervisor.refresh()?;
        let generation = supervisor
            .status()
            .worker_generation
            .ok_or("missing generation")?
            .0;
        assert!(generation > previous_worker);
        previous_worker = generation;
        let reservation = authority.reserve()?;
        let result = authority.validate(
            &mut supervisor,
            snapshot.devices[0].handle,
            reservation,
            |request, controller, sender, retries, _, _| {
                assert_eq!(retries, Some(8));
                let binding = request.binding();
                let mut controller = controller.lock().map_err(|_| "controller")?;
                controller
                    .resolve(PromptOutcome::Approved(binding), Instant::now())
                    .map_err(|_| "resolve")?;
                controller
                    .did_teardown(binding, Instant::now())
                    .map_err(|_| "teardown")?;
                let pin = PinSecret::collect(|b| {
                    b[..4].copy_from_slice(b"fake");
                    Some(4)
                })
                .map_err(|_| "pin")?;
                sender
                    .send(PinCompletion {
                        binding,
                        outcome: PromptOutcome::Approved(binding),
                        pin: Some(pin),
                    })
                    .map_err(|_| "send")
            },
        );
        assert_eq!(result.status, Status::Validated);
        assert!(result.attached_puat_cleared && result.worker_quiescent && result.prompt_torn_down);
        assert!(
            supervisor
                .resolve_handle(snapshot.devices[0].handle)
                .is_none()
        );
        std::thread::sleep(Duration::from_millis(1_020));
    }
    Ok(())
}

#[test]
fn two_keys_use_selected_native_target_and_discard_both_old_handles() -> TestResult {
    let mut supervisor = DiscoverySupervisor::new(
        launcher(&["--authentication", "--two-devices"])?,
        DiscoveryPolicy::default(),
        RestartPolicy::default(),
    )?;
    let authority = initialized_authority()?;
    let mut previous_history_ids = None;
    let mut retired_handles = Vec::new();
    for (selected, kind) in [
        (1, fido_auth::GrantKind::CredManReadOnly),
        (0, fido_auth::GrantKind::CredMan),
    ] {
        let snapshot = supervisor.refresh()?;
        assert_eq!(snapshot.devices.len(), 2);
        let presentations =
            fido_service::presentation::authenticator_presentations(&snapshot.devices);
        assert!(presentations[0].detail.ends_with(" · Key 1"));
        assert!(presentations[1].detail.ends_with(" · Key 2"));
        for (device, presentation) in snapshot.devices.iter().zip(&presentations) {
            assert!(
                !presentation
                    .label()
                    .contains(&format!("{:032x}", device.handle.as_raw()))
            );
            assert!(!presentation.label().contains("session"));
        }
        let history_ids = [
            snapshot.devices[0].verification_history_id,
            snapshot.devices[1].verification_history_id,
        ];
        assert!(history_ids.iter().all(Option::is_some));
        assert_ne!(history_ids[0], history_ids[1]);
        if let Some(previous) = previous_history_ids {
            assert_eq!(history_ids, previous);
        }
        previous_history_ids = Some(history_ids);
        let result = authority.validate(
            &mut supervisor,
            snapshot.devices[selected].handle,
            authority.reserve()?,
            |request, controller, sender, _, _, _| {
                let binding = request.binding();
                let mut controller = controller.lock().map_err(|_| "controller")?;
                controller
                    .resolve(PromptOutcome::Approved(binding), Instant::now())
                    .map_err(|_| "resolve")?;
                controller
                    .did_teardown(binding, Instant::now())
                    .map_err(|_| "teardown")?;
                let pin = PinSecret::collect(|b| {
                    b[..4].copy_from_slice(b"fake");
                    Some(4)
                })
                .map_err(|_| "pin")?;
                sender
                    .send(PinCompletion {
                        binding,
                        outcome: PromptOutcome::Approved(binding),
                        pin: Some(pin),
                    })
                    .map_err(|_| "send")
            },
        );
        assert_eq!(result.status, Status::Validated);
        assert_eq!(result.grant_kind, Some(kind));
        assert!(result.attached_puat_cleared && result.worker_quiescent && result.prompt_torn_down);
        for device in snapshot.devices {
            assert!(supervisor.resolve_handle(device.handle).is_none());
            retired_handles.push(device.handle);
        }
        std::thread::sleep(Duration::from_millis(1_020));
    }
    // Rediscovery can yield the same visible labels, but no old handle may bind to either key.
    let replacement = supervisor.refresh()?;
    let presentations =
        fido_service::presentation::authenticator_presentations(&replacement.devices);
    assert!(presentations[0].detail.ends_with(" · Key 1"));
    assert!(presentations[1].detail.ends_with(" · Key 2"));
    let result = authority.validate(
        &mut supervisor,
        retired_handles[0],
        authority.reserve()?,
        |_, _, _, _, _, _| panic!("Stale selection must fail before presenting a PIN prompt"),
    );
    assert_eq!(result.status, Status::StaleAcquisition);
    assert!(result.grant_kind.is_none());
    assert!(result.worker_quiescent && result.prompt_torn_down);
    Ok(())
}

#[test]
fn cleanup_poison_wrong_pin_cancel_and_revocation_retire_real_worker() -> TestResult {
    for (args, expected, revoke) in [
        (
            &["--authentication", "--cleanup-failed"][..],
            Status::CleanupFailed,
            false,
        ),
        (
            &["--authentication", "--wrong-pin"][..],
            Status::WrongPin,
            false,
        ),
        (&["--authentication"][..], Status::Revoked, true),
    ] {
        let mut supervisor = DiscoverySupervisor::new(
            launcher(args)?,
            DiscoveryPolicy::default(),
            RestartPolicy::default(),
        )?;
        let snapshot = supervisor.refresh()?;
        let authority = initialized_authority()?;
        let result = authority.validate(
            &mut supervisor,
            snapshot.devices[0].handle,
            authority.reserve()?,
            |request, controller, sender, _, epoch, _| {
                let binding = request.binding();
                let mut controller = controller.lock().map_err(|_| "controller")?;
                controller
                    .resolve(PromptOutcome::Approved(binding), Instant::now())
                    .map_err(|_| "resolve")?;
                controller
                    .did_teardown(binding, Instant::now())
                    .map_err(|_| "teardown")?;
                if revoke {
                    epoch.fetch_add(1, Ordering::SeqCst);
                }
                let pin = PinSecret::collect(|b| {
                    b[..4].copy_from_slice(b"fake");
                    Some(4)
                })
                .map_err(|_| "pin")?;
                sender
                    .send(PinCompletion {
                        binding,
                        outcome: PromptOutcome::Approved(binding),
                        pin: Some(pin),
                    })
                    .map_err(|_| "send")
            },
        );
        assert_eq!(result.status, expected);
        assert!(result.worker_quiescent && result.prompt_torn_down);
        assert!(
            supervisor
                .resolve_handle(snapshot.devices[0].handle)
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn teardown_proof_is_required_and_unpresented_failure_releases_safely() -> TestResult {
    for acknowledged in [true, false] {
        let mut supervisor = DiscoverySupervisor::new(
            launcher(&["--authentication"])?,
            DiscoveryPolicy::default(),
            RestartPolicy::default(),
        )?;
        let snapshot = supervisor.refresh()?;
        let authority = initialized_authority()?;
        let result = authority.validate(
            &mut supervisor,
            snapshot.devices[0].handle,
            authority.reserve()?,
            |request, controller, sender, _, _, _| {
                let binding = request.binding();
                if acknowledged {
                    fido_service::authentication::presentation_failed(binding, controller, sender);
                } else {
                    let _ = sender.send(PinCompletion {
                        binding,
                        outcome: PromptOutcome::Cancelled(binding),
                        pin: None,
                    });
                }
                Ok(())
            },
        );
        assert!(result.worker_quiescent);
        assert_eq!(result.prompt_torn_down, acknowledged);
        assert_eq!(authority.reserve().is_ok(), acknowledged);
    }
    Ok(())
}

#[test]
fn host_deadline_kills_and_reaps_without_claiming_authenticator_cancel() -> TestResult {
    use fido_service::{WorkerEndpoint, WorkerGeneration, WorkerLauncher};
    // This endpoint test uses an in-flight discovery call to exercise the same containment loop.
    let mut endpoint = launcher(&["--script=hang"])?.launch(WorkerGeneration(1))?;
    let pid = endpoint.worker_pid();
    // Service-specific atomic revocation is covered by the complete workflow above; here the
    // exchange deadline proves kill/reap while native execution ignores its host deadline.
    let result = endpoint.exchange(common::list_request(1, 1, 50));
    assert!(result.is_err());
    assert!(!common::pid_exists(pid));
    Ok(())
}

#[test]
fn complete_inspection_transaction_clears_reaps_and_restarts_fresh() -> TestResult {
    let mut supervisor = DiscoverySupervisor::new(
        launcher(&["--authentication"])?,
        DiscoveryPolicy::default(),
        RestartPolicy::default(),
    )?;
    let authority = initialized_authority()?;
    let mut previous_worker = 0;
    for _ in 0..2 {
        let snapshot = supervisor.refresh()?;
        let generation = supervisor
            .status()
            .worker_generation
            .ok_or("missing generation")?
            .0;
        assert!(generation > previous_worker);
        previous_worker = generation;
        let reservation = authority.reserve()?;
        let result = authority.inspect(
            &mut supervisor,
            snapshot.devices[0].handle,
            reservation,
            |request, controller, sender, retries, _, _| {
                assert_eq!(retries, Some(8));
                let binding = request.binding();
                let mut controller = controller.lock().map_err(|_| "controller")?;
                controller
                    .resolve(PromptOutcome::Approved(binding), Instant::now())
                    .map_err(|_| "resolve")?;
                controller
                    .did_teardown(binding, Instant::now())
                    .map_err(|_| "teardown")?;
                let pin = PinSecret::collect(|b| {
                    b[..4].copy_from_slice(b"fake");
                    Some(4)
                })
                .map_err(|_| "pin")?;
                sender
                    .send(PinCompletion {
                        binding,
                        outcome: PromptOutcome::Approved(binding),
                        pin: Some(pin),
                    })
                    .map_err(|_| "send")
            },
        );
        assert_eq!(result.status, Status::Validated);
        assert_eq!(
            result.inventory.ok_or("inventory")?.assess().total,
            fido_core::inventory::CredentialTotal::Exact(0)
        );
        assert!(result.attached_puat_cleared && result.worker_quiescent && result.prompt_torn_down);
        assert!(
            supervisor
                .resolve_handle(snapshot.devices[0].handle)
                .is_none()
        );
        std::thread::sleep(Duration::from_millis(1_020));
    }
    Ok(())
}

#[test]
fn two_inspected_inventories_survive_real_worker_retirement_and_cancel() -> TestResult {
    use fido_service::inspection::InspectionStore;
    let mut supervisor = DiscoverySupervisor::new(
        launcher(&["--authentication", "--two-devices"])?,
        DiscoveryPolicy::default(),
        RestartPolicy::default(),
    )?;
    let authority = initialized_authority()?;
    let mut store = InspectionStore::default();
    let mut epochs = [None, None];
    for (selected, cancel) in [(0, false), (1, false), (0, false), (0, true)] {
        let snapshot = supervisor.refresh()?;
        let worker = supervisor.status().worker_generation.ok_or("generation")?;
        let ids = store
            .reconcile_connected(&snapshot.devices, worker)
            .map_err(|_| "reconcile")?;
        for i in 0..2 {
            assert_eq!(store.snapshot_for(ids[i]).map(|s| s.epoch), epochs[i]);
        }
        store.invalidate(ids[selected]);
        let mut result = authority.inspect(
            &mut supervisor,
            snapshot.devices[selected].handle,
            authority.reserve()?,
            |request, controller, sender, _, _, _| {
                let binding = request.binding();
                let outcome = if cancel {
                    PromptOutcome::Cancelled(binding)
                } else {
                    PromptOutcome::Approved(binding)
                };
                let mut controller = controller.lock().map_err(|_| "controller")?;
                controller
                    .resolve(outcome, Instant::now())
                    .map_err(|_| "resolve")?;
                controller
                    .did_teardown(binding, Instant::now())
                    .map_err(|_| "teardown")?;
                let pin = if cancel {
                    None
                } else {
                    Some(
                        PinSecret::collect(|b| {
                            b[..4].copy_from_slice(b"fake");
                            Some(4)
                        })
                        .map_err(|_| "pin")?,
                    )
                };
                sender
                    .send(PinCompletion {
                        binding,
                        outcome,
                        pin,
                    })
                    .map_err(|_| "send")
            },
        );
        assert!(result.worker_quiescent && result.prompt_torn_down);
        assert_eq!(
            result.status,
            if cancel {
                Status::Cancelled
            } else {
                Status::Validated
            }
        );
        for device in &snapshot.devices {
            assert!(supervisor.resolve_handle(device.handle).is_none());
        }
        store.proven_retirement(worker);
        let settling_error = supervisor
            .refresh()
            .err()
            .ok_or("expected restart settling")?;
        assert_eq!(
            store.discovery_problem::<()>(settling_error),
            fido_service::discovery_presentation::DiscoveryPresentation::Settling {}
        );
        if let Some(inventory) = result.inventory.take() {
            store
                .replace(ids[selected], "Identical label".into(), inventory)
                .map_err(|_| "replace")?;
        }
        assert!(ids.iter().all(|d| store.snapshot_for(*d).is_none()));
        std::thread::sleep(Duration::from_millis(1_020));
        let next = supervisor.refresh()?;
        let new_ids = store
            .reconcile_connected(
                &next.devices,
                supervisor.status().worker_generation.ok_or("generation")?,
            )
            .map_err(|_| "reconcile")?;
        assert_eq!(ids, new_ids);
        let new_epoch = store.snapshot_for(new_ids[selected]).map(|s| s.epoch);
        if !cancel {
            assert!(new_epoch.is_some());
            assert_ne!(new_epoch, epochs[selected]);
        } else {
            assert!(new_epoch.is_none());
        }
        epochs[selected] = new_epoch;
        assert_eq!(
            store.snapshot_for(new_ids[1 - selected]).map(|s| s.epoch),
            epochs[1 - selected]
        );
    }
    assert!(epochs[0].is_none() && epochs[1].is_some());
    Ok(())
}
