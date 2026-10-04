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

#[test]
fn complete_native_auth_transaction_clears_reaps_and_restarts_fresh() -> TestResult {
    let mut supervisor = DiscoverySupervisor::new(
        launcher(&["--authentication"])?,
        DiscoveryPolicy::default(),
        RestartPolicy::default(),
    )?;
    let authority = AuthenticationAuthority::default();
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
    let authority = AuthenticationAuthority::default();
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
        let authority = AuthenticationAuthority::default();
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
        let authority = AuthenticationAuthority::default();
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
    let authority = AuthenticationAuthority::default();
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
