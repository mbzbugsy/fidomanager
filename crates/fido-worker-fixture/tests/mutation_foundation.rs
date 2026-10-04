//! Real process refresh/retirement around seeded persistent recovery state; no hardware or PINs.
#![cfg(unix)]
mod common;
use common::{ManualClock, TestResult, launcher};
use fido_service::{
    AdmissionError, DiscoveryPolicy, DiscoverySupervisor, RestartPolicy,
    authentication::AuthenticationAuthority,
    mutation::MutationError,
    recovery::{JournalStorage, PinOperation},
};

struct StartupRecord(&'static str);
impl JournalStorage for StartupRecord {
    fn read(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(Some(format!(r#"{{"schema":1,"application":"fidomanager-m4-v1","incident":"00000000000000000000000000000001","operation":"change_pin","created_unix_secs":1,"phase":"{}","resolution":null}}"#, self.0).into_bytes()))
    }
    fn replace_durable(&mut self, _: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::other("read-only startup fixture"))
    }
}
#[test]
fn dispatch_barrier_survives_real_worker_retirement_reconnect_and_authority_restart() -> TestResult
{
    let clock = ManualClock::default();
    let mut supervisor = DiscoverySupervisor::with_clock(
        launcher(&["--script=ok,crash"])?,
        DiscoveryPolicy::default(),
        RestartPolicy::default(),
        clock.clone(),
    )?;
    for _restart in 0..2 {
        let authority = AuthenticationAuthority::default();
        authority.initialize_recovery(Box::new(StartupRecord("dispatch_capable")))?;
        for _reconnect in 0..2 {
            let snapshot = supervisor.refresh()?;
            let handle = snapshot.devices.first().ok_or("no fixture target")?.handle;
            assert!(matches!(
                authority.reserve(),
                Err(AdmissionError::RecoveryBarrier)
            ));
            for operation in [PinOperation::SetPin, PinOperation::ChangePin] {
                assert!(matches!(
                    authority.reserve_pin_intent(&mut supervisor, handle, operation),
                    Err(MutationError::Admission(AdmissionError::RecoveryBarrier))
                ));
            }
            // The next fixture discovery call crashes; replacement requires actual reap.
            assert!(supervisor.refresh().is_err());
            clock.advance(1_000);
            assert!(supervisor.resolve_handle(handle).is_none());
        }
    }
    Ok(())
}
#[test]
fn pending_only_startup_does_not_claim_dispatch_or_block_inspection() -> TestResult {
    let authority = AuthenticationAuthority::default();
    authority.initialize_recovery(Box::new(StartupRecord("pending")))?;
    assert!(authority.reserve().is_ok());
    Ok(())
}
