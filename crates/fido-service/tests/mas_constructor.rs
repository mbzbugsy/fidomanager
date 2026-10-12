//! Exercises the service as a normal dependency (not cfg(test)), where development construction
//! must refuse in the MAS flavor. No process, credential, journal or physical device is used.
#![cfg(all(target_os = "macos", feature = "macos-mas-signing"))]
use fido_core::ExecutionQuiescence;
use fido_service::{
    LaunchError, ProcessWorkerConfig, ProcessWorkerLauncher, ResolvedWorkerExecutable,
    WorkerLauncher,
};
use fido_worker_protocol::WorkerGeneration;

#[test]
fn production_mas_development_constructor_is_permanently_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let executable = ResolvedWorkerExecutable::from_absolute_path("/bin/sh".into())?;
    let mut launcher = ProcessWorkerLauncher::new(executable, ProcessWorkerConfig::default())?;
    for generation in 1..=3 {
        assert!(matches!(
            launcher.launch(WorkerGeneration(generation)),
            Err(LaunchError::WorkerIdentityRejected {
                quiescence: ExecutionQuiescence::Quiescent
            })
        ));
    }
    Ok(())
}
