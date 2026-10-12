//! Disposable MAS.2 protocol peer: health only, no discovery, device, PIN or recovery APIs.
use fido_worker_protocol::{
    ChildHello, MAX_WORKER_FRAME_BYTES, MAX_WORKER_HANDSHAKE_FRAME_BYTES,
    MAX_WORKER_REQUEST_FRAME_BYTES, ParentHello, WORKER_PROTOCOL_VERSION, WorkerRequest,
    WorkerRequestEnvelope, WorkerResponse, WorkerResponseEnvelope, WorkerResponseEvidence,
    read_message, write_message,
};
use std::io::{Write, stdin, stdout};

#[cfg(target_os = "macos")]
fn kernel() -> serde_json::Value {
    unsafe extern "C" {
        fn sandbox_check(pid: i32, operation: *const std::ffi::c_char, kind: i32, ...) -> i32;
        fn csops(pid: i32, operation: u32, address: *mut std::ffi::c_void, size: usize) -> i32;
    }
    let pid = std::process::id();
    let mut flags = 0u32;
    // SAFETY: null-operation kernel sandbox query, and a writable four-byte STATUS buffer.
    let (sandboxed, status) = unsafe {
        (
            sandbox_check(pid as i32, std::ptr::null(), 0),
            csops(pid as i32, 0, std::ptr::from_mut(&mut flags).cast(), 4),
        )
    };
    serde_json::json!({"event":"child-kernel", "pid":pid, "sandboxed":sandboxed,
        "cs_status":status,"cs_flags":flags})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let variant = std::hint::black_box("FIDOMANAGER-MAS2-DISPOSABLE-VARIANT-A");
    #[cfg(target_os = "macos")]
    {
        let evidence = kernel();
        eprintln!("MAS2_CHILD_EVIDENCE {evidence}");
        assert_eq!(evidence["sandboxed"], 1);
        assert_eq!(evidence["cs_status"], 0);
    }
    let mut input = stdin().lock();
    let mut output = stdout().lock();
    let hello: ParentHello = read_message(&mut input, MAX_WORKER_HANDSHAKE_FRAME_BYTES)?;
    // This receipt is created ONLY after a valid ParentHello was actually received. It is
    // confined to the disposable peer's directory, which the parent guard restricts to its UUID.
    let receipt = std::env::current_exe()?
        .parent()
        .ok_or("fixture layout")?
        .join("hello-receipt");
    let mut receipt = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(receipt)?;
    writeln!(receipt, "{variant}")?;
    let build_id =
        if variant.ends_with('B') && std::env::args().any(|arg| arg == "--wrong-build-id") {
            "0.0.0+wrong.mas"
        } else {
            fido_platform::build_identity::WORKER_BUILD_ID
        };
    write_message(
        &mut output,
        &ChildHello::new(hello.worker_generation, std::process::id(), build_id),
        MAX_WORKER_HANDSHAKE_FRAME_BYTES,
    )?;
    loop {
        let request: WorkerRequestEnvelope =
            match read_message(&mut input, MAX_WORKER_REQUEST_FRAME_BYTES) {
                Ok(request) => request,
                Err(_) => return Ok(()),
            };
        if !matches!(request.request, WorkerRequest::HealthCheck) {
            return Err("fixture supports health only".into());
        }
        write_message(
            &mut output,
            &WorkerResponseEnvelope {
                protocol_version: WORKER_PROTOCOL_VERSION,
                request_id: request.request_id,
                worker_generation: request.worker_generation,
                device_generation: None,
                evidence: WorkerResponseEvidence {
                    execution_quiescence: fido_core::ExecutionQuiescence::Quiescent,
                    mutation_outcome: None,
                },
                response: WorkerResponse::Healthy,
            },
            MAX_WORKER_FRAME_BYTES,
        )?;
    }
}
