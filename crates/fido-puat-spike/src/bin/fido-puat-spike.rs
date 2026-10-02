//! Manual hardware harness for the M1.5 libfido2 PUAT fit spike. Never shipped.
//!
//! Every subcommand prints `RESULT` lines that contain only libfido2 return codes, counts, lengths
//! and booleans. It never prints the PIN, token bytes, RP IDs, user names, or credential IDs.
//! The PIN is read from the controlling terminal (`/dev/tty`, not stdin) with echo disabled, used
//! for at most the acquisitions the subcommand announces, and wiped when dropped. Nothing is
//! written to disk.
//!
//! Subcommands that need no PIN: `info`, `timeout-probe`.
//! Subcommands that send the PIN (each asks for typed confirmation first and never retries):
//! `acquire`, `stale-token`, `replug`, `probe-ro-enforcement`, `rp-inventory` (read-only RP and
//! credential enumeration for the RP-hash spike, structural output only).

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fido_core::DeviceGeneration;
use fido_platform::process::exit_immediately;
use fido_puat_spike::contract::AuthorizationGrant;
use fido_puat_spike::contract::{
    AcquisitionPlan, PlanError, RequestedAuthorization, RpId, TokenCapabilities,
    VerificationMethod, plan,
};
use fido_puat_spike::guard::{DeviceSession, PuatDevice, PuatGuard};
use fido_puat_spike::native::{self, InfoReport, LibFido2Device};
use fido_puat_spike::retry::{
    PreSubmission, classify_acquisition_error, classify_token_use, pre_submission,
};
use fido_puat_spike::rp_identity::{
    Continuation, CredentialEnumeration, CredentialTotal, MalformedHash, RawRp, RpEntry, RpList,
    RpTextState, assess,
};
use fido_puat_spike::secret::{PinInputError, PinSecret};

/// Finite libfido2 timeout for every non-UV call.
const CALL_TIMEOUT_MS: i32 = 5_000;
/// Finite libfido2 timeout for an acquisition that waits for built-in UV.
const UV_TIMEOUT_MS: i32 = 30_000;
/// Extra time the process watchdog allows beyond the libfido2 timeout before killing the process.
const WATCHDOG_MARGIN_MS: u64 = 2_000;
/// `fido_dev_info_manifest` takes no timeout; the watchdog alone bounds it.
const MANIFEST_BUDGET_MS: u64 = 5_000;
const REPLUG_WAIT: Duration = Duration::from_secs(60);
const WATCHDOG_EXIT: i32 = 70;

type HarnessResult = Result<(), String>;

fn main() {
    // Before the watchdog thread exists and before any libfido2 call: a FIDO_DEBUG in the
    // environment would turn on libfido2 protocol logging inside fido_init().
    if let Err(refusal) = native::init() {
        eprintln!("{refusal}");
        std::process::exit(2);
    }
    let watch = NativeCallWatch::start();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.first().map(String::as_str) {
        Some("info") => info(&watch),
        Some("timeout-probe") => timeout_probe(&watch),
        Some("acquire") => acquire(&watch, &args[1..]),
        Some("stale-token") => stale_token(&watch, &args[1..]),
        Some("replug") => replug(&watch, &args[1..]),
        Some("probe-ro-enforcement") => probe_ro_enforcement(&watch),
        Some("rp-inventory") => rp_inventory(&watch, &args[1..]),
        _ => Err(USAGE.to_owned()),
    };
    if let Err(message) = outcome {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

const USAGE: &str = "usage: fido-puat-spike <command>
  info                                     GetInfo, flags, retry counts, planned modes (no PIN)
  timeout-probe                            fido_dev_set_timeout behaviour on a retry query (no PIN)
  acquire --mode ro|cm [--rp-id ID] [--uv] acquire once, read metadata, test close/reopen + cleanup
  stale-token --first ro|cm                acquire, supersede with a second token, reuse the first
  replug --mode ro|cm                      acquire, unplug/replug, test fresh object + old token
  probe-ro-enforcement                     OPT-IN: delete of a random non-existent credential
                                           under a read-only token (asks before sending)
  rp-inventory --mode ro|cm                acquire once, enumerate RPs and credentials READ-ONLY,
                                           print structure only (counts, lengths, booleans)";

// ---------------------------------------------------------------------------------------------
// Process watchdog: the harness's stand-in for the worker kill boundary.
// ---------------------------------------------------------------------------------------------

struct NativeCallWatch {
    armed: Arc<Mutex<Option<(Instant, &'static str)>>>,
}

impl NativeCallWatch {
    fn start() -> Self {
        let armed: Arc<Mutex<Option<(Instant, &'static str)>>> = Arc::new(Mutex::new(None));
        let shared = Arc::clone(&armed);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_millis(100));
                let expired = match shared.lock() {
                    Ok(slot) => slot.and_then(|(deadline, label)| {
                        (Instant::now() >= deadline).then_some(label)
                    }),
                    Err(_) => Some("poisoned"),
                };
                if let Some(label) = expired {
                    eprintln!(
                        "RESULT step=watchdog call={label} outcome=process_terminated \
                         (native call outlived its libfido2 timeout + margin)"
                    );
                    exit_immediately(WATCHDOG_EXIT);
                }
            }
        });
        Self { armed }
    }

    fn run<R>(&self, label: &'static str, budget_ms: u64, call: impl FnOnce() -> R) -> R {
        if let Ok(mut slot) = self.armed.lock() {
            *slot = Some((Instant::now() + Duration::from_millis(budget_ms), label));
        }
        let result = call();
        if let Ok(mut slot) = self.armed.lock() {
            *slot = None;
        }
        result
    }

    fn native<R>(&self, label: &'static str, timeout_ms: i32, call: impl FnOnce() -> R) -> R {
        let budget = u64::try_from(timeout_ms).unwrap_or(0) + WATCHDOG_MARGIN_MS;
        self.run(label, budget, call)
    }
}

// ---------------------------------------------------------------------------------------------
// Terminal input
// ---------------------------------------------------------------------------------------------

fn tty() -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| format!("cannot open the controlling terminal: {error}"))
}

/// Restores terminal echo on drop (including on early return and unwind). If the process is
/// killed while echo is off, run `stty sane`.
struct EchoOff {
    fd: i32,
    saved: libc::termios,
}

impl EchoOff {
    fn new(terminal: &File) -> Result<Self, String> {
        let fd = terminal.as_raw_fd();
        // SAFETY: zeroed termios is a valid out-parameter; fd is an open terminal.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: valid fd and out pointer.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err("cannot read terminal settings".to_owned());
        }
        let mut quiet = saved;
        quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
        // SAFETY: valid fd and settings struct.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
            return Err("cannot disable terminal echo".to_owned());
        }
        Ok(Self { fd, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restoring the settings read in `new` on the same fd.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
    }
}

/// Reads one PIN line with echo off into a fixed-capacity buffer that is never reallocated.
fn read_pin(prompt: &str) -> Result<PinSecret, String> {
    let mut terminal = tty()?;
    write!(terminal, "{prompt}").map_err(|e| e.to_string())?;
    terminal.flush().map_err(|e| e.to_string())?;

    const CAPACITY: usize = 128;
    let mut buffer: Vec<u8> = Vec::with_capacity(CAPACITY);
    let mut overflow = false;
    {
        let _echo = EchoOff::new(&terminal)?;
        let mut byte = [0u8; 1];
        loop {
            match terminal.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    if byte[0] == b'\n' || byte[0] == b'\r' {
                        break;
                    }
                    if buffer.len() + 1 >= CAPACITY {
                        overflow = true;
                        continue; // keep draining the line, never grow the buffer
                    }
                    buffer.push(byte[0]);
                }
                Err(_) => break,
            }
            byte[0] = 0;
        }
    }
    let _ = writeln!(terminal);
    if overflow {
        drop(PinSecret::from_utf8_bytes(buffer)); // wipes
        return Err(PinInputError::TooLong.to_string());
    }
    PinSecret::from_utf8_bytes(buffer).map_err(|error| error.to_string())
}

/// Ask for an exact typed word. Anything else declines.
fn confirm(question: &str, expected: &str) -> Result<bool, String> {
    let mut terminal = tty()?;
    write!(
        terminal,
        "{question}\nType {expected} to continue, anything else to stop: "
    )
    .map_err(|e| e.to_string())?;
    terminal.flush().map_err(|e| e.to_string())?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while let Ok(1) = terminal.read(&mut byte) {
        if byte[0] == b'\n' {
            break;
        }
        if line.len() < 64 {
            line.push(byte[0]);
        }
    }
    Ok(String::from_utf8_lossy(&line).trim() == expected)
}

// ---------------------------------------------------------------------------------------------
// Shared steps
// ---------------------------------------------------------------------------------------------

fn result(step: &str, code: i32) {
    println!(
        "RESULT step={step} code={code} name={} token_use={:?}",
        native::error_name(code),
        classify_token_use(code)
    );
}

fn single_device(watch: &NativeCallWatch) -> Result<native::DiscoveredDevice, String> {
    let devices = watch
        .run("manifest", MANIFEST_BUDGET_MS, native::manifest)
        .map_err(|code| {
            format!(
                "fido_dev_info_manifest failed: {}",
                native::error_name(code)
            )
        })?;
    let count = devices.len();
    let mut devices = devices.into_iter();
    match (devices.next(), count) {
        (Some(device), 1) => {
            println!(
                "device: vid:pid={:04x}:{:04x}",
                device.vendor_id, device.product_id
            );
            Ok(device)
        }
        _ => Err(format!(
            "exactly one FIDO device must be connected (found {count}); unplug any others"
        )),
    }
}

fn open_fresh(watch: &NativeCallWatch, path: &CStr) -> Result<LibFido2Device, String> {
    let device = watch
        .native("open", CALL_TIMEOUT_MS, || {
            LibFido2Device::open(path, CALL_TIMEOUT_MS)
        })
        .map_err(|code| format!("fido_dev_open failed: {}", native::error_name(code)))?;
    println!(
        "RESULT step=fresh_object token_len={} token_ptr_null={}",
        device.attached_token_len(),
        device.token_pointer_is_null()
    );
    Ok(device)
}

fn read_info(watch: &NativeCallWatch, device: &mut LibFido2Device) -> Result<InfoReport, String> {
    watch
        .native("get_cbor_info", CALL_TIMEOUT_MS, || {
            device.info(CALL_TIMEOUT_MS)
        })
        .map_err(|code| format!("GetInfo failed: {}", native::error_name(code)))
}

fn capabilities(info: &InfoReport) -> TokenCapabilities {
    TokenCapabilities::from_options(
        info.options
            .iter()
            .map(|(name, value)| (name.as_str(), *value)),
    )
}

fn has_option(info: &InfoReport, name: &str) -> bool {
    info.options.iter().any(|(option, _)| option == name)
}

fn query_pin_retries(
    watch: &NativeCallWatch,
    device: &mut LibFido2Device,
    step: &str,
) -> Result<i32, i32> {
    let outcome = watch.native("get_retry_count", CALL_TIMEOUT_MS, || {
        device.pin_retries(CALL_TIMEOUT_MS)
    });
    match outcome {
        Ok(remaining) => println!("RESULT step={step} pin_retries={remaining}"),
        Err(code) => result(step, code),
    }
    outcome
}

fn parse_mode(args: &[String], flag: &str) -> Result<RequestedAuthorization, String> {
    let value = args
        .iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .ok_or_else(|| format!("missing {flag} ro|cm\n\n{USAGE}"))?;
    let rp = match args.iter().position(|arg| arg == "--rp-id") {
        Some(index) => Some(
            RpId::new(args.get(index + 1).map(String::as_str).unwrap_or_default())
                .map_err(|e| e.to_string())?,
        ),
        None => None,
    };
    match (value.as_str(), rp) {
        ("ro", None) => Ok(RequestedAuthorization::CredManReadOnly),
        ("ro", Some(_)) => Err("read-only tokens are never RP-scoped; drop --rp-id".to_owned()),
        ("cm", rp) => Ok(RequestedAuthorization::CredMan { rp }),
        _ => Err(format!("{flag} must be ro or cm")),
    }
}

/// Retry-count gate, explanation, typed confirmation, then the PIN. Returns `None` if declined.
fn gate_and_read_pin(
    watch: &NativeCallWatch,
    device: &mut LibFido2Device,
    announcement: &str,
) -> Result<Option<PinSecret>, String> {
    let advice = pre_submission(query_pin_retries(watch, device, "pin_retries_before"));
    println!("pre_submission={advice:?} power_cycle_state=not_exposed_by_libfido2");
    match advice {
        PreSubmission::RefuseBlocked => return Err("PIN is blocked; stopping".to_owned()),
        PreSubmission::Unknown { .. } => {
            return Err("retry count unknown; the spike refuses to submit a PIN blind".to_owned());
        }
        PreSubmission::RequireLastRetryAcknowledgement => {
            if !confirm(
                "ONLY ONE PIN RETRY REMAINS. A wrong PIN will block the PIN until reset.",
                "LAST",
            )? {
                return Ok(None);
            }
        }
        PreSubmission::WarnLowRetries { remaining } => {
            println!("WARNING: only {remaining} PIN retries remain.");
        }
        PreSubmission::Proceed { .. } => {}
    }
    if !confirm(announcement, "yes")? {
        return Ok(None);
    }
    read_pin("Authenticator PIN (not echoed): ").map(Some)
}

fn plan_or_explain(
    capabilities: &TokenCapabilities,
    request: &RequestedAuthorization,
    method: VerificationMethod,
) -> Result<AcquisitionPlan, String> {
    plan(capabilities, request, method).map_err(|error: PlanError| {
        format!(
            "RESULT step=plan request={request:?} method={method:?} planned=false reason={error:?}"
        )
    })
}

fn report_acquire_failure(
    watch: &NativeCallWatch,
    session: &mut DeviceSession<LibFido2Device>,
    error: &fido_puat_spike::guard::AcquireError,
) {
    println!("RESULT step=acquire outcome=failed error={error:?}");
    if let fido_puat_spike::guard::AcquireError::Native { code, failure } = error {
        println!(
            "RESULT step=acquire name={} retry_effect={:?} blocks_further_attempts={}",
            native::error_name(*code),
            failure.retry_effect(),
            failure.blocks_further_attempts()
        );
    }
    let _ = session
        .without_token(|device| query_pin_retries(watch, device, "pin_retries_after_failure"));
    println!("No automatic retry. Stopping.");
}

// ---------------------------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------------------------

fn info(watch: &NativeCallWatch) -> HarnessResult {
    let target = single_device(watch)?;
    let mut device = open_fresh(watch, &target.path)?;
    let info = read_info(watch, &mut device)?;

    println!("ctaphid_version={:?}", info.ctaphid_version);
    println!("versions={:?}", info.versions);
    println!("pin_protocols={:?}", info.pin_protocols);
    println!("aaguid={}", info.aaguid_hex.as_deref().unwrap_or("absent"));
    println!("firmware_version={:#x}", info.firmware_version);
    println!(
        "min_pin_length={} force_pin_change={}",
        info.min_pin_length, info.force_pin_change
    );
    println!(
        "rk_remaining={} uv_attempts={} uv_modality={:#x}",
        info.rk_remaining, info.uv_attempts, info.uv_modality
    );
    for (name, value) in &info.options {
        println!("option {name}={value}");
    }
    for name in [
        "clientPin",
        "uv",
        "pinUvAuthToken",
        "credMgmt",
        "credentialMgmtPreview",
        "perCredMgmtRO",
        "alwaysUv",
        "bioEnroll",
        "noMcGaPermissionsWithClientPin",
    ] {
        if !has_option(&info, name) {
            println!("option {name}=absent");
        }
    }
    println!(
        "libfido2_flags supports_permissions={} supports_pin={} has_pin={} supports_uv={} has_uv={} supports_credman={}",
        info.supports_permissions,
        info.supports_pin,
        info.has_pin,
        info.supports_uv,
        info.has_uv,
        info.supports_credman
    );

    if has_option(&info, "clientPin") {
        let _ = query_pin_retries(watch, &mut device, "pin_retries");
    }
    if has_option(&info, "uv") {
        match watch.native("get_uv_retry_count", CALL_TIMEOUT_MS, || {
            device.uv_retries(CALL_TIMEOUT_MS)
        }) {
            Ok(remaining) => println!("RESULT step=uv_retries uv_retries={remaining}"),
            Err(code) => result("uv_retries", code),
        }
    }

    let capabilities = capabilities(&info);
    println!("contract_capabilities={capabilities:?}");
    for (request, method) in [
        (
            RequestedAuthorization::CredManReadOnly,
            VerificationMethod::Pin,
        ),
        (
            RequestedAuthorization::CredManReadOnly,
            VerificationMethod::BuiltInUv,
        ),
        (
            RequestedAuthorization::CredMan { rp: None },
            VerificationMethod::Pin,
        ),
        (
            RequestedAuthorization::CredMan { rp: None },
            VerificationMethod::BuiltInUv,
        ),
        (
            RequestedAuthorization::LegacyUnscoped,
            VerificationMethod::Pin,
        ),
    ] {
        match plan(&capabilities, &request, method) {
            Ok(planned) => println!(
                "RESULT step=plan request={request:?} method={method:?} planned=true grant={:?} perm={:#x}",
                planned.kind(),
                planned.permissions()
            ),
            Err(error) => println!(
                "RESULT step=plan request={request:?} method={method:?} planned=false reason={error:?}"
            ),
        }
    }
    Ok(())
}

fn timeout_probe(watch: &NativeCallWatch) -> HarnessResult {
    let target = single_device(watch)?;
    {
        let mut device = open_fresh(watch, &target.path)?;
        let started = Instant::now();
        let normal = watch.native("retry_normal", CALL_TIMEOUT_MS, || {
            device.pin_retries(CALL_TIMEOUT_MS)
        });
        println!(
            "RESULT step=retry_query_timeout_5000ms ok={} code={} elapsed_ms={}",
            normal.is_ok(),
            normal.err().unwrap_or(0),
            started.elapsed().as_millis()
        );
        let started = Instant::now();
        let short = watch.native("retry_1ms", 1, || device.pin_retries(1));
        println!(
            "RESULT step=retry_query_timeout_1ms ok={} code={} name={} elapsed_ms={}",
            short.is_ok(),
            short.err().unwrap_or(0),
            native::error_name(short.err().unwrap_or(0)),
            started.elapsed().as_millis()
        );
        // The object may now hold a half-read exchange; it is freed, never reused.
    }
    let mut device = open_fresh(watch, &target.path)?;
    let recovered = watch.native("retry_after", CALL_TIMEOUT_MS, || {
        device.pin_retries(CALL_TIMEOUT_MS)
    });
    println!(
        "RESULT step=retry_query_on_fresh_object ok={}",
        recovered.is_ok()
    );
    Ok(())
}

fn acquire(watch: &NativeCallWatch, args: &[String]) -> HarnessResult {
    let request = parse_mode(args, "--mode")?;
    let method = if args.iter().any(|arg| arg == "--uv") {
        VerificationMethod::BuiltInUv
    } else {
        VerificationMethod::Pin
    };
    let target = single_device(watch)?;
    let mut device = open_fresh(watch, &target.path)?;
    let info = read_info(watch, &mut device)?;
    let planned = plan_or_explain(&capabilities(&info), &request, method)?;

    let pin = match method {
        VerificationMethod::Pin => {
            let announcement = format!(
                "This sends your PIN ONCE to request {:?} (permission {:#x}). It reads only \
                 credential COUNTS, then clears the token. A wrong PIN consumes one retry; there is \
                 no automatic retry. Nothing is deleted or changed.",
                planned.kind(),
                planned.permissions()
            );
            match gate_and_read_pin(watch, &mut device, &announcement)? {
                Some(pin) => Some(pin),
                None => {
                    println!("declined; nothing was sent");
                    return Ok(());
                }
            }
        }
        VerificationMethod::BuiltInUv => {
            if !confirm(
                "This asks the authenticator for built-in user verification once (touch/biometric). A failed UV may consume a UV retry.",
                "yes",
            )? {
                {
                    println!("declined; nothing was sent");
                    return Ok(());
                };
            }
            None
        }
    };

    let mut session = DeviceSession::open(device, DeviceGeneration(1))
        .map_err(|error| format!("fresh object refused: {error:?}"))?;
    let timeout = if pin.is_some() {
        CALL_TIMEOUT_MS
    } else {
        UV_TIMEOUT_MS
    };
    // The acquisition result is a temporary of this statement, so the guard's borrow of the
    // session ends here on every path (a named `Result` would stay borrowed until scope end).
    let failure = match watch.native("get_puat", timeout, || {
        session.acquire(&planned, pin.as_ref(), timeout)
    }) {
        Ok((guard, grant)) => {
            drop(pin); // wiped; not needed again in this subcommand
            acquire_transaction(watch, guard, &grant, &planned, &target.path)?;
            None
        }
        Err(error) => Some(error),
    };
    if let Some(error) = failure {
        report_acquire_failure(watch, &mut session, &error);
        return Ok(());
    }
    let after = session.without_token(|d| (d.attached_token_len(), d.token_pointer_is_null()));
    println!("RESULT step=after_release token_len_and_ptr_null={after:?}");

    // With no token attached and no PIN passed, libfido2 must refuse before sending a PIN. On a
    // UV-capable authenticator it would instead start built-in UV, so skip there.
    if info.has_uv {
        println!(
            "RESULT step=no_token_read skipped=true reason=has_uv (libfido2 would start built-in UV)"
        );
    } else {
        let code = session
            .without_token(|d| {
                watch.native("metadata_no_token", CALL_TIMEOUT_MS, || {
                    d.credman_metadata(CALL_TIMEOUT_MS)
                })
            })
            .map(|outcome| outcome.err().unwrap_or(0));
        match code {
            Ok(code) => result("metadata_without_token", code),
            Err(refused) => {
                println!("RESULT step=metadata_without_token skipped=true reason={refused:?}")
            }
        }
    }
    Ok(())
}

fn acquire_transaction(
    watch: &NativeCallWatch,
    mut guard: PuatGuard<'_, LibFido2Device>,
    grant: &AuthorizationGrant,
    planned: &AcquisitionPlan,
    path: &CStr,
) -> HarnessResult {
    println!(
        "RESULT step=acquire outcome=ok grant={:?} token_len={}",
        grant.kind(),
        guard.device_for_experiment().attached_token_len()
    );

    let metadata = guard
        .use_token(grant, |d| {
            watch.native("credman_metadata", CALL_TIMEOUT_MS, || {
                d.credman_metadata(CALL_TIMEOUT_MS)
            })
        })
        .map_err(|e| e.to_string())?;
    match metadata {
        Ok((existing, remaining)) => {
            println!("RESULT step=metadata code=0 rk_existing={existing} rk_remaining={remaining}")
        }
        Err(code) => result("metadata", code),
    }
    let rps = guard
        .use_token(grant, |d| {
            watch.native("credman_rp", CALL_TIMEOUT_MS, || {
                d.credman_rp_count(CALL_TIMEOUT_MS)
            })
        })
        .map_err(|e| e.to_string())?;
    match rps {
        Ok(count) => println!("RESULT step=enumerate_rps code=0 rp_count={count}"),
        Err(code) => result("enumerate_rps", code),
    }
    if let Some(rp) = planned.rp() {
        let rks = guard
            .use_token(grant, |d| {
                watch.native("credman_rk", CALL_TIMEOUT_MS, || {
                    d.credman_rk_count(rp, CALL_TIMEOUT_MS)
                })
            })
            .map_err(|e| e.to_string())?;
        match rks {
            Ok(count) => println!("RESULT step=enumerate_rks_scoped_rp code=0 rk_count={count}"),
            Err(code) => result("enumerate_rks_scoped_rp", code),
        }
    }

    let device = guard.device_for_experiment();
    let _ = query_pin_retries(watch, device, "pin_retries_after_success");

    // Negative control: close + reopen the SAME object without clearing (the contract never does
    // this). libfido2 source says the token survives close; does the authenticator still take it?
    let close_code = device.close();
    let reopened = watch.native("reopen", CALL_TIMEOUT_MS, || {
        device.reopen_at(path, CALL_TIMEOUT_MS)
    });
    println!(
        "RESULT step=close_reopen_same_object close_code={close_code} reopen_ok={} token_len_after_reopen={}",
        reopened.is_ok(),
        device.attached_token_len()
    );
    if reopened.is_ok() {
        match watch.native("metadata_after_reopen", CALL_TIMEOUT_MS, || {
            device.credman_metadata(CALL_TIMEOUT_MS)
        }) {
            Ok(_) => result("metadata_with_token_after_reopen", 0),
            Err(code) => result("metadata_with_token_after_reopen", code),
        }
    }

    release(guard)
}

/// Result of the `rp-inventory` credential enumeration for one RP, kept aligned with the RP list.
fn enumerate_credentials_for(
    watch: &NativeCallWatch,
    guard: &mut PuatGuard<'_, LibFido2Device>,
    grant: &AuthorizationGrant,
    entry: &RpEntry,
) -> Result<CredentialEnumeration, String> {
    let Continuation::ViaVerifiedText(rp_id) = entry.continuation() else {
        // No public libfido2 entry point continues from a hash alone, and the harness must not
        // guess text: nothing is sent for this RP.
        return Ok(CredentialEnumeration::NotAttempted);
    };
    let outcome = guard
        .use_token(grant, |d| {
            watch.native("credman_rk", CALL_TIMEOUT_MS, || {
                d.credman_rk_count_for(rp_id.as_c_str(), CALL_TIMEOUT_MS)
            })
        })
        .map_err(|e| e.to_string())?;
    Ok(match outcome {
        Ok(count) => CredentialEnumeration::Counted(u64::try_from(count).unwrap_or(u64::MAX)),
        Err(code) => CredentialEnumeration::Failed { code },
    })
}

/// CTAP2_ERR_NO_CREDENTIALS: what a device with no resident credentials answers to
/// enumerateRPsBegin.
const FIDO_ERR_NO_CREDENTIALS: i32 = 0x2e;

fn rp_inventory(watch: &NativeCallWatch, args: &[String]) -> HarnessResult {
    if args.iter().any(|arg| arg == "--rp-id" || arg == "--uv") {
        return Err(
            "rp-inventory takes only --mode ro|cm (an RP-scoped token cannot list RPs)".to_owned(),
        );
    }
    let request = parse_mode(args, "--mode")?;
    let target = single_device(watch)?;
    let mut device = open_fresh(watch, &target.path)?;
    let info = read_info(watch, &mut device)?;
    let planned = plan_or_explain(&capabilities(&info), &request, VerificationMethod::Pin)?;

    let announcement = format!(
        "This sends your PIN ONCE to request {:?} (permission {:#x}). If the grant is not \
         read-only (the Thetis has no perCredMgmtRO, so this is ordinary credential management) \
         the token the authenticator issues COULD delete credentials, although this command only \
         issues read requests: getCredsMetadata, enumerateRPs, enumerateCredentials. It prints \
         ONLY counts, lengths and true/false values: no RP IDs, RP names, user names, credential \
         IDs, hashes, PIN or token bytes. RP and credential data is read into memory by libfido2, \
         compared in memory, and freed; nothing is written to disk. The token is cleared at the \
         end. A wrong PIN consumes one retry and there is no automatic retry. Nothing is \
         deleted or changed.",
        planned.kind(),
        planned.permissions()
    );
    let Some(pin) = gate_and_read_pin(watch, &mut device, &announcement)? else {
        println!("declined; nothing was sent");
        return Ok(());
    };

    let mut session = DeviceSession::open(device, DeviceGeneration(1))
        .map_err(|error| format!("fresh object refused: {error:?}"))?;
    let failure = match watch.native("get_puat", CALL_TIMEOUT_MS, || {
        session.acquire(&planned, Some(&pin), CALL_TIMEOUT_MS)
    }) {
        Ok((guard, grant)) => {
            drop(pin); // wiped; not needed again
            inventory_transaction(watch, guard, &grant)?;
            None
        }
        Err(error) => Some(error),
    };
    if let Some(error) = failure {
        report_acquire_failure(watch, &mut session, &error);
        return Ok(());
    }
    let after = session.without_token(|d| (d.attached_token_len(), d.token_pointer_is_null()));
    println!("RESULT step=after_release token_len_and_ptr_null={after:?}");
    Ok(())
}

fn inventory_transaction(
    watch: &NativeCallWatch,
    mut guard: PuatGuard<'_, LibFido2Device>,
    grant: &AuthorizationGrant,
) -> HarnessResult {
    println!(
        "RESULT step=acquire outcome=ok grant={:?} token_len={}",
        grant.kind(),
        guard.device_for_experiment().attached_token_len()
    );

    // getCredsMetadata: the authenticator's own credential count.
    let reported_existing = match guard
        .use_token(grant, |d| {
            watch.native("credman_metadata", CALL_TIMEOUT_MS, || {
                d.credman_metadata(CALL_TIMEOUT_MS)
            })
        })
        .map_err(|e| e.to_string())?
    {
        Ok((existing, remaining)) => {
            println!(
                "RESULT step=metadata code=0 metadata_existing={existing} rk_remaining={remaining}"
            );
            Some(existing)
        }
        Err(code) => {
            result("metadata", code);
            None
        }
    };

    // enumerateRPs: copy hash + text out for the identity contract.
    let listed = guard
        .use_token(grant, |d| {
            watch.native("credman_rp_list", CALL_TIMEOUT_MS, || {
                d.credman_rp_list(CALL_TIMEOUT_MS)
            })
        })
        .map_err(|e| e.to_string())?;
    let owned = match listed {
        Ok(list) => list,
        Err(FIDO_ERR_NO_CREDENTIALS) => {
            println!(
                "RESULT step=enumerate_rps code=0x2e name=NO_CREDENTIALS rp_count=0 note=device_reports_no_resident_credentials"
            );
            Vec::new()
        }
        Err(code) => {
            result("enumerate_rps", code);
            println!("No RP list; stopping without a completeness claim.");
            return release(guard);
        }
    };
    let raw: Vec<RawRp<'_>> = owned
        .iter()
        .map(|rp| RawRp {
            hash: rp.hash.as_deref(),
            text: rp.text.as_deref(),
        })
        .collect();
    let list = RpList::from_raw(&raw);

    // Structural evidence only. Lengths and booleans, never content.
    let (mut absent, mut wrong_len, mut verified, mut mismatch, mut malformed, mut unavailable) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut hash_lens = Vec::new();
    for (entry, source) in list.entries().iter().zip(&owned) {
        hash_lens.push(source.hash.as_ref().map(Vec::len));
        match entry {
            RpEntry::MalformedHash(MalformedHash::Absent) => absent += 1,
            RpEntry::MalformedHash(MalformedHash::WrongLength { .. }) => wrong_len += 1,
            RpEntry::Identified(record) => match record.text() {
                RpTextState::VerifiedText(_) => verified += 1,
                RpTextState::TextHashMismatch => mismatch += 1,
                RpTextState::TextMalformed => malformed += 1,
                RpTextState::TextUnavailable => unavailable += 1,
            },
        }
    }
    let text_present = verified + mismatch + malformed;
    println!(
        "RESULT step=enumerate_rps code=0 rp_count={} rp_hash_len={:?} rp_hash_absent={absent} \
         rp_hash_wrong_len={wrong_len} duplicate_hashes={} rp_text_present={text_present} \
         rp_text_hash_matches={verified} rp_text_hash_mismatch={mismatch} \
         rp_text_malformed={malformed} rp_text_unavailable={unavailable}",
        list.entries().len(),
        hash_lens,
        list.issues()
            .iter()
            .filter(|issue| matches!(
                issue,
                fido_puat_spike::rp_identity::RpListIssue::DuplicateHash { .. }
            ))
            .count(),
    );

    // enumerateCredentials for each RP whose text verified; every other RP is blocked, not empty.
    let mut credentials = Vec::with_capacity(list.entries().len());
    for (index, entry) in list.entries().iter().enumerate() {
        let outcome = enumerate_credentials_for(watch, &mut guard, grant, entry)?;
        match outcome {
            CredentialEnumeration::Counted(count) => {
                println!(
                    "RESULT step=enumerate_rks rp_index={index} code=0 credential_count={count}"
                );
            }
            CredentialEnumeration::Failed { code } => {
                result(&format!("enumerate_rks_rp_{index}"), code);
            }
            CredentialEnumeration::NotAttempted => {
                println!(
                    "RESULT step=enumerate_rks rp_index={index} attempted=false reason={:?}",
                    entry.continuation()
                );
            }
        }
        credentials.push(outcome);
    }

    let assessment = assess(&list, &credentials, reported_existing);
    // Diagnostic sum only; what may be claimed is `assessment.credentials`.
    let enumerated = assessment.observed_enumerated;
    println!(
        "RESULT step=reconcile metadata_existing={reported_existing:?} credential_count={enumerated} \
         counts_reconcile={} completeness={:?} credentials={:?} incomplete={:?} inconsistent={:?}",
        reported_existing == Some(enumerated),
        assessment.completeness,
        assessment.credentials,
        assessment.incomplete,
        assessment.inconsistent,
    );
    match assessment.credentials {
        CredentialTotal::Exact(_) => {}
        CredentialTotal::AtLeast(_) => {
            println!(
                "NOTE: inspection is NOT complete; credentials=AtLeast(n) is a lower bound only."
            );
        }
        CredentialTotal::Unknown => {
            println!(
                "NOTE: inspection is INCONSISTENT; no trustworthy total (credential_count above is a diagnostic sum, not a bound)."
            );
        }
    }

    release(guard)
}

fn stale_token(watch: &NativeCallWatch, args: &[String]) -> HarnessResult {
    let first_request = parse_mode(args, "--first")?;
    let second_request = RequestedAuthorization::CredMan { rp: None };
    let target = single_device(watch)?;
    let mut device = open_fresh(watch, &target.path)?;
    let info = read_info(watch, &mut device)?;
    let caps = capabilities(&info);
    let first_plan = plan_or_explain(&caps, &first_request, VerificationMethod::Pin)?;
    let second_plan = plan_or_explain(&caps, &second_request, VerificationMethod::Pin)?;

    let announcement = format!(
        "This sends your PIN TWICE (same PIN, typed once): first for {:?}, then for {:?} on a \
         second object, then checks whether the first token still works. Only counts are read. \
         If the first attempt fails, the second is NOT sent.",
        first_plan.kind(),
        second_plan.kind()
    );
    let Some(pin) = gate_and_read_pin(watch, &mut device, &announcement)? else {
        println!("declined; nothing was sent");
        return Ok(());
    };

    let mut first = DeviceSession::open(device, DeviceGeneration(1)).map_err(|e| e.to_string())?;
    let failure = match watch.native("get_puat_first", CALL_TIMEOUT_MS, || {
        first.acquire(&first_plan, Some(&pin), CALL_TIMEOUT_MS)
    }) {
        Ok((guard, grant)) => {
            return stale_continue(watch, guard, &grant, &second_plan, pin, &target.path);
        }
        Err(error) => error,
    };
    drop(pin);
    report_acquire_failure(watch, &mut first, &failure);
    Ok(())
}

fn stale_continue(
    watch: &NativeCallWatch,
    mut first_guard: PuatGuard<'_, LibFido2Device>,
    first_grant: &AuthorizationGrant,
    second_plan: &AcquisitionPlan,
    pin: PinSecret,
    path: &CStr,
) -> HarnessResult {
    match first_guard
        .use_token(first_grant, |d| {
            watch.native("metadata_first", CALL_TIMEOUT_MS, || {
                d.credman_metadata(CALL_TIMEOUT_MS)
            })
        })
        .map_err(|e| e.to_string())?
    {
        Ok(_) => result("first_token_metadata", 0),
        Err(code) => result("first_token_metadata", code),
    }
    // Keep the first token attached in host memory; release the HID device for the second object.
    let close_code = first_guard.device_for_experiment().close();
    println!("RESULT step=first_object_closed close_code={close_code}");

    {
        let second_device = open_fresh(watch, path)?;
        let mut second =
            DeviceSession::open(second_device, DeviceGeneration(2)).map_err(|e| e.to_string())?;
        let failure = match watch.native("get_puat_second", CALL_TIMEOUT_MS, || {
            second.acquire(second_plan, Some(&pin), CALL_TIMEOUT_MS)
        }) {
            Ok((mut guard, grant)) => {
                println!(
                    "RESULT step=second_acquire outcome=ok grant={:?}",
                    grant.kind()
                );
                match guard
                    .use_token(&grant, |d| {
                        watch.native("metadata_second", CALL_TIMEOUT_MS, || {
                            d.credman_metadata(CALL_TIMEOUT_MS)
                        })
                    })
                    .map_err(|e| e.to_string())?
                {
                    Ok(_) => result("second_token_metadata", 0),
                    Err(code) => result("second_token_metadata", code),
                }
                release(guard)?; // poisoned => stop; `second` is dropped (object freed) on return
                None
            }
            Err(error) => Some(error),
        };
        if let Some(error) = failure {
            report_acquire_failure(watch, &mut second, &error);
        }
        // `second` drops here: close + fido_dev_free.
    }
    drop(pin);

    let device = first_guard.device_for_experiment();
    let reopened = watch.native("reopen_first", CALL_TIMEOUT_MS, || {
        device.reopen_at(path, CALL_TIMEOUT_MS)
    });
    println!(
        "RESULT step=first_object_reopened ok={} token_len={}",
        reopened.is_ok(),
        device.attached_token_len()
    );
    if reopened.is_ok() {
        match watch.native("metadata_stale", CALL_TIMEOUT_MS, || {
            device.credman_metadata(CALL_TIMEOUT_MS)
        }) {
            Ok(_) => result("first_token_after_second_issued", 0),
            Err(code) => result("first_token_after_second_issued", code),
        }
        let _ = query_pin_retries(watch, device, "pin_retries_after_stale_use");
    }
    release(first_guard)
}

/// Releases the guard. A cleanup that cannot be proven poisons the session; the harness then
/// stops (the caller returns the error, which drops and frees the native object) and never reuses
/// the object or continues the experiment.
fn release(guard: PuatGuard<'_, LibFido2Device>) -> HarnessResult {
    match guard.release() {
        Ok(()) => {
            println!("RESULT step=release cleared=true");
            Ok(())
        }
        Err(error) => {
            println!("RESULT step=release cleared=false error={error:?} session=poisoned");
            Err("PUAT cleanup could not be proven; the native object is being discarded".to_owned())
        }
    }
}

fn wait_for_device_count(
    watch: &NativeCallWatch,
    wanted: usize,
) -> Result<Option<native::DiscoveredDevice>, String> {
    let started = Instant::now();
    loop {
        let devices = watch
            .run("manifest_poll", MANIFEST_BUDGET_MS, native::manifest)
            .map_err(native::error_name)?;
        if devices.len() == wanted {
            return Ok(devices.into_iter().next());
        }
        if started.elapsed() > REPLUG_WAIT {
            return Err(format!("timed out waiting for {wanted} device(s)"));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn replug(watch: &NativeCallWatch, args: &[String]) -> HarnessResult {
    let request = parse_mode(args, "--mode")?;
    let target = single_device(watch)?;
    let mut device = open_fresh(watch, &target.path)?;
    let info = read_info(watch, &mut device)?;
    let planned = plan_or_explain(&capabilities(&info), &request, VerificationMethod::Pin)?;
    let announcement = format!(
        "This sends your PIN ONCE for {:?}, asks you to unplug and replug the key, then checks a \
         fresh object and whether the old token is still accepted. Only counts are read.",
        planned.kind()
    );
    let Some(pin) = gate_and_read_pin(watch, &mut device, &announcement)? else {
        println!("declined; nothing was sent");
        return Ok(());
    };

    let mut old = DeviceSession::open(device, DeviceGeneration(1)).map_err(|e| e.to_string())?;
    let failure = match watch.native("get_puat", CALL_TIMEOUT_MS, || {
        old.acquire(&planned, Some(&pin), CALL_TIMEOUT_MS)
    }) {
        Ok((guard, grant)) => {
            drop(pin);
            return replug_continue(watch, guard, &grant, &target.path);
        }
        Err(error) => error,
    };
    drop(pin);
    report_acquire_failure(watch, &mut old, &failure);
    Ok(())
}

fn replug_continue(
    watch: &NativeCallWatch,
    mut guard: PuatGuard<'_, LibFido2Device>,
    grant: &AuthorizationGrant,
    path: &CStr,
) -> HarnessResult {
    match guard
        .use_token(grant, |d| {
            watch.native("metadata_before", CALL_TIMEOUT_MS, || {
                d.credman_metadata(CALL_TIMEOUT_MS)
            })
        })
        .map_err(|e| e.to_string())?
    {
        Ok(_) => result("metadata_before_replug", 0),
        Err(code) => result("metadata_before_replug", code),
    }
    guard.device_for_experiment().close();

    println!(">>> Unplug the key now.");
    wait_for_device_count(watch, 0)?;
    println!(">>> Unplugged. Plug the same key back in.");
    let replugged =
        wait_for_device_count(watch, 1)?.ok_or_else(|| "device disappeared again".to_owned())?;
    println!(
        "RESULT step=replugged same_os_path={}",
        replugged.path.as_c_str() == path
    );

    {
        let fresh_device = open_fresh(watch, &replugged.path)?;
        let fresh = DeviceSession::open(fresh_device, DeviceGeneration(2));
        println!(
            "RESULT step=fresh_session_after_replug accepted={}",
            fresh.is_ok()
        );
        // Freed here, before the negative control reopens the old object (macOS seizes the HID).
    }

    // Negative control the contract forbids: reuse the OLD object (still holding the old token).
    let device = guard.device_for_experiment();
    let reopened = watch.native("reopen_old", CALL_TIMEOUT_MS, || {
        device.reopen_at(&replugged.path, CALL_TIMEOUT_MS)
    });
    println!(
        "RESULT step=old_object_reopened_after_replug ok={} token_len={}",
        reopened.is_ok(),
        device.attached_token_len()
    );
    if reopened.is_ok() {
        match watch.native("metadata_old_token", CALL_TIMEOUT_MS, || {
            device.credman_metadata(CALL_TIMEOUT_MS)
        }) {
            Ok(_) => result("old_token_after_power_cycle", 0),
            Err(code) => result("old_token_after_power_cycle", code),
        }
        let _ = query_pin_retries(watch, device, "pin_retries_after_replug");
    }
    release(guard)
}

fn probe_ro_enforcement(watch: &NativeCallWatch) -> HarnessResult {
    let target = single_device(watch)?;
    let mut device = open_fresh(watch, &target.path)?;
    let info = read_info(watch, &mut device)?;
    let planned = plan_or_explain(
        &capabilities(&info),
        &RequestedAuthorization::CredManReadOnly,
        VerificationMethod::Pin,
    )?;
    if !confirm(
        "OPT-IN PROBE. This acquires a READ-ONLY token, then sends ONE credential-management \
         DELETE for a freshly generated random 64-byte credential ID that does not exist on the \
         key. A read-only-enforcing key must refuse it on permission. If the key ignores read-only \
         it will look the ID up and report 'no credentials'. No existing credential can match a \
         random 64-byte ID, but this IS a delete command on the wire.",
        "PROBE",
    )? {
        println!("declined; nothing was sent");
        return Ok(());
    }
    let Some(pin) = gate_and_read_pin(
        watch,
        &mut device,
        "Send the PIN once for the read-only token?",
    )?
    else {
        println!("declined; nothing was sent");
        return Ok(());
    };

    let mut random_id = [0u8; 64];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random_id))
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;

    let mut session =
        DeviceSession::open(device, DeviceGeneration(1)).map_err(|e| e.to_string())?;
    let failure = match watch.native("get_puat", CALL_TIMEOUT_MS, || {
        session.acquire(&planned, Some(&pin), CALL_TIMEOUT_MS)
    }) {
        Ok((mut guard, grant)) => {
            drop(pin);
            let code = guard
                .use_token(&grant, |d| {
                    watch.native("delete_probe", CALL_TIMEOUT_MS, || {
                        d.delete_probe(&random_id, CALL_TIMEOUT_MS)
                    })
                })
                .map_err(|e| e.to_string())?;
            let verdict = match code {
                0x33 | 0x40 | 0x30 => "read_only_enforced_for_delete",
                0x2e => "read_only_NOT_enforced (authenticator looked the credential up)",
                _ => "inconclusive",
            };
            println!(
                "RESULT step=ro_delete_probe code={code} name={} verdict={verdict} class={:?}",
                native::error_name(code),
                classify_acquisition_error(code)
            );
            return release(guard);
        }
        Err(error) => error,
    };
    drop(pin);
    report_acquire_failure(watch, &mut session, &failure);
    Ok(())
}
