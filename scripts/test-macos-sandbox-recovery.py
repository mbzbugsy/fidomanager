#!/usr/bin/env python3
"""MAS.1 credential-free, LOCAL App Sandbox recovery/persistence validation.

Builds the ignored fido-service libtest fixture, bundles and signs it ad hoc using only the
existing MAS.0 entitlements. No production app commands, FIDO worker or signing credentials.
Each invocation uses a fresh UUID namespace in a dedicated container. Records are synthetic;
this script never opens the user's production incident.json or any other channel's journal.

--build-only is CI packaging coverage, NOT runtime or power-loss evidence.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import queue
import shutil
import signal
import subprocess
import threading
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "target/mas1-recovery"
IDENTIFIER = "eu.fidomanager.desktop.mas1recoverytest"
TEST = "recovery::sandbox_persistence::run"
APP = OUTPUT / "MAS.1 Recovery Test.app"
ARGS = ["--exact", TEST, "--ignored", "--nocapture", "--test-threads=1"]
CASES = ("dispatch", "pending", "not-dispatched", "rejected", "confirmed-successful", "acknowledged-unknown")


class Failure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def run(command, **options):
    result = subprocess.run([str(part) for part in command], capture_output=True, text=True, **options)
    require(result.returncode == 0, f"command failed: {command[0]}\n{result.stdout}\n{result.stderr}")
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_checker():
    spec = importlib.util.spec_from_file_location("mas1_checker", ROOT / "scripts/check-macos-sandbox-bundle.py")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    return checker


def build():
    require(platform.system() == "Darwin", "MAS.1 requires a macOS host")
    forbidden = [name for name in os.environ if name.startswith(("APPLE_", "TAURI_SIGNING_"))]
    require(not forbidden, "credential-free runner refuses signing variables: " + ", ".join(forbidden))
    environment = dict(os.environ, MACOSX_DEPLOYMENT_TARGET="11.0")
    require(not OUTPUT.is_symlink(), "refusing symlinked output directory")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    result = run(["cargo", "test", "-p", "fido-service", "--lib", "--locked", "--no-run",
                  "--message-format=json"], cwd=ROOT, env=environment)
    artifacts = []
    for line in result.stdout.splitlines():
        entry = json.loads(line)
        if (entry.get("reason") == "compiler-artifact" and entry.get("profile", {}).get("test")
                and entry.get("target", {}).get("name") == "fido_service" and entry.get("executable")):
            artifacts.append(Path(entry["executable"]))
    require(len(artifacts) == 1, "expected exactly one service libtest executable")
    artifact = artifacts[0]
    listing = run([artifact, "--list", "--ignored"]).stdout
    require(f"{TEST}: test" in listing, "MAS.1 ignored fixture is absent")
    if APP.exists():
        shutil.rmtree(APP)
    macos = APP / "Contents/MacOS"
    macos.mkdir(parents=True)
    main = macos / "mas1-recovery-test"
    child = macos / "mas1-inherit-probe"
    for binary in (main, child):
        shutil.copyfile(artifact, binary)
        binary.chmod(0o755)
    info = {"CFBundleIdentifier": IDENTIFIER, "CFBundleName": "MAS.1 Recovery Test",
            "CFBundleExecutable": main.name, "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1", "CFBundleShortVersionString": "1", "LSBackgroundOnly": True,
            "LSMinimumSystemVersion": "11.0"}
    (APP / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    checker = load_checker()
    app_grants, child_grants = checker.check_reviewed_files()
    for target, grants, identifier in ((child, "worker.entitlements", f"{IDENTIFIER}.inherit-probe"),
                                       (APP, "app.entitlements", IDENTIFIER)):
        run(["codesign", "--force", "--sign", "-", "--timestamp=none", "--options", "runtime",
             "--identifier", identifier, "--entitlements", ROOT / "packaging/macos-app-sandbox" / grants, target])
    run(["codesign", "--verify", "--strict", "--deep", APP])
    for binary, expected in ((main, app_grants), (child, child_grants)):
        require(checker.base.entitlements(binary) == expected, "fixture entitlements differ from MAS.0")
        fields = checker.base.signature(binary)
        require(fields.get("Signature") == ["adhoc"] and fields.get("TeamIdentifier") == ["not set"],
                "fixture must be credential-free, ad-hoc code")
        require("runtime" in " ".join(fields.get("CodeDirectory v", [])), "Hardened Runtime missing")
        dependencies = run(["otool", "-L", binary]).stdout
        require(not any(name in dependencies for name in ("libfido2", "libcrypto", "libssl", "libcbor")),
                "recovery fixture unexpectedly links a native FIDO library")
    sources = ("crates/fido-platform/src/recovery_file.rs", "crates/fido-platform/src/instance_lock.rs",
               "crates/fido-service/src/recovery.rs", "crates/fido-service/src/authentication.rs",
               "crates/fido-service/src/recovery/sandbox_persistence.rs")
    summary = {"identifier": IDENTIFIER, "app_entitlements": app_grants, "child_entitlements": child_grants,
               "signature": "ad-hoc + Hardened Runtime", "native_fido_linkage": False,
               "binary_sha256": {p.name: digest(p) for p in (main, child)},
               "source_sha256": {path: digest(ROOT / path) for path in sources}}
    (OUTPUT / "build-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return main, artifact, summary


def events(output):
    found = []
    for line in output.splitlines():
        if "MAS1_EVIDENCE " in line:
            found.append(json.loads(line.split("MAS1_EVIDENCE ", 1)[1]))
    return found


def validate_kernel(found, expected_pids=None):
    kernels = [entry for entry in found if entry.get("event") == "kernel"]
    require(kernels, "missing runtime kernel evidence")
    pids = []
    for entry in kernels:
        require(all(type(entry.get(key)) is int for key in ("pid", "sandboxed", "cs_status", "cs_flags")),
                "invalid kernel evidence fields")
        require(entry["pid"] > 0 and entry["sandboxed"] == 1 and entry["cs_status"] == 0
                and entry["cs_flags"] & 0x10001 == 0x10001, "kernel sandbox/runtime checks failed")
        pids.append(entry["pid"])
    require(len(set(pids)) == len(pids), "duplicate kernel evidence")
    if expected_pids is not None:
        require(set(pids) == set(expected_pids), "missing or unexpected process kernel evidence")
    else:
        require(len(pids) == 1, "expected exactly one completed-process kernel event")


BAD_RECORD_CASES = ("malformed", "corrupted-utf8", "empty", "oversized", "unknown-field",
                    "unsupported-schema", "inconsistent-resolution", "invalid-incident",
                    "unknown-operation", "wrong-application", "unresolved-tombstone",
                    "unreadable", "permissive-record", "record-symlink", "record-hardlink", "record-directory")
UNAVAILABLE_CASES = ("permissive-namespace", "namespace-symlink", "permissive-root")


def expected_authorities(step):
    action, case = step.split(":")
    if action in ("contend", "child"):
        return {}
    if action == "negative":
        expected = {name: ("loaded", "Barrier", None, True) for name in BAD_RECORD_CASES}
        expected.update({name: ("unavailable", "Barrier", None, None) for name in UNAVAILABLE_CASES})
        expected["failed-acknowledgement"] = ("loaded", "Barrier", "dispatch_capable", False)
        expected["write-denied-after-pending"] = ("loaded", "Open", "pending", False)
        return expected
    if action == "g5":
        return {"g5-continuity": ("loaded", "Open", None, False)}
    if case == "lock":
        return {case: ("loaded", "Open", None, False)}
    require(case in CASES and action in ("seed", "reload"), "unknown fixture step")
    phase = "dispatch_capable" if case == "dispatch" else "pending" if case == "pending" else "resolved"
    admission = "Barrier" if case == "dispatch" else "Open"
    return {case: ("loaded", admission, phase, False)}


def validate_admissions(found, step):
    expected = expected_authorities(step)
    rows = [entry for entry in found if entry.get("event") == "authority"]
    require(len(rows) == len(expected) and {row.get("case") for row in rows} == set(expected),
            "missing, duplicate or unexpected authority evidence")
    for row in rows:
        initialization, admission, phase, poisoned = expected[row["case"]]
        require(row.get("initialization") == initialization and row.get("admission") == admission
                and row.get("phase") == phase and "phase" in row
                and "poisoned" in row and row["poisoned"] is poisoned
                and row.get("journal_present") is (initialization == "loaded"),
                f"unexpected initialization/admission: {row['case']}")
    action, case = step.split(":")
    if action in ("seed", "reload") and case in CASES:
        record = select(found, "record")
        require(record.get("step") == step and record.get("admission") == expected[case][1],
                "record admission does not match expected authority admission")


def validate_success(result, step):
    require(result.returncode == 0, f"fixture failed ({step}): {result.stdout}\n{result.stderr}")
    require("test result: ok. 1 passed; 0 failed; 0 ignored;" in result.stdout,
            "fixture must execute exactly one test, not merely match an empty filter")
    found = events(result.stdout)
    require(found and found[0].get("event") == "kernel", "missing initial kernel evidence")
    validate_kernel(found)
    validate_admissions(found, step)
    return found


def validate_holding(found, step, parent_pid):
    require(found and found[0].get("event") == "kernel", "missing holding kernel evidence")
    pids = [parent_pid]
    if step == "hold:lock":
        child_pid = select(found, "lock-held").get("child_pid")
        require(type(child_pid) is int and child_pid > 0 and child_pid != parent_pid, "invalid inherit child PID")
        require(select(found, "child-ready").get("pid") == child_pid, "wrong inherit child")
        pids.append(child_pid)
    validate_kernel(found, pids)
    validate_admissions(found, step)


def fixture_environment(run_id, step):
    # secinit redirects HOME into the container; the fixture independently checks the identity.
    return {"HOME": str(Path.home()), "FIDOMANAGER_MAS1_RUN": run_id, "FIDOMANAGER_MAS1_STEP": step}


def complete(binary, run_id, step, extra_environment=None):
    environment = fixture_environment(run_id, step)
    environment.update(extra_environment or {})
    result = subprocess.run([str(binary), *ARGS], env=environment,
                            capture_output=True, text=True, timeout=30)
    return validate_success(result, step)


class HoldingFixture:
    def __init__(self, binary, run_id, step):
        self.step = step
        self.process = subprocess.Popen([str(binary), *ARGS], env=fixture_environment(run_id, step),
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.lines = []
        self.queue = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            self.lines.append(line)
            if "MAS1_EVIDENCE " in line:
                self.queue.put(json.loads(line.split("MAS1_EVIDENCE ", 1)[1]))

    def until(self, expected):
        deadline = time.monotonic() + 15
        found = []
        while time.monotonic() < deadline:
            try:
                entry = self.queue.get(timeout=0.1)
                found.append(entry)
                if expected(found):
                    require(self.process.poll() is None, "holding fixture exited prematurely")
                    validate_holding(found, self.step, self.process.pid)
                    return found
            except queue.Empty:
                require(self.process.poll() is None, "fixture exited before evidence: " + "".join(self.lines))
        raise Failure("timed out waiting for fixture evidence: " + "".join(self.lines))

    def kill(self):
        self.process.kill()
        require(self.process.wait(timeout=5) == -signal.SIGKILL, "expected a forced process termination")


def select(found, kind):
    matches = [entry for entry in found if entry["event"] == kind]
    require(len(matches) == 1, f"expected exactly one {kind} event")
    return matches[0]


def live_child(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat=,command="], capture_output=True, text=True)
    parts = result.stdout.strip().split(None, 1)
    return (result.returncode == 0 and len(parts) == 2 and not parts[0].startswith("Z")
            and parts[1].startswith(str(APP / "Contents/MacOS/mas1-inherit-probe") + " "))


def runtime(binary, artifact, summary):
    sip = run(["csrutil", "status"]).stdout.strip()
    require("enabled" in sip and "disabled" not in sip, "local evidence requires SIP enabled")
    run_id = uuid.uuid4().hex
    report = {"identity": IDENTIFIER, "run_id": run_id, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "macos": run(["sw_vers", "-productVersion"]).stdout.strip(), "sip": sip,
              "build": summary, "checks": [], "power_loss_tested": False, "physical_fido_operations": False}
    # Refuse the same fixture outside a sandbox before it even resolves a storage path.
    control = subprocess.run([str(artifact), *ARGS], env=fixture_environment(run_id, "seed:dispatch"),
                             capture_output=True, text=True, timeout=15)
    require(control.returncode != 0 and "MAS.1 refuses to touch storage without a kernel sandbox" in (control.stdout + control.stderr),
            "unsandboxed fixture must fail at the first storage guard: " + control.stdout + control.stderr)
    kernel = select(events(control.stdout), "kernel")
    require(kernel["sandboxed"] == 0, "unsandboxed negative control was not unsandboxed")
    report["checks"].append({"case": "unsandboxed-refused-before-storage", "result": "PASS", "kernel": kernel})
    for case in CASES:
        step = "seed:" + case
        if case in ("dispatch", "pending"):
            holding = HoldingFixture(binary, run_id, step)
            try:
                seeded = holding.until(lambda rows: any(row["event"] == "record" for row in rows))
                holding.kill()
            finally:
                if holding.process.poll() is None:
                    holding.kill()
            termination = "SIGKILL after durable write acknowledgement"
        else:
            seeded = complete(binary, run_id, step)
            termination = "normal process exit"
        loaded = complete(binary, run_id, "reload:" + case)
        before, after = select(seeded, "record"), select(loaded, "record")
        require(before["sha256"] == after["sha256"] and before["record"] == after["record"],
                "restart must preserve the exact synthetic bytes and incident")
        require(select(seeded, "kernel")["pid"] != select(loaded, "kernel")["pid"], "restart must be a new process")
        report["checks"].append({"case": case, "result": "PASS", "termination": termination,
                                 "seed": seeded, "reload": loaded})
    negative = complete(binary, run_id, "negative:matrix")
    require(len({entry["case"] for entry in negative if entry["event"] == "negative"}) == 21,
            "negative matrix must execute all 21 distinct cases")
    report["checks"].append({"case": "negative-matrix", "result": "PASS", "evidence": negative})
    with tempfile.TemporaryDirectory(dir="/private/tmp", prefix=f"mas1-g5-{run_id}-") as temporary:
        marker = Path(temporary) / "synthetic-channel-marker.json"
        synthetic = {"schema": 1, "application": "fidomanager-m4-v1", "incident": "0123456789abcdef0123456789abcdef",
                     "operation": "delete_credential", "created_unix_secs": 1700000000,
                     "phase": "dispatch_capable", "resolution": None}
        marker.write_text(json.dumps(synthetic))
        marker.chmod(0o600)
        before = digest(marker)
        rows = complete(binary, run_id, "g5:continuity", {"FIDOMANAGER_MAS1_SYNTHETIC_CHANNEL": str(marker)})
        select(rows, "g5")
        require(digest(marker) == before, "external synthetic marker must remain unchanged")
        report["checks"].append({"case": "G5-synthetic-storage-separation", "result": "PASS", "evidence": rows,
                                 "external_synthetic_marker_unchanged": True, "real_channel_journals_accessed": False})
    holder = HoldingFixture(binary, run_id, "hold:lock")
    child_pid = None
    try:
        rows = holder.until(lambda entries: any(row["event"] == "lock-held" for row in entries)
                             and any(row["event"] == "child-ready" for row in entries))
        child_pid = select(rows, "lock-held")["child_pid"]
        require(select(rows, "child-ready")["pid"] == child_pid, "wrong inherit child")
        # The second process must exit successfully at the lock refusal, BEFORE journal loading.
        refused = complete(binary, run_id, "contend:lock")
        select(refused, "lock-refused")
        holder.kill()
        require(live_child(child_pid), "inherit child must still be executing, not a zombie/recycled PID")
        reacquired = complete(binary, run_id, "reload:lock")
        require(live_child(child_pid), "inherit child must remain executing during lock reacquisition")
        select(reacquired, "lock-reacquired")
        report["checks"].append({"case": "singleton-crash-and-CLOEXEC", "result": "PASS",
                                 "holder": rows, "second_process": refused, "restart": reacquired,
                                 "inherit_child_alive_during_reacquisition": True})
    finally:
        if holder.process.poll() is None:
            holder.kill()
        if child_pid is None:
            held = [row for row in events("".join(holder.lines)) if row["event"] == "lock-held"]
            child_pid = held[0]["child_pid"] if held else None
        if child_pid is not None and live_child(child_pid):
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    # The successful real replace is source-level evidence for both mandatory F_FULLFSYNC calls;
    # this is not syscall tracing, injected success, or an observed power-loss guarantee.
    report["synchronization_evidence"] = {
        "implementation": "unchanged production DurableRecoveryFile::replace",
        "successful_path": "write/flush -> F_FULLFSYNC -> renameat -> fsync(directory) -> F_FULLFSYNC",
        "basis": "successful production return plus hashed source with mandatory error propagation",
        "syscall_trace_collected": False, "power_loss_tested": False}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--report", type=Path, default=OUTPUT / "runtime-report.json")
    arguments = parser.parse_args()
    binary, artifact, summary = build()
    if arguments.build_only:
        print("PASS: MAS.1 fixture built, ad-hoc sandbox-signed and verified (runtime NOT tested)")
        return
    report = runtime(binary, artifact, summary)
    # Evidence paths are reproducible without exposing the operator's home directory/worktree.
    text = json.dumps(report, indent=2).replace(str(Path.home()), "~").replace(str(ROOT), "<worktree>")
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(text + "\n")
    print(text)
    print("PASS: MAS.1 sandbox recovery/persistence (process restart; NOT a power-loss test)")


if __name__ == "__main__":
    main()
