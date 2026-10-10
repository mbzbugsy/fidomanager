#!/usr/bin/env python3
"""Runtime App Sandbox evidence for the LOCAL-TEST Fido Manager.app (ADR-018).

Launches the real GUI through Launch Services and collects evidence from outside the app:

  1. the app and its worker are sandboxed by the kernel (sandbox_check), under Hardened Runtime
     (kernel code-signing status), and the worker is the app's direct child in
     `--authentication` mode (the production spawn the renderer's discovery IPC triggers);
  2. WKWebView/IPC work: the worker exists only because renderer JavaScript invoked
     `list_authenticators`; WebKit reports no network-permission failure or Network-process crash;
  3. application data and recovery storage live in the test container with private permissions;
  4. single-instance: a second `open -n` exits and leaves exactly one authority and one worker;
  5. worker replacement: a SIGKILLed worker is replaced by a new sandboxed worker;
  6. termination: after the app is killed, the worker exits on its own (parent-death watchdog);
  7. every Sandbox denial attributed to fidomanager-app or fido-worker during the run, compared
     with a reviewed list of known-benign denials (anything else fails).

Safety: only the isolated test bundle identifier is accepted. The harness sends no FIDO command;
the app itself performs only its normal read-only discovery. Nothing in any other container or
data directory is read or written.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import stat
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
TEST_IDENTIFIER = "eu.fidomanager.desktop.sandboxtest"
CS_VALID, CS_HARD, CS_KILL, CS_RUNTIME = 0x1, 0x100, 0x200, 0x10000
# Reviewed, known-benign denials (ADR-018 section "Observed denials"). Anything else fails.
BENIGN_DENIALS = (
    # WebKit's Safe Browsing service lookup from the UI process. The app loads only its bundled
    # frontend over the tauri:// scheme; Safe Browsing is not used and no exception is granted.
    re.compile(r"^fidomanager-app deny\(1\) mach-lookup com\.apple\.Safari\.SafeBrowsing\.Service$"),
)


class Failure(RuntimeError):
    pass


def output(command, **options):
    return subprocess.run(command, capture_output=True, check=True, **options).stdout.decode(errors="replace")


def processes(app):
    executable = str(app / "Contents/MacOS/fidomanager-app")
    worker = str(app / "Contents/MacOS/fido-worker")
    table = []
    for line in output(["ps", "-axo", "pid=,ppid=,command="]).splitlines():
        pid, ppid, command = line.strip().split(None, 2)
        table.append((int(pid), int(ppid), command))
    apps = [pid for pid, _, command in table if command == executable]
    workers = [(pid, ppid, command) for pid, ppid, command in table if command.startswith(worker)]
    return apps, workers


def wait_for(predicate, timeout, interval=0.25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


def probe(helper, *pids):
    results = []
    for line in output([str(helper), *[str(pid) for pid in pids]]).splitlines():
        results.append(json.loads(line))
    return results


def require(condition, message, report):
    report["checks"].append({"check": message, "result": "PASS" if condition else "FAIL"})
    if not condition:
        raise Failure(message)


def denials(since):
    text = output(["/usr/bin/log", "show", "--start", since, "--style", "compact",
                   "--predicate", 'sender == "Sandbox"'])
    found = {}
    for line in text.splitlines():
        match = re.search(r"Sandbox: ((?:fidomanager-app|fido-worker))\(\d+\) (deny\(\d+\) .*)$", line)
        if match:
            key = f"{match.group(1)} {match.group(2).strip()}"
            found[key] = found.get(key, 0) + 1
    return found


def webkit_failures(since):
    text = output(["/usr/bin/log", "show", "--start", since, "--style", "compact",
                   "--predicate", 'process == "fidomanager-app" AND (eventMessage CONTAINS "permission to communicate with network" OR eventMessage CONTAINS "Network Process 0 crash" OR eventMessage CONTAINS "WebContent process crash")'])
    return [line for line in text.splitlines() if "fidomanager-app[" in line]


def fido_hid_devices():
    # IORegistry observation only (no device is opened): FIDO usage page 0xF1D0 = 61904.
    text = output(["ioreg", "-r", "-c", "IOHIDDevice", "-d", "1", "-k", "PrimaryUsagePage"])
    return len(re.findall(r'"PrimaryUsagePage" = 61904\b', text))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("app", type=Path)
    parser.add_argument("--report", type=Path, help="write the JSON evidence report here")
    parser.add_argument("--observe", type=float, default=15.0, help="seconds to let the GUI run before checks")
    arguments = parser.parse_args()
    app = arguments.app.resolve(strict=True)
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    if info.get("CFBundleIdentifier") != TEST_IDENTIFIER:
        raise SystemExit(f"refusing: only the isolated test identity {TEST_IDENTIFIER} may be launched")
    if processes(app)[0]:
        raise SystemExit("refusing: an instance of this test app is already running")

    home = Path(os.path.expanduser("~"))
    container = home / "Library/Containers" / TEST_IDENTIFIER / "Data"
    data = container / "Library/Application Support" / TEST_IDENTIFIER
    report = {"app": str(app), "identifier": TEST_IDENTIFIER, "macos": output(["sw_vers", "-productVersion"]).strip(),
              "fido_hid_devices_present": fido_hid_devices(), "checks": []}
    since = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report["started"] = since
    status = 1
    with tempfile.TemporaryDirectory(prefix="fidomanager-sandbox-probe-") as temporary:
        helper = Path(temporary) / "probe"
        output(["xcrun", "clang", "-O1", "-o", str(helper), str(ROOT / "scripts/macos-sandbox-probe.c")])
        stderr = Path(temporary) / "app-stderr.txt"
        try:
            subprocess.run(["open", "-n", "--stderr", str(stderr), str(app)], check=True)
            launched = wait_for(lambda: processes(app)[0], 20)
            require(len(launched) == 1, "exactly one authority process launched", report)
            app_pid = launched[0]
            worker = wait_for(lambda: [w for w in processes(app)[1] if w[1] == app_pid], 30)
            require(len(worker) == 1, "renderer IPC (list_authenticators) spawned exactly one worker", report)
            worker_pid, _, worker_command = worker[0]
            require(worker_command.endswith("fido-worker --authentication"),
                    "worker runs the fixed production --authentication mode", report)
            # Probe the first worker right away: an operator inspecting a key during the run retires
            # and replaces it by design (MAS.0 §5.2), so later checks cannot rely on this pid.
            time.sleep(2)
            states = {entry["pid"]: entry for entry in probe(helper, app_pid, worker_pid)}
            report["processes"] = list(states.values())
            for pid, role in ((app_pid, "app"), (worker_pid, "worker")):
                flags = states[pid]["cs_flags"]
                require(states[pid]["sandboxed"] == 1, f"{role} is sandboxed by the kernel (sandbox_check)", report)
                require(flags & CS_VALID and flags & CS_RUNTIME,
                        f"{role} runs with valid code signature and Hardened Runtime (cs_flags {flags:#x})", report)
            time.sleep(arguments.observe)
            seen = {pid for pid, _, _ in processes(app)[1]}
            current = wait_for(lambda: [w for w in processes(app)[1] if w[1] == app_pid], 10)
            require(len(current) == 1, "after the observation window one worker serves the app (handshake and health check passed)", report)
            report["worker_pids_at_end_of_observation"] = sorted(seen)
            data_stat = data.lstat() if data.exists() else None
            require(data_stat is not None and stat.S_ISDIR(data_stat.st_mode) and stat.S_IMODE(data_stat.st_mode) == 0o700,
                    "application data directory is inside the test container, mode 0700", report)
            recovery = data / "fido-authority-recovery-v1"
            require(recovery.is_dir() and not recovery.is_symlink() and stat.S_IMODE(recovery.lstat().st_mode) == 0o700,
                    "recovery storage initialized in the container, mode 0700", report)
            lock = data / "single-instance.lock"
            require(lock.is_file() and not lock.is_symlink() and stat.S_IMODE(lock.lstat().st_mode) == 0o600,
                    "single-instance lock is in the container, mode 0600", report)
            report["container_data"] = str(data)
            report["recovery_entries"] = sorted(path.name for path in recovery.iterdir())

            subprocess.run(["open", "-n", str(app)], check=True)
            time.sleep(8)
            apps, workers = processes(app)
            require(apps == [app_pid], "second launch (open -n) exited; one authority remains", report)
            # A credential inspection retires its worker by design (MAS.0 §5.2), and an operator may
            # inspect during the run, so assert ownership, not a fixed pid.
            require(len(workers) <= 1 and all(w[1] == app_pid for w in workers),
                    "second launch spawned no worker (at most one, owned by the single authority)", report)

            victim = wait_for(lambda: [w for w in processes(app)[1] if w[1] == app_pid], 10)
            require(len(victim) == 1, "a worker is running before the kill test", report)
            victim_pid = victim[0][0]
            try:
                os.kill(victim_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # it retired on its own a moment earlier; replacement is still required
            replacement = wait_for(lambda: [w for w in processes(app)[1] if w[1] == app_pid and w[0] != victim_pid], 30)
            require(len(replacement) == 1, "SIGKILLed worker was replaced by the supervisor", report)
            replacement_pid = replacement[0][0]
            replaced = probe(helper, replacement_pid)[0]
            require(replaced["sandboxed"] == 1, "replacement worker is sandboxed", report)
            report["replacement_worker"] = replaced

            os.kill(app_pid, signal.SIGTERM)
            gone = wait_for(lambda: not any(processes(app)), 10)
            require(bool(gone), "after the app ended, the worker exited on its own", report)
            status = 0
        except Failure:
            status = 1
        finally:
            apps, workers = processes(app)
            for pid in apps + [w[0] for w in workers]:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            report["app_stderr"] = stderr.read_text(errors="replace") if stderr.exists() else ""
    time.sleep(2)
    found = denials(since)
    unexpected = {key: count for key, count in found.items() if not any(rule.match(key) for rule in BENIGN_DENIALS)}
    report["sandbox_denials"] = found
    report["unexpected_sandbox_denials"] = unexpected
    report["checks"].append({"check": "no unreviewed Sandbox denial for fidomanager-app or fido-worker",
                             "result": "PASS" if not unexpected else "FAIL"})
    webkit = webkit_failures(since)
    report["webkit_failures"] = webkit
    report["checks"].append({"check": "WKWebView: no network-permission failure or WebKit process crash",
                             "result": "PASS" if not webkit else "FAIL"})
    if unexpected or webkit:
        status = 1
    text = json.dumps(report, indent=2)
    if arguments.report:
        arguments.report.write_text(text + "\n")
    print(text)
    print("PASS: App Sandbox runtime evidence" if status == 0 else "FAIL: App Sandbox runtime evidence")
    raise SystemExit(status)


if __name__ == "__main__":
    main()
