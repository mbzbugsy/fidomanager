#!/usr/bin/env python3
"""Run the debug-only native sheet scenarios in this local checkout; never supply a PIN.

Build first with:
  cargo build -p fido-worker --locked
  cargo build -p fidomanager-app --features native-ui-spike,tauri/custom-protocol --locked
An existing FidoManager instance must be closed first (second-launch arguments are ignored).
Mechanical native-button fixtures prove callback plumbing, not human authorization.
"""
import pathlib
import subprocess
import sys

if sys.platform != "darwin":
    raise SystemExit("This empirical harness requires macOS and a foreground GUI session.")
root = pathlib.Path(__file__).resolve().parent.parent
binary = root / "target/debug/fidomanager-app"
scenarios = {
    "native-cancel": "Cancelled",
    "native-continue": "Approved",
    "cancel": "Cancelled",
    "timeout": "TimedOut",
    "teardown": "TornDown",
    "parent-close": "ParentLost",
    "replace-parent": "ParentLost",
    "shutdown": "Shutdown",
}
report = []
for scenario, expected in scenarios.items():
    # The subprocess timeout kills and reaps only this runner's own child on failure.
    result = subprocess.run(
        [str(binary), f"--native-ui-spike={scenario}"],
        cwd=root, capture_output=True, text=True, timeout=15,
    )
    output = result.stdout + result.stderr
    print(output, end="", flush=True)
    report.append(f"=== {scenario} exit={result.returncode} ===\n{output}")
    checks = {
        "exit": result.returncode == 0,
        "parenting/default": "attached=true sheet_parent=true default_cancel=true approval_focused=false" in output,
        "event loop": "ordinary main-run-loop timer progressed while sheet open" in output,
        "teardown": output.count("teardown main=true detached=true") == 1,
        "exactly one result": output.count("Rust authority result=") == 1,
        "outcome": f"Rust authority result={expected}(PromptBinding" in output,
        "workflow release": "workflow_released=true second_result=Err(Disconnected)" in output,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise SystemExit(f"FAIL {scenario}: {', '.join(failed)}")
out = root / "target/native-ui-spike/validation.log"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("\n".join(report))
print(f"PASS: {len(scenarios)} real AppKit/Tauri-window scenarios; log: {out}")
