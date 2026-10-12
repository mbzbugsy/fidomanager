#!/usr/bin/env python3
"""MAS.2 disposable SIP-enabled sandbox/ad-hoc mechanics. No production app or credentials.
--build-only is fixture packaging coverage, not runtime or Apple signing validation.
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
import re
import shutil
import subprocess
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'target/mas2-authenticity'
APP = OUTPUT / 'MAS.2 Auth Test.app'
ID = 'eu.fidomanager.desktop.mas2authtest'
TEST = 'process_worker::mas2_sandbox_fixture::run'
ARGS = ['--exact', TEST, '--ignored', '--nocapture', '--test-threads=1']
COMMIT = '0123456789abcdef0123456789abcdef01234567'  # synthetic fixture label, NOT release provenance
NEGATIVES = ('older-release', 'wrong-flavor', 'wrong-commit', 'extra-grant', 'missing-inherit',
             'false-inherit', 'integer-inherit', 'no-runtime', 'unexpected-flags', 'fat-worker',
             'production-publisher-refuses-adhoc', 'world-writable', 'group-writable', 'symlink',
             'directory', 'missing-worker', 'static-to-spawn-swap', 'post-static-exec-refusal')
CASES = set(NEGATIVES) | {'correct-release', 'independent-per-spawn-tokens', 'build-id-consistency', 'no-unsigned-fallback'}
FILES = {'correct-a', 'correct-b', *NEGATIVES[:10]}
UNSAFE_PATHS = {'world-writable', 'group-writable', 'symlink', 'directory', 'missing-worker'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def run(command, **options):
    result = subprocess.run([str(value) for value in command], capture_output=True, text=True, **options)
    require(result.returncode == 0, f'command failed: {command[0]}\n{result.stdout}\n{result.stderr}')
    return result


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load('mas_policy', 'mas-worker-policy.py')
base = load('bundle_checker', 'check-macos-bundle.py')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build():
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'MAS.2 fixtures require arm64 macOS')
    require(not any(key.startswith(('APPLE_', 'TAURI_SIGNING_')) for key in os.environ), 'refusing signing environment')
    policy.check_source()
    environment = dict(os.environ, MACOSX_DEPLOYMENT_TARGET='11.0', FIDOMANAGER_RELEASE_SOURCE_COMMIT=COMMIT)
    result = run(['cargo', 'test', '-p', 'fido-service', '--lib', '--features', 'macos-mas-signing',
                  '--locked', '--offline', '--no-run', '--message-format=json'], cwd=ROOT, env=environment)
    artifacts = [Path(row['executable']) for row in (json.loads(line) for line in result.stdout.splitlines())
                 if row.get('reason') == 'compiler-artifact' and row.get('profile', {}).get('test')
                 and row.get('target', {}).get('name') == 'fido_service' and row.get('executable')]
    require(len(artifacts) == 1, 'expected exactly one libtest parent')
    artifact = artifacts[0]
    require(f'{TEST}: test' in run([artifact, '--list', '--ignored']).stdout, 'missing ignored runtime fixture')
    run(['cargo', 'build', '-p', 'fido-worker-fixture', '--bin', 'mas2-worker-fixture', '--features',
         'macos-mas-signing', '--locked', '--offline'], cwd=ROOT, env=environment)
    peer = ROOT / 'target/debug/mas2-worker-fixture'
    require(not OUTPUT.is_symlink(), 'symlinked fixture output')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if APP.exists():
        shutil.rmtree(APP)
    macos, cases = APP / 'Contents/MacOS', APP / 'Contents/Resources/cases'
    macos.mkdir(parents=True)
    cases.mkdir(parents=True)
    main = macos / 'mas2-auth-test'
    shutil.copyfile(artifact, main)
    main.chmod(0o755)
    version = json.loads((ROOT / 'src-tauri/tauri.conf.json').read_text())['version']
    expected_id = policy.identifier(version, COMMIT)
    variants = {'correct-a': {}, 'correct-b': {'variant': True},
                'older-release': {'id': policy.identifier('0.0.9', COMMIT)},
                'wrong-flavor': {'id': expected_id.removesuffix('.mas') + '.developer-id'},
                'wrong-commit': {'id': policy.identifier(version, 'a' * 40)},
                'extra-grant': {'grants': {**policy.GRANTS, 'com.apple.security.device.usb': True}},
                'missing-inherit': {'grants': {'com.apple.security.app-sandbox': True}},
                'false-inherit': {'grants': {**policy.GRANTS, 'com.apple.security.inherit': False}},
                'integer-inherit': {'grants': {**policy.GRANTS, 'com.apple.security.inherit': 1}},
                'no-runtime': {'options': 'kill'}, 'unexpected-flags': {'options': 'runtime,kill,hard'}}
    for name, config in variants.items():
        binary = cases / name
        data = peer.read_bytes()
        if config.get('variant'):
            marker = b'FIDOMANAGER-MAS2-DISPOSABLE-VARIANT-A'
            require(data.count(marker) == 1, 'variant byte must occur exactly once')
            data = data.replace(marker, marker[:-1] + b'B')
        binary.write_bytes(data)
        binary.chmod(0o755)
        grants = OUTPUT / f'{name}.entitlements'
        grants.write_bytes(plistlib.dumps(config.get('grants', policy.GRANTS)))
        run(['codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', config.get('id', expected_id),
             '--options', config.get('options', 'runtime,kill'), '--entitlements', grants, binary])
    x86_source, x86 = OUTPUT / 'x86.c', OUTPUT / 'x86-probe'
    x86_source.write_text('#include <unistd.h>\nint main(void) { char b; while(read(0,&b,1)>0){} return 0; }\n')
    run(['xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=11.0', x86_source, '-o', x86])
    fat = cases / 'fat-worker'
    run(['lipo', '-create', cases / 'correct-a', x86, '-output', fat])
    fat.chmod(0o755)
    run(['codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', expected_id,
         '--options', 'runtime,kill', '--entitlements', ROOT / 'packaging/macos-app-sandbox/worker.entitlements', fat])
    worker = macos / 'fido-worker'
    shutil.copyfile(cases / 'correct-a', worker)
    worker.chmod(0o755)
    info = {'CFBundleIdentifier': ID, 'CFBundleExecutable': main.name, 'CFBundleName': 'MAS.2 Auth Test',
            'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'CFBundleShortVersionString': '1',
            'LSMinimumSystemVersion': '11.0', 'LSBackgroundOnly': True}
    (APP / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    run(['codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', ID, '--options', 'runtime,kill',
         '--entitlements', ROOT / 'packaging/macos-app-sandbox/app.entitlements', APP])
    run(['codesign', '--verify', '--strict', '--deep', APP])
    expected_main = {'com.apple.security.app-sandbox': True, 'com.apple.security.device.usb': True,
                     'com.apple.security.network.client': True}
    require(base.entitlements(main) == expected_main, 'unexpected fixture main grants')
    require(policy.exact_grants(base.entitlements(worker)), 'unexpected fixture worker grants')
    for binary in [main, *cases.iterdir()]:
        fields = base.signature(binary)
        require(fields.get('Signature') == ['adhoc'] and fields.get('TeamIdentifier') == ['not set'], 'fixture uses credentials')
        deps = run(['otool', '-L', binary]).stdout
        symbols = run(['nm', '-gU', binary]).stdout
        require(not any(name in deps for name in ('libfido2', 'libcrypto', 'libssl', 'libcbor'))
                and not re.search(r'\b_fido_(?:dev|cred|assert)_', symbols), 'fixture contains native FIDO linkage')
    sources = ['crates/fido-service/src/mas_worker_authenticity.rs', 'crates/fido-service/src/mas_worker_policy.rs',
               'crates/fido-service/src/worker_authenticity.rs', 'crates/fido-service/src/process_worker.rs',
               'crates/fido-service/src/process_worker/mas2_sandbox_fixture.rs',
               'crates/fido-platform/src/macos_code_signing.rs', 'crates/fido-platform/src/build_identity.rs',
               'crates/fido-worker-fixture/src/bin/mas2-worker-fixture.rs']
    summary = {'identifier': ID, 'worker_identifier': expected_id, 'synthetic_commit_label': COMMIT,
               'worker_build_id': f'{version}+{COMMIT}.mas', 'main_entitlements': expected_main,
               'worker_entitlements': policy.GRANTS, 'signature': 'ad-hoc', 'native_fido_linkage': False,
               'binary_sha256': {str(p.relative_to(APP)): sha(p) for p in [main, *cases.iterdir()]},
               'source_sha256': {name: sha(ROOT / name) for name in sources}}
    (OUTPUT / 'build-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return artifact, main, summary


def events(text, prefix):
    return [json.loads(line.split(prefix, 1)[1]) for line in text.splitlines() if prefix in line]


def kernel(row):
    require(all(type(row.get(key)) is int for key in ('pid', 'sandboxed', 'cs_status', 'cs_flags')), 'invalid kernel fields')
    require(row['pid'] > 0 and row['sandboxed'] == 1 and row['cs_status'] == 0
            and row['cs_flags'] & 0x10201 == 0x10201, 'kernel sandbox/runtime/kill checks failed')


def validate(result, action):
    require(result.returncode == 0 and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', result.stdout, re.M),
            f'fixture failed or empty test filter\n{result.stdout}\n{result.stderr}')
    rows = events(result.stdout, 'MAS2_EVIDENCE ')
    require(rows and rows[0].get('event') == 'kernel', 'missing initial kernel evidence')
    kernel(rows[0])
    if action == 'stage':
        require(len(rows) == 2 and rows[1].get('event') == 'staged', 'unexpected staging evidence')
        return rows
    require(rows[-1].get('event') == 'complete' and rows[-1].get('real_recovery_accessed') is False
            and rows[-1].get('physical_fido_operations') is False, 'missing completion evidence')
    cases = [row for row in rows if row.get('event') == 'case']
    prep = [row for row in rows if row.get('event') == 'fixture-prep']
    for row in prep:
        require((row.get('action') == 'install' and row.get('case') in FILES)
                or (row.get('action') == 'swap' and row.get('case') == 'correct-b')
                or (row.get('action') == 'unsafe-path' and row.get('case') in UNSAFE_PATHS), 'unreviewed preparation action')
    require(len(rows) == len(CASES) + 2 + len(prep) and len(cases) == len(CASES)
            and {row.get('case') for row in cases} == CASES, 'missing/duplicate/unexpected scenario')
    for row in cases:
        name = row['case']
        expected = {'accepted': name in ('correct-release', 'independent-per-spawn-tokens'),
                    'hello': name in ('correct-release', 'build-id-consistency'), 'contained': True,
                    'latched': name not in ('correct-release', 'independent-per-spawn-tokens', 'no-unsigned-fallback')}
        require(all(row.get(key) is value for key, value in expected.items()), f'wrong identity/admission outcome: {name}')
    children = events(result.stderr, 'MAS2_CHILD_EVIDENCE ')
    require(children, 'missing inherited child kernel evidence')
    require(len({row.get('pid') for row in children}) == len(children), 'duplicate child kernel evidence')
    for row in children:
        kernel(row)
    correct = next(row for row in cases if row['case'] == 'correct-release')
    tokens = next(row for row in cases if row['case'] == 'independent-per-spawn-tokens')
    require(type(correct.get('child_pid')) is int and type(tokens.get('child_pids')) is list
            and len(tokens['child_pids']) == 2 and all(type(pid) is int and pid > 0 for pid in tokens['child_pids']), 'invalid child IDs')
    required = {correct['child_pid'], *tokens['child_pids']}
    require(len(required) == 3 and required <= {row['pid'] for row in children}, 'missing verified child kernel evidence')
    require(tokens.get('cross_hash_rejected') is True and tokens.get('foreign_token_rejected') is True,
            'missing cross-spawn/token provenance evidence')
    require(all(type(tokens.get(key)) is str and re.fullmatch('[0-9a-f]{40}', tokens[key]) for key in ('static_a', 'static_b'))
            and tokens['static_a'] != tokens['static_b'], 'missing/distinct authenticated C_s evidence')
    return rows + children


def environment(run_id, action):
    return {'HOME': str(Path.home()), 'FIDOMANAGER_MAS2_RUN': run_id, 'FIDOMANAGER_MAS2_ACTION': action}


def prepare(root, row):
    macos = root / APP.name / 'Contents/MacOS'
    worker = macos / 'fido-worker'
    cases = root / APP.name / 'Contents/Resources/cases'
    action, name = row.get('action'), row.get('case')
    require(set(row) == {'event', 'action', 'case'} and row['event'] == 'fixture-prep', 'invalid preparation request')
    if action == 'install':
        require(name in FILES, 'unreviewed fixture file')
        if worker.is_symlink() or worker.is_file(): worker.unlink()
        elif worker.is_dir(): worker.rmdir()
        receipt = macos / 'hello-receipt'
        if receipt.exists(): receipt.unlink()
        shutil.copyfile(cases / name, worker)
        worker.chmod(0o755)
    elif action == 'swap':
        require(name == 'correct-b', 'unreviewed replacement')
        replacement = macos / 'signed-swap'
        shutil.copyfile(cases / name, replacement)
        replacement.chmod(0o755)
        os.replace(replacement, worker)
    else:
        require(action == 'unsafe-path' and name in UNSAFE_PATHS, 'unreviewed path mutation')
        if name in ('world-writable', 'group-writable'):
            worker.chmod(0o757 if name == 'world-writable' else 0o775)
        else:
            worker.unlink()
            if name == 'symlink': worker.symlink_to(cases / 'correct-a')
            elif name == 'directory': worker.mkdir()


def matrix_process(main, root, nonce):
    process = subprocess.Popen([str(main), *ARGS], env=environment(nonce, 'matrix'),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines, errors, output = [], [], queue.Queue()
    def read_stdout():
        for line in process.stdout: output.put(line)
        output.put(None)
    def read_stderr():
        errors.extend(process.stderr.readlines())
    readers = [threading.Thread(target=read_stdout, daemon=True), threading.Thread(target=read_stderr, daemon=True)]
    for reader in readers: reader.start()
    deadline = time.monotonic() + 60
    try:
        while True:
            line = output.get(timeout=max(0.01, deadline-time.monotonic()))
            if line is None: break
            lines.append(line)
            found = events(line, 'MAS2_EVIDENCE ')
            if found and found[0].get('event') == 'fixture-prep':
                prepare(root, found[0])
                process.stdin.write('READY\n')
                process.stdin.flush()
        code = process.wait(timeout=5)
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)
        for reader in readers: reader.join(timeout=5)
    return subprocess.CompletedProcess([], code, ''.join(lines), ''.join(errors))


def runtime(artifact, main, summary):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    sip = run(['csrutil', 'status']).stdout.strip()
    require('enabled' in sip and 'disabled' not in sip, 'runtime evidence requires SIP enabled')
    nonce = uuid.uuid4().hex
    control = subprocess.run([str(artifact), *ARGS], env=environment(nonce, 'stage'), capture_output=True, text=True, timeout=30)
    require(control.returncode != 0 and 'MAS.2 fixture refuses storage without a kernel sandbox' in control.stdout + control.stderr,
            'unsandboxed negative control failed')
    control_rows = events(control.stdout, 'MAS2_EVIDENCE ')
    require(len(control_rows) == 1 and control_rows[0].get('sandboxed') == 0, 'unsandboxed control must really be unsandboxed')
    staged = subprocess.run([str(main), *ARGS], env=environment(nonce, 'stage'), capture_output=True, text=True, timeout=30)
    staging = validate(staged, 'stage')
    root = Path(staging[1]['root'])
    expected = Path.home() / 'Library/Containers' / ID / 'Data/mas2-runs' / nonce
    require(root == expected and root.resolve(strict=True) == root, 'unsafe disposable staging root')
    copied = root / APP.name
    shutil.copytree(APP, copied)
    result = matrix_process(copied / 'Contents/MacOS/mas2-auth-test', root, nonce)
    (OUTPUT / 'matrix-last.stdout').write_text(result.stdout)
    (OUTPUT / 'matrix-last.stderr').write_text(result.stderr)
    evidence = validate(result, 'matrix')
    return {'identity': ID, 'run_id': nonce, 'started_utc': started,
            'macos': run(['sw_vers', '-productVersion']).stdout.strip(), 'sip': sip, 'build': summary,
            'unsandboxed_control': control_rows, 'staging': staging, 'evidence': evidence,
            'apple_signed_validation': 'BLOCKED (M1-M6)', 'store_main_validation': 'BLOCKED (G1/G5)',
            'real_recovery_accessed': False, 'physical_fido_operations': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-only', action='store_true')
    parser.add_argument('--report', type=Path, default=OUTPUT / 'runtime.json')
    args = parser.parse_args()
    artifact, main, summary = build()
    if args.build_only:
        print('PASS: MAS.2 ad-hoc fixture packaging only; runtime and Apple gates NOT established')
    else:
        report = runtime(artifact, main, summary)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(f'PASS: {len(CASES)} disposable sandbox scenarios; Apple-signed gates remain BLOCKED; {args.report}')
