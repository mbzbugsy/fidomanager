import assert from 'node:assert/strict';
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

// Exercise the real checker against isolated copies, never mutate the working checkout.
const fixture = mkdtempSync(join(tmpdir(), 'fidomanager-renderer-boundary-'));
const checker = resolve('scripts/check-renderer-boundary.mjs');
try {
  cpSync('src-tauri', join(fixture, 'src-tauri'), {
    recursive: true,
    filter: (path) => !path.includes('/gen'),
  });
  cpSync('src', join(fixture, 'src'), { recursive: true });
  cpSync('crates', join(fixture, 'crates'), { recursive: true });
  cpSync('packaging', join(fixture, 'packaging'), { recursive: true });
  const manifestPath = join(fixture, 'src-tauri/Cargo.toml');
  const manifest = readFileSync(manifestPath, 'utf8');
  let checks = 0;
  const check = () => {
    checks += 1;
    return spawnSync(process.execPath, [checker], {
      cwd: fixture,
      encoding: 'utf8',
    });
  };
  assert.equal(
    check().status,
    0,
    'Existing command/permission allowlist must pass.',
  );
  for (const crate of [
    'fido-auth',
    'fido-core',
    'fido-worker-protocol',
    'fido-worker',
    'fido-worker-fixture',
    'fido-libfido2',
    'fido-platform',
    'fido-native-ui',
  ]) {
    writeFileSync(
      manifestPath,
      manifest.replace(
        '[dependencies]',
        `[dependencies]\n${crate} = { path = "../crates/${crate}" }`,
      ),
    );
    const result = check();
    assert.notEqual(result.status, 0, `Direct ${crate} dependency must fail.`);
    assert.match(result.stderr, /must depend on fido-service only/);
  }
  writeFileSync(manifestPath, manifest);
  const capabilityPath = join(fixture, 'src-tauri/capabilities/main.json');
  const capabilityText = readFileSync(capabilityPath, 'utf8');
  const capability = JSON.parse(capabilityText);
  capability.permissions.push('allow-authenticate');
  writeFileSync(capabilityPath, JSON.stringify(capability));
  assert.match(check().stderr, /unexpected permission set/);
  writeFileSync(capabilityPath, capabilityText);
  const commandPath = join(fixture, 'src-tauri/src/commands/mod.rs');
  const commandText = readFileSync(commandPath, 'utf8');
  writeFileSync(
    commandPath,
    commandText.replace(
      'pub struct FoundationStatus {',
      'pub struct FoundationStatus {\n    pin: String,',
    ),
  );
  assert.match(check().stderr, /unreviewed renderer field/);
  writeFileSync(commandPath, commandText);
  writeFileSync(
    commandPath,
    commandText.replace(
      'struct AuthenticatorSummary {',
      'struct AuthenticatorSummary {\n    puat: String,',
    ),
  );
  assert.match(check().stderr, /unreviewed renderer field/);
  writeFileSync(commandPath, commandText);
  const appPath = join(fixture, 'src/App.svelte');
  const appText = readFileSync(appPath, 'utf8');
  writeFileSync(
    appPath,
    appText + `\n<script>invoke('inspect_credentials')</script>`,
  );
  assert.match(check().stderr, /invoke surface/);
  writeFileSync(appPath, appText);
  const buildPath = join(fixture, 'src-tauri/build.rs');
  const buildText = readFileSync(buildPath, 'utf8');
  writeFileSync(
    buildPath,
    buildText.replace('"foundation_status"', '"authenticate"'),
  );
  assert.match(check().stderr, /command allowlist/);
  writeFileSync(buildPath, buildText);
  assert.equal(check().status, 0, 'Restored fixture must pass.');
  // BooGooCypher status must stay structurally separated from every FIDO path.
  const mutate = (path, edit, pattern, label) => {
    const full = join(fixture, path);
    const original = readFileSync(full, 'utf8');
    writeFileSync(full, edit(original));
    const result = check();
    writeFileSync(full, original);
    assert.notEqual(result.status, 0, `${label} must fail.`);
    assert.match(result.stderr, pattern, label);
  };
  mutate(
    'src-tauri/src/commands/mod.rs',
    (text) =>
      text.replace(
        'pub async fn list_authenticators(',
        'pub async fn list_authenticators(\n    classification: DiscoveryPresentation<()>,',
      ),
    /only authority-owned Tauri State/,
    'renderer providing a discovery classification',
  );
  mutate(
    'src-tauri/src/commands/mod.rs',
    (text) =>
      text.replace(
        'Result<DiscoveryPresentation<AuthenticatorList>, ()>',
        'Result<AuthenticatorList, String>',
      ),
    /reviewed typed discovery presentation/,
    'raw discovery error contract',
  );
  mutate(
    'crates/fido-service/src/discovery_presentation.rs',
    (text) => text.replace('Settling {},', 'Settling { binding: String },'),
    /unreviewed renderer field or state/,
    'authority inside the settling response',
  );
  mutate(
    'src/discovery.ts',
    (text) => `${text}\n// classify errors containing RestartBackoff\n`,
    /must not infer settling from backend error text/,
    'renderer interpreting a backend error string',
  );
  mutate(
    'src-tauri/src/authentication.rs',
    (text) => text.replace('authority.reserve()', 'authority.skip_gate()'),
    /still reserve through the gate/,
    'a native start that bypasses the gate',
  );
  mutate(
    'src-tauri/src/authentication.rs',
    (text) => text.replace('.activity.try_claim()', '.activity.skip_claim()'),
    /claim the presentation slot/,
    'a native start without the presentation claim',
  );
  mutate(
    'src/App.svelte',
    (text) => `${text}\n<strong>Authentication result</strong>`,
    /Authentication result/,
    'the generic Authentication result wording',
  );
  const statusManifestPath = 'crates/boogoocypher-status/Cargo.toml';
  mutate(
    statusManifestPath,
    (text) =>
      text.replace(
        '[dependencies]',
        '[dependencies]\nfido-service = { path = "../fido-service" }',
      ),
    /must not depend on any project or FIDO crate/,
    'BooGooCypher depending on a project crate',
  );
  for (const word of [
    'pin',
    'puat',
    'credential',
    'rp_hash',
    'user_id',
    'AcquisitionBinding',
    'WorkflowId',
    'PromptInstanceId',
    'DeviceHandle',
  ]) {
    mutate(
      'crates/boogoocypher-status/src/http.rs',
      (text) => `${text}\nfn leak(${word}: u8) {}\n`,
      /must not reference FIDO\/secret state/,
      `BooGooCypher code referencing ${word}`,
    );
  }
  mutate(
    'crates/boogoocypher-status/src/lib.rs',
    (text) =>
      text.replace(
        'boogoocypher.foladigroup.com/health/ready";',
        'boogoocypher.foladigroup.com/health/ready?x=1";',
      ),
    /fixed constant/,
    'a changed or parameterized endpoint',
  );
  mutate(
    'crates/boogoocypher-status/src/lib.rs',
    (text) =>
      text.replace(
        'pub const fn fixed() -> Self {',
        "pub const fn custom(url: &'static str) -> Self {\n        Self { url }\n    }\n\n    pub const fn fixed() -> Self {",
      ),
    /no input-accepting public constructor/,
    'a HealthRequest constructor accepting input',
  );
  mutate(
    'crates/boogoocypher-status/src/lib.rs',
    (text) => text.replace('    Offline,\n}', '    Offline,\n    Detail,\n}'),
    /exactly Checking\/Online\/Offline/,
    'a richer renderer status',
  );
  mutate(
    'src-tauri/src/commands/mod.rs',
    (text) =>
      text.replace(
        'Ok(readiness.status().await)',
        'let _ = &state.inspection;\n    Ok(readiness.status().await)',
      ),
    /only the readiness service/,
    'boogoocypher_status reading other state',
  );
  mutate(
    'src-tauri/src/commands/mod.rs',
    (text) =>
      text.replace(
        'let inspection = Arc::clone(&state.inspection);',
        'let inspection = Arc::clone(&state.inspection);\n    let _ = &state.boogoocypher;',
      ),
    /must not be referenced by discovery, inspection or authentication/,
    'inspection command referencing BooGooCypher',
  );
  mutate(
    'src-tauri/src/authentication.rs',
    (text) => `${text}\n// boogoocypher\n`,
    /must not appear in/,
    'native authentication referencing BooGooCypher',
  );
  mutate(
    'crates/fido-service/Cargo.toml',
    (text) =>
      `${text}\nboogoocypher-status = { path = "../boogoocypher-status" }\n`,
    /No other crate may depend on BooGooCypher status/,
    'a FIDO crate depending on BooGooCypher',
  );
  mutate(
    'src/App.svelte',
    (text) => `${text}\n<script>fetch('https://example.org')</script>`,
    /network APIs are not approved/,
    'renderer fetch',
  );
  mutate(
    'src/App.svelte',
    (text) => `${text}\n<!-- boogoocypher.foladigroup.com -->`,
    /must not know the BooGooCypher endpoint/,
    'renderer knowing the endpoint',
  );
  mutate(
    'src-tauri/tauri.conf.json',
    (text) => text.replace('connect-src ipc:', 'connect-src https: ipc:'),
    /CSP must not allow network/,
    'a CSP allowing network access',
  );
  const overlay = 'src-tauri/tauri.macos-bundle.conf.json';
  for (const [edit, pattern, label] of [
    [
      (text) =>
        text.replace(
          '"bundle": {',
          '"app": { "security": { "capabilities": [] } },\n  "bundle": {',
        ),
      /may configure only bundling/,
      'an overlay overriding app security',
    ],
    [
      (text) =>
        text.replace(
          '"bundle": {',
          '"plugins": { "updater": {} },\n  "bundle": {',
        ),
      /may configure only bundling/,
      'an overlay adding an updater plugin',
    ],
    [
      (text) =>
        text.replace(
          '"active": true,',
          '"active": true,\n    "resources": ["../secrets"],',
        ),
      /unreviewed bundle key/,
      'an overlay adding resources',
    ],
    [
      (text) =>
        text.replace(
          'sidecar/fido-worker"]',
          'sidecar/fido-worker", "/usr/local/bin/fido-worker"]',
        ),
      /exactly the staged fido-worker sidecar/,
      'an overlay adding a second worker',
    ],
    [
      (text) =>
        text.replace(
          '"createUpdaterArtifacts": false',
          '"createUpdaterArtifacts": true',
        ),
      /must not create updater artifacts/,
      'an overlay creating updater artifacts',
    ],
    [
      (text) =>
        text.replace(
          '"entitlements": null',
          '"entitlements": "debug.entitlements"',
        ),
      /must not sign or grant entitlements/,
      'an overlay granting entitlements',
    ],
    [
      (text) =>
        text.replace('"signingIdentity": null', '"signingIdentity": "-"'),
      /must not sign or grant entitlements/,
      'an overlay signing during the Tauri build',
    ],
  ]) {
    mutate(overlay, edit, pattern, label);
  }
  const platformConfig = join(fixture, 'src-tauri/tauri.macos.conf.json');
  writeFileSync(platformConfig, '{}');
  const platformResult = check();
  rmSync(platformConfig);
  assert.notEqual(
    platformResult.status,
    0,
    'An auto-merged platform config must fail.',
  );
  assert.match(platformResult.stderr, /permitted Tauri configs/);
  mutate(
    'src-tauri/tauri.conf.json',
    (text) =>
      text.replace(
        '"active": false,',
        '"active": false,\n    "externalBin": ["fido-worker"],',
      ),
    /must not set bundle.externalBin/,
    'a base config sidecar',
  );
  for (const [edit, label] of [
    [
      (text) =>
        text.replace(
          'ProcessWorkerLauncher::beside_current_exe()',
          'ProcessWorkerLauncher::from_path()',
        ),
      'an application without the fixed worker resolution',
    ],
    [
      (text) =>
        `${text}\nfn spawn() { let _ = std::process::Command::new("fido-worker"); }\n`,
      'an application spawning a PATH-resolved worker',
    ],
    [
      (text) =>
        `${text}\nfn path() { let _ = fido_service::ResolvedWorkerExecutable::from_absolute_path(p); }\n`,
      'an application choosing an absolute worker path',
    ],
  ]) {
    mutate(
      'src-tauri/src/lib.rs',
      edit,
      /only via ProcessWorkerLauncher::beside_current_exe/,
      label,
    );
  }
  for (const field of [
    'old_pin',
    'new_pin',
    'operation_permit',
    'approval',
    'recovery_journal_path',
    'workflow_id',
    'dispatch_capable',
  ]) {
    mutate(
      'src-tauri/src/commands/mod.rs',
      (text) =>
        text.replace(
          'pub struct FoundationStatus {',
          `pub struct FoundationStatus {\n    ${field}: String,`,
        ),
      /unreviewed renderer field/,
      `M4 authority field ${field}`,
    );
  }
  mutate(
    'crates/fido-worker-protocol/src/lib.rs',
    (text) =>
      text.replace(
        'pub enum WorkerRequest {',
        'pub enum WorkerRequest {\n    SetPin,',
      ),
    /must not add an unreviewed executable mutation worker request/,
    'executable SetPin worker request',
  );
  mutate(
    'crates/fido-libfido2/src/lib.rs',
    (text) => text + '\nunsafe extern "C" { fn fido_dev_set_pin(); }\n',
    /must not declare or call authenticator mutation/,
    'native PIN mutation FFI',
  );
  mutate(
    'src/App.svelte',
    (text) => text + '\n<script>let OperationPermit = true;</script>\n',
    /authority or recovery data must not enter renderer/,
    'renderer permit reference',
  );
  for (const [path, type] of [
    ['crates/fido-auth/src/mutation.rs', 'PinMutationSecrets'],
    ['crates/fido-service/src/mutation.rs', 'OperationPermit'],
    ['crates/fido-service/src/mutation.rs', 'PinMutationDispatchPermit'],
    ['crates/fido-service/src/recovery.rs', 'DurablePinDispatch'],
    ['crates/fido-service/src/deletion.rs', 'DeleteCredentialPermit'],
    ['crates/fido-service/src/deletion.rs', 'CredentialDeletionDispatchPermit'],
    [
      'crates/fido-service/src/recovery.rs',
      'DurableCredentialDeletionDispatch',
    ],
  ]) {
    for (const trait of ['Serialize', 'Clone', 'Debug']) {
      mutate(
        path,
        (text) =>
          text.replace(
            new RegExp(
              '((?:pub(?:\\([^)]*\\))? )?(?:struct|enum) ' + type + ')',
            ),
            `#[derive(${trait})]\n$1`,
          ),
        /secret\/permit traits must remain forbidden/,
        `${type} derives ${trait}`,
      );
    }
  }
  mutate(
    'crates/fido-service/src/mutation.rs',
    (text) =>
      text.replace(
        'struct PinMutationDispatchPermit',
        'pub struct PinMutationDispatchPermit',
      ),
    /dispatch authority must remain private/,
    'public dispatch capability',
  );
  mutate(
    'crates/fido-service/src/mutation.rs',
    (text) =>
      text.replace(
        'self.mark_dispatch_capable(supervisor, &mut r, permit)?;',
        '// bypass durable marker',
      ),
    /requires durable Pending and DispatchCapable ordering/,
    'dispatch before durable acknowledgement',
  );
  mutate(
    'crates/fido-service/src/mutation.rs',
    (text) =>
      text.replace(
        'fn mark_dispatch_capable<',
        'pub fn mark_dispatch_capable<',
      ),
    /dispatch transition must remain private/,
    'public dispatch transition',
  );
  mutate(
    'crates/fido-service/src/mutation.rs',
    (text) =>
      text.replace(
        'permit: PinMutationDispatchPermit,',
        'permit: &PinMutationDispatchPermit,',
      ),
    /dispatch must consume its capability by value/,
    'borrowed reusable dispatch capability',
  );
  mutate(
    'crates/fido-service/src/mutation.rs',
    (text) => text.replace('durable: crate::recovery::DurablePinDispatch,', ''),
    /dispatch capability must own a durable journal receipt/,
    'dispatch capability without durable receipt',
  );
  mutate(
    'crates/fido-service/src/recovery.rs',
    (text) =>
      text.replace('self.persist(record)?;', 'let _ = self.persist(record);'),
    /durable receipt requires successful journal persistence/,
    'receipt despite failed journal persistence',
  );
  mutate(
    'crates/fido-auth/src/mutation.rs',
    (text) => text + '\nimpl serde::Serialize for PinMutationSecrets {}\n',
    /secret\/permit traits must remain forbidden/,
    'manually implemented secret serialization',
  );
  for (const control of [
    'cancel.setKeyEquivalent(&NSString::from_str("\\r"))',
    'makeFirstResponder(Some(&cancel))',
    '!default_cancel',
  ]) {
    mutate(
      'crates/fido-native-ui/src/macos_pin.rs',
      (text) => text.replace(control, 'unsafe_default'),
      /must prove Cancel is the safe default/,
      'unsafe native sheet default',
    );
  }
  for (const name of [
    'PinMutationSecrets',
    'DeleteCredentialIntent',
    'DeleteCredentialPermit',
    'ExactCredentialTarget',
    'DeletionIdentity',
    'DeletionRecoveryCompletion',
    'PinMutationDispatchPermit',
    'current_pin',
    'new_pin',
    'confirm_pin',
  ]) {
    mutate(
      'src/App.svelte',
      (text) => text + `\n<!-- ${name} -->\n`,
      /authority or recovery data must not enter renderer/,
      `renderer ${name}`,
    );
  }

  for (const [before, after, pattern] of [
    [
      'struct CredentialDeletionDispatchPermit',
      'pub struct CredentialDeletionDispatchPermit',
      /dispatch authority must remain private/,
    ],
    [
      'permit: CredentialDeletionDispatchPermit,',
      'permit: &CredentialDeletionDispatchPermit,',
      /dispatch must consume its capability by value/,
    ],
    [
      'self.write_delete_pending(&mut reservation, &permit)?;',
      '',
      /requires durable Pending and DispatchCapable ordering/,
    ],
    [
      'let proof = self.prove_delete(',
      'let proof = self.skip_proof(',
      /proof must complete before durable Pending and DispatchCapable/,
    ],
    [
      'fn dispatch_delete(',
      'fn dispatch_delete_with_pin(pin: u8, ',
      /dispatch must not carry or re-prove the PIN/,
    ],
    [
      'let dispatch = self.mark_delete_dispatch_capable(',
      'let dispatch = self.skip_durable_transition(',
      /requires durable Pending and DispatchCapable ordering/,
    ],
    [
      'durable: crate::recovery::DurableCredentialDeletionDispatch,',
      '',
      /dispatch capability must own a durable journal receipt/,
    ],
    [
      'fn write_delete_pending(',
      'pub fn write_delete_pending(',
      /deletion helper must remain private/,
    ],
  ]) {
    mutate(
      'crates/fido-service/src/deletion.rs',
      (text) => text.replace(before, after),
      pattern,
      'M5 ' + before,
    );
  }
  for (const field of [
    'credential_id',
    'user_id',
    'rp_hash',
    'native_handle',
  ]) {
    for (const dto of [
      'CredentialDisplay',
      'RpDisplay',
      'InspectionSnapshot',
    ]) {
      mutate(
        'crates/fido-service/src/inspection.rs',
        (text) =>
          text.replace(
            'pub struct ' + dto + ' {',
            'pub struct ' + dto + ' {\n    pub ' + field + ': Vec<u8>,',
          ),
        /raw identity cannot enter renderer-facing DTOs/,
        'M5 DTO ' + field,
      );
    }
  }
  for (const field of [
    'credential_id',
    'user_id',
    'rp_hash',
    'native_handle',
    'pin',
  ]) {
    mutate(
      'src-tauri/src/commands/mod.rs',
      (text) =>
        text.replace(
          'pub struct DeleteCredentialRequest {',
          'pub struct DeleteCredentialRequest {\n    pub ' +
            field +
            ': String,',
        ),
      /DeleteCredentialRequest contains an unreviewed renderer field/,
      'DeleteCredentialRequest ' + field,
    );
  }
  for (const field of ['permit', 'receipt', 'journal_path', 'pin']) {
    mutate(
      'src-tauri/src/commands/mod.rs',
      (text) =>
        text.replace(
          'pub struct DeleteCredentialResponse {',
          'pub struct DeleteCredentialResponse {\n    pub ' +
            field +
            ': String,',
        ),
      /DeleteCredentialResponse contains an unreviewed renderer field/,
      'DeleteCredentialResponse ' + field,
    );
  }
  mutate(
    'src-tauri/src/commands/mod.rs',
    (text) =>
      text.replace(
        'request: DeleteCredentialRequest,',
        'request: DeleteCredentialRequest,\n    pin: String,',
      ),
    /delete_credential must accept only AppHandle, AppState and DeleteCredentialRequest/,
    'delete_credential with pin parameter',
  );
  // ADR-017 (M7.2a) worker authenticity stays backend-only.
  mutate(
    'crates/fido-service/src/discovery_presentation.rs',
    (text) =>
      text.replace(
        'IntegrityFailure {},',
        'IntegrityFailure { team_id: String },',
      ),
    /unreviewed renderer field or state/,
    'identity detail inside the integrity category',
  );
  mutate(
    'crates/fido-service/src/process_worker.rs',
    (text) => `${text}\nconst OVERRIDE_TEAM_ID: &str = "ABCDE12345";\n`,
    /exactly one reviewed Team ID constant/,
    'a second Team ID constant',
  );
  mutate(
    'crates/fido-service/src/supervisor.rs',
    (text) =>
      `${text}\nfn weaker() { let _ = crate::worker_authenticity::WorkerAuthenticity::Enforced(todo!()); }\n`,
    /single enforcing WorkerAuthenticity construction site/,
    'a second enforcing construction site',
  );
  mutate(
    'crates/fido-service/src/process_worker.rs',
    (text) =>
      text.replace(
        'let authenticity = crate::worker_authenticity::release_startup();',
        'let authenticity = WorkerAuthenticity::UnsignedDevelopment;',
      ),
    /Release startup authentication must run only/,
    'a release flavor that skips startup authentication',
  );
  mutate(
    'crates/fido-service/src/process_worker.rs',
    (text) =>
      `${text}\n#[link(name = "Security", kind = "framework")]\nunsafe extern "C" {}\n`,
    /Security.framework FFI must stay in/,
    'Security.framework FFI outside the reviewed binding',
  );
  mutate(
    'crates/fido-service/src/inspection.rs',
    (text) => `${text}\n// reads release-worker-identity.json\n`,
    /Only the release-identity module may name the record/,
    'the record read outside the release-identity module',
  );
  for (const [path, leak] of [
    ['src/discovery.ts', '\nexport const cdhash = "";\n'],
    ['src/App.svelte', '\n<p>{teamId}</p>\n'],
    ['src/discovery.ts', '\nexport const verificationMode = "weak";\n'],
    [
      'src-tauri/src/commands/mod.rs',
      '\n// fido_service::WorkerAuthenticity\n',
    ],
    ['src-tauri/src/lib.rs', '\n// build_id override\n'],
    ['src-tauri/src/lib.rs', '\n// release-worker-identity path\n'],
  ]) {
    mutate(
      path,
      (text) => `${text}${leak}`,
      /Worker authenticity internals must not reach the renderer or Tauri adapter/,
      `authenticity internals in ${path}`,
    );
  }
  mutate(
    'src-tauri/Cargo.toml',
    (text) =>
      text.replace(
        'default = ["native-pin"]',
        'default = ["native-pin", "macos-release-signing"]',
      ),
    /must never be a default feature/,
    'release flavor as a default feature',
  );
  mutate(
    'crates/fido-worker/Cargo.toml',
    (text) =>
      text.replace(
        'fido-platform = { path = "../fido-platform" }',
        'fido-platform = { path = "../fido-platform", features = ["macos-code-signing"] }',
      ),
    /worker must not enable the Security.framework binding/,
    'the worker linking the Security.framework binding',
  );
  // ADR-018 App Sandbox flavor.
  mutate(
    'src-tauri/Cargo.toml',
    (text) =>
      text.replace(
        'default = ["native-pin"]',
        'default = ["native-pin", "macos-app-sandbox"]',
      ),
    /macos-app-sandbox flavor must never be a default feature/,
    'sandbox flavor as a default feature',
  );
  mutate(
    'src-tauri/Cargo.toml',
    (text) =>
      text.replace(
        'macos-app-sandbox = []',
        'macos-app-sandbox = ["fido-service/macos-release-signing"]',
      ),
    /must exist in the app manifest and enable nothing else/,
    'sandbox flavor enabling another feature',
  );
  mutate(
    'crates/fido-service/Cargo.toml',
    (text) =>
      text.replace('default = []', 'default = []\nmacos-app-sandbox = []'),
    /belongs to the app crate only/,
    'sandbox flavor in a service crate',
  );
  mutate(
    'src-tauri/src/lib.rs',
    (text) =>
      text.replace(
        '#[cfg(not(feature = "macos-app-sandbox"))]\n    let builder = builder.plugin(',
        'let builder = builder.plugin(',
      ),
    /Exactly one single-instance mechanism per flavor/,
    'both single-instance mechanisms in the sandbox flavor',
  );
  mutate(
    'src-tauri/src/lib.rs',
    (text) =>
      text.replace(
        '    let builder = builder\n        .manage(',
        '    let builder = builder\n        .plugin(sandbox_instance::init())\n        .manage(',
      ),
    /Exactly one single-instance mechanism per flavor/,
    'an additional plugin registration',
  );
  for (const [path, edit, label] of [
    [
      'packaging/macos-app-sandbox/app.entitlements',
      (text) =>
        text.replace(
          '</dict>',
          '\t<key>com.apple.security.files.user-selected.read-write</key>\n\t<true/>\n</dict>',
        ),
      'an extra app entitlement',
    ],
    [
      'packaging/macos-app-sandbox/app.entitlements',
      (text) =>
        text.replace(
          '<key>com.apple.security.device.usb</key>\n\t<true/>',
          '<key>com.apple.security.device.usb</key>\n\t<false/>',
        ),
      'a non-boolean-true app entitlement',
    ],
    [
      'packaging/macos-app-sandbox/worker.entitlements',
      (text) =>
        text.replace(
          '</dict>',
          '\t<key>com.apple.security.device.usb</key>\n\t<true/>\n</dict>',
        ),
      'a worker entitlement beyond inheritance',
    ],
    [
      'packaging/macos-app-sandbox/worker.entitlements',
      (text) =>
        text.replace('<key>com.apple.security.inherit</key>\n\t<true/>', ''),
      'a worker without sandbox inheritance',
    ],
  ]) {
    mutate(path, edit, /not the reviewed set \(ADR-018\)/, label);
  }
  {
    const extra = join(
      fixture,
      'packaging/macos-app-sandbox/extra.entitlements',
    );
    writeFileSync(extra, '<plist><dict></dict></plist>');
    const result = check();
    rmSync(extra);
    assert.notEqual(result.status, 0, 'An extra entitlement file must fail.');
    assert.match(result.stderr, /only the two reviewed entitlement files/);
  }
  mutate(
    'crates/fido-service/src/recovery.rs',
    (text) =>
      text.replace(
        '#[cfg(all(test, target_os = "macos"))]',
        '#[cfg(target_os = "macos")]',
      ),
    /MAS\.1 recovery fixture must remain macOS test-only/,
    'MAS.1 fixture compiled into the production service',
  );
  assert.equal(check().status, 0, 'All restored M4 fixtures must pass.');
  console.log(
    `Renderer boundary regression checks passed (${checks} checker executions; 8 denied crates, command/permission allowlists, service separation and M4 controls).`,
  );
} finally {
  rmSync(fixture, { recursive: true, force: true });
}
