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
  const manifestPath = join(fixture, 'src-tauri/Cargo.toml');
  const manifest = readFileSync(manifestPath, 'utf8');
  const check = () =>
    spawnSync(process.execPath, [checker], { cwd: fixture, encoding: 'utf8' });
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
  console.log(
    'Renderer boundary regression checks passed (8 denied crates, command and permission allowlists, BooGooCypher separation).',
  );
} finally {
  rmSync(fixture, { recursive: true, force: true });
}
