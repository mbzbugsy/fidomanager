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
  const appPath = join(fixture, 'src/App.svelte');
  const appText = readFileSync(appPath, 'utf8');
  writeFileSync(
    appPath,
    appText + `\n<script>invoke('inspect_credentials')</script>`,
  );
  assert.match(check().stderr, /invoke surface/);
  writeFileSync(appPath, appText);
  const buildPath = join(fixture, 'src-tauri/build.rs');
  writeFileSync(
    buildPath,
    readFileSync(buildPath, 'utf8').replace(
      '"foundation_status"',
      '"authenticate"',
    ),
  );
  assert.match(check().stderr, /command allowlist/);
  console.log(
    'Renderer boundary regression checks passed (8 denied crates, command and permission allowlists).',
  );
} finally {
  rmSync(fixture, { recursive: true, force: true });
}
