import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

const EXPECTED_CAPABILITY = 'main';
const EXPECTED_COMMAND = 'foundation_status';
const EXPECTED_PERMISSION = 'allow-foundation-status';

function listFiles(root, predicate) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(path, predicate));
    } else if (predicate(path)) {
      files.push(path);
    }
  }
  return files;
}

function assertExactArray(actual, expected, message) {
  if (
    !Array.isArray(actual) ||
    actual.length !== expected.length ||
    actual.some((value, index) => value !== expected[index])
  ) {
    throw new Error(message);
  }
}

const capabilityFiles = listFiles(
  'src-tauri/capabilities',
  (path) => path.endsWith('.json') || path.endsWith('.toml'),
).map((path) => relative('src-tauri/capabilities', path));

assertExactArray(
  capabilityFiles,
  ['main.json'],
  'Milestone 0 must have exactly one explicitly selected capability file: main.json.',
);

const capability = JSON.parse(
  readFileSync('src-tauri/capabilities/main.json', 'utf8'),
);
if (capability.identifier !== EXPECTED_CAPABILITY) {
  throw new Error('Milestone 0 renderer capability identifier must be "main".');
}
assertExactArray(
  capability.windows,
  ['main'],
  'Milestone 0 renderer capability must target only the main window.',
);
assertExactArray(
  capability.permissions,
  [EXPECTED_PERMISSION],
  'Milestone 0 renderer capability must grant only allow-foundation-status.',
);
if ('remote' in capability) {
  throw new Error('Remote capability sources are not approved in Milestone 0.');
}

const tauriConfig = JSON.parse(
  readFileSync('src-tauri/tauri.conf.json', 'utf8'),
);
assertExactArray(
  tauriConfig?.app?.security?.capabilities,
  [EXPECTED_CAPABILITY],
  'tauri.conf.json must explicitly select only the main capability.',
);

const buildSource = readFileSync('src-tauri/build.rs', 'utf8');
if (
  !/AppManifest::new\(\)\.commands\(&\[\s*"foundation_status"\s*\]\)/s.test(
    buildSource,
  )
) {
  throw new Error(
    'Tauri app ACL manifest must explicitly generate permission for foundation_status.',
  );
}

const rustFiles = listFiles('src-tauri/src', (path) => path.endsWith('.rs'));
const discoveredCommands = [];
const commandPattern =
  /#\s*\[\s*tauri::command(?:\s*\([^)]*\))?\s*\]\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/g;

for (const file of rustFiles) {
  const source = readFileSync(file, 'utf8');
  for (const match of source.matchAll(commandPattern)) {
    discoveredCommands.push({
      name: match[1],
      parameters: match[2].trim(),
      file,
    });
  }
}

if (
  discoveredCommands.length !== 1 ||
  discoveredCommands[0].name !== EXPECTED_COMMAND
) {
  throw new Error(
    `Milestone 0 must expose exactly one app command (${EXPECTED_COMMAND}); found: ${
      discoveredCommands.map(({ name }) => name).join(', ') || 'none'
    }.`,
  );
}
if (discoveredCommands[0].parameters !== '') {
  throw new Error(
    'Milestone 0 renderer commands may not accept parameters. Update this checker with an explicit typed allowlist before adding command inputs.',
  );
}

const appSource = readFileSync('src-tauri/src/lib.rs', 'utf8');
const handlerMatch = appSource.match(/generate_handler!\[([^\]]*)\]/s);
if (!handlerMatch) {
  throw new Error('Expected an explicit Tauri generate_handler! registration.');
}
const registeredCommands = handlerMatch[1]
  .split(',')
  .map((entry) => entry.trim())
  .filter(Boolean)
  .map((entry) => entry.split('::').at(-1));
assertExactArray(
  registeredCommands,
  [EXPECTED_COMMAND],
  'Milestone 0 generate_handler! must register only foundation_status.',
);

const cargoToml = readFileSync('src-tauri/Cargo.toml', 'utf8');
const pluginDependencies = [
  ...cargoToml.matchAll(/^([A-Za-z0-9_-]*tauri-plugin-[A-Za-z0-9_-]+)\s*=/gm),
].map((match) => match[1]);
assertExactArray(
  pluginDependencies,
  ['tauri-plugin-single-instance'],
  'Milestone 0 permits only tauri-plugin-single-instance.',
);

const rendererFiles = listFiles(
  'src',
  (path) => path.endsWith('.ts') || path.endsWith('.svelte'),
);
for (const file of rendererFiles) {
  const source = readFileSync(file, 'utf8');
  if (source.includes('@tauri-apps/api/event')) {
    throw new Error(
      `Renderer event API is not approved in Milestone 0: ${file}`,
    );
  }
  if (source.includes('@tauri-apps/plugin-')) {
    throw new Error(
      `Renderer plugin API is not approved in Milestone 0: ${file}`,
    );
  }
  if (source.includes('__TAURI_INTERNALS__')) {
    throw new Error(
      `Direct internal Tauri IPC access is not approved in Milestone 0: ${file}`,
    );
  }
}

const generatedCapabilitiesPath = 'src-tauri/gen/schemas/capabilities.json';
const generatedAclPath = 'src-tauri/gen/schemas/acl-manifests.json';
if (existsSync(generatedCapabilitiesPath) || existsSync(generatedAclPath)) {
  if (!existsSync(generatedCapabilitiesPath) || !existsSync(generatedAclPath)) {
    throw new Error('Generated Tauri ACL output is incomplete.');
  }

  const generatedCapabilities = JSON.parse(
    readFileSync(generatedCapabilitiesPath, 'utf8'),
  );
  const resolvedMain = generatedCapabilities[EXPECTED_CAPABILITY];
  if (!resolvedMain) {
    throw new Error(
      'Generated Tauri capabilities are missing the main capability.',
    );
  }
  assertExactArray(
    resolvedMain.permissions,
    [EXPECTED_PERMISSION],
    'Generated Tauri main capability does not resolve to the expected app permission.',
  );

  const generatedAcl = JSON.parse(readFileSync(generatedAclPath, 'utf8'));
  const appAcl = generatedAcl['__app-acl__'];
  if (!appAcl) {
    throw new Error(
      'Generated Tauri ACL is missing the application ACL manifest.',
    );
  }
  const serializedAppAcl = JSON.stringify(appAcl);
  if (
    !serializedAppAcl.includes(EXPECTED_PERMISSION) ||
    !serializedAppAcl.includes(EXPECTED_COMMAND)
  ) {
    throw new Error(
      'Generated application ACL does not bind allow-foundation-status to foundation_status.',
    );
  }
}

console.log('Renderer boundary check passed.');
