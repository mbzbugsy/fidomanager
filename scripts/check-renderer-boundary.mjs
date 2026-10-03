import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

const EXPECTED_CAPABILITY = 'main';
const EXPECTED_COMMANDS = ['foundation_status', 'list_authenticators'];
const EXPECTED_PERMISSIONS = [
  'allow-foundation-status',
  'allow-list-authenticators',
];

function listFiles(root, predicate) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) files.push(...listFiles(path, predicate));
    else if (predicate(path)) files.push(path);
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
  'Milestone 1 must have exactly one explicitly selected capability file: main.json.',
);

const capability = JSON.parse(
  readFileSync('src-tauri/capabilities/main.json', 'utf8'),
);
if (capability.identifier !== EXPECTED_CAPABILITY) {
  throw new Error('Milestone 1 renderer capability identifier must be "main".');
}
assertExactArray(
  capability.windows,
  ['main'],
  'Milestone 1 renderer capability must target only the main window.',
);
assertExactArray(
  capability.permissions,
  EXPECTED_PERMISSIONS,
  'Milestone 1 renderer capability grants an unexpected permission set.',
);
if ('remote' in capability) {
  throw new Error('Remote capability sources are not approved in Milestone 1.');
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
const manifestMatch = buildSource.match(
  /AppManifest::new\(\)[\s\S]*?\.commands\(&\[([^\]]*)\]\)/,
);
if (!manifestMatch) {
  throw new Error(
    'Tauri app ACL manifest must explicitly register app commands.',
  );
}
const manifestCommands = [
  ...manifestMatch[1].matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"/g),
].map((match) => match[1]);
assertExactArray(
  manifestCommands,
  EXPECTED_COMMANDS,
  'Tauri app ACL manifest does not match the Milestone 1 command allowlist.',
);

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
    });
  }
}
assertExactArray(
  discoveredCommands.map(({ name }) => name),
  EXPECTED_COMMANDS,
  `Milestone 1 must expose exactly: ${EXPECTED_COMMANDS.join(', ')}.`,
);

const foundation = discoveredCommands.find(
  ({ name }) => name === 'foundation_status',
);
if (
  !foundation ||
  foundation.parameters.replace(/\s+/g, '').replace(/,$/, '') !==
    "state:tauri::State<'_,AppState>"
) {
  throw new Error(
    'foundation_status must not accept renderer-controlled parameters.',
  );
}
const discovery = discoveredCommands.find(
  ({ name }) => name === 'list_authenticators',
);
if (
  !discovery ||
  discovery.parameters.replace(/\s+/g, '').replace(/,$/, '') !==
    "state:tauri::State<'_,AppState>"
) {
  throw new Error(
    'list_authenticators may accept only authority-owned Tauri State.',
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
  EXPECTED_COMMANDS,
  'Milestone 1 generate_handler! does not match the command allowlist.',
);

const cargoToml = readFileSync('src-tauri/Cargo.toml', 'utf8');
const pluginDependencies = [
  ...cargoToml.matchAll(/^([A-Za-z0-9_-]*tauri-plugin-[A-Za-z0-9_-]+)\s*=/gm),
].map((match) => match[1]);
assertExactArray(
  pluginDependencies,
  ['tauri-plugin-single-instance'],
  'Milestone 1 permits only tauri-plugin-single-instance.',
);
if (
  /fido-(?:core|worker-protocol|worker|worker-fixture|libfido2|platform|native-ui)\s*=/.test(
    cargoToml,
  )
) {
  throw new Error(
    'The Tauri adapter must depend on fido-service only among project trust crates.',
  );
}

const rendererFiles = listFiles(
  'src',
  (path) => path.endsWith('.ts') || path.endsWith('.svelte'),
);
const invokedCommands = new Set();
for (const file of rendererFiles) {
  const source = readFileSync(file, 'utf8');
  if (source.includes('@tauri-apps/api/event')) {
    throw new Error(
      `Renderer event API is not approved in Milestone 1: ${file}`,
    );
  }
  if (source.includes('@tauri-apps/plugin-')) {
    throw new Error(
      `Renderer plugin API is not approved in Milestone 1: ${file}`,
    );
  }
  if (source.includes('__TAURI_INTERNALS__')) {
    throw new Error(
      `Direct internal Tauri IPC access is not approved: ${file}`,
    );
  }
  for (const match of source.matchAll(
    /invoke(?:<[^>]+>)?\(\s*['"]([^'"]+)['"]/g,
  )) {
    invokedCommands.add(match[1]);
  }
}
assertExactArray(
  [...invokedCommands].sort(),
  [...EXPECTED_COMMANDS].sort(),
  'Renderer invoke surface does not match the approved Milestone 1 command allowlist.',
);

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
    EXPECTED_PERMISSIONS,
    'Generated Tauri main capability has an unexpected permission set.',
  );

  const generatedAcl = JSON.parse(readFileSync(generatedAclPath, 'utf8'));
  const serializedAppAcl = JSON.stringify(generatedAcl['__app-acl__'] ?? {});
  for (const permission of EXPECTED_PERMISSIONS) {
    if (!serializedAppAcl.includes(permission)) {
      throw new Error(`Generated application ACL is missing ${permission}.`);
    }
  }
  for (const command of EXPECTED_COMMANDS) {
    if (!serializedAppAcl.includes(command)) {
      throw new Error(`Generated application ACL is missing ${command}.`);
    }
  }
}

console.log('Renderer boundary check passed.');
