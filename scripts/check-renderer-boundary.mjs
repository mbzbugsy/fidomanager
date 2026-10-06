import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

const EXPECTED_CAPABILITY = 'main';
const EXPECTED_COMMANDS = [
  'foundation_status',
  'list_authenticators',
  'boogoocypher_status',
];
const EXPECTED_PERMISSIONS = [
  'allow-foundation-status',
  'allow-list-authenticators',
  'allow-boogoocypher-status',
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

const readiness = discoveredCommands.find(
  ({ name }) => name === 'boogoocypher_status',
);
if (
  !readiness ||
  readiness.parameters.replace(/\s+/g, '').replace(/,$/, '') !==
    "state:tauri::State<'_,AppState>"
) {
  throw new Error(
    'boogoocypher_status may accept only authority-owned Tauri State.',
  );
}

// foundation_status retrieves a backend-created snapshot; it must never return authority.
const commandSource = readFileSync('src-tauri/src/commands/mod.rs', 'utf8');
// Discovery classification is backend-owned and carries no error text or authority.
if (
  !/pub async fn list_authenticators\([\s\S]*?\)\s*->\s*Result<DiscoveryPresentation<AuthenticatorList>, \(\)>/.test(
    commandSource,
  )
) {
  throw new Error(
    'list_authenticators must return only the reviewed typed discovery presentation.',
  );
}
const discoveryDto = readFileSync(
  'crates/fido-service/src/discovery_presentation.rs',
  'utf8',
);
const discoveryShape = discoveryDto
  .match(/pub enum DiscoveryPresentation<T> \{([\s\S]*?)^\}/m)?.[1]
  ?.replace(/\s/g, '');
if (discoveryShape !== 'Fresh{list:T},Settling{},Unavailable{},') {
  throw new Error(
    'DiscoveryPresentation contains an unreviewed renderer field or state.',
  );
}
const foundationFields = [
  ...(
    commandSource.match(/pub struct FoundationStatus \{([^}]+)\}/s)?.[1] ?? ''
  ).matchAll(/^\s*([a-z0-9_]+):/gm),
].map((m) => m[1]);
assertExactArray(
  foundationFields,
  [
    'phase',
    'worker_protocol_version',
    'reviewed_libfido2_baseline',
    'inspection_activity',
  ],
  'FoundationStatus contains an unreviewed renderer field.',
);
if (
  !commandSource.includes(
    'inspection: fido_service::inspection::InspectionDisplay',
  )
) {
  throw new Error(
    'Only the reviewed per-device InspectionDisplay may cross list_authenticators.',
  );
}

const authenticatorFields = [
  ...(
    commandSource.match(/struct AuthenticatorSummary \{([^}]+)\}/s)?.[1] ?? ''
  ).matchAll(/^\s*([a-z0-9_]+):/gm),
].map((m) => m[1]);
assertExactArray(
  authenticatorFields,
  [
    'inspection',
    'display_name',
    'display_detail',
    'handle',
    'generation',
    'vendor_id',
    'product_id',
    'manufacturer',
    'product',
    'aaguid',
    'versions',
    'extensions',
    'transports',
    'options',
    'max_message_size',
    'firmware_version',
    'read_status',
    'freshness',
    'pin_check_passed',
  ],
  'AuthenticatorSummary contains an unreviewed renderer field.',
);

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
  /fido-(?:auth|core|worker-protocol|worker|worker-fixture|libfido2|platform|native-ui)\s*=/.test(
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
  if (/RestartBackoff/.test(source)) {
    throw new Error(
      `Renderer must not infer settling from backend error text: ${file}`,
    );
  }
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

// Start suppression is presentation only: the sensitive-workflow gate stays the sole admission
// authority, and the native menu start must still reserve through it after the presentation claim.
if (
  !commandSource.includes(
    'inspection_activity: fido_service::activity::ActivityView',
  )
) {
  throw new Error(
    'Only the reviewed ActivityView may cross foundation_status as inspection activity.',
  );
}
const nativeStartSource = readFileSync(
  'src-tauri/src/authentication.rs',
  'utf8',
);
const claimAt = nativeStartSource.indexOf('.activity.try_claim()');
const reserveAt = nativeStartSource.indexOf('authority.reserve()');
if (claimAt < 0 || reserveAt < 0 || claimAt > reserveAt) {
  throw new Error(
    'Native inspection start must claim the presentation slot and then still reserve through the gate.',
  );
}
for (const file of rendererFiles) {
  if (/Authentication result/i.test(readFileSync(file, 'utf8'))) {
    throw new Error(
      `Generic "Authentication result" wording returned: ${file}`,
    );
  }
}

// BooGooCypher readiness is status only and is structurally separated from every FIDO path.
const READINESS_URL = 'https://boogoocypher.foladigroup.com/health/ready';
const statusCrate = 'crates/boogoocypher-status';
const statusManifest = readFileSync(`${statusCrate}/Cargo.toml`, 'utf8')
  .split('\n')
  .filter((line) => !line.trim().startsWith('#'))
  .join('\n');
if (/path\s*=/.test(statusManifest) || /fido/i.test(statusManifest)) {
  throw new Error(
    'BooGooCypher status crate must not depend on any project or FIDO crate.',
  );
}
const statusSources = listFiles(`${statusCrate}/src`, (path) =>
  path.endsWith('.rs'),
);
const forbiddenIdentifiers =
  /\b(?:pin|puat|credentials?|rp_?hash|user_?id|acquisition\w*|workflow\w*|prompt\w*|device_?handle|fido\w*|authenticat\w*)\b/i;
let urlLiterals = 0;
for (const file of statusSources) {
  const source = readFileSync(file, 'utf8');
  const hit = source.match(forbiddenIdentifiers);
  if (hit) {
    throw new Error(
      `BooGooCypher status code must not reference FIDO/secret state (${hit[0]}): ${file}`,
    );
  }
  if (file.endsWith('tests.rs')) continue;
  for (const match of source.matchAll(/https?:\/\/[^\s"')]+/g)) {
    urlLiterals += 1;
    if (match[0] !== READINESS_URL && !file.endsWith('lib.rs')) {
      throw new Error(`Unexpected URL in BooGooCypher status code: ${file}`);
    }
  }
}
const statusLib = readFileSync(`${statusCrate}/src/lib.rs`, 'utf8');
if (
  !statusLib.includes(`pub const READINESS_URL: &str = "${READINESS_URL}";`)
) {
  throw new Error(
    'BooGooCypher readiness endpoint must be the fixed constant.',
  );
}
if (urlLiterals !== 1) {
  throw new Error('BooGooCypher status code must contain exactly one URL.');
}
const statusEnum =
  statusLib.match(/pub enum ReadinessStatus \{([^}]+)\}/s)?.[1] ?? '';
assertExactArray(
  [...statusEnum.matchAll(/^\s*([A-Za-z]+),/gm)].map((m) => m[1]),
  ['Checking', 'Online', 'Offline'],
  'BooGooCypher renderer status must be exactly Checking/Online/Offline.',
);
// Test-only helpers (#[cfg(test)]) are not part of the production surface.
const requestImpl = (
  statusLib.match(/impl HealthRequest \{([\s\S]*?)\n\}/)?.[1] ?? ''
).replace(/#\[cfg\(test\)\][\s\S]*?\n    \}(?:\n|$)/g, '');
const requestConstructors = [
  ...requestImpl.matchAll(
    /pub(?:\(crate\))?\s+(?:const\s+)?fn\s+(\w+)\(([^)]*)\)/g,
  ),
].filter(([, , args]) => !/self/.test(args));
assertExactArray(
  requestConstructors.map(([, name, args]) => `${name}(${args.trim()})`),
  ['fixed()'],
  'HealthRequest must have no input-accepting public constructor.',
);
if (
  !commandSource.includes(
    ') -> Result<boogoocypher_status::ReadinessStatus, String>',
  )
) {
  throw new Error('boogoocypher_status may return only the typed status.');
}
const readinessFn =
  commandSource.match(
    /(?:\/\/\/[^\n]*\n)*#\[tauri::command\]\npub async fn boogoocypher_status[\s\S]*?\n}\n/,
  )?.[0] ?? '';
if (!readinessFn) {
  throw new Error('boogoocypher_status command definition not found.');
}
const otherCommandSource = commandSource.replace(readinessFn, '');
if (/boogoocypher/i.test(otherCommandSource)) {
  throw new Error(
    'BooGooCypher must not be referenced by discovery, inspection or authentication commands.',
  );
}
if (/state\.(?!boogoocypher\b)\w+/.test(readinessFn)) {
  throw new Error('boogoocypher_status may read only the readiness service.');
}
for (const file of rustFiles) {
  if (file.endsWith('lib.rs') || file.endsWith('commands/mod.rs')) continue;
  if (/boogoocypher/i.test(readFileSync(file, 'utf8'))) {
    throw new Error(`BooGooCypher must not appear in ${file}.`);
  }
}
for (const file of listFiles('crates', (path) => path.endsWith('Cargo.toml'))) {
  if (file.startsWith(statusCrate)) continue;
  if (/boogoocypher/i.test(readFileSync(file, 'utf8'))) {
    throw new Error(
      `No other crate may depend on BooGooCypher status: ${file}`,
    );
  }
}
for (const file of listFiles('crates', (path) => path.endsWith('.rs'))) {
  if (file.startsWith(statusCrate)) continue;
  if (/boogoocypher/i.test(readFileSync(file, 'utf8'))) {
    throw new Error(`FIDO crates must not reference BooGooCypher: ${file}`);
  }
}
const csp = tauriConfig?.app?.security?.csp ?? '';
if (
  !/connect-src ipc: http:\/\/ipc\.localhost;/.test(csp) ||
  /boogoocypher/i.test(csp)
) {
  throw new Error(
    'Renderer CSP must not allow network or BooGooCypher access.',
  );
}
for (const file of rendererFiles) {
  const source = readFileSync(file, 'utf8');
  if (/boogoocypher\.foladigroup/i.test(source)) {
    throw new Error(
      `Renderer must not know the BooGooCypher endpoint: ${file}`,
    );
  }
  if (
    /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b/.test(source)
  ) {
    throw new Error(`Renderer network APIs are not approved: ${file}`);
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

// M4 permits only the reviewed typed PIN path; reset, deletion and generic mutation stay forbidden.
const workerProtocol = readFileSync(
  'crates/fido-worker-protocol/src/lib.rs',
  'utf8',
);
const requestShape =
  workerProtocol.match(/pub enum WorkerRequest \{([\s\S]*?)^\}/m)?.[1] ?? '';
assertExactArray(
  [...requestShape.matchAll(/^    ([A-Z][A-Za-z]+)(?:,| \{)/gm)].map(
    (m) => m[1],
  ),
  [
    'PrepareCredentialDeletion',
    'ExecuteCredentialDeletion',
    'PreparePinMutation',
    'ExecutePinMutation',
    'HealthCheck',
    'Cancel',
    'ListDevices',
    'GetDeviceInfo',
    'PrepareAuthentication',
    'InspectCredentials',
    'ValidateAuthentication',
  ],
  'M4 must not add an unreviewed executable mutation worker request.',
);
for (const file of [
  ...listFiles('crates', (path) => path.endsWith('.rs')),
  ...rustFiles,
]) {
  const source = readFileSync(file, 'utf8');
  // The pre-existing opt-in M1.5 manual harness has one reviewed deletion probe. Freeze it
  // byte-for-byte, and keep it outside production dependencies; no M4 path may use that probe.
  const manualSpike = file === 'crates/fido-puat-spike/src/native.rs';
  if (
    manualSpike &&
    createHash('sha256').update(source).digest('hex') !==
      '9e2b92cd7f416d9633bac9de21d903e784697de3a5d495face2d7bd451565a22'
  ) {
    throw new Error(
      'M4 foundation must not change the opt-in manual mutation spike.',
    );
  }
  if (
    /\bfido_dev_reset\s*\(/.test(source) ||
    (file !== 'crates/fido-libfido2/src/native/mutation.rs' &&
      /\bfido_dev_set_pin\s*\(/.test(source)) ||
    (!manualSpike &&
      file !== 'crates/fido-libfido2/src/native/deletion.rs' &&
      /\bfido_credman_del_dev_rk\s*\(/.test(source))
  ) {
    throw new Error(
      `M4 foundation must not declare or call authenticator mutation: ${file}`,
    );
  }
}
for (const file of rendererFiles) {
  if (
    /\b(?:OperationPermit|OperationIntent|DeleteCredentialIntent|DeleteCredentialPermit|ExactCredentialTarget|PinMutationSecrets|PinMutationDispatchPermit|MutationCompletion|WorkflowId|PromptInstanceId|recovery_journal|journal_path|dispatch_capable|current_pin|new_pin|confirm_pin)\b/.test(
      readFileSync(file, 'utf8'),
    )
  ) {
    throw new Error(
      `M4 foundation authority or recovery data must not enter renderer: ${file}`,
    );
  }
}

for (const file of [
  ...listFiles('crates', (path) => path.endsWith('Cargo.toml')),
  'src-tauri/Cargo.toml',
]) {
  if (file === 'crates/fido-puat-spike/Cargo.toml') continue;
  if (/^fido-puat-spike\s*=/m.test(readFileSync(file, 'utf8'))) {
    throw new Error(
      'M4 production dependencies must not include the manual PUAT spike.',
    );
  }
}
const spikeManifest = readFileSync('crates/fido-puat-spike/Cargo.toml', 'utf8');
if (
  !/^default = \[\]/m.test(spikeManifest) ||
  !spikeManifest.includes('required-features = ["native-puat"]')
) {
  throw new Error('M4 must leave the manual spike opt-in and non-shipping.');
}

for (const [file, name] of [
  ['crates/fido-auth/src/mutation.rs', 'PinMutationSecrets'],
  ['crates/fido-service/src/mutation.rs', 'OperationPermit'],
  ['crates/fido-service/src/mutation.rs', 'PinMutationDispatchPermit'],
  ['crates/fido-service/src/recovery.rs', 'DurablePinDispatch'],
  ['crates/fido-service/src/deletion.rs', 'DeleteCredentialPermit'],
  ['crates/fido-service/src/recovery.rs', 'DurableCredentialDeletionDispatch'],
]) {
  const text = readFileSync(file, 'utf8');
  const unsafeDerive = new RegExp(
    '#\\[derive\\([^)]*(?:Serialize|Deserialize|Clone|Copy|Debug|Display)[^)]*\\)\\]\\s*(?:pub(?:\\([^)]*\\))? )?(?:struct|enum) ' +
      name +
      '\\b',
  );
  const unsafeImpl = new RegExp(
    '\\bimpl(?:<[^>]*>)?\\s+(?:[A-Za-z_][A-Za-z0-9_]*::)*(?:Serialize|Deserialize(?:<[^>]*>)?|Clone|Copy|Debug|Display)\\s+for\\s+' +
      name +
      '\\b',
  );
  if (unsafeDerive.test(text) || unsafeImpl.test(text))
    throw new Error(`M4 secret/permit traits must remain forbidden: ${name}`);
}
const nativeSheet = readFileSync(
  'crates/fido-native-ui/src/macos_pin.rs',
  'utf8',
);
if (
  !nativeSheet.includes(
    'cancel.setKeyEquivalent(&NSString::from_str("\\r"))',
  ) ||
  !nativeSheet.includes('makeFirstResponder(Some(&cancel))') ||
  !nativeSheet.includes('defaultButtonCell()') ||
  !nativeSheet.includes('!default_cancel')
)
  throw new Error('M4 native sheets must prove Cancel is the safe default.');
const pinAdapter = readFileSync(
  'crates/fido-libfido2/src/native/mutation.rs',
  'utf8',
);
if ([...pinAdapter.matchAll(/\bfido_dev_set_pin\s*\(/g)].length !== 2)
  throw new Error(
    'M4 requires exactly one private PIN declaration and one execution call.',
  );
const mutationService = readFileSync(
  'crates/fido-service/src/mutation.rs',
  'utf8',
);
if (/pub (?:struct|enum) PinMutationDispatchPermit/.test(mutationService))
  throw new Error('M4 dispatch authority must remain private.');
if (/pub(?:\([^)]*\))? fn mark_dispatch_capable/.test(mutationService))
  throw new Error('M4 dispatch transition must remain private.');
if (!/permit: PinMutationDispatchPermit,/.test(mutationService))
  throw new Error('M4 dispatch must consume its capability by value.');
if (!/durable: crate::recovery::DurablePinDispatch,/.test(mutationService))
  throw new Error('M4 dispatch capability must own a durable journal receipt.');
if (
  !/self\.write_pending\(&mut r, &permit\)\?;\s*let dispatch = self\.mark_dispatch_capable\(supervisor, &mut r, permit\)\?;/.test(
    mutationService,
  )
)
  throw new Error(
    'M4 dispatch capability requires durable Pending and DispatchCapable ordering.',
  );
const recoveryService = readFileSync(
  'crates/fido-service/src/recovery.rs',
  'utf8',
);
if (
  !/self\.persist\(record\)\?;\s*Ok\(DurablePinDispatch/.test(recoveryService)
)
  throw new Error(
    'M4 durable receipt requires successful journal persistence.',
  );
console.log(
  'Renderer boundary check passed; only reviewed backend PIN mutation path.',
);
