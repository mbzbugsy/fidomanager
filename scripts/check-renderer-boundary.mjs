import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const capability = JSON.parse(
  readFileSync('src-tauri/capabilities/main.json', 'utf8'),
);
if (
  !Array.isArray(capability.permissions) ||
  capability.permissions.length !== 0
) {
  throw new Error(
    'Milestone 0 renderer capability permissions must remain empty.',
  );
}

const commandSource = readFileSync('src-tauri/src/commands/mod.rs', 'utf8');
const commands = [
  ...commandSource.matchAll(
    /#\[tauri::command\][\s\S]*?pub\s+fn\s+\w+\s*\(([^)]*)\)/g,
  ),
];
if (commands.length === 0) {
  throw new Error('Expected at least one explicitly registered Tauri command.');
}

for (const command of commands) {
  if (command[1].trim() !== '') {
    throw new Error(
      'Milestone 0 renderer commands are deny-by-default and may not accept parameters. ' +
        'Update this checker with an explicit typed allowlist before adding command inputs.',
    );
  }
}

const rendererFiles = readdirSync('src', { recursive: true })
  .filter((entry) => typeof entry === 'string' && /\.(ts|svelte)$/.test(entry))
  .map((entry) => join('src', entry));

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
}

console.log('Renderer boundary check passed.');
