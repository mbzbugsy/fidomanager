import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type { InspectionDisplay, InspectionSnapshot } from '../src/inspection';

// Compile the actual component for server rendering; this needs neither a browser nor secrets.
const require = createRequire(import.meta.url);
const source = readFileSync(
  new URL('../src/CredentialInventory.svelte', import.meta.url),
  'utf8',
);
const compiled = compile(source, {
  generate: 'server',
  filename: 'CredentialInventory.svelte',
});
const code = compiled.js.code.replace(
  /(['"])(svelte[^'"]*)\1/g,
  (_, quote, name) =>
    `${quote}${pathToFileURL(require.resolve(name)).href}${quote}`,
);
const inventoryModule = `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
const Inventory = (await import(inventoryModule)).default as Component<{
  inspection: InspectionDisplay;
}>;
// Supply a discovery snapshot to the actual App template in the SSR-only harness.
// The production component and its backend-only invocation surface stay unchanged.
const appSource = readFileSync(
  new URL('../src/App.svelte', import.meta.url),
  'utf8',
)
  .replace(
    "import { invoke } from '@tauri-apps/api/core';",
    "const invoke = () => { throw new Error('SSR must not invoke native APIs'); };",
  )
  .replace(
    "import CredentialInventory from './CredentialInventory.svelte';",
    `import CredentialInventory from '${inventoryModule}';`,
  )
  .replace(
    "import logoUrl from './assets/fidomanager-logo.png';",
    "const logoUrl = 'logo.png';",
  )
  .replace(
    'let snapshot: AuthenticatorList | null = null;',
    'export let snapshot: AuthenticatorList | null = null;',
  );
const appCode = compile(appSource, {
  generate: 'server',
  filename: 'App.svelte',
}).js.code.replace(
  /(['"])(svelte[^'"]*)\1/g,
  (_, quote, name) =>
    `${quote}${pathToFileURL(require.resolve(name)).href}${quote}`,
);
const App = (
  await import(
    `data:text/javascript;base64,${Buffer.from(appCode).toString('base64')}`
  )
).default;
const appHtml = (inspections: InspectionDisplay[]) =>
  render(App, {
    props: {
      snapshot: {
        enumerationEpoch: '1',
        devices: inspections.map((inspection, i) => ({
          inspection,
          handle: `opaque-device-${i}`,
          generation: '1',
          displayName: 'Thetis',
          displayDetail: `USB · Key ${i + 1}`,
          vendorId: 1,
          productId: 2,
          manufacturer: 'Thetis',
          product: 'Same label',
          aaguid: null,
          versions: [],
          extensions: [],
          transports: ['USB'],
          options: [],
          maxMessageSize: null,
          firmwareVersion: null,
          readStatus: 'ready',
          freshness: 'fresh',
          pinCheckPassed: false,
        })),
      },
    },
  }).body;
const inspected = (total: number): InspectionDisplay => ({
  state: 'inspected',
  snapshot: {
    deviceHandle: 'opaque-device',
    deviceGeneration: '1',
    epoch: 'opaque-epoch',
    authenticator: 'Thetis',
    assessment: {
      completeness: 'complete',
      total: { kind: 'exact', value: total },
      duplicate_rps: false,
      duplicate_credentials: false,
      count_contradiction: false,
    },
    rps: total
      ? [
          {
            verifiedText: 'example.com',
            issue: null,
            credentials: [
              {
                handle: 'opaque-credential',
                userName: 'Account',
                displayName: null,
              },
            ],
          },
        ]
      : [],
  },
});
const html = (inspection: InspectionDisplay) =>
  render(Inventory, { props: { inspection } }).body;

describe('connected-key credential display', () => {
  it('has no inventory cards when zero keys are connected', () => {
    const devices: InspectionDisplay[] = [];
    const result = appHtml(devices);
    expect(result).toContain('No authenticator connected');
    expect(result).not.toContain('Credential inspection');
  });
  it('uninspected keys do not claim empty credentials or a total', () => {
    const result = appHtml([
      { state: 'not_inspected' },
      { state: 'not_inspected' },
    ]);
    expect(result).toContain('Not inspected');
    expect(result).not.toContain('No resident credentials');
    expect(result).not.toContain('Exact:');
    expect(result.match(/Not inspected/g)?.length).toBe(2);
  });
  it('two inspected inventories and a mixed uninspected key remain separate', () => {
    const result = appHtml([
      inspected(1),
      inspected(1),
      { state: 'not_inspected' } as InspectionDisplay,
    ]);
    expect(result.match(/example\.com/g)?.length).toBe(2);
    expect(result.match(/Exact:/g)?.length).toBe(2);
    expect(result).toContain('Not inspected');
    expect(result).not.toContain('opaque-device');
    expect(result).not.toContain('opaque-credential');
  });
  it('a complete exact zero is distinct from not inspected', () => {
    const result = html(inspected(0));
    expect(result).toContain('Exact: 0');
    expect(result).toContain('No resident credentials');
    expect(result).not.toContain('Not inspected');
  });
  it('incomplete and inconsistent inventories keep typed totals', () => {
    const partial = inspected(0) as {
      state: 'inspected';
      snapshot: InspectionSnapshot;
    };
    partial.snapshot.assessment.completeness = 'incomplete';
    partial.snapshot.assessment.total = { kind: 'at_least', value: 0 };
    partial.snapshot.rps = [
      { verifiedText: null, issue: 'text_unavailable', credentials: [] },
    ];
    expect(html(partial)).toContain('At least: 0');
    expect(html(partial)).not.toContain('No resident credentials');
    partial.snapshot.assessment.completeness = 'inconsistent';
    partial.snapshot.assessment.total = { kind: 'unknown' };
    expect(html(partial)).toContain('Unknown total');
    expect(html(partial)).not.toContain('Exact:');
  });
});
