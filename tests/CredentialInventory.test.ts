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
type Cred = { userName: string | null; displayName: string | null };
type Rp = {
  verifiedText: string | null;
  issue: string | null;
  credentials: Cred[];
};
let handleCounter = 0;
const rp = (
  verifiedText: string | null,
  credentials: Cred[],
  issue = null,
): Rp => ({
  verifiedText,
  issue,
  credentials,
});
const build = (
  completeness: 'complete' | 'incomplete' | 'inconsistent',
  total: { kind: 'exact' | 'at_least' | 'unknown'; value?: number },
  rps: Rp[],
): InspectionDisplay => ({
  state: 'inspected',
  snapshot: {
    deviceHandle: 'opaque-device',
    deviceGeneration: '1',
    epoch: 'opaque-epoch',
    authenticator: 'Thetis',
    assessment: {
      completeness,
      total,
      duplicate_rps: false,
      duplicate_credentials: false,
      count_contradiction: false,
    },
    rps: rps.map((group) => ({
      ...group,
      credentials: group.credentials.map((credential) => ({
        ...credential,
        handle: `opaque-credential-${handleCounter++}`,
      })),
    })),
  },
});
const inspected = (total: number): InspectionDisplay =>
  build(
    'complete',
    { kind: 'exact', value: total },
    total
      ? [rp('example.com', [{ userName: 'Account', displayName: null }])]
      : [],
  );
const html = (inspection: InspectionDisplay) =>
  render(Inventory, { props: { inspection } }).body;

describe('connected-key credential display', () => {
  it('has no inventory cards when zero keys are connected', () => {
    const result = appHtml([]);
    expect(result).toContain('No authenticator connected');
    expect(result).not.toContain('Credential inspection');
  });
  it('uninspected keys do not claim empty credentials or a total', () => {
    const result = appHtml([
      { state: 'not_inspected' },
      { state: 'not_inspected' },
    ]);
    expect(result).toContain('Not inspected');
    expect(result).toContain('native Security key menu');
    expect(result).not.toContain('No resident credentials');
    expect(result).not.toMatch(/\d+ credentials?/);
    expect(result.match(/Not inspected/g)?.length).toBe(2);
  });
  it('multiple connected keys keep independent inventories', () => {
    const result = appHtml([
      inspected(1),
      build('complete', { kind: 'exact', value: 2 }, [
        rp('github.com', [
          { userName: 'a', displayName: 'A' },
          { userName: 'b', displayName: 'B' },
        ]),
      ]),
      { state: 'not_inspected' } as InspectionDisplay,
    ]);
    expect(result.match(/example\.com/g)?.length).toBe(1);
    expect(result.match(/github\.com/g)?.length).toBe(1);
    expect(result.match(/1 credential</g)?.length).toBe(2); // total + RP group
    expect(result.match(/2 credentials</g)?.length).toBe(2);
    expect(result.match(/Not inspected/g)?.length).toBe(1);
    expect(result).not.toContain('opaque-device');
    expect(result).not.toContain('opaque-credential');
  });
  it('complete Exact(1) reads "1 credential" without backend wording', () => {
    const result = html(inspected(1));
    expect(result).toContain('1 credential<');
    expect(result).not.toContain('1 credentials');
    expect(result).not.toContain('Exact');
    expect(result).not.toContain('Complete:');
    expect(result).toContain('Inventory complete');
  });
  it('complete Exact(7) is plural', () => {
    const result = html(build('complete', { kind: 'exact', value: 7 }, []));
    expect(result).toContain('7 credentials');
    expect(result).not.toContain('Exact');
  });
  it('a complete exact zero is distinct from not inspected', () => {
    const result = html(inspected(0));
    expect(result).toContain('0 credentials');
    expect(result).toContain('No resident credentials were reported.');
    expect(result).not.toContain('Not inspected');
  });
  it('incomplete AtLeast is a lower bound with a warning', () => {
    const result = html(
      build('incomplete', { kind: 'at_least', value: 3 }, [
        rp('example.com', [{ userName: 'u', displayName: null }]),
        rp(null, [], 'text_unavailable' as never),
      ]),
    );
    expect(result).toContain('At least 3 credentials');
    expect(result).toContain(
      'Some credentials could not be read. The actual total may be higher.',
    );
    expect(result).toContain('RP identity unavailable');
    expect(result).toContain('Incomplete');
    expect(result).not.toContain('AtLeast');
    expect(result).not.toContain('at_least');
    expect(result).not.toContain('No resident credentials');
    expect(result).not.toContain('Inventory complete');
  });
  it('incomplete AtLeast(0) never claims zero', () => {
    const result = html(
      build('incomplete', { kind: 'at_least', value: 0 }, [
        rp(null, [], 'text_unavailable' as never),
      ]),
    );
    expect(result).toContain('At least 0 credentials');
    expect(result).not.toContain('No resident credentials');
  });
  it('inconsistent Unknown shows no count', () => {
    const result = html(build('inconsistent', { kind: 'unknown' }, []));
    expect(result).toContain('Credential count unavailable');
    expect(result).toContain(
      'The authenticator returned conflicting inventory information.',
    );
    expect(result).not.toMatch(/\d+ credentials?/);
    expect(result).not.toContain('Exact');
    expect(result).not.toContain('No resident credentials');
  });
  it('shows an identical displayName and userName once', () => {
    const result = html(
      build('complete', { kind: 'exact', value: 1 }, [
        rp('openai.com', [
          {
            userName: 'nima.foladi@gmail.com',
            displayName: 'nima.foladi@gmail.com',
          },
        ]),
      ]),
    );
    expect(result.match(/nima\.foladi@gmail\.com/g)?.length).toBe(1);
    expect(result).not.toContain('·');
  });
  it('shows differing names as primary and secondary', () => {
    const result = html(
      build('complete', { kind: 'exact', value: 1 }, [
        rp('github.com', [
          { userName: 'nima@example.com', displayName: 'Nima Foladi' },
        ]),
      ]),
    );
    expect(result).toMatch(
      /class="credential-name">Nima Foladi<\/span>.*class="credential-sub">nima@example\.com</s,
    );
  });
  it('shows the single available name, else Passkey', () => {
    const result = html(
      build('complete', { kind: 'exact', value: 3 }, [
        rp('example.org', [
          { userName: 'only-user', displayName: null },
          { userName: null, displayName: 'Only Display' },
          { userName: null, displayName: null },
        ]),
      ]),
    );
    expect(result).toContain('only-user');
    expect(result).toContain('Only Display');
    expect(result).toContain('>Passkey<');
    expect(result).not.toContain('credential-sub');
  });
  it('groups several RPs with their own counts', () => {
    const result = html(
      build('complete', { kind: 'exact', value: 4 }, [
        rp('openai.com', [{ userName: 'o', displayName: null }]),
        rp('github.com', [
          { userName: 'g1', displayName: null },
          { userName: 'g2', displayName: null },
        ]),
        rp('example.org', [{ userName: null, displayName: null }]),
      ]),
    );
    expect(result).toContain('4 credentials');
    expect(result).toMatch(
      /openai\.com<\/h5>\s*(?:<!--\[0-->)?<span>1 credential</,
    );
    expect(result).toMatch(
      /github\.com<\/h5>\s*(?:<!--\[0-->)?<span>2 credentials</,
    );
    expect(result).toMatch(
      /example\.org<\/h5>\s*(?:<!--\[0-->)?<span>1 credential</,
    );
  });
  it('keeps semantic headings and lists', () => {
    const result = html(inspected(1));
    expect(result).toContain('<h4 class="credential-label">Credentials</h4>');
    expect(result).toContain('<h5>example.com</h5>');
    expect(result).toContain('<ul class="credential-list">');
  });
});
