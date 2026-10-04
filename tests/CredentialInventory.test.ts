import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type {
  InspectionActivity,
  InspectionDisplay,
  InspectionSnapshot,
} from '../src/inspection';

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
  )
  .replace(
    "let boogoocypher: BooGooCypherStatus = 'checking';",
    "export let boogoocypher: BooGooCypherStatus = 'checking';",
  )
  .replace(
    'let foundation: FoundationStatus | null = null;',
    'export let foundation: FoundationStatus | null = null;',
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
const appHtml = (
  inspections: InspectionDisplay[],
  boogoocypher?: 'checking' | 'online' | 'offline',
  activity?: Partial<InspectionActivity>,
) =>
  render(App, {
    props: {
      ...(boogoocypher ? { boogoocypher } : {}),
      ...(activity
        ? {
            foundation: {
              phase: 'Milestone 3',
              workerProtocolVersion: 3,
              reviewedLibfido2Baseline: '1.17.0',
              inspectionActivity: {
                device: null,
                phase: null,
                issue: null,
                notice: null,
                ...activity,
              },
            },
          }
        : {}),
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
  it('incomplete AtLeast(0) reads as an incomplete count, never zero', () => {
    const result = html(
      build('incomplete', { kind: 'at_least', value: 0 }, [
        rp(null, [], 'text_unavailable' as never),
      ]),
    );
    expect(result).toContain('Credential count incomplete');
    expect(result).not.toContain('At least 0');
    expect(result).not.toMatch(/\b0 credentials/);
    expect(result).toContain(
      'Some credentials could not be read. The actual total may be higher.',
    );
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

describe('BooGooCypher readiness chip', () => {
  const chip = (status?: 'checking' | 'online' | 'offline') =>
    appHtml([], status)
      .replace(/<!--.*?-->/g, '')
      .replace(/\s+/g, ' ');
  it('starts as checking before the backend answers', () => {
    expect(chip()).toMatch(/BooGooCypher <strong>checking…<\/strong>/);
  });
  it('shows online and offline from the typed backend status only', () => {
    expect(chip('online')).toMatch(/BooGooCypher <strong>online<\/strong>/);
    const offline = chip('offline');
    expect(offline).toMatch(/BooGooCypher <strong>offline<\/strong>/);
    // Informational: the offline chip uses the neutral dot, never the warning style.
    expect(offline).toMatch(/<i[^>]*class="neutral"[^>]*><\/i> BooGooCypher/);
    expect(offline).not.toMatch(/class="warning"[^>]*><\/i> BooGooCypher/);
  });
  it('sits with the native service and libfido2 system status', () => {
    const result = chip('online');
    expect(result).toMatch(/Native service.*BooGooCypher.*libfido2/);
  });
  it('states that it is readiness only', () => {
    expect(chip('online')).toContain('Readiness status only');
  });
});

describe('inspection activity presentation', () => {
  const flat = (result: string) =>
    result.replace(/<!--.*?-->/g, '').replace(/\s+/g, ' ');
  const none: InspectionDisplay = { state: 'not_inspected' };
  const INTERNAL =
    /workflow|admission|cooldown|cooling|recovery|barrier|acquisition|binding|authentication result/i;

  it('shows Waiting for PIN on the targeted key only and keeps every card visible', () => {
    const result = flat(
      appHtml([none, inspected(1), none], undefined, {
        device: 'opaque-device-0',
        phase: 'waiting_for_pin',
      }),
    );
    expect(result.match(/Waiting for PIN…/g)?.length).toBe(1);
    expect(result).toContain('Enter your PIN in the native Security key sheet');
    expect(result.match(/class="device-card"/g)?.length).toBe(3);
    expect(result).toContain('Authenticators');
    expect(result).toContain('1 credential');
    expect(result.match(/Not inspected/g)?.length).toBe(1);
    expect(result).not.toMatch(INTERNAL);
    expect(result).not.toContain('Authentication result');
  });
  it('shows Reading credentials after the PIN and hides the stale inventory', () => {
    const result = flat(
      appHtml([inspected(1)], undefined, {
        device: 'opaque-device-0',
        phase: 'reading_credentials',
      }),
    );
    expect(result).toContain('Reading credentials…');
    expect(result).not.toContain('Waiting for PIN…');
    expect(result).not.toContain('example.com');
    expect(result).toContain('class="device-card"');
  });
  it('an activity for another key never marks this card', () => {
    const result = flat(
      appHtml([none], undefined, {
        device: 'some-other-handle',
        phase: 'waiting_for_pin',
      }),
    );
    expect(result).not.toContain('Waiting for PIN…');
    expect(result).toContain('Not inspected');
  });
  it('success returns to the normal inventory in place with a small confirmation', () => {
    const result = flat(
      appHtml([inspected(2), none], undefined, {
        notice: {
          revision: '1',
          tone: 'success',
          message: 'Credentials refreshed',
        },
      }),
    );
    expect(result).toContain('Credentials refreshed');
    expect(result).toContain('class="inspection-toast"');
    expect(result).toContain('1 credential');
    expect(result).not.toContain('Waiting for PIN…');
    expect(result).not.toContain('Reading credentials…');
    expect(result.match(/class="device-card"/g)?.length).toBe(2);
    expect(result).not.toContain('Authentication result');
  });
  it('cancellation is quiet: no toast, no alert, back to the normal state', () => {
    const result = flat(appHtml([none], undefined, {}));
    expect(result).toContain('Not inspected');
    expect(result).not.toContain('inspection-toast');
    expect(result).not.toContain('role="alert"');
    expect(result).not.toContain('Waiting for PIN…');
  });
  it('a problem is shown contextually on its own key', () => {
    const result = flat(
      appHtml([none, none], undefined, {
        issue: {
          device: 'opaque-device-1',
          message: 'Incorrect PIN. No retry was made.',
        },
      }),
    );
    expect(result.match(/Incorrect PIN\. No retry was made\./g)?.length).toBe(
      1,
    );
    expect(result.match(/role="alert"/g)?.length).toBe(1);
    expect(result).not.toContain('inspection-toast');
  });
  it('a genuine concurrent attempt shows only plain wording', () => {
    const result = flat(
      appHtml([none], undefined, {
        notice: {
          revision: '2',
          tone: 'problem',
          message:
            'Security key operation still finishing. Try again in a moment.',
        },
      }),
    );
    expect(result).toContain(
      'Security key operation still finishing. Try again in a moment.',
    );
    expect(result).toContain('class="inspection-toast problem"');
    expect(result).not.toMatch(INTERNAL);
    expect(result).toContain('Not inspected');
  });
  it('the inventory component renders each activity state on its own', () => {
    for (const [state, text] of [
      ['waiting_for_pin', 'Waiting for PIN…'],
      ['reading_credentials', 'Reading credentials…'],
    ] as const) {
      const result = flat(
        render(Inventory, {
          props: { inspection: none, activity: { state } },
        }).body,
      );
      expect(result).toContain(text);
      expect(result).not.toContain('Not inspected');
    }
  });
});
