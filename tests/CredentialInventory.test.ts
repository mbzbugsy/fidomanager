import { describe, it, expect, vi } from 'vitest';
import ts from 'typescript';
import {
  applyDiscovery,
  INTEGRITY_FAILURE_MESSAGE,
  type DiscoveryResult,
  type DiscoveryView,
} from '../src/discovery';
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
const discoveryModule = `data:text/javascript;base64,${Buffer.from(ts.transpileModule(readFileSync(new URL('../src/discovery.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText).toString('base64')}`;
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
    'let discovery: DiscoveryView<AuthenticatorList>',
    'export let discovery: DiscoveryView<AuthenticatorList>',
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
const resolvedAppCode = appCode.replace(
  "'./discovery'",
  `'${discoveryModule}'`,
);
const App = (
  await import(
    `data:text/javascript;base64,${Buffer.from(resolvedAppCode).toString('base64')}`
  )
).default;
const appHtml = (
  inspections: InspectionDisplay[],
  boogoocypher?: 'checking' | 'online' | 'offline',
  activity?: Partial<InspectionActivity>,
  discoveryState:
    'fresh' | 'settling' | 'unavailable' | 'integrity_failure' = 'fresh',
  generations: string[] = [],
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
                generation: null,
                phase: null,
                issue: null,
                notice: null,
                ...activity,
              },
            },
          }
        : {}),
      discovery: {
        state: discoveryState,
        list: {
          enumerationEpoch: '1',
          devices: inspections.map((inspection, i) => ({
            inspection,
            handle: `opaque-device-${i}`,
            generation: generations[i] ?? '1',
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
        credentialFingerprint: '001122aabbcc',
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
    expect(result.match(/Fingerprint: 001122aabbcc/g)?.length).toBe(3);
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
        generation: '1',
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
        generation: '1',
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
        generation: '1',
        phase: 'waiting_for_pin',
      }),
    );
    expect(result).not.toContain('Waiting for PIN…');
    expect(result).toContain('Not inspected');
  });
  it('cached issues for the old generation do not appear on the same handle in a newer generation', () => {
    for (const message of [
      'Incorrect PIN. No retry was made.',
      'The PIN prompt timed out. No retry was made.',
    ]) {
      const activity = {
        issue: { device: 'opaque-device-0', generation: '1', message },
      };
      const same = flat(appHtml([none, inspected(1)], undefined, activity));
      expect(same).toContain(message);
      const newer = flat(
        appHtml([none, inspected(1)], undefined, activity, 'fresh', ['2', '1']),
      );
      expect(newer).not.toContain(message);
      expect(newer.match(/class="device-card"/g)?.length).toBe(2);
      expect(newer).toContain('Not inspected');
      expect(newer).toContain('example.com');
      expect(newer).not.toContain(
        'Security key scanning is temporarily unavailable.',
      );
    }
  });
  it('cached active phases cannot hide the inventory of a newer generation', () => {
    for (const phase of ['waiting_for_pin', 'reading_credentials'] as const) {
      const result = flat(
        appHtml(
          [inspected(1)],
          undefined,
          {
            device: 'opaque-device-0',
            generation: '1',
            phase,
          },
          'fresh',
          ['2'],
        ),
      );
      expect(result).not.toContain('Waiting for PIN…');
      expect(result).not.toContain('Reading credentials…');
      expect(result).toContain('example.com');
      expect(result).toContain('class="device-card"');
    }
  });
  it('matches activity on the exact newer generation without affecting the other key', () => {
    const message = 'Incorrect PIN. No retry was made.';
    const result = flat(
      appHtml(
        [none, inspected(1)],
        undefined,
        {
          issue: { device: 'opaque-device-0', generation: '2', message },
        },
        'fresh',
        ['2', '1'],
      ),
    );
    expect(result.match(/Incorrect PIN/g)?.length).toBe(1);
    expect(result).toContain('example.com');
    expect(result.match(/class="device-card"/g)?.length).toBe(2);
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
          generation: '1',
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

describe('typed discovery continuity', () => {
  const flat = (text: string) =>
    text.replace(/<!--.*?-->/g, '').replace(/\s+/g, ' ');
  const none: InspectionDisplay = { state: 'not_inspected' };
  const forbidden =
    /workflow|admission|cooldown|recovery barrier|acquisition|binding|puat|worker|snapshot/i;
  // Execute the actual polling function with a fake parameter-free IPC and scheduler.
  const pollBody = appSource.match(
    /  async function refreshDevices[\s\S]*?(?=  function refreshNow)/,
  )?.[0];
  if (!pollBody) throw new Error('Missing actual App polling function');
  const pollModule = ts.transpileModule(
    `
    let discovery = initial;
    let refreshing = false, stopped = false, manualScanning = false, lastScan = null, timer = null;
    const pollDelayMs = 1000;
    ${pollBody}
    return { refresh: refreshDevices, view: () => discovery };
  `,
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } },
  ).outputText;
  function harness(results: (DiscoveryResult<string[]> | Error)[]) {
    const callbacks: (() => Promise<void>)[] = [];
    const invoke = vi.fn(async () => {
      const result = results.shift();
      if (result instanceof Error) throw result;
      if (!result) throw new Error('No IPC result');
      return result;
    });
    const create = new Function(
      'invoke',
      'applyDiscovery',
      'setTimeout',
      'initial',
      pollModule,
    );
    const poll = create(
      invoke,
      applyDiscovery,
      (callback: () => Promise<void>) => {
        callbacks.push(callback);
        return 1;
      },
      { state: 'starting', list: null },
    ) as { refresh: () => Promise<void>; view: () => DiscoveryView<string[]> };
    return { poll, invoke, callbacks };
  }
  it('keeps cards and progress exactly unchanged and silent while settling', () => {
    for (const phase of [
      null,
      'waiting_for_pin',
      'reading_credentials',
    ] as const) {
      const activity = { device: 'opaque-device-0', generation: '1', phase };
      const fresh = flat(appHtml([inspected(1), none], undefined, activity));
      const settling = flat(
        appHtml([inspected(1), none], undefined, activity, 'settling'),
      );
      expect(settling).toBe(fresh);
      expect(settling.match(/class="device-card"/g)?.length).toBe(2);
      expect(settling).toMatch(/Native service <strong>online</);
      expect(settling).not.toContain('role="alert"');
      expect(settling).not.toContain('Refreshing');
      expect(settling).not.toMatch(forbidden);
    }
  });
  it('genuine failure hides stale cards and uses only friendly wording', () => {
    const result = flat(
      appHtml([inspected(1)], undefined, undefined, 'unavailable'),
    );
    expect(result).not.toContain('class="device-card"');
    expect(result).not.toContain('example.com');
    expect(result).toContain(
      'Security key scanning is temporarily unavailable.',
    );
    expect(result).toContain(
      'The device list will return when scanning succeeds.',
    );
    expect(result).toMatch(/Native service <strong>attention</);
    expect(result).toContain('role="alert"');
    expect(result).not.toMatch(forbidden);
  });
  it('actual polling retains only explicit settling and continues to fresh data', async () => {
    const initial = ['Key A'];
    const renewed = ['Key A refreshed', 'Key B'];
    const { poll, invoke, callbacks } = harness([
      { state: 'fresh', list: initial },
      { state: 'settling' },
      { state: 'fresh', list: renewed },
    ]);
    await poll.refresh();
    expect(poll.view().list).toBe(initial);
    await callbacks.shift()?.();
    expect(poll.view()).toEqual({ state: 'settling', list: initial });
    await callbacks.shift()?.();
    expect(poll.view()).toEqual({ state: 'fresh', list: renewed });
    expect(callbacks).toHaveLength(1);
    expect(invoke.mock.calls).toEqual([
      ['list_authenticators'],
      ['list_authenticators'],
      ['list_authenticators'],
    ]);
  });
  it('actual polling clears genuine unavailability and can recover', async () => {
    const { poll, callbacks } = harness([
      { state: 'fresh', list: ['old'] },
      { state: 'unavailable' },
      { state: 'fresh', list: ['new'] },
    ]);
    await poll.refresh();
    await callbacks.shift()?.();
    expect(poll.view()).toEqual({ state: 'unavailable', list: null });
    await callbacks.shift()?.();
    expect(poll.view()).toEqual({ state: 'fresh', list: ['new'] });
  });
  it('integrity failure shows only the fixed category and offers no retry or controls', () => {
    const result = flat(
      appHtml([inspected(1)], undefined, undefined, 'integrity_failure'),
    );
    expect(result).toContain(INTEGRITY_FAILURE_MESSAGE);
    expect(INTEGRITY_FAILURE_MESSAGE).toBe(
      'Fido Manager could not verify its own components. Reinstall it from the official release.',
    );
    expect(result).toContain('Security key functions are disabled.');
    expect(result).toMatch(/Native service <strong>disabled</);
    expect(result).toContain('role="alert"');
    expect(result).not.toContain('class="device-card"');
    expect(result).not.toContain('example.com');
    expect(result).not.toContain('Use Scan now to retry.');
    expect(result).toMatch(
      /<button[^>]*disabled[^>]*>[^<]*<svg[\s\S]*?Scan now/,
    );
    expect(result).not.toMatch(forbidden);
    expect(result).not.toMatch(
      /team|cdhash|requirement|certificate|signature|release-worker|build.?id|osstatus|developer id|verification mode/i,
    );
  });
  it('actual polling keeps an integrity failure and drops every card', async () => {
    const { poll, callbacks } = harness([
      { state: 'fresh', list: ['old'] },
      { state: 'integrity_failure' },
      new Error('IPC failure'),
    ]);
    await poll.refresh();
    await callbacks.shift()?.();
    expect(poll.view()).toEqual({ state: 'integrity_failure', list: null });
    await callbacks.shift()?.();
    expect(poll.view()).toEqual({ state: 'integrity_failure', list: null });
    expect(
      applyDiscovery(
        { state: 'fresh', list: ['x'] },
        {
          state: 'integrity_failure',
        },
      ),
    ).toEqual({ state: 'integrity_failure', list: null });
  });
  it('IPC errors containing implementation text never become settling or UI text', async () => {
    const { poll, callbacks } = harness([
      { state: 'fresh', list: ['old'] },
      new Error('RestartBackoff: the native worker is restarting'),
    ]);
    await poll.refresh();
    await callbacks.shift()?.();
    expect(poll.view()).toEqual({ state: 'unavailable', list: null });
    expect(callbacks).toHaveLength(1);
  });
  it('inspection phases, silent settling and refreshed inventory keep cards continuous', () => {
    const steps = [
      appHtml([none, inspected(1)], undefined, {
        device: 'opaque-device-0',
        generation: '1',
        phase: 'waiting_for_pin',
      }),
      appHtml([none, inspected(1)], undefined, {
        device: 'opaque-device-0',
        generation: '1',
        phase: 'reading_credentials',
      }),
      appHtml(
        [none, inspected(1)],
        undefined,
        {
          device: 'opaque-device-0',
          generation: '1',
          phase: 'reading_credentials',
        },
        'settling',
      ),
      appHtml([inspected(2), inspected(1)], undefined, {
        notice: {
          revision: '1',
          tone: 'success',
          message: 'Credentials refreshed',
        },
      }),
    ].map(flat);
    expect(steps[0]).toContain('Waiting for PIN…');
    expect(steps[1]).toContain('Reading credentials…');
    expect(steps[2]).toBe(steps[1]);
    expect(steps[3]).toContain('Credentials refreshed');
    for (const step of steps) {
      expect(step.match(/class="device-card"/g)?.length).toBe(2);
      expect(step).not.toContain('role="alert"');
      expect(step).not.toMatch(forbidden);
    }
  });
  it('cancel followed by settling is quiet and fresh state returns normally', () => {
    const quiet = flat(appHtml([none, inspected(1)], undefined, {}));
    expect(flat(appHtml([none, inspected(1)], undefined, {}, 'settling'))).toBe(
      quiet,
    );
    expect(quiet).not.toContain('inspection-toast');
    expect(quiet).not.toContain('role="alert"');
    expect(quiet).toContain('Not inspected');
  });
});

describe('operation-local issues during settling', () => {
  it('wrong PIN, blocked PIN and timeout update one card without clearing any card', () => {
    const none: InspectionDisplay = { state: 'not_inspected' };
    for (const message of [
      'Incorrect PIN. No retry was made.',
      'The security key PIN is blocked.',
      'Credential inspection timed out. Try again.',
    ]) {
      const activity = {
        issue: { device: 'opaque-device-0', generation: '1', message },
      };
      const fresh = appHtml([none, inspected(1)], undefined, activity);
      const settling = appHtml(
        [none, inspected(1)],
        undefined,
        activity,
        'settling',
      );
      expect(settling).toBe(fresh);
      expect(settling.match(/class="device-card"/g)?.length).toBe(2);
      expect(settling).toContain(message);
      expect(settling).toContain('example.com');
      expect(settling).not.toContain(
        'Security key scanning is temporarily unavailable.',
      );
      expect(settling).not.toContain('inspection-toast');
    }
  });
});

describe('credential deletion UI eligibility and presentation', () => {
  it('one delete click invokes only the typed callback with the opaque tuple', () => {
    // Execute the actual button expression and component handler without a DOM or native IPC.
    const handler = source.match(
      /  function handleDelete\([\s\S]*?(?=  type Assessment)/,
    )?.[0];
    const onclick = source.match(/onclick=\{([\s\S]*?)\}/)?.[1];
    if (!handler || !onclick)
      throw new Error('Missing actual delete click handler');
    const ondelete = vi.fn();
    const dispatch = vi.fn();
    const inventory = {
      deviceHandle: 'opaque-device',
      deviceGeneration: '2',
      epoch: 'opaque-epoch',
    };
    const credential = { handle: 'opaque-credential' };
    const click = new Function(
      'ondelete',
      'dispatch',
      'inventory',
      'credential',
      ts.transpileModule(`${handler}\nreturn (${onclick});`, {
        compilerOptions: { target: ts.ScriptTarget.ES2022 },
      }).outputText,
    )(ondelete, dispatch, inventory, credential) as () => void;

    click();

    expect(ondelete).toHaveBeenCalledExactlyOnceWith({
      displayDeviceHandle: 'opaque-device',
      deviceGeneration: '2',
      enumerationEpoch: 'opaque-epoch',
      credentialHandle: 'opaque-credential',
    });
    expect(dispatch).not.toHaveBeenCalled();
    expect(appSource.match(/ondelete=\{handleDelete\}/g)).toHaveLength(1);
    expect(appSource).not.toContain('on:delete=');
    expect(source).not.toContain('createEventDispatcher');
  });

  it('shows Delete action only for credentials that can be resolved for mutation', () => {
    // Eligible complete inventory with no RP issue
    const eligible = html(
      build('complete', { kind: 'exact', value: 1 }, [
        rp('example.com', [{ userName: 'Alice', displayName: 'Alice A' }]),
      ]),
    );
    expect(eligible).toContain('credential-delete-button');
    expect(eligible).toContain('>Delete</button>');
    expect(eligible).toContain('aria-label="Delete passkey"');

    // RP with issue (e.g. timeout) cannot resolve for mutation -> no Delete button
    const rpIssue = html(
      build('complete', { kind: 'exact', value: 1 }, [
        rp(
          'example.com',
          [{ userName: 'Alice', displayName: 'Alice A' }],
          'timeout' as any,
        ),
      ]),
    );
    expect(rpIssue).not.toContain('credential-delete-button');
  });

  it('inconsistent inventory does not expose an actionable mutation path', () => {
    const inconsistent = html(
      build('inconsistent', { kind: 'unknown' }, [
        rp('example.com', [{ userName: 'Alice', displayName: 'Alice A' }]),
      ]),
    );
    expect(inconsistent).not.toContain('credential-delete-button');
    expect(inconsistent).not.toContain('>Delete</button>');
  });

  it('incomplete inventory can target an exact listed credential but shows the incomplete warning', () => {
    const incomplete = html(
      build('incomplete', { kind: 'at_least', value: 1 }, [
        rp('example.com', [{ userName: 'Alice', displayName: 'Alice A' }]),
      ]),
    );
    expect(incomplete).toContain('credential-delete-button');
    expect(incomplete).toContain('>Delete</button>');
    expect(incomplete).toContain('Some credentials could not be read');
  });

  it('delete button is disabled when device activity is not idle', () => {
    const idleHtml = render(Inventory, {
      props: {
        inspection: build('complete', { kind: 'exact', value: 1 }, [
          rp('example.com', [{ userName: 'Alice', displayName: 'Alice A' }]),
        ]),
        activity: { state: 'idle' },
      },
    }).body;
    expect(idleHtml).toContain('class="credential-delete-button"');
    expect(idleHtml).not.toContain('disabled=""');

    const busyHtml = render(Inventory, {
      props: {
        inspection: build('complete', { kind: 'exact', value: 1 }, [
          rp('example.com', [{ userName: 'Alice', displayName: 'Alice A' }]),
        ]),
        activity: { state: 'attention', message: 'Incorrect PIN.' },
      },
    }).body;
    expect(busyHtml).toContain('disabled=""');
  });

  it('renderer request carries only opaque presentation tuple and no raw secrets', () => {
    const tuple = {
      displayDeviceHandle: 'opaque-dev-123',
      deviceGeneration: '1',
      enumerationEpoch: 'epoch-456',
      credentialHandle: 'cred-789',
    };
    const keys = Object.keys(tuple).sort();
    expect(keys).toEqual([
      'credentialHandle',
      'deviceGeneration',
      'displayDeviceHandle',
      'enumerationEpoch',
    ]);
    const forbidden = [
      'credentialId',
      'userId',
      'rpHash',
      'nativeHandle',
      'worker',
      'pin',
      'permit',
    ];
    for (const f of forbidden) {
      expect(tuple).not.toHaveProperty(f);
    }
  });
});
