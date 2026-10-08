/** Regression: CSS-only dependencies must not disappear from shipped SBOM. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { frontendSbom } from './frontend-sbom.mjs';

test('includes emitted package CSS even when rendered JS length is zero', () => {
  const before = process.cwd();
  const temp = mkdtempSync(join(tmpdir(), 'fidomanager-css-sbom-'));
  try {
    process.chdir(temp);
    writeFileSync('pnpm-lock.yaml', "lockfileVersion: '9.0'\n");
    const cssId = join(temp, 'node_modules/css-only/dist/theme.css');
    const jsId = join(temp, 'node_modules/unused/dist/unused.js');
    for (const [file, name] of [[cssId, 'css-only'], [jsId, 'unused']]) {
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(join(dirname(dirname(file)), 'package.json'),
        JSON.stringify({ name, version: '1.0.0', license: 'MIT' }));
    }
    const createChunk = (hasCss) => ({
      type: 'chunk', fileName: 'assets/main.js', code: 'console.log(1)',
      viteMetadata: { importedCss: new Set(hasCss ? ['assets/theme.css'] : []) },
      modules: {
        [cssId]: { renderedLength: 0 },
        [jsId]: { renderedLength: 0 },
      },
    });
    const run = (hasCss) => {
      const bundle = {
        'assets/main.js': createChunk(hasCss),
        'index.html': { type: 'asset', fileName: 'index.html', source: '<html></html>' },
        ...(hasCss
          ? { 'assets/theme.css': { type: 'asset', fileName: 'assets/theme.css', source: '.example{}' } }
          : {}),
      };
      frontendSbom().writeBundle({}, bundle);
      return JSON.parse(readFileSync('target/macos-package/frontend-sbom-inputs.json', 'utf8'));
    };

    const withCss = run(true);
    assert.deepEqual(withCss.packages, [{ name: 'css-only', version: '1.0.0', license: 'MIT' }]);
    assert.equal(withCss.assets['assets/theme.css'],
      createHash('sha256').update('.example{}').digest('hex'));

    const withoutCss = run(false);
    assert.deepEqual(withoutCss.packages, []);
    assert.equal('assets/theme.css' in withoutCss.assets, false);
  } finally {
    process.chdir(before);
    rmSync(temp, { recursive: true, force: true });
  }
});
