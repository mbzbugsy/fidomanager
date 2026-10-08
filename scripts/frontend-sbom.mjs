/** Build-job evidence only: inventory packages contributing modules to emitted JS chunks. */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export function frontendSbom() {
  return {
    name: 'fidomanager-frontend-sbom',
    apply: 'build',
    writeBundle(_options, bundle) {
      const packages = new Map();
      const sha256 = (bytes) =>
        createHash('sha256').update(bytes).digest('hex');
      const assets = {};
      for (const [name, output] of Object.entries(bundle)) {
        assets[name] = sha256(
          output.type === 'chunk' ? output.code : output.source,
        );
        if (output.type !== 'chunk') continue;
        // Vite emits stylesheets as CSS assets, while their Rollup modules can
        // contribute zero rendered JavaScript bytes. Track a stylesheet only
        // when this chunk actually imports emitted CSS.
        const emittedCss = output.viteMetadata?.importedCss?.size > 0;
        for (const [id, module] of Object.entries(output.modules)) {
          if (!id.includes('/node_modules/')) continue;
          const stylesheet =
            /\.(?:css|scss|sass|less|styl|stylus)(?:\?.*)?$/.test(id);
          if (module.renderedLength === 0 && !(stylesheet && emittedCss))
            continue;
          let directory = dirname(id.split('?')[0]);
          while (!existsSync(join(directory, 'package.json'))) {
            const parent = dirname(directory);
            if (parent === directory)
              throw new Error(`No package identity for bundled module: ${id}`);
            directory = parent;
          }
          const pkg = JSON.parse(
            readFileSync(join(directory, 'package.json'), 'utf8'),
          );
          if (typeof pkg.name !== 'string' || typeof pkg.version !== 'string')
            throw new Error(`Malformed bundled package: ${id}`);
          packages.set(`${pkg.name}@${pkg.version}`, {
            name: pkg.name,
            version: pkg.version,
            license: typeof pkg.license === 'string' ? pkg.license : null,
          });
        }
      }
      const directory = resolve('target/macos-package');
      mkdirSync(directory, { recursive: true });
      writeFileSync(
        join(directory, 'frontend-sbom-inputs.json'),
        JSON.stringify(
          {
            pnpm_lock_sha256: sha256(readFileSync('pnpm-lock.yaml')),
            packages: [...packages]
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([, p]) => p),
            assets: Object.fromEntries(
              Object.entries(assets).sort(([a], [b]) => a.localeCompare(b)),
            ),
          },
          null,
          2,
        ) + '\n',
      );
    },
  };
}
