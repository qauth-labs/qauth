#!/usr/bin/env node
/**
 * Install a packed SDK tarball into an empty project and use it the way a
 * stranger would (#596):
 *
 *   node scripts/sdk-release/smoke.mjs <tarball> <projectRoot> <tsc>
 *
 * 1. `npm install` the tarball alone, so optional peer dependencies are absent.
 *    The root entry must import, and every entry that loads must export exactly
 *    the run-time names `api-report.md` lists for it.
 * 2. Install the optional peers and import every entry again.
 * 3. Type-check a consumer that imports every entry, with `nodenext`
 *    resolution and the library checks on, so broken declarations fail here.
 *
 * It needs network access to the npm registry for the package's dependencies.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { valueExportsFromReport } from './lib.mjs';

const [tarballArg, projectRootArg, tscArg] = process.argv.slice(2);
if (!tarballArg || !projectRootArg || !tscArg) {
  console.error('usage: smoke.mjs <tarball> <projectRoot> <tsc>');
  process.exit(2);
}
const tarball = resolve(tarballArg);
const projectRoot = resolve(projectRootArg);
const tsc = resolve(tscArg);

const dir = mkdtempSync(join(tmpdir(), 'sdk-smoke-'));
const run = (command, args) =>
  execFileSync(command, args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const npm = (...args) => run('npm', ['--no-audit', '--no-fund', '--loglevel=error', ...args]);

writeFileSync(
  join(dir, 'package.json'),
  JSON.stringify({ name: 'sdk-smoke', private: true, type: 'module' }, null, 2)
);
npm('install', '--ignore-scripts', tarball);

const name = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8')).name;
const manifest = JSON.parse(readFileSync(join(dir, 'node_modules', name, 'package.json'), 'utf8'));
const report = valueExportsFromReport(readFileSync(join(projectRoot, 'api-report.md'), 'utf8'));
const specifiers = Object.keys(manifest.exports)
  .filter((entry) => entry !== './package.json')
  .map((entry) => (entry === '.' ? name : `${name}${entry.slice(1)}`));

/** The sorted run-time export names of `specifier`, or the error that stopped the import. */
function importNames(specifier) {
  const script = `const m = await import(${JSON.stringify(specifier)}); console.log(JSON.stringify(Object.keys(m).sort()));`;
  try {
    return { names: JSON.parse(run(process.execPath, ['--input-type=module', '-e', script])) };
  } catch (error) {
    return { error: String(error.stderr || error.message) };
  }
}

const problems = [];
const expectNames = (specifier, result, phase) => {
  const expected = [...(report[specifier] ?? [])].sort();
  if (result.error) {
    problems.push(`${phase}: ${specifier} did not import:\n${result.error}`);
  } else if (JSON.stringify(result.names) !== JSON.stringify(expected)) {
    problems.push(
      `${phase}: ${specifier} exports ${JSON.stringify(result.names)}, api-report.md lists ${JSON.stringify(expected)}`
    );
  } else {
    console.log(`${phase}: ${specifier} — ${result.names.length} exports, as api-report.md lists`);
  }
};

for (const specifier of specifiers) {
  if (!report[specifier]) problems.push(`api-report.md has no section for ${specifier}`);
}

// 1. Without the optional peers.
const optionalPeers = Object.entries(manifest.peerDependenciesMeta ?? {})
  .filter(([, meta]) => meta?.optional)
  .map(([peer]) => peer);
for (const specifier of specifiers) {
  const result = importNames(specifier);
  const missingPeer = optionalPeers.find((peer) => result.error?.includes(`'${peer}'`));
  if (specifier !== name && missingPeer) {
    console.log(`without optional peers: ${specifier} needs ${missingPeer}, as declared`);
    continue;
  }
  expectNames(specifier, result, 'without optional peers');
}

// 2. With them.
if (optionalPeers.length > 0) {
  npm(
    'install',
    '--ignore-scripts',
    ...optionalPeers.map((peer) => `${peer}@${manifest.peerDependencies[peer]}`)
  );
  for (const specifier of specifiers) expectNames(specifier, importNames(specifier), 'with peers');
}

// 3. Types, as a nodenext consumer sees them.
npm('install', '--ignore-scripts', '@types/node@^22');
writeFileSync(
  join(dir, 'consumer.ts'),
  specifiers
    .map(
      (specifier, i) =>
        `import * as entry${i} from ${JSON.stringify(specifier)};\nexport const names${i} = Object.keys(entry${i});`
    )
    .join('\n') + '\n'
);
writeFileSync(
  join(dir, 'tsconfig.json'),
  JSON.stringify(
    {
      compilerOptions: {
        target: 'ES2022',
        module: 'nodenext',
        moduleResolution: 'nodenext',
        strict: true,
        noEmit: true,
        skipLibCheck: false,
        types: ['node'],
      },
      files: ['consumer.ts'],
    },
    null,
    2
  )
);
try {
  run(process.execPath, [tsc, '-p', 'tsconfig.json']);
  console.log('types: a nodenext consumer type-checks against every entry');
} catch (error) {
  problems.push(`types: the consumer does not type-check:\n${error.stdout}${error.stderr}`);
}

if (problems.length > 0) {
  console.error(`\n${problems.length} problem(s):`);
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}
console.log(`\n${name}: installs, imports and type-checks from the tarball.`);
