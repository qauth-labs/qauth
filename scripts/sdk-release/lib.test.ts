/**
 * The rules a packed SDK must pass before `release-npm` stages it (#596). The
 * committed SDKs are read too, so a manifest edit that would fail the release
 * fails here first, in the unit suite.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  checkFileContent,
  checkFileList,
  checkManifest,
  distTagFor,
  hasReleaseSection,
  latestReleasedVersion,
  parseReleaseTag,
  releaseNotes,
  SdkReleaseError,
  valueExportsFromReport,
} from './lib.mjs';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const GOOD_FILES = [
  'package/package.json',
  'package/README.md',
  'package/LICENSE',
  'package/dist/index.js',
  'package/dist/index.d.ts',
  'package/dist/lib/core.js',
  'package/dist/lib/core.d.ts',
];

/** A published manifest as `pnpm pack` writes it, with publishConfig applied. */
function goodManifest(overrides: Record<string, unknown> = {}) {
  return {
    name: '@qauth-labs/resource-guard',
    version: '0.1.0',
    type: 'module',
    license: 'Apache-2.0',
    engines: { node: '>=22' },
    repository: {
      type: 'git',
      url: 'git+https://example.com/qauth.git',
      directory: 'libs/sdk/resource-guard',
    },
    homepage: 'https://docs.qauth.dev/',
    main: './dist/index.js',
    types: './dist/index.d.ts',
    files: ['dist', 'README.md', 'LICENSE'],
    exports: {
      '.': { types: './dist/index.d.ts', import: './dist/index.js' },
      './fastify': { types: './dist/fastify.d.ts', import: './dist/fastify.js' },
      './package.json': './package.json',
    },
    dependencies: { jose: '^6.2.12' },
    peerDependencies: { fastify: '^5.12.7' },
    peerDependenciesMeta: { fastify: { optional: true } },
    ...overrides,
  };
}

const CONTEXT = { projectRoot: 'libs/sdk/resource-guard', version: '0.1.0' };

describe('distTagFor', () => {
  it('sends a release to latest and a release candidate to next', () => {
    expect(distTagFor('0.1.0')).toBe('latest');
    expect(distTagFor('0.2.0-rc.3')).toBe('next');
  });

  it('refuses 1.x before the stability review, and any other shape', () => {
    expect(() => distTagFor('1.0.0')).toThrow(SdkReleaseError);
    expect(() => distTagFor('0.1.0-beta.1')).toThrow(SdkReleaseError);
    expect(() => distTagFor('v0.1.0')).toThrow(SdkReleaseError);
    expect(() => distTagFor('0.01.0')).toThrow(SdkReleaseError);
  });
});

describe('parseReleaseTag', () => {
  it("reads the version from QAuth's release tag", () => {
    expect(parseReleaseTag('v0.2.0')).toBe('0.2.0');
    expect(parseReleaseTag('v0.2.0-rc.1')).toBe('0.2.0-rc.1');
  });

  it('refuses an SDK-style tag, a tag without the v and 1.x', () => {
    expect(() => parseReleaseTag('resource-guard@0.1.0')).toThrow(SdkReleaseError);
    expect(() => parseReleaseTag('0.2.0')).toThrow(SdkReleaseError);
    expect(() => parseReleaseTag('v1.0.0')).toThrow(/stays on 0\.x/);
  });
});

const CHANGELOG = `# Changelog

## [Unreleased]

### Added

- Coming next.

## [0.1.3] - 2026-10-21

### Fixed

- The 0.1.3 fix.

## [0.1.2] - 2026-10-21

- The 0.1.2 fix.

[0.1.3]: https://example.com/compare/v0.1.2...v0.1.3
`;

describe("QAuth's CHANGELOG", () => {
  it('names the newest released version, never Unreleased', () => {
    expect(latestReleasedVersion(CHANGELOG)).toBe('0.1.3');
    expect(() => latestReleasedVersion('# Changelog\n\n## [Unreleased]\n')).toThrow(
      SdkReleaseError
    );
  });

  it('knows which versions have a section', () => {
    expect(hasReleaseSection(CHANGELOG, '0.1.2')).toBe(true);
    expect(hasReleaseSection(CHANGELOG, '0.1.4')).toBe(false);
  });

  it('gives a release its own section and a release candidate the Unreleased one', () => {
    expect(releaseNotes(CHANGELOG, '0.1.3')).toBe('### Fixed\n\n- The 0.1.3 fix.');
    expect(releaseNotes(CHANGELOG, '0.2.0-rc.0')).toBe('### Added\n\n- Coming next.');
    expect(() => releaseNotes(CHANGELOG, '0.1.4')).toThrow(SdkReleaseError);
  });

  it('as committed, gives the dry run a version every SDK can be stamped with', () => {
    const committed = readFileSync(join(REPO_ROOT, 'CHANGELOG.md'), 'utf8');
    expect(() => distTagFor(latestReleasedVersion(committed))).not.toThrow();
  });
});

describe('checkFileList', () => {
  it('passes the manifest, README, LICENSE and compiled dist', () => {
    expect(checkFileList(GOOD_FILES)).toEqual([]);
  });

  it.each([
    ['package/.env', 'an environment file'],
    ['package/dist/.env.production', 'an environment file'],
    ['package/dist/core.test.js', 'a test file'],
    ['package/dist/lib/core.spec.d.ts', 'a test file'],
    ['package/dist/index.js.map', 'a source map'],
    ['package/src/index.ts', 'a TypeScript source'],
    ['package/tsconfig.json', 'not in the allowed set'],
    ['package/examples/memory-mcp/server.ts', 'a TypeScript source'],
  ])('fails a tarball holding %s', (file, reason) => {
    expect(checkFileList([...GOOD_FILES, file])).toEqual([expect.stringContaining(reason)]);
  });

  it('fails a tarball without build output or a LICENSE', () => {
    const problems = checkFileList(['package/package.json', 'package/README.md']);
    expect(problems).toContainEqual(expect.stringContaining('LICENSE is missing'));
    expect(problems).toContainEqual(expect.stringContaining('was the npm build run'));
  });
});

describe('checkFileContent', () => {
  it('passes ordinary compiled code', () => {
    expect(
      checkFileContent('package/dist/index.js', "export const a = '/.well-known/x';\n")
    ).toEqual([]);
  });

  it('fails a private key, a source-map pointer and a build-machine path', () => {
    expect(
      checkFileContent('f.js', '-----BEGIN PRIVATE KEY-----\nMC4CAQ\n-----END PRIVATE KEY-----')
    ).toEqual([expect.stringContaining('private key')]);
    expect(checkFileContent('f.js', '//# sourceMappingURL=f.js.map')).toEqual([
      expect.stringContaining('source map'),
    ]);
    expect(checkFileContent('f.js', "const p = '/home/runner/work/x';")).toEqual([
      expect.stringContaining('build-machine path'),
    ]);
  });
});

describe('checkManifest', () => {
  it('passes a complete published manifest', () => {
    expect(checkManifest(goodManifest(), CONTEXT)).toEqual([]);
  });

  it.each([
    [{ version: '0.1.1' }, 'the tag says 0.1.0'],
    [{ private: true }, 'private: true'],
    [{ type: 'commonjs' }, 'type must be "module"'],
    [{ license: 'MIT' }, 'license must be Apache-2.0'],
    [{ engines: undefined }, 'engines.node'],
    [{ main: './src/index.ts' }, 'main must point into ./dist'],
    [{ exports: { '.': './src/index.ts' } }, 'exports must map'],
    [{ dependencies: { '@qauth-labs/shared-errors': '0.0.0' } }, 'depends on no workspace package'],
    [{ dependencies: { jose: 'catalog:' } }, 'was not resolved by pnpm pack'],
    [{ peerDependencies: {} }, 'peerDependenciesMeta.fastify has no peerDependencies entry'],
  ])('fails %j', (override, message) => {
    expect(checkManifest(goodManifest(override), CONTEXT)).toContainEqual(
      expect.stringContaining(message)
    );
  });
});

describe('valueExportsFromReport', () => {
  it('keeps run-time names per entry and leaves out type-only ones', () => {
    const report = '## `@x/a`\n\n- `A`\n- `B` (type)\n\n## `@x/a/sub`\n\n- `c`\n';
    expect(valueExportsFromReport(report)).toEqual({ '@x/a': ['A'], '@x/a/sub': ['c'] });
  });
});

describe('the committed SDKs', () => {
  const sdks = readdirSync(join(REPO_ROOT, 'libs/sdk'), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);

  it('include resource-guard', () => {
    expect(sdks).toContain('resource-guard');
  });

  it.each(sdks)('%s is publishable as written and has an API report', (sdk) => {
    const root = join(REPO_ROOT, 'libs/sdk', sdk);
    const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    // What `pnpm pack` publishes: publishConfig over the workspace manifest.
    const { publishConfig, ...rest } = manifest;
    const published = { ...rest, ...publishConfig };
    delete published.access;
    // Catalog ranges are resolved at pack time; check the rest as published.
    for (const field of ['dependencies', 'peerDependencies']) {
      for (const name of Object.keys(published[field] ?? {})) published[field][name] = '^1.0.0';
    }
    expect(
      checkManifest(published, { projectRoot: `libs/sdk/${sdk}`, version: manifest.version })
    ).toEqual([]);
    expect(
      Object.keys(valueExportsFromReport(readFileSync(join(root, 'api-report.md'), 'utf8')))
    ).toEqual(expect.arrayContaining([manifest.name]));
  });
});
