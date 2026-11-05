/**
 * The rules a packed SDK must pass before `release-npm` stages it (#596). The
 * committed SDKs are read too, so a manifest edit that would fail the release
 * fails here first, in the unit suite.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  changelogAnchor,
  checkFileContent,
  checkFileList,
  checkManifest,
  distTagFor,
  hasReleaseSection,
  latestReleasedVersion,
  parseReleaseTag,
  releaseBody,
  releaseFiles,
  releaseNotes,
  SdkReleaseError,
  UPGRADE_GUIDE_URL,
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

  it('reads the escaped Markdown form of a heading too', () => {
    const escaped = CHANGELOG.replace('## [Unreleased]', '## \\[Unreleased\\]').replace(
      '## [0.1.3]',
      '## \\[0.1.3\\]'
    );
    expect(latestReleasedVersion(escaped)).toBe('0.1.3');
    expect(releaseNotes(escaped, '0.2.0-rc.0')).toBe('### Added\n\n- Coming next.');
  });

  it('as committed, gives the dry run a version every SDK can be stamped with', () => {
    const committed = readFileSync(join(REPO_ROOT, 'CHANGELOG.md'), 'utf8');
    expect(() => distTagFor(latestReleasedVersion(committed))).not.toThrow();
  });
});

const REPOSITORY = 'https://github.com/qauth-labs/qauth';

/** The repository host refuses a longer release body (`HTTP 422: body is too long`). */
const RELEASE_BODY_LIMIT = 125_000;

describe('the draft release', () => {
  it('links a release candidate to the Unreleased section and a release to its own heading', () => {
    expect(changelogAnchor(CHANGELOG, '0.2.0-rc.0')).toBe('unreleased');
    expect(changelogAnchor(CHANGELOG, '0.1.3')).toBe('013---2026-10-21');
    expect(() => changelogAnchor(CHANGELOG, '0.1.4')).toThrow(SdkReleaseError);
  });

  it('gives the escaped Markdown form of a heading the same anchor', () => {
    const escaped = CHANGELOG.replace('## [Unreleased]', '## \\[Unreleased\\]').replace(
      '## [0.1.3]',
      '## \\[0.1.3\\]'
    );
    expect(changelogAnchor(escaped, '0.2.0-rc.0')).toBe('unreleased');
    expect(changelogAnchor(escaped, '0.1.3')).toBe('013---2026-10-21');
  });

  it('writes a short body for a release candidate that links its notes', () => {
    const body = releaseBody(CHANGELOG, '0.2.0-rc.1', REPOSITORY);
    expect(body).toContain('QAuth `0.2.0-rc.1` is a release candidate for 0.2.0.');
    expect(body).toContain(
      '[`Unreleased` section of CHANGELOG.md](https://github.com/qauth-labs/qauth/blob/v0.2.0-rc.1/CHANGELOG.md#unreleased)'
    );
    expect(body).toContain('`release-notes-0.2.0-rc.1.md`');
    expect(body).toContain(`[upgrade guide](${UPGRADE_GUIDE_URL})`);
    expect(body).toContain('staged on npm as `0.2.0-rc.1` (dist-tag `next`)');
    expect(body).not.toContain('Coming next.');
  });

  it('writes a short body for a release that links its own section', () => {
    const body = releaseBody(CHANGELOG, '0.1.3', REPOSITORY);
    expect(body).toContain('QAuth `0.1.3` is a release.');
    expect(body).toContain(
      '[`0.1.3` section of CHANGELOG.md](https://github.com/qauth-labs/qauth/blob/v0.1.3/CHANGELOG.md#013---2026-10-21)'
    );
    expect(body).toContain('`release-notes-0.1.3.md`');
    expect(body).toContain('staged on npm as `0.1.3` (dist-tag `latest`)');
    expect(body).not.toContain('The 0.1.3 fix.');
  });

  it('refuses a version without notes, and an address that is not a repository', () => {
    expect(() => releaseBody(CHANGELOG, '0.1.4', REPOSITORY)).toThrow(SdkReleaseError);
    expect(() => releaseBody(CHANGELOG, '1.0.0', REPOSITORY)).toThrow(SdkReleaseError);
    for (const address of [
      'qauth-labs/qauth',
      'http://github.com/qauth-labs/qauth',
      `${REPOSITORY}/`,
      'https://github.com/qauth-labs',
      'https://github.com/qauth-labs/qauth) [x](https://example.com',
    ]) {
      expect(() => releaseBody(CHANGELOG, '0.1.3', address)).toThrow(SdkReleaseError);
    }
  });

  it('pairs the body with the notes in full', () => {
    expect(releaseFiles(CHANGELOG, '0.2.0-rc.1', REPOSITORY)).toEqual([
      { name: 'release-body.md', text: releaseBody(CHANGELOG, '0.2.0-rc.1', REPOSITORY) },
      { name: 'release-notes-0.2.0-rc.1.md', text: '### Added\n\n- Coming next.\n' },
    ]);
  });

  describe('for the committed CHANGELOG', () => {
    const committed = readFileSync(join(REPO_ROOT, 'CHANGELOG.md'), 'utf8');
    const latest = latestReleasedVersion(committed);
    const candidate = `0.${Number(latest.split('.')[1]) + 1}.0-rc.0`;

    it.each([candidate, latest])('keeps the body of %s far under the limit', (version) => {
      const [body] = releaseFiles(committed, version, REPOSITORY);
      expect(body.text.length).toBeLessThan(RELEASE_BODY_LIMIT / 100);
    });

    it.each([candidate, latest])('attaches the section of %s in full', (version) => {
      const heading = version === candidate ? '## [Unreleased]' : `## [${version}]`;
      const start = committed.indexOf('\n', committed.indexOf(`\n${heading}`) + 1) + 1;
      const end = committed.indexOf('\n## ', start);
      const section = committed.slice(start, end === -1 ? undefined : end).trim();
      expect(section.length).toBeGreaterThan(0);
      const [, notes] = releaseFiles(committed, version, REPOSITORY);
      expect(notes).toEqual({ name: `release-notes-${version}.md`, text: `${section}\n` });
    });
  });

  it('notes.mjs writes both files into the directory it is given', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sdk-release-notes-'));
    try {
      writeFileSync(join(dir, 'CHANGELOG.md'), CHANGELOG);
      const script = join(REPO_ROOT, 'scripts/sdk-release/notes.mjs');
      const run = (...args: string[]) =>
        spawnSync(process.execPath, [script, ...args], { cwd: dir, encoding: 'utf8' });

      expect(run('0.1.3', REPOSITORY, 'out').status).toBe(0);
      expect(readFileSync(join(dir, 'out/release-body.md'), 'utf8')).toBe(
        releaseBody(CHANGELOG, '0.1.3', REPOSITORY)
      );
      expect(readFileSync(join(dir, 'out/release-notes-0.1.3.md'), 'utf8')).toBe(
        '### Fixed\n\n- The 0.1.3 fix.\n'
      );

      const missing = run('0.1.4', REPOSITORY, 'out');
      expect(missing.status).toBe(1);
      expect(missing.stderr).toContain('no `## [0.1.4]` section');
      expect(run('0.1.3').status).toBe(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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
