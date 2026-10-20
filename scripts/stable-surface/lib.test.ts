/**
 * Guard for the stable-surface check (#451): the registry, the stability tags,
 * the comparison inputs, the release-tag rules and the approvals, and the
 * whole pipeline over a fixture repository that registers a second surface.
 *
 * oasdiff itself is not run here — the unit suite stays offline. Its rules are
 * pinned by `node scripts/stable-surface/check.mjs --self-test`, which the
 * stable-surface CI job runs over `__fixtures__/break-rules/cases.json`; this
 * file only checks that every one of those fixtures still applies to its base.
 * The pipeline tests below use a small structural differ in oasdiff's output
 * shape instead.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import {
  annotations,
  applyJsonPatch,
  approvalTemplate,
  checkStabilityTags,
  compareReleases,
  exitCodeOf,
  InputError,
  isRepoRelativePath,
  LEVEL,
  listOperations,
  matchApprovals,
  parseRegistry,
  parseReleaseTag,
  prepareOpenApiPair,
  RAISED_TO_BREAK,
  renderSummary,
  runBreakRuleCase,
  runChecks,
  selectBaselineTag,
  severityLevelsFile,
  validateApprovals,
  withoutOperations,
  wrapJsonSchema,
} from './lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..');
const FIXTURES = join(HERE, '__fixtures__');

const readJson = (path: string) => JSON.parse(readFileSync(path, 'utf8'));

const workspaces: string[] = [];
afterAll(() => {
  for (const dir of workspaces) rmSync(dir, { recursive: true, force: true });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- fixture documents are free-form JSON
type Doc = Record<string, any>;

function op(stability?: string, extra: Doc = {}): Doc {
  return {
    ...(stability === undefined ? {} : { 'x-qauth-stability': stability }),
    responses: { 200: { description: 'ok' } },
    ...extra,
  };
}

function api(paths: Doc): Doc {
  return { openapi: '3.1.0', info: { title: 't', version: '1' }, paths };
}

function surface(overrides: Doc = {}): Doc {
  return {
    name: 'openapi',
    format: 'openapi',
    generator: 'gen',
    path: 'stable-surface/openapi.json',
    stability: 'stable',
    ...overrides,
  };
}

describe('the registry (stable-surface/surfaces.json)', () => {
  it("accepts the repository's own registry, whose first entry is the OpenAPI document", () => {
    const surfaces = parseRegistry(readJson(join(REPO_ROOT, 'stable-surface', 'surfaces.json')));
    expect(surfaces[0]).toMatchObject({
      name: 'openapi',
      format: 'openapi',
      path: 'stable-surface/openapi.json',
      stability: 'stable',
    });
    expect(surfaces.find((s) => s.maximalOf === 'openapi')?.path).toBe(
      'apps/docs-site/public/openapi.json'
    );
  });

  it('defaults formerPaths to an empty list', () => {
    expect(parseRegistry({ surfaces: [surface()] })[0].formerPaths).toEqual([]);
  });

  it.each([
    ['an unknown key', [surface({ stabilty: 'stable' })], 'unknown key "stabilty"'],
    ['a duplicate name', [surface(), surface({ path: 'b.json' })], 'used twice'],
    ['a duplicate path', [surface(), surface({ name: 'other' })], 'registered by both'],
    ['a path outside the repository', [surface({ path: '../x.json' })], 'repository-relative'],
    ['an absolute path', [surface({ path: '/etc/x.json' })], 'repository-relative'],
    ['a bad stability', [surface({ stability: 'beta' })], '"stability"'],
    ['a json-schema surface without a role', [surface({ format: 'json-schema' })], '"role"'],
    ['a role on an openapi surface', [surface({ role: 'output' })], 'json-schema surfaces only'],
    [
      'a maximal export of itself',
      [surface({ maximalOf: 'openapi', stability: 'experimental' })],
      '"maximalOf" must name another openapi surface',
    ],
    [
      'a stable maximal export',
      [surface(), surface({ name: 'max', path: 'm.json', maximalOf: 'openapi' })],
      'must be "experimental"',
    ],
    ['an empty generator', [surface({ generator: ' ' })], '"generator"'],
  ])('refuses %s', (_label, surfaces, message) => {
    expect(() => parseRegistry({ surfaces })).toThrow(InputError);
    expect(() => parseRegistry({ surfaces })).toThrow(message);
  });

  it('refuses a file without a surfaces array', () => {
    expect(() => parseRegistry({ entries: [] })).toThrow('"surfaces" array');
  });

  it('knows a repository-relative path', () => {
    expect(isRepoRelativePath('a/b.json')).toBe(true);
    for (const bad of ['', 'a/../b', './a', 'a//b', 'C:/a', 'a\\b']) {
      expect(isRepoRelativePath(bad)).toBe(false);
    }
  });
});

describe('x-qauth-stability on every operation', () => {
  const registry = [surface()];

  it('fails an operation without x-qauth-stability', () => {
    const docs = new Map([['openapi', api({ '/a': { get: op('stable'), post: op() } })]]);
    const { problems } = checkStabilityTags(registry, docs);
    expect(problems).toEqual([
      {
        surface: 'openapi',
        file: 'stable-surface/openapi.json',
        message: 'POST /a has no x-qauth-stability',
      },
    ]);
  });

  it('fails a value other than stable or experimental', () => {
    const docs = new Map([['openapi', api({ '/a': { get: op('beta') } })]]);
    expect(checkStabilityTags(registry, docs).problems[0].message).toContain(
      'expected stable or experimental'
    );
  });

  it('counts the tagged operations', () => {
    const docs = new Map([
      ['openapi', api({ '/a': { get: op('stable'), post: op('experimental') } })],
    ]);
    const { problems, counts } = checkStabilityTags(registry, docs);
    expect(problems).toEqual([]);
    expect(counts.get('openapi')).toEqual({ stable: 1, experimental: 1 });
  });

  describe('in a maximal export', () => {
    const withMaximal = [
      surface(),
      surface({ name: 'max', path: 'max.json', stability: 'experimental', maximalOf: 'openapi' }),
    ];
    const defaults = api({ '/a': { get: op('stable') } });

    it('requires an operation only a switch registers to be experimental', () => {
      const docs = new Map([
        ['openapi', defaults],
        ['max', api({ '/a': { get: op('stable') }, '/wallet': { post: op('stable') } })],
      ]);
      expect(checkStabilityTags(withMaximal, docs).problems.map((p) => p.message)).toEqual([
        'POST /wallet is registered only behind a switch (it is not in openapi), so it must be x-qauth-stability: experimental',
      ]);
    });

    it('accepts it when it is experimental', () => {
      const docs = new Map([
        ['openapi', defaults],
        ['max', api({ '/a': { get: op('stable') }, '/wallet': { post: op('experimental') } })],
      ]);
      expect(checkStabilityTags(withMaximal, docs).problems).toEqual([]);
    });

    it('requires an operation both exports have to carry the same tag', () => {
      const docs = new Map([
        ['openapi', defaults],
        ['max', api({ '/a': { get: op('experimental') } })],
      ]);
      expect(checkStabilityTags(withMaximal, docs).problems[0].message).toBe(
        'GET /a is experimental here but stable in openapi'
      );
    });
  });

  it('passes on both committed exports of the auth server', () => {
    const surfaces = parseRegistry(readJson(join(REPO_ROOT, 'stable-surface', 'surfaces.json')));
    const docs = new Map(surfaces.map((s) => [s.name, readJson(join(REPO_ROOT, s.path))]));
    const { problems, counts } = checkStabilityTags(surfaces, docs);
    expect(problems).toEqual([]);
    expect(counts.get('openapi')?.stable).toBeGreaterThan(0);
  });
});

describe('the documents the break check compares', () => {
  it('lists operations as METHOD /path', () => {
    const keys = listOperations(api({ '/a': { get: op(), post: op(), parameters: [] } })).map(
      (o) => o.key
    );
    expect(keys).toEqual(['GET /a', 'POST /a']);
  });

  it('drops a path once its last operation is gone', () => {
    const doc = withoutOperations(
      api({ '/a': { get: op('experimental') }, '/b': { get: op() } }),
      (key) => key.startsWith('GET /a')
    );
    expect(Object.keys(doc.paths)).toEqual(['/b']);
  });

  it('leaves experimental operations out of both sides', () => {
    const doc = api({ '/a': { get: op('stable') }, '/x': { post: op('experimental') } });
    const { base, revision } = prepareOpenApiPair({ baseline: doc, current: doc });
    expect(Object.keys(base.paths)).toEqual(['/a']);
    expect(Object.keys(revision.paths)).toEqual(['/a']);
  });

  it('keeps a stable operation that turned experimental in the baseline only, so it reads as removed', () => {
    const { base, revision } = prepareOpenApiPair({
      baseline: api({ '/a': { get: op('stable') } }),
      current: api({ '/a': { get: op('experimental') } }),
    });
    expect(Object.keys(base.paths)).toEqual(['/a']);
    expect(revision.paths).toEqual({});
  });

  it('judges an untagged baseline operation by its tag today, here or in the maximal export', () => {
    const { base } = prepareOpenApiPair({
      baseline: api({ '/a': { get: op() }, '/wallet': { post: op() }, '/gone': { get: op() } }),
      current: api({ '/a': { get: op('stable') } }),
      maximal: api({ '/a': { get: op('stable') }, '/wallet': { post: op('experimental') } }),
    });
    expect(Object.keys(base.paths).sort()).toEqual(['/a', '/gone']);
  });

  it('compares the release tag, not info.version', () => {
    const { base, revision } = prepareOpenApiPair({
      baseline: { ...api({}), info: { title: 'old', version: '1.0.0' } },
      current: { ...api({}), info: { title: 'new', version: '2.0.0' } },
    });
    expect(base.info).toEqual(revision.info);
  });
});

describe('a JSON Schema surface, wrapped for oasdiff', () => {
  const schema = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://example.test/s.json',
    type: 'object',
    properties: { subject: { $ref: '#/$defs/Subject' }, legacy: { $ref: '#/definitions/Old' } },
    $defs: { Subject: { type: 'object', properties: { id: { type: 'string' } } } },
    definitions: { Old: { type: 'string' } },
  };

  it('is the response of an output schema', () => {
    const doc = wrapJsonSchema(schema, { name: 'events', role: 'output' });
    const operation = doc.paths['/events'].post;
    expect(operation.requestBody).toBeUndefined();
    expect(operation.responses[200].content['application/json'].schema.properties.subject).toEqual({
      $ref: '#/components/schemas/Subject',
    });
    expect(doc.components.schemas).toEqual({
      Subject: schema.$defs.Subject,
      Old: { type: 'string' },
    });
  });

  it('is the request body of an input schema', () => {
    const operation = wrapJsonSchema(schema, { name: 'realm', role: 'input' }).paths['/realm'].post;
    expect(operation.requestBody.required).toBe(true);
    expect(operation.responses).toEqual({ 204: { description: 'Accepted' } });
  });

  it('is both for a schema that is both', () => {
    const operation = wrapJsonSchema(schema, { name: 'step', role: 'both' }).paths['/step'].post;
    expect(operation.requestBody).toBeDefined();
    expect(operation.responses[200]).toBeDefined();
  });

  it('drops $id and $schema from the root', () => {
    const body = wrapJsonSchema(schema, { name: 'e', role: 'output' }).paths['/e'].post
      .responses[200].content['application/json'].schema;
    expect(body.$id).toBeUndefined();
    expect(body.$schema).toBeUndefined();
  });

  it.each(['#', '#/properties/subject', 'other.json#/$defs/X'])(
    'refuses the reference %s',
    (ref) => {
      expect(() =>
        wrapJsonSchema({ properties: { a: { $ref: ref } } }, { name: 'e', role: 'output' })
      ).toThrow('is not supported');
    }
  );

  it('refuses a file that is not one schema object', () => {
    expect(() => wrapJsonSchema([], { name: 'e', role: 'output' })).toThrow(InputError);
  });
});

describe('release tags and the baseline', () => {
  it('parses release tags and nothing else', () => {
    expect(parseReleaseTag('v0.1.0-rc.2')).toEqual({
      tag: 'v0.1.0-rc.2',
      major: 0,
      minor: 1,
      patch: 0,
      prerelease: ['rc', '2'],
    });
    for (const name of ['0.1.0', 'v1.0', 'v01.0.0', 'release-1', 'v1.0.0-']) {
      expect(parseReleaseTag(name)).toBeNull();
    }
  });

  it.each([
    ['v0.1.0-rc.3', 'v0.1.0', -1],
    ['v0.1.0-rc.2', 'v0.1.0-rc.10', -1],
    ['v1.0.0-1', 'v1.0.0-alpha', -1],
    ['v1.0.0-alpha', 'v1.0.0-alpha.1', -1],
    ['v1.2.0', 'v1.10.0', -1],
    ['v2.0.0', 'v1.9.9', 1],
    ['v1.0.0', 'v1.0.0', 0],
  ])('orders %s against %s', (a, b, expected) => {
    expect(compareReleases(parseReleaseTag(a), parseReleaseTag(b))).toBe(expected);
  });

  it('uses the latest tag of any kind until a 1.0 release exists', () => {
    expect(selectBaselineTag(['v0.1.0-rc.0', 'v0.1.0', 'v0.1.0-rc.3', 'nightly'])).toBe('v0.1.0');
    expect(selectBaselineTag(['v0.1.0', 'v1.0.0-rc.1'])).toBe('v1.0.0-rc.1');
  });

  it('uses the latest 1.0-or-later release once one exists, ignoring later pre-releases', () => {
    expect(selectBaselineTag(['v0.9.0', 'v1.0.0', 'v1.1.0', 'v2.0.0-rc.1'])).toBe('v1.1.0');
  });

  it('has no baseline without a release tag', () => {
    expect(selectBaselineTag([])).toBeNull();
    expect(selectBaselineTag(['latest'])).toBeNull();
  });
});

describe('approved breaks (stable-surface/approved-breaks.json)', () => {
  const surfaces = parseRegistry({
    surfaces: [
      surface(),
      surface({ name: 'max', path: 'max.json', stability: 'experimental', maximalOf: 'openapi' }),
    ],
  });
  const tagged = new Set(['v0.1.0', 'v0.2.0']);
  const context = { surfaces, tagExists: (tag: string) => tagged.has(tag), baselineTag: 'v0.2.0' };
  const entry = (overrides: Doc = {}) => ({
    surface: 'openapi',
    change: {
      rule: 'response-optional-property-removed',
      operation: 'GET /a',
      fingerprint: '0123456789ab',
    },
    ref: '#451',
    release: 'v0.3.0',
    ...overrides,
  });

  it('accepts an entry for a release that is not tagged yet', () => {
    const { approvals, problems } = validateApprovals({ approvals: [entry()] }, context);
    expect(problems).toEqual([]);
    expect(approvals).toHaveLength(1);
  });

  it('refuses an entry for a release that is already tagged', () => {
    const { approvals, problems } = validateApprovals(
      { approvals: [entry({ release: 'v0.1.0' })] },
      context
    );
    expect(approvals).toEqual([]);
    expect(problems[0].message).toContain('release v0.1.0 is already tagged');
  });

  it('refuses an untagged release that is not later than the baseline', () => {
    const { problems } = validateApprovals({ approvals: [entry({ release: 'v0.1.5' })] }, context);
    expect(problems[0].message).toContain('not later than the baseline v0.2.0');
  });

  it.each([
    ['an unknown surface', { surface: 'nope' }, 'registered surface'],
    ['an experimental surface', { surface: 'max' }, 'is not stable'],
    ['a ref that is neither an issue nor an ADR', { ref: 'see the chat' }, '"ref"'],
    ['a release that is not a tag', { release: '0.3' }, '"release"'],
    [
      'a fingerprint of the wrong shape',
      { change: { rule: 'r', operation: 'GET /a', fingerprint: 'xyz' } },
      'fingerprint',
    ],
    ['an unknown key', { reason: 'because' }, 'unknown key "reason"'],
  ])('refuses %s', (_label, overrides, message) => {
    expect(
      validateApprovals({ approvals: [entry(overrides)] }, context).problems[0].message
    ).toContain(message);
  });

  it('accepts an ADR reference', () => {
    expect(
      validateApprovals({ approvals: [entry({ ref: 'ADR-018 §5' })] }, context).problems
    ).toEqual([]);
  });

  it('refuses a second entry for the same change', () => {
    const { approvals, problems } = validateApprovals({ approvals: [entry(), entry()] }, context);
    expect(approvals).toHaveLength(1);
    expect(problems[0].message).toContain('another entry already approves this change');
  });

  it('refuses a file without an approvals array', () => {
    expect(() => validateApprovals({}, context)).toThrow(InputError);
  });

  const finding = (fingerprint: string, overrides: Doc = {}) => ({
    id: 'response-optional-property-removed',
    text: `removed ${fingerprint}`,
    level: LEVEL.ERR,
    operation: 'GET',
    path: '/a',
    section: 'paths',
    fingerprint,
    ...overrides,
  });

  it('lets exactly the approved change through', () => {
    const { approvals } = validateApprovals({ approvals: [entry()] }, context);
    const { approved, unapproved } = matchApprovals(
      'openapi',
      [finding('0123456789ab'), finding('ba9876543210')],
      approvals
    );
    expect(approved.map((a) => a.finding.fingerprint)).toEqual(['0123456789ab']);
    expect(unapproved.map((f) => f.fingerprint)).toEqual(['ba9876543210']);
  });

  it('does not approve a change on another surface, rule or operation', () => {
    const { approvals } = validateApprovals({ approvals: [entry()] }, context);
    expect(matchApprovals('other', [finding('0123456789ab')], approvals).approved).toEqual([]);
    expect(
      matchApprovals('openapi', [finding('0123456789ab', { id: 'x' })], approvals).approved
    ).toEqual([]);
    expect(
      matchApprovals('openapi', [finding('0123456789ab', { path: '/b' })], approvals).approved
    ).toEqual([]);
  });

  it('prints a ready-to-fill entry for an unapproved break', () => {
    expect(approvalTemplate('openapi', finding('0123456789ab'))).toEqual({
      surface: 'openapi',
      change: {
        rule: 'response-optional-property-removed',
        operation: 'GET /a',
        fingerprint: '0123456789ab',
        text: 'removed 0123456789ab',
      },
      ref: '#<issue>',
      release: 'v<next release>',
    });
  });
});

describe('the definition of a break', () => {
  it('raises the rules oasdiff rates below an error to errors', () => {
    expect(severityLevelsFile().trim().split('\n')).toEqual(
      RAISED_TO_BREAK.map((rule) => `${rule} err`)
    );
    expect(RAISED_TO_BREAK).toContain('response-optional-property-removed');
  });
});

describe('the break-rule fixtures the self-test runs through oasdiff', () => {
  const dir = join(FIXTURES, 'break-rules');
  const cases = readJson(join(dir, 'cases.json'));
  const bases = {
    openapi: readJson(join(dir, 'openapi.json')),
    'json-schema': readJson(join(dir, 'schema.json')),
  };

  it.each(cases.map((c: Doc) => [c.name, c]))(
    '%s: its patch applies to its base',
    (_name, testCase) => {
      const base = applyJsonPatch(bases[testCase.format as 'openapi'], testCase.basePatch ?? []);
      const revised = applyJsonPatch(base, testCase.patch);
      expect(revised).not.toEqual(base);
      expect(Array.isArray(testCase.breaks)).toBe(true);
    }
  );

  it('covers every category of the definition, and both outcomes', () => {
    const expected = new Set(cases.flatMap((c: Doc) => c.breaks));
    for (const rule of [
      'api-removed-without-deprecation',
      'response-optional-property-removed',
      'response-required-property-removed',
      'new-required-request-property',
      'request-property-enum-value-removed',
      'response-property-type-changed',
      'api-security-scope-added',
    ]) {
      expect(expected).toContain(rule);
    }
    expect(cases.some((c: Doc) => c.breaks.length === 0)).toBe(true);
  });

  it('reports a case whose rule ids differ from the expectation', async () => {
    const differ = async () => [
      { id: 'something-else', level: LEVEL.ERR, fingerprint: '000000000000' },
    ];
    const result = await runBreakRuleCase(cases[0], bases, differ);
    expect(result.ok).toBe(false);
    expect(result.actual).toEqual(['something-else']);
  });

  it('refuses a patch whose path does not resolve', () => {
    expect(() => applyJsonPatch({ a: {} }, [{ op: 'remove', path: '/a/b' }])).toThrow(
      'does not resolve'
    );
    expect(() => applyJsonPatch({ a: [] }, [{ op: 'replace', path: '/a/0', value: 1 }])).toThrow(
      'does not resolve'
    );
    expect(() => applyJsonPatch({ a: 1 }, [{ op: 'move', path: '/a' }])).toThrow(
      'unsupported patch op'
    );
  });
});

// ---------------------------------------------------------------------------
// The pipeline, over a fixture repository with a second surface
// ---------------------------------------------------------------------------

/**
 * A structural stand-in for oasdiff, in its output shape: a removed operation
 * and a removed response property, the two changes these tests make.
 */
async function structuralDiffer(base: Doc, revision: Doc) {
  const fingerprint = (...parts: string[]) =>
    createHash('sha256').update(parts.join(':')).digest('hex').slice(0, 12);
  const findings: Doc[] = [];
  for (const { method, path, operation } of listOperations(base)) {
    const revised = revision.paths?.[path]?.[method];
    if (!revised) {
      const id = 'api-removed-without-deprecation';
      findings.push({
        id,
        text: 'api removed without deprecation',
        level: LEVEL.ERR,
        operation: method.toUpperCase(),
        path,
        section: 'paths',
        fingerprint: fingerprint(id, method, path),
      });
      continue;
    }
    const properties = (o: Doc) =>
      Object.keys(o.responses?.[200]?.content?.['application/json']?.schema?.properties ?? {});
    for (const name of properties(operation)) {
      if (properties(revised).includes(name)) continue;
      const id = 'response-optional-property-removed';
      findings.push({
        id,
        text: `removed the optional property \`${name}\` from the response`,
        level: LEVEL.ERR,
        operation: method.toUpperCase(),
        path,
        section: 'paths',
        fingerprint: fingerprint(id, method, path, name),
      });
    }
  }
  return findings;
}

function fixtureRepo() {
  const root = mkdtempSync(join(tmpdir(), 'stable-surface-fixture-'));
  workspaces.push(root);
  cpSync(join(FIXTURES, 'second-surface'), root, { recursive: true });
  // "Commit" the generated files, as the repository commits its exports.
  expect(spawnSync('node', ['generate.mjs'], { cwd: root }).status).toBe(0);
  return root;
}

function setup(root: string, { tags = ['v1.0.0'] }: { tags?: string[] } = {}) {
  const generated: string[] = [];
  const differCalls: Doc[] = [];
  const git = {
    releaseTags: () => tags,
    tagExists: (tag: string) => tags.includes(tag),
    show: (_ref: string, path: string) => {
      try {
        return readFileSync(join(root, 'baseline', path), 'utf8');
      } catch {
        return null;
      }
    },
    diff: (_before: string, _after: string, path: string) =>
      `--- committed/${path}\n+++ generated/${path}`,
  };
  const runCommand = (command: string) => {
    generated.push(command);
    const result = spawnSync(command, { cwd: root, shell: true, encoding: 'utf8' });
    return { status: result.status ?? 1, output: `${result.stdout}${result.stderr}` };
  };
  const differ = async (base: Doc, revision: Doc) => {
    differCalls.push(revision);
    return structuralDiffer(base, revision);
  };
  const run = (steps: Doc = { drift: true, tags: true, breaks: true }, baselineRef?: string) =>
    runChecks({ root, steps, baselineRef, git, runCommand, differ });
  return { run, generated, differCalls };
}

const editJson = (path: string, edit: (doc: Doc) => void) => {
  const doc = readJson(path);
  edit(doc);
  writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
};

/** Remove `occurred_at` from the event schema, in the source and in the committed file. */
function removeEventField(root: string) {
  for (const file of ['source/events.schema.json', 'stable-surface/events.schema.json']) {
    editJson(join(root, file), (doc) => delete doc.properties.occurred_at);
  }
}

describe('a second surface needs only its registry entry', () => {
  it('checks the JSON Schema surface for drift and breaks alongside the OpenAPI document', async () => {
    const root = fixtureRepo();
    const { run, generated, differCalls } = setup(root);
    const report = await run();

    expect(exitCodeOf(report)).toBe(0);
    expect(generated).toEqual(['node generate.mjs']);
    expect(
      report.surfaces.map((s: Doc) => [s.surface.name, s.drift.status, s.breaks.status])
    ).toEqual([
      ['openapi', 'ok', 'ok'],
      ['events', 'ok', 'ok'],
    ]);
    expect(differCalls.map((doc) => Object.keys(doc.paths))).toEqual([['/things'], ['/events']]);
    expect(report.surfaces[1].breaks.source).toBe('v1.0.0:stable-surface/events.schema.json');
  });

  it('fails when the committed schema is not what the generator writes', async () => {
    const root = fixtureRepo();
    editJson(join(root, 'source', 'events.schema.json'), (doc) => {
      doc.properties.trace_id = { type: 'string' };
    });
    const report = await setup(root).run({ drift: true });
    expect(report.surfaces.map((s: Doc) => s.drift.status)).toEqual(['ok', 'drift']);
    expect(exitCodeOf(report)).toBe(1);
    expect(renderSummary(report)).toContain('### Drift: `stable-surface/events.schema.json`');
  });

  it('fails on a removed event field, and prints the entry that would approve it', async () => {
    const root = fixtureRepo();
    removeEventField(root);
    const report = await setup(root).run();

    expect(exitCodeOf(report)).toBe(1);
    const events = report.surfaces[1].breaks;
    expect(events.status).toBe('breaks');
    expect(events.unapproved.map((f: Doc) => f.text)).toEqual([
      'removed the optional property `occurred_at` from the response',
    ]);
    const summary = renderSummary(report);
    expect(summary).toContain('| ❌ break | `response-optional-property-removed` | POST /events |');
    expect(summary).toContain('"surface": "events"');
    expect(annotations(report)).toContainEqual(
      expect.objectContaining({ level: 'error', file: 'stable-surface/events.schema.json' })
    );
  });

  it('passes that exact break once approved, and lists the approval in the summary', async () => {
    const root = fixtureRepo();
    removeEventField(root);
    const { fingerprint } = (await setup(root).run()).surfaces[1].breaks.unapproved[0];
    editJson(join(root, 'stable-surface', 'approved-breaks.json'), (doc) => {
      doc.approvals.push({
        surface: 'events',
        change: {
          rule: 'response-optional-property-removed',
          operation: 'POST /events',
          fingerprint,
        },
        ref: '#451',
        release: 'v1.1.0',
      });
    });
    const report = await setup(root).run();

    expect(exitCodeOf(report)).toBe(0);
    expect(report.surfaces[1].breaks.approved).toHaveLength(1);
    expect(report.approvalsUsed).toHaveLength(1);
    expect(renderSummary(report)).toContain(
      '| ✅ approved break | `response-optional-property-removed` | POST /events | removed the optional property `occurred_at` from the response | v1.1.0, #451 |'
    );
  });

  it('refuses the same approval for a release that is already tagged', async () => {
    const root = fixtureRepo();
    removeEventField(root);
    const { fingerprint } = (await setup(root).run()).surfaces[1].breaks.unapproved[0];
    editJson(join(root, 'stable-surface', 'approved-breaks.json'), (doc) => {
      doc.approvals.push({
        surface: 'events',
        change: {
          rule: 'response-optional-property-removed',
          operation: 'POST /events',
          fingerprint,
        },
        ref: '#451',
        release: 'v1.1.0',
      });
    });
    const report = await setup(root, { tags: ['v1.0.0', 'v1.1.0'] }).run(undefined, 'v1.0.0');

    expect(exitCodeOf(report)).toBe(1);
    expect(report.surfaces[1].breaks.status).toBe('breaks');
    expect(report.approvalProblems[0]).toContain('release v1.1.0 is already tagged');
    expect(renderSummary(report)).toContain('### Refused approvals');
  });

  it('refuses an approval that matches no break', async () => {
    const root = fixtureRepo();
    editJson(join(root, 'stable-surface', 'approved-breaks.json'), (doc) => {
      doc.approvals.push({
        surface: 'openapi',
        change: {
          rule: 'api-removed-without-deprecation',
          operation: 'GET /things',
          fingerprint: 'aaaaaaaaaaaa',
        },
        ref: 'ADR-018',
        release: 'v1.1.0',
      });
    });
    const report = await setup(root).run();
    expect(exitCodeOf(report)).toBe(1);
    expect(report.approvalProblems[0]).toContain('found no such break; remove the entry');
  });

  it('fails an OpenAPI operation that lost its stability tag', async () => {
    const root = fixtureRepo();
    editJson(join(root, 'stable-surface', 'openapi.json'), (doc) => {
      delete doc.paths['/things'].get['x-qauth-stability'];
    });
    const report = await setup(root).run({ tags: true });
    expect(exitCodeOf(report)).toBe(1);
    expect(report.tagProblems[0].message).toBe('GET /things has no x-qauth-stability');
  });

  it('has nothing to compare before the first release tag, or before the file was released', async () => {
    const root = fixtureRepo();
    expect((await setup(root, { tags: [] }).run({ breaks: true })).surfaces[0].breaks.status).toBe(
      'no-baseline'
    );

    rmSync(join(root, 'baseline', 'stable-surface', 'events.schema.json'));
    const report = await setup(root).run({ breaks: true });
    expect(report.surfaces[1].breaks).toEqual({
      status: 'no-baseline',
      note: 'stable-surface/events.schema.json is not in v1.0.0; the first release that contains it becomes its baseline',
    });
    expect(exitCodeOf(report)).toBe(0);
  });

  it('reads a former path when the file has moved since the baseline', async () => {
    const root = fixtureRepo();
    editJson(join(root, 'stable-surface', 'surfaces.json'), (doc) => {
      doc.surfaces[1].formerPaths = ['schemas/events.json'];
    });
    mkdirSync(join(root, 'baseline', 'schemas'));
    cpSync(
      join(root, 'baseline', 'stable-surface', 'events.schema.json'),
      join(root, 'baseline', 'schemas', 'events.json')
    );
    rmSync(join(root, 'baseline', 'stable-surface', 'events.schema.json'));
    const report = await setup(root).run({ breaks: true });
    expect(report.surfaces[1].breaks.source).toBe('v1.0.0:schemas/events.json');
  });

  it('cannot run when a generator fails', async () => {
    const root = fixtureRepo();
    rmSync(join(root, 'source', 'openapi.json'));
    const report = await setup(root).run({ drift: true });
    expect(exitCodeOf(report)).toBe(2);
    expect(report.errors[0]).toContain('generator failed (exit 1): node generate.mjs');
  });
});
