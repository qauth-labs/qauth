import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import * as ts from 'typescript';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * The request-authority guard of `.oxlintrc.json` (ADR-019 Decision 1, issue
 * #490): no URL is built from the request, so only the realm resolver
 * (`plugins/realm-resolver.ts`) may read `request.host`, `request.hostname`,
 * `request.port`, `request.protocol`, the `Host` header or an `X-Forwarded-*`
 * header. Everything else builds URLs from the realm row (`realmIssuer`,
 * `buildRealmUrl` in `helpers/realm-url.ts`).
 *
 * Oxlint reads only files on disk, so the samples go to a temporary directory
 * laid out like the workspace, next to a configuration holding the guard's
 * block exactly as `.oxlintrc.json` has it and the local plugin that
 * implements the rule. The rest of the workspace configuration stays out: its
 * other plugins resolve only from the workspace, and the Nx boundaries rule
 * needs the project graph. The first test checks that nothing else in it
 * configures the guard's rule.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../..');
const OXLINT = join(
  dirname(createRequire(__filename).resolve('oxlint/package.json')),
  'bin',
  'oxlint'
);

const GUARD_RULE = 'qauth/no-request-authority';

interface OxlintConfig {
  plugins?: string[];
  jsPlugins?: string[];
  rules?: Record<string, unknown>;
  overrides?: Array<{ files: string[]; excludeFiles?: string[]; rules?: Record<string, unknown> }>;
}

interface Diagnostic {
  message: string;
  code: string;
  filename: string;
}

/** `.oxlintrc.json`, which has comments, read the way TypeScript reads a tsconfig. */
function workspaceConfig(): OxlintConfig {
  const path = join(WORKSPACE_ROOT, '.oxlintrc.json');
  const { config, error } = ts.parseConfigFileTextToJson(path, readFileSync(path, 'utf8'));
  if (error) throw new Error(ts.flattenDiagnosticMessageText(error.messageText, '\n'));
  return config as OxlintConfig;
}

const configures = (rules: Record<string, unknown> | undefined) =>
  rules !== undefined && GUARD_RULE in rules;

/** Where request-time code lives: the auth server's routes and helpers, and its libraries. */
const GUARDED = [
  'apps/auth-server/src/app/routes/oauth/sample.ts',
  'apps/auth-server/src/app/helpers/sample.ts',
  'apps/auth-server/src/app/plugins/sample.ts',
  'libs/fastify/plugins/dpop/src/lib/sample.ts',
  'libs/server/federation/src/lib/sample.ts',
];

/** The realm resolver, and tests, which send spoofed hosts on purpose. */
const EXEMPT = [
  'apps/auth-server/src/app/plugins/realm-resolver.ts',
  'apps/auth-server/src/app/routes/oauth/sample.test.ts',
  'apps/auth-server/src/app/routes/sample.integration.test.ts',
  'apps/auth-server/src/testing/sample.ts',
];

interface Sample {
  readonly kind: 'authority' | 'allowed';
  readonly what: string;
  readonly code: string;
}

/** The parameter every sample's function takes, typed loosely enough for all of them. */
const REQUEST =
  'request: { host: string; hostname: string; port: number; protocol: string; url: string; ' +
  'headers: Record<string, string | undefined>; raw: { headers: Record<string, string | undefined> } }';

const SAMPLES: readonly Sample[] = [
  {
    kind: 'authority',
    what: 'request.hostname',
    code: `export const read = (${REQUEST}) => request.hostname;\n`,
  },
  {
    kind: 'authority',
    what: 'request.host',
    code: `export const read = (${REQUEST}) => request.host;\n`,
  },
  {
    kind: 'authority',
    what: 'request.protocol',
    code: `export const read = (${REQUEST}) => request.protocol;\n`,
  },
  {
    kind: 'authority',
    what: 'request.port',
    code: `export const read = (${REQUEST}) => request.port;\n`,
  },
  {
    kind: 'authority',
    what: "a computed request['hostname']",
    code: `export const read = (${REQUEST}) => request['hostname'];\n`,
  },
  {
    kind: 'authority',
    what: 'req.hostname',
    code: `export const read = (req: { hostname: string }) => req.hostname;\n`,
  },
  {
    kind: 'authority',
    what: 'a destructured hostname',
    code: `export function read(${REQUEST}) {\n  const { hostname } = request;\n  return hostname;\n}\n`,
  },
  {
    kind: 'authority',
    what: 'request.headers.host',
    code: `export const read = (${REQUEST}) => request.headers.host;\n`,
  },
  {
    kind: 'authority',
    what: "request.headers['Host']",
    code: `export const read = (${REQUEST}) => request.headers['Host'];\n`,
  },
  {
    kind: 'authority',
    what: 'request.raw.headers.host',
    code: `export const read = (${REQUEST}) => request.raw.headers.host;\n`,
  },
  {
    kind: 'authority',
    what: 'a destructured Host header',
    code: `export function read(${REQUEST}) {\n  const { host } = request.headers;\n  return host;\n}\n`,
  },
  {
    kind: 'authority',
    what: 'the X-Forwarded-Host header',
    code: `export const read = (${REQUEST}) => request.headers['x-forwarded-host'];\n`,
  },
  {
    kind: 'authority',
    what: 'the X-Forwarded-Proto header, in any case',
    code: `export const read = (${REQUEST}) => request.headers['X-Forwarded-Proto'];\n`,
  },
  {
    kind: 'authority',
    what: 'an X-Forwarded-* name in a template literal',
    code: 'export const header = `x-forwarded-prefix`;\n',
  },
  {
    kind: 'authority',
    what: '_request.hostname',
    code: `export const read = (_${REQUEST}) => _request.hostname;\n`,
  },
  {
    kind: 'authority',
    what: 'reply.request.hostname',
    code: 'export const read = (reply: { request: { hostname: string } }) => reply.request.hostname;\n',
  },
  {
    kind: 'authority',
    what: 'this.request.protocol',
    code: 'export class Handler {\n  constructor(private readonly request: { protocol: string }) {}\n  read() {\n    return this.request.protocol;\n  }\n}\n',
  },
  {
    kind: 'authority',
    what: 'a hostname destructured from a FastifyRequest parameter',
    code: "import type { FastifyRequest } from 'fastify';\nexport const read = ({ hostname }: FastifyRequest) => hostname;\n",
  },
  {
    kind: 'authority',
    what: 'a Host header destructured through headers',
    code: `export function read(${REQUEST}) {\n  const {\n    headers: { host },\n  } = request;\n  return host;\n}\n`,
  },
  {
    kind: 'authority',
    what: 'a hostname destructured in an assignment',
    code: `export function read(${REQUEST}) {\n  let name = '';\n  ({ hostname: name } = request);\n  return name;\n}\n`,
  },
  {
    kind: 'authority',
    what: 'the Forwarded header',
    code: `export const read = (${REQUEST}) => request.headers.forwarded;\n`,
  },
  {
    kind: 'allowed',
    what: 'the url destructured from a request',
    code: `export function read(${REQUEST}) {\n  const { url } = request;\n  return url;\n}\n`,
  },
  {
    // The browser's own origin, which a CSRF check compares with the realm's.
    kind: 'allowed',
    what: 'the Origin header',
    code: `export const read = (${REQUEST}) => request.headers.origin;\n`,
  },
  {
    kind: 'allowed',
    what: 'a hostname destructured from a value that is no request',
    code: 'export const read = ({ hostname }: URL) => hostname;\n',
  },
  {
    // The path is the route's, not the authority: the DPoP `htu` check joins it
    // onto the realm's issuer.
    kind: 'allowed',
    what: 'request.url',
    code: `export const read = (${REQUEST}) => request.url;\n`,
  },
  {
    kind: 'allowed',
    what: 'the host of a URL the server built',
    code: "export const host = new URL('https://auth.example.com').host;\n",
  },
  {
    kind: 'allowed',
    what: 'a host key in an object literal',
    code: "export const options = { host: '127.0.0.1', protocol: 'https' };\n",
  },
  {
    kind: 'allowed',
    what: 'prose that names X-Forwarded-Host',
    code: "export const note = 'X-Forwarded-Host counts only from a TRUST_PROXY hop';\n",
  },
];

/** The path a sample is linted as: a numbered sibling, or the resolver itself. */
function samplePath(path: string, index: number): string {
  return path.endsWith('/realm-resolver.ts')
    ? path
    : path.replace(/sample((\.integration)?(\.test)?)\.ts$/, `sample-${index}$1.ts`);
}

let sandbox: string;
/** Messages per `${sample index}|${path}`. */
const messages = new Map<string, string[]>();
const reportedRules = new Set<string>();

/**
 * Lint every sample. The resolver holds one sample at a time, so each sample
 * gets its own directory, laid out like the workspace, with the guard's block
 * as it is and the local plugin at its absolute path.
 */
beforeAll(() => {
  const config = workspaceConfig();
  const sandboxConfig: OxlintConfig & { categories: Record<string, string> } = {
    plugins: config.plugins,
    jsPlugins: (config.jsPlugins ?? [])
      .filter((plugin) => plugin.startsWith('.'))
      .map((plugin) => join(WORKSPACE_ROOT, plugin)),
    categories: { correctness: 'off' },
    overrides: (config.overrides ?? []).filter((override) => configures(override.rules)),
  };
  sandbox = mkdtempSync(join(tmpdir(), 'qauth-request-authority-guard-'));

  SAMPLES.forEach((sample, index) => {
    const root = join(sandbox, String(index));
    const paths = [...GUARDED, ...EXEMPT].map((path) => samplePath(path, index));
    mkdirSync(root);
    writeFileSync(join(root, '.oxlintrc.json'), JSON.stringify(sandboxConfig));
    for (const path of paths) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), sample.code);
      messages.set(`${index}|${path}`, []);
    }

    const run = spawnSync(
      process.execPath,
      [OXLINT, '-c', '.oxlintrc.json', '--format=json', ...paths],
      { cwd: root, encoding: 'utf8' }
    );
    let report: { diagnostics: Diagnostic[] };
    try {
      report = JSON.parse(run.stdout) as { diagnostics: Diagnostic[] };
    } catch {
      throw new Error(`Oxlint did not report: ${run.stdout}${run.stderr}`);
    }
    for (const diagnostic of report.diagnostics) {
      // `qauth(no-request-authority)`.
      const [, plugin, rule] = /^(.+)\((.+)\)$/.exec(diagnostic.code) ?? [];
      reportedRules.add(`${plugin}/${rule}`);
      messages.get(`${index}|${diagnostic.filename}`)?.push(diagnostic.message);
    }
  });
}, 60_000);

afterAll(() => {
  if (sandbox) rmSync(sandbox, { recursive: true, force: true });
});

/** `[path, what, key]` rows for `it.each`, for the samples of `kind` linted at `paths`. */
function cases(paths: readonly string[], kind: Sample['kind']): [string, string, string][] {
  return paths.flatMap((path) =>
    SAMPLES.flatMap((sample, index) =>
      sample.kind === kind
        ? [[path, sample.what, `${index}|${samplePath(path, index)}`] as [string, string, string]]
        : []
    )
  );
}

describe('request-authority lint guard (#490)', () => {
  it('is one block of the workspace configuration, and nothing else sets its rule', () => {
    const config = workspaceConfig();
    const blocks = (config.overrides ?? []).filter((override) => configures(override.rules));

    expect(configures(config.rules)).toBe(false);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].files).toEqual(['apps/auth-server/**', 'libs/fastify/**', 'libs/server/**']);
    expect(blocks[0].excludeFiles).toEqual([
      'apps/auth-server/src/app/plugins/realm-resolver.ts',
      '**/*.test.ts',
      '**/*.test.tsx',
      '**/testing/**',
    ]);
  });

  it('reports through the guard rule only', () => {
    expect([...reportedRules]).toEqual([GUARD_RULE]);
  });

  it.each(cases(GUARDED, 'authority'))('fails lint in %s for %s', (_p, _w, key) => {
    const found = messages.get(key);

    expect(found).toHaveLength(1);
    expect(found?.[0]).toContain('Build URLs from the realm row (ADR-019 Decision 1)');
  });

  it.each(cases(EXEMPT, 'authority'))('lets %s read %s', (_p, _w, key) => {
    expect(messages.get(key)).toEqual([]);
  });

  it.each(cases([...GUARDED, ...EXEMPT], 'allowed'))('lets %s use %s', (_p, _w, key) => {
    expect(messages.get(key)).toEqual([]);
  });
});
