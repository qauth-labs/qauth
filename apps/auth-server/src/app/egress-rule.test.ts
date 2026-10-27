import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import * as ts from 'typescript';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * The egress guard of `.oxlintrc.json` (ADR-019 Decision 8, issue #481):
 * server code makes outbound calls through the egress client, never through
 * the global `fetch`, the connecting exports of `node:http(s)`, `node:http2`,
 * `node:net` and `node:tls`, or `undici`.
 *
 * Oxlint reads only files on disk, so the samples go to a temporary directory
 * laid out like the workspace, next to a configuration holding the guard's
 * block exactly as `.oxlintrc.json` has it and the local plugin that holds the
 * rule. The first test checks that nothing else in the workspace configuration
 * sets the rule, so the block tested here is the one that applies.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../..');
const OXLINT = join(
  dirname(createRequire(__filename).resolve('oxlint/package.json')),
  'bin',
  'oxlint'
);

const GUARD_RULE = 'qauth/no-direct-network';

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

/** Server code: the auth server's routes and helpers, a fastify plugin, a server library. */
const SERVER_CODE = [
  'apps/auth-server/src/app/helpers/sample.ts',
  'apps/auth-server/src/app/routes/oauth/sample.ts',
  'libs/fastify/plugins/ssf/src/lib/sample.ts',
  'libs/server/federation/src/sample.ts',
];

/**
 * Where the guard does not apply: the egress library, tests and their
 * fixtures, a KEK custody adapter (ADR-019 amendment of 2026-10-27), and
 * projects that are not server code.
 */
const EXEMPT = [
  'libs/server/egress/src/lib/sample.ts',
  'apps/auth-server/src/app/helpers/sample.test.ts',
  'apps/auth-server/src/testing/sample.ts',
  'libs/keys/cloud-kms/src/lib/sample.ts',
  'apps/wire-suite/src/sample.ts',
];

const FORBIDDEN: readonly (readonly [what: string, code: string])[] = [
  ['a direct fetch', 'export const get = (url: string) => fetch(url);\n'],
  ['globalThis.fetch', 'export const get = (url: string) => globalThis.fetch(url);\n'],
  ["globalThis['fetch']", "export const get = (url: string) => globalThis['fetch'](url);\n"],
  ['fetch as a value', 'export const client = fetch;\n'],
  [
    'https.request on a default import',
    "import https from 'node:https';\nexport const send = (url: string) => https.request(url);\n",
  ],
  [
    'http.get on a namespace import',
    "import * as http from 'node:http';\nexport const send = (url: string) => http.get(url);\n",
  ],
  ['https.request as a value', "import https from 'https';\nexport const send = https.request;\n"],
  ['a named import of request', "import { request } from 'node:https';\nexport { request };\n"],
  [
    'a renamed import of get',
    "import { get as httpGet } from 'node:http';\nexport const send = httpGet;\n",
  ],
  [
    'https.request on a require',
    "const https = require('node:https');\nexport const send = (url: string) => https.request(url);\n",
  ],
  ['a destructured require of get', "const { get } = require('http');\nexport const send = get;\n"],
  [
    'request on a require call',
    "export const send = (url: string) => require('https').request(url);\n",
  ],
  [
    'a destructuring of the module object',
    "import * as https from 'node:https';\nconst { request } = https;\nexport { request };\n",
  ],
  ['a re-export of request', "export { request } from 'node:https';\n"],
  ['export * from the module', "export * from 'node:http';\n"],
  ['a dynamic import', "export const load = () => import('node:https');\n"],
  [
    'http2.connect on a namespace import',
    "import * as http2 from 'node:http2';\nexport const open = (url: string) => http2.connect(url);\n",
  ],
  [
    'a named import of connect from net',
    "import { connect } from 'node:net';\nexport const open = () => connect(443, 'example.com');\n",
  ],
  [
    'createConnection on a require of net',
    "const net = require('net');\nexport const open = () => net.createConnection(443);\n",
  ],
  ['a net Socket', "import net from 'node:net';\nexport const socket = () => new net.Socket();\n"],
  [
    'tls.connect on a default import',
    "import tls from 'node:tls';\nexport const open = () => tls.connect(443, 'example.com');\n",
  ],
  ['a destructured require of tls', "const { connect } = require('tls');\nexport { connect };\n"],
  [
    'a named import from undici',
    "import { request } from 'undici';\nexport const send = (url: string) => request(url);\n",
  ],
  [
    'a namespace import of undici',
    "import * as undici from 'undici';\nexport const send = (url: string) => undici.fetch(url);\n",
  ],
  ['a require of undici', "export const send = (url: string) => require('undici').request(url);\n"],
  ['a dynamic import of undici', "export const load = () => import('undici');\n"],
];

const ALLOWED: readonly (readonly [what: string, code: string])[] = [
  ['a parameter named fetch', 'export const run = (fetch: () => Promise<void>) => fetch();\n'],
  ['a fetch property of another object', 'export const value = { fetch: 1 }.fetch;\n'],
  [
    "node:http's other exports",
    "import { STATUS_CODES } from 'node:http';\nexport { STATUS_CODES };\n",
  ],
  [
    'a type import from node:http',
    "import type { IncomingMessage } from 'node:http';\nexport type Message = IncomingMessage;\n",
  ],
  [
    'the egress client',
    "export const send = (egress: { request(r: object): Promise<unknown> }) =>\n  egress.request({ method: 'GET' });\n",
  ],
  ['a re-export of another node:http export', "export { STATUS_CODES } from 'node:http';\n"],
  ["node:net's address helpers", "import { isIP } from 'node:net';\nexport const ip = isIP;\n"],
  [
    'a type import from node:net',
    "import type { Socket } from 'node:net';\nexport type Connection = Socket;\n",
  ],
  [
    'a type import from undici',
    "import type { Dispatcher } from 'undici';\nexport type Handler = Dispatcher;\n",
  ],
  [
    'fetch in a page script string',
    "export const page = '<script>fetch(statusUrl).then(function () {});</script>';\n",
  ],
];

/** The path a sample is linted as: a numbered sibling of `path`. */
function samplePath(path: string, kind: 'forbidden' | 'allowed', index: number): string {
  return path.replace(/sample(\.test)?\.ts$/, `sample-${kind}-${index}$1.ts`);
}

let sandbox: string;
const messagesByPath = new Map<string, string[]>();
const reportedRules = new Set<string>();

beforeAll(() => {
  const config = workspaceConfig();
  const [guard] = (config.overrides ?? []).filter((override) => configures(override.rules));
  sandbox = mkdtempSync(join(tmpdir(), 'qauth-egress-guard-'));

  // The guard block as it is, and the local plugins with their paths made
  // absolute, since the configuration no longer sits at the workspace root.
  const sandboxConfig: OxlintConfig & { categories: Record<string, string> } = {
    plugins: config.plugins,
    jsPlugins: (config.jsPlugins ?? [])
      .filter((plugin) => plugin.startsWith('.'))
      .map((plugin) => join(WORKSPACE_ROOT, plugin)),
    categories: { correctness: 'off' },
    overrides: [guard],
  };
  writeFileSync(join(sandbox, '.oxlintrc.json'), JSON.stringify(sandboxConfig));

  const samples = new Map<string, string>();
  for (const path of [...SERVER_CODE, ...EXEMPT]) {
    FORBIDDEN.forEach(([, code], index) => samples.set(samplePath(path, 'forbidden', index), code));
    ALLOWED.forEach(([, code], index) => samples.set(samplePath(path, 'allowed', index), code));
  }
  for (const [path, code] of samples) {
    mkdirSync(dirname(join(sandbox, path)), { recursive: true });
    writeFileSync(join(sandbox, path), code);
    messagesByPath.set(path, []);
  }

  const run = spawnSync(
    process.execPath,
    [OXLINT, '-c', '.oxlintrc.json', '--format=json', ...samples.keys()],
    { cwd: sandbox, encoding: 'utf8' }
  );
  let report: { diagnostics: Diagnostic[] };
  try {
    report = JSON.parse(run.stdout) as { diagnostics: Diagnostic[] };
  } catch {
    throw new Error(`Oxlint did not report: ${run.stdout}${run.stderr}`);
  }
  for (const diagnostic of report.diagnostics) {
    // `qauth(no-direct-network)`.
    const [, plugin, rule] = /^(.+)\((.+)\)$/.exec(diagnostic.code) ?? [];
    reportedRules.add(`${plugin}/${rule}`);
    messagesByPath.get(diagnostic.filename)?.push(diagnostic.message);
  }
}, 60_000);

afterAll(() => {
  if (sandbox) rmSync(sandbox, { recursive: true, force: true });
});

describe('egress lint guard (#481)', () => {
  it('is one block of the workspace configuration, and nothing else sets its rule', () => {
    const config = workspaceConfig();
    const blocks = (config.overrides ?? []).filter((override) => configures(override.rules));

    expect(configures(config.rules)).toBe(false);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].excludeFiles).toEqual(
      expect.arrayContaining(['libs/server/egress/**', '**/*.test.ts', '**/src/testing/**'])
    );
  });

  it('reports through the guard rule only', () => {
    expect([...reportedRules]).toEqual([GUARD_RULE]);
  });

  it.each(
    SERVER_CODE.flatMap((path) =>
      FORBIDDEN.map(([what], index) => [path, what, samplePath(path, 'forbidden', index)])
    )
  )('fails lint in %s for %s', (_path, _what, key) => {
    const found = messagesByPath.get(key) ?? [];

    expect(found).toHaveLength(1);
    expect(found[0]).toContain('bypasses the egress client');
  });

  it.each(
    SERVER_CODE.flatMap((path) =>
      ALLOWED.map(([what], index) => [path, what, samplePath(path, 'allowed', index)])
    )
  )('lets %s use %s', (_path, _what, key) => {
    expect(messagesByPath.get(key)).toEqual([]);
  });

  it.each(
    EXEMPT.flatMap((path) =>
      FORBIDDEN.map(([what], index) => [path, what, samplePath(path, 'forbidden', index)])
    )
  )('leaves %s alone, even for %s', (_path, _what, key) => {
    expect(messagesByPath.get(key)).toEqual([]);
  });
});
