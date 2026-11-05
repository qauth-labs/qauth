import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * #635 acceptance: "No outbound call bypasses the egress client". The range
 * lookup reaches its host through `@qauth-labs/server-egress` only (ADR-019
 * Decision 8). Oxlint's `qauth/no-direct-network` covers every server
 * library, this one included (`.oxlintrc.json`); this test pins it for this
 * library alone, by reading what it ships.
 */

const SOURCE_ROOT = join(__dirname, '..');

const PACKAGE_JSON = JSON.parse(readFileSync(join(SOURCE_ROOT, '..', 'package.json'), 'utf8')) as {
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

/** The modules that open a connection, or wrap one. */
const NETWORK_MODULES = [
  'http',
  'https',
  'http2',
  'net',
  'tls',
  'dgram',
  'undici',
  'axios',
  'node-fetch',
  'got',
] as const;

const MODULE_NAMES = NETWORK_MODULES.map((name) => name.replace('-', '\\-')).join('|');

/** `import … from 'x'`, `import 'x'`, `export … from 'x'`, `import('x')`, `require('x')`, with or without `node:` and a subpath. */
const NETWORK_IMPORT = new RegExp(
  `(?:\\bfrom\\s*|\\bimport\\s*\\(?\\s*|\\brequire\\s*\\(\\s*)['"\`](?:node:)?(?:${MODULE_NAMES})(?:/[^'"\`]*)?['"\`]`
);

/** A call of the global `fetch`, bare or through `globalThis`, `global`, `window` or `self`. */
const GLOBAL_FETCH =
  /(?:^|[^.\w$])fetch\s*\(|\b(?:globalThis|global|window|self)\s*(?:\.\s*fetch\b|\[\s*['"`]fetch['"`]\s*\])/;

/** Every `.ts` file under `directory` that is not a test. */
function shippedSources(directory: string): string[] {
  return readdirSync(directory, { recursive: true, encoding: 'utf8' })
    .filter((path) => path.endsWith('.ts') && !/\.(test|spec)\.ts$/.test(path))
    .map((path) => join(directory, path));
}

/** What in `source` reaches the network without the egress client. */
function directNetworkUses(source: string): string[] {
  const found: string[] = [];
  if (NETWORK_IMPORT.test(source)) found.push('imports a network module');
  if (GLOBAL_FETCH.test(source)) found.push('calls the global fetch');
  return found;
}

describe('the breach check reaches the network through the egress client only (#635)', () => {
  it('ships no source that imports a network module or calls fetch', () => {
    const files = shippedSources(SOURCE_ROOT);
    expect(files.map((file) => relative(SOURCE_ROOT, file))).toEqual(
      expect.arrayContaining(['index.ts', 'lib/range-lookup.ts', 'lib/operator-list.ts'])
    );
    const offenders = Object.fromEntries(
      files
        .map((file) => [relative(SOURCE_ROOT, file), directNetworkUses(readFileSync(file, 'utf8'))])
        .filter(([, uses]) => uses.length > 0)
    );
    expect(offenders).toEqual({});
  });

  it('declares no network library among its dependencies', () => {
    const declared = Object.keys({
      ...PACKAGE_JSON.dependencies,
      ...PACKAGE_JSON.peerDependencies,
    });
    expect(
      declared.filter((name) => (NETWORK_MODULES as readonly string[]).includes(name))
    ).toEqual([]);
    expect(declared).toContain('@qauth-labs/server-egress');
  });

  it('catches each way around the egress client (the check itself)', () => {
    const forbidden = [
      "import https from 'node:https';",
      "import * as http from 'http';",
      "import { connect } from 'node:tls';",
      "import { Socket } from 'net';",
      "import { request } from 'undici';",
      "import axios from 'axios';",
      "import fetch from 'node-fetch';",
      "import 'node:http2';",
      "export { request } from 'node:https';",
      "const https = require('https');",
      "const http = await import('node:http');",
      "import { Agent } from 'undici/lib/agent';",
      'const res = await fetch(url);',
      'return fetch (url, { method: "GET" });',
      'globalThis.fetch(url);',
      "globalThis['fetch'](url);",
    ];
    for (const sample of forbidden) {
      expect(directNetworkUses(sample), sample).not.toEqual([]);
    }

    const allowed = [
      "import { createHash } from 'node:crypto';",
      "import { open } from 'node:fs/promises';",
      "import { createInterface } from 'node:readline';",
      "import { isEgressError } from '@qauth-labs/server-egress';",
      'await egress.request({ method: "GET" });',
      'const prefetch = (x: number) => x;',
      'lookup.fetch(url);',
      '// the egress client does the fetching',
    ];
    for (const sample of allowed) {
      expect(directNetworkUses(sample), sample).toEqual([]);
    }
  });
});
