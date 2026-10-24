import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import * as schemas from '../schemas';
import { DEV_SESSION_COOKIE_SECRET_DEFAULT } from '../schemas';
import { envSchemaShape } from './drift';
import { CONFIG_KEY_REGISTRY, SERVER_CONFIG_KEYS } from './keys';
import { CONFIGURATION_PAGE_PATH, describeDefault, renderConfigurationPage } from './page';
import { type ConfigKey, defineKeys } from './types';

/**
 * The configuration page on the docs site is generated from the registry
 * (`operate/configuration.md`). This test is the generator: when the registry
 * changes, `pnpm nx test server-config -- -u` rewrites the page, and without
 * `-u` the test fails until the committed page matches.
 *
 * The rendered page goes through Oxfmt first, so the committed file is
 * already formatted and the pre-commit hook never rewrites it.
 */

const REPO_ROOT = resolve(__dirname, '../../../../../..');
const PAGE_PATH = join(REPO_ROOT, CONFIGURATION_PAGE_PATH);

/** Oxfmt's command line, which formats with the repository's `.oxfmtrc.json`. */
const OXFMT = join(
  dirname(createRequire(__filename).resolve('oxfmt/package.json')),
  'bin',
  'oxfmt'
);

/** `text` as Oxfmt formats the file at `path`. */
function formatAs(path: string, text: string): string {
  return execFileSync(process.execPath, [OXFMT, `--stdin-filepath=${path}`], {
    cwd: REPO_ROOT,
    input: text,
    encoding: 'utf8',
  });
}

async function formattedPage(registry: readonly ConfigKey[]): Promise<string> {
  return formatAs(PAGE_PATH, renderConfigurationPage(registry));
}

/**
 * The generated page. The first test pins the committed file to it, so the
 * other tests read it from memory and pass or fail in any order.
 */
let generated = '';
beforeAll(async () => {
  generated = await formattedPage(CONFIG_KEY_REGISTRY);
});

function generatedPage(): string {
  return generated;
}

/** The page's table row for a key. */
function rowOf(page: string, name: string): string | undefined {
  return page.split('\n').find((line) => line.startsWith(`| \`${name}\` `));
}

describe('the configuration page', () => {
  it('is what the registry renders (regenerate with `pnpm nx test server-config -- -u`)', async () => {
    await expect(generated).toMatchFileSnapshot(PAGE_PATH);
  });

  it.each(
    CONFIG_KEY_REGISTRY.filter((key) => key.tier === 'stable').map(
      (key) => [key.name, key] as const
    )
  )('lists the stable key %s with its default and its sentence', (name, key) => {
    const page = generatedPage();
    const row = rowOf(page, name);

    expect(row).toBeDefined();
    expect(row).toContain(describeDefault(key));
    expect(row).toContain(key.docs);

    // In the stable section, not a later one.
    const at = page.indexOf(row ?? '');
    expect(at).toBeGreaterThan(page.indexOf('\n## Stable keys\n'));
    expect(at).toBeLessThan(page.indexOf('\n## Advanced keys\n'));
  });

  it('lists every key once', () => {
    const page = generatedPage();

    for (const key of CONFIG_KEY_REGISTRY) {
      expect(page.split('\n').filter((line) => line.startsWith(`| \`${key.name}\` `))).toHaveLength(
        key.experimentalValues.length > 0 ? 2 : 1
      );
    }
  });

  it('orders the sections: stable, advanced, experimental, then renamed keys', () => {
    const page = generatedPage();
    const headings = [
      '## Stable keys',
      '## Advanced keys',
      '## Experimental keys',
      '## Renamed keys',
    ].map((heading) => page.indexOf(`\n${heading}\n`));

    expect(headings.every((at) => at > 0)).toBe(true);
    expect([...headings].sort((a, b) => a - b)).toEqual(headings);
  });

  it('lists each old name with the key that replaces it', () => {
    expect(generatedPage()).toMatch(
      /^\| `REQUIRE_EMAIL_VERIFIED` +\| `REQUIRE_VERIFIED_ACCOUNT` +\| 0\.1\.0 +\|$/m
    );
  });

  it('states the rule of each tier', () => {
    const page = generatedPage();

    expect(page).toContain('**Stable** keys follow the deprecation policy.');
    expect(page).toContain('**Advanced** keys may change in a minor release.');
    expect(page).toContain('**Experimental** keys may change at any time');
  });
});

describe('no secret value reaches the configuration page', () => {
  it("never prints a secret key's schema default", () => {
    const page = generatedPage();
    const fields = new Map<string, unknown>();
    for (const [name, schema] of Object.entries(schemas)) {
      if (!name.endsWith('EnvSchema')) continue;
      for (const [key, field] of Object.entries(envSchemaShape(schema as never))) {
        fields.set(key, field);
      }
    }

    const secrets = SERVER_CONFIG_KEYS.filter((key) => key.secret);
    expect(secrets.length).toBeGreaterThan(0);
    for (const key of secrets) {
      const field = fields.get(key.name) as { safeParse(value: unknown): { data?: unknown } };
      const fallback = field.safeParse(undefined).data;
      if (typeof fallback === 'string' && fallback !== '') {
        expect(page, key.name).not.toContain(fallback);
      }
    }
    expect(page).not.toContain(DEV_SESSION_COOKIE_SECRET_DEFAULT);
  });

  it('prints "not shown" for a secret that has a literal default', () => {
    const [secret] = defineKeys([
      {
        name: 'A_SECRET',
        tier: 'stable',
        role: 'deployment',
        owner: 'server',
        default: 'hunter2-default-secret',
        since: '0.1.0',
        secret: true,
        docs: 'A secret for this test.',
      },
    ]);

    const page = renderConfigurationPage([secret]);

    expect(page).not.toContain('hunter2-default-secret');
    expect(rowOf(page, 'A_SECRET')).toContain('| not shown |');
  });
});
