import { describe, expect, it } from 'vitest';

import * as schemas from '../schemas';
import { DEV_SESSION_COOKIE_SECRET_DEFAULT } from '../schemas';
import { envSchemaShape } from './drift';
import { CONFIG_KEY_REGISTRY, SERVER_CONFIG_KEYS } from './keys';
import { describeDefault, renderConfigurationPage } from './page';
import { defineKeys } from './types';

/**
 * The configuration page on the docs site is generated from the registry
 * (`operate/configuration.md`). These tests check what the registry renders.
 * The check that the committed page is that rendering, formatted with Oxfmt,
 * lives in the `docs-checks` project (apps/docs-checks), beside the docs it
 * reads: `pnpm nx test docs-checks -- -u` rewrites the page (#1044).
 */

const generated = renderConfigurationPage(CONFIG_KEY_REGISTRY);

function generatedPage(): string {
  return generated;
}

/** The page's table row for a key. */
function rowOf(page: string, name: string): string | undefined {
  return page.split('\n').find((line) => line.startsWith(`| \`${name}\` `));
}

describe('the configuration page', () => {
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
