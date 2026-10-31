import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { ordered, policyField } from './field';
import {
  describeClass,
  describePolicyDefault,
  describeStricterWhen,
  REALM_POLICIES_PAGE_PATH,
  renderRealmPoliciesPage,
} from './page';
import { REALM_POLICY_REGISTRY } from './realm-policies';
import { createPolicyRegistry } from './registry';

/**
 * The docs page `reference/realm-policies.md` is generated from the schema
 * (#514). This test is the generator: when the schema changes,
 * `pnpm nx test server-realm-policy -- -u` rewrites the page, and without
 * `-u` the test fails until the committed page matches.
 *
 * The rendered page goes through Oxfmt first, so the committed file is
 * already formatted and the formatter never rewrites it.
 */

const REPO_ROOT = join(__dirname, '..', '..', '..', '..', '..');
const PAGE_PATH = join(REPO_ROOT, REALM_POLICIES_PAGE_PATH);

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

/** The body of the `### <heading>` section, up to the next heading. */
function sectionOf(page: string, heading: string): string {
  const start = page.indexOf(`\n### ${heading}\n`);
  if (start === -1) return '';
  const next = page.slice(start + 1).search(/\n#{2,3} /);
  return next === -1 ? page.slice(start) : page.slice(start, start + 1 + next);
}

/** The rows of a table in `section`, as trimmed cells, without the header and the rule. */
function tableRows(section: string): string[][] {
  return section
    .split('\n')
    .filter((line) => line.startsWith('|'))
    .slice(2)
    .map((line) =>
      line
        .slice(1, -1)
        .split(/(?<!\\)\|/)
        .map((cell) => cell.trim())
    );
}

let page = '';
beforeAll(() => {
  page = formatAs(PAGE_PATH, renderRealmPoliciesPage(REALM_POLICY_REGISTRY));
});

describe('the realm policies page (#514)', () => {
  // Acceptance criterion of #514: the generated page matches the schema.
  it('is what the schema renders (regenerate with `pnpm nx test server-realm-policy -- -u`)', async () => {
    await expect(page).toMatchFileSnapshot(PAGE_PATH);
  });

  it('carries the frontmatter the docs collection requires', () => {
    expect(page).toMatch(
      /^---\ntitle: Realm policies\ndescription: .+\nsidebar:\n {2}order: \d+\nlastVerified: '\d{4}-\d{2}-\d{2}'\n---\n/
    );
  });

  it('lists every field of every group with its default, seed key, direction and class', () => {
    for (const group of REALM_POLICY_REGISTRY.groups()) {
      const rows = tableRows(sectionOf(page, `\`${group}\``));
      const fields = REALM_POLICY_REGISTRY.fields().filter((entry) => entry.segments[0] === group);
      expect(
        rows.map((cells) => cells.slice(0, 5)),
        group
      ).toEqual(
        fields.map(({ path, field }) => [
          `\`${path}\``,
          describePolicyDefault(field),
          field.seedEnv === null ? 'none' : `\`${field.seedEnv}\``,
          describeStricterWhen(field),
          describeClass(field),
        ])
      );
      for (const { field } of fields) expect(page).toContain(field.doc.summary);
    }
  });

  it('keeps a default or an order value with a pipe, a backslash or a backtick in its cell and its code', () => {
    const annotations = {
      seedEnv: null,
      secret: false,
      environmentBound: false,
      doc: { summary: 'A setting for this test.', link: 'https://docs.qauth.dev/reference/' },
    } as const;
    const registry = createPolicyRegistry();
    registry.registerPolicyGroup('odd', {
      name: policyField(z.string(), {
        ...annotations,
        default: 'a|b`c',
        direction: 'opaque',
        securityWhen: 'never',
        effects: [],
      }),
      path: policyField(z.string(), {
        ...annotations,
        default: 'C:\\x|y\\',
        direction: 'opaque',
        securityWhen: 'never',
        effects: [],
      }),
      tick: policyField(z.string(), {
        ...annotations,
        default: 'x`y',
        direction: 'opaque',
        securityWhen: 'never',
        effects: [],
      }),
      level: policyField(z.enum(['lo|w', '`high`']), {
        ...annotations,
        default: 'lo|w',
        direction: ordered(['lo|w', '`high`']),
        securityWhen: 'never',
        effects: [],
      }),
    });
    const rows = tableRows(sectionOf(renderRealmPoliciesPage(registry), '`odd`'));
    expect(rows.map((cells) => cells.length)).toEqual([6, 6, 6, 6]);
    expect(rows[0][1]).toBe('<code>a&#124;b&#96;c</code>');
    expect(rows[1][1]).toBe('<code>C:&#92;x&#124;y&#92;</code>');
    expect(rows[2][1]).toBe('``x`y``');
    expect(rows[3][1]).toBe('<code>lo&#124;w</code>');
    expect(rows[3][3]).toBe('closer to `` `high` `` (<code>lo&#124;w</code> < `` `high` ``)');
  });

  it('names the schema version', () => {
    expect(page).toContain(`Schema version: \`${REALM_POLICY_REGISTRY.version}\`.`);
  });
});
