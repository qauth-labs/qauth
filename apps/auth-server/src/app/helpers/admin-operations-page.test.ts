import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

import { SECURITY_EFFECTS } from '@qauth-labs/shared-validation';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  type AdminOperation,
  createOperationRegistry,
  defineOperation,
  OPERATION_REGISTRY,
  type OperationRegistry,
} from './admin-operations';
import {
  renderSecurityOperationsPage,
  SECURITY_OPERATIONS_PAGE_PATH,
} from './admin-operations-page';
import type { ReservedOperation } from './admin-operations-reserved';

/**
 * The docs page `reference/security-operations.md` is generated from the
 * operation registry (#508). This test is the generator: when the registry or
 * the reserved table changes, `pnpm nx test auth-server -- -u` rewrites the
 * page, and without `-u` the test fails until the committed page matches.
 *
 * The rendered page goes through Oxfmt first, so the committed file is
 * already formatted and the formatter never rewrites it.
 */

const REPO_ROOT = join(__dirname, '..', '..', '..', '..', '..');
const PAGE_PATH = join(REPO_ROOT, SECURITY_OPERATIONS_PAGE_PATH);

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

/** The body of the `<marker> <heading>` section, up to the next heading of that level or above. */
function sectionOf(page: string, heading: string, marker = '##'): string {
  const start = page.indexOf(`\n${marker} ${heading}\n`);
  if (start === -1) return '';
  const next = page.slice(start + 1).search(new RegExp(`\\n#{2,${marker.length}} `));
  return page.slice(start, next === -1 ? undefined : start + 1 + next);
}

/** The rows of the tables in `section`, as trimmed cells, without headers and rules. */
function tableRows(section: string): string[][] {
  return section
    .split('\n')
    .filter((line) => line.startsWith('|') && !/^\|[\s|:-]+\|$/.test(line))
    .map((line) =>
      line
        .slice(1, -1)
        .split(/(?<!\\)\|/)
        .map((cell) => cell.trim())
    )
    .filter((cells) => cells[0] !== 'Operation' && cells[0] !== 'Effect');
}

const listCell = (values: readonly string[]) =>
  values.length === 0 ? 'none' : values.map((value) => `\`${value}\``).join(', ');

let page = '';
beforeAll(() => {
  page = formatAs(PAGE_PATH, renderSecurityOperationsPage(OPERATION_REGISTRY));
});

/** Every operation row of a page rendered from `registry`: id, class, effects, permissions. */
function operationRows(rendered: string) {
  return tableRows(sectionOf(rendered, 'Operations')).map(([id, cls, effects, permissions]) => [
    id,
    cls,
    effects,
    permissions,
  ]);
}

const expectedOperationRows = (registry: OperationRegistry) =>
  registry.all.map((operation) => [
    `\`${operation.id}\``,
    operation.class,
    listCell(operation.effects),
    listCell(operation.permissions),
  ]);

describe('the security operations page (#508)', () => {
  it('is what the registry renders (regenerate with `pnpm nx test auth-server -- -u`)', async () => {
    await expect(page).toMatchFileSnapshot(PAGE_PATH);
  });

  it('carries the frontmatter the docs collection requires', () => {
    expect(page).toMatch(
      /^---\ntitle: Security operations\ndescription: .+\nsidebar:\n {2}order: \d+\nlastVerified: '\d{4}-\d{2}-\d{2}'\n---\n/
    );
  });

  it('lists every effect tag with its description', () => {
    expect(tableRows(sectionOf(page, 'Effects')).map(([effect]) => effect)).toEqual(
      SECURITY_EFFECTS.map((effect) => `\`${effect}\``)
    );
  });

  // Acceptance criterion: the generated page lists every operation, class and
  // effect, compared with the registry.
  it('lists every registered operation with its class, effects and permissions, and nothing else', () => {
    expect(operationRows(page)).toEqual(expectedOperationRows(OPERATION_REGISTRY));
    if (OPERATION_REGISTRY.all.length === 0) {
      expect(sectionOf(page, 'Operations')).toContain('No admin operation is registered yet.');
    }
  });

  it('lists every reserved id under each of its effects, with its effects', () => {
    for (const effect of SECURITY_EFFECTS) {
      const rows = tableRows(sectionOf(page, `\`${effect}\``, '###'));
      expect(rows.map(([id, effects]) => [id, effects])).toEqual(
        OPERATION_REGISTRY.reserved
          .filter((entry) => entry.effects.includes(effect))
          .map((entry) => [`\`${entry.id}\``, listCell(entry.effects)])
      );
    }
  });

  // No admin route exists yet (#511 adds the listener): the page states the
  // rules for the routes that come, never that they protect today.
  it('says that no admin API route exists yet', () => {
    expect(page.replace(/\s+/g, ' ')).toContain(
      'No admin API route exists yet, so the rules below protect nothing today'
    );
  });

  // ADR-019 Decision 7 and #508: the two exceptions the registry respects.
  it('states what is not a security operation', () => {
    const flat = page.replace(/\s+/g, ' ');
    expect(flat).toContain(
      'Sending a set-up or reset link to the contact address already on the account.'
    );
    expect(flat).toContain('Copying the link is a security operation.');
    expect(flat).toContain(
      'Brand strings and links. They are display data, under `qauth:admin:write`.'
    );
  });

  it('promises the ids from 1.0.0 on, not from their first publication', () => {
    expect(sectionOf(page, 'Stability').replace(/\s+/g, ' ')).toContain(
      'they are promised from 1.0.0 on'
    );
  });
});

describe('renderSecurityOperationsPage', () => {
  const reserved: readonly ReservedOperation[] = [
    {
      id: 'widgets.rotate',
      effects: ['key-custody', 'token-content'],
      source: 'a | test',
      description: 'Rotate a widget.',
    },
  ];
  const operations = [
    defineOperation({
      id: 'widgets.get',
      class: 'read',
      effects: [],
      permissions: ['realms.read'],
      description: 'Read a widget.',
    }),
    defineOperation({
      id: 'widgets.rotate',
      class: 'security',
      effects: ['key-custody', 'token-content'],
      permissions: ['realms.policies.security'],
      description: 'Rotate a | widget.',
    }),
    defineOperation({
      id: 'widgets.policies.update',
      class: 'security',
      effects: ['credential-path'],
      permissions: ['realms.policies.write', 'realms.policies.security'],
      description: 'Change widget policies.',
      classify: () => ({ class: 'write', effects: [], permissions: ['realms.policies.write'] }),
    }),
  ] as AdminOperation[];
  const registry = createOperationRegistry(operations, { reserved });
  const rendered = renderSecurityOperationsPage(registry);

  it('renders operations another issue registers, every class and effect', () => {
    expect(operationRows(rendered)).toEqual(expectedOperationRows(registry));
    expect(rendered).toContain('Rotate a \\| widget.');
    expect(rendered).toContain('Change widget policies. Decided per request.');
  });

  it('marks a reserved id registered once its operation is, under each of its effects', () => {
    for (const effect of ['key-custody', 'token-content']) {
      expect(tableRows(sectionOf(rendered, `\`${effect}\``, '###'))).toEqual([
        [
          '`widgets.rotate`',
          '`key-custody`, `token-content`',
          'yes',
          'a \\| test',
          'Rotate a widget.',
        ],
      ]);
    }
  });

  it('names the effects no reserved id covers', () => {
    expect(rendered).toContain('No operation is reserved yet for `credential-path`');
  });
});
