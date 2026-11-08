import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  REALM_POLICIES_PAGE_PATH,
  REALM_POLICY_REGISTRY,
  renderRealmPoliciesPage,
} from '@qauth-labs/server-realm-policy';
import { describe, expect, it } from 'vitest';

import { formatAs, REPO_ROOT } from './workspace';

/**
 * The realm policy schema of `@qauth-labs/server-realm-policy` against the
 * docs site (#514). The library's own tests check what the page renders;
 * these check the committed page and the pages the fields link to.
 */

const PAGE_PATH = join(REPO_ROOT, REALM_POLICIES_PAGE_PATH);

describe('the realm policies page (#514)', () => {
  // Acceptance criterion of #514: the generated page matches the schema. This
  // test is the generator: when the schema changes,
  // `pnpm nx test docs-checks -- -u` rewrites the page, and without `-u` the
  // test fails until the committed page matches.
  it('is what the schema renders (regenerate with `pnpm nx test docs-checks -- -u`)', async () => {
    const page = formatAs(PAGE_PATH, renderRealmPoliciesPage(REALM_POLICY_REGISTRY));
    await expect(page).toMatchFileSnapshot(PAGE_PATH);
  });
});

describe('every realm policy field', () => {
  it('links to a page of the docs site, and to a heading on it', () => {
    const generated = renderRealmPoliciesPage(REALM_POLICY_REGISTRY);
    for (const { path, field } of REALM_POLICY_REGISTRY.fields()) {
      const [, page, anchor] =
        /^https:\/\/docs\.qauth\.dev\/([^#]*?)\/?(?:#(.+))?$/.exec(field.doc.link) ?? [];
      const base = join(REPO_ROOT, 'apps/docs-site/src/content/docs', page ?? '');
      const file = [
        `${base}.md`,
        `${base}.mdx`,
        join(base, 'index.md'),
        join(base, 'index.mdx'),
      ].find(existsSync);
      expect(file, `${path}: ${field.doc.link}`).toBeDefined();
      if (anchor === undefined || file === undefined) continue;
      const body = page === 'reference/realm-policies' ? generated : readFileSync(file, 'utf8');
      const anchors = [...body.matchAll(/^#{2,6} (.+)$/gm)].map((match) =>
        match[1]
          .replace(/`/g, '')
          .toLowerCase()
          .replace(/[^a-z0-9 _-]/g, '')
          .replace(/ /g, '-')
      );
      expect(anchors, `${path}: #${anchor}`).toContain(anchor);
    }
  });
});
