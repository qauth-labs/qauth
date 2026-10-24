import { join, resolve } from 'node:path';

import { format, resolveConfig } from 'prettier';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  evidenceLink,
  EXPERIMENTAL_FEATURES_PAGE_PATH,
  renderExperimentalFeaturesPage,
} from './docs-page';
import { experimentalDocsUrl, headingAnchor } from './enabled';
import { PROMOTION_CONDITIONS } from './item';
import { EXPERIMENTAL_ITEMS } from './items';

/**
 * The docs page `reference/experimental-features.md` is generated from the
 * registry. This test is the generator: when the registry changes,
 * `pnpm nx test shared-stability -- -u` rewrites the page, and without `-u`
 * the test fails until the committed page matches.
 *
 * The rendered page goes through Prettier first, so the committed file is
 * already formatted and the pre-commit hook never rewrites it.
 */

const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');
const PAGE_PATH = join(REPO_ROOT, EXPERIMENTAL_FEATURES_PAGE_PATH);

let page = '';
beforeAll(async () => {
  const options = await resolveConfig(PAGE_PATH);
  page = await format(renderExperimentalFeaturesPage(EXPERIMENTAL_ITEMS), {
    ...options,
    filepath: PAGE_PATH,
  });
});

/** The section of one item: from its heading to the next. */
function sectionOf(id: string): string {
  const start = page.indexOf(`\n### ${id}\n`);
  if (start === -1) return '';
  const next = page.indexOf('\n### ', start + 1);
  return page.slice(start, next === -1 ? undefined : next);
}

describe('the experimental features page', () => {
  it('is what the registry renders (regenerate with `pnpm nx test shared-stability -- -u`)', async () => {
    await expect(page).toMatchFileSnapshot(PAGE_PATH);
  });

  it('carries the frontmatter the docs collection requires', () => {
    expect(page).toMatch(
      /^---\ntitle: Experimental features\ndescription: .+\nsidebar:\n {2}order: \d+\nlastVerified: '\d{4}-\d{2}-\d{2}'\n---\n/
    );
  });

  // The acceptance criterion of #476: the page lists all six items with their
  // conditions.
  it.each(EXPERIMENTAL_ITEMS.map((item) => [item.id, item] as const))(
    'lists %s with its four conditions',
    (id, item) => {
      expect(page).toContain(`[\`${id}\`](#${headingAnchor(id)})`);
      const section = sectionOf(id);
      expect(section).not.toBe('');
      expect(section).toContain(item.description);
      for (const condition of PROMOTION_CONDITIONS) {
        expect(section).toMatch(
          new RegExp(`\\| \\d\\. ${condition.text.replace(/\./g, '\\.')} +\\| (yes|no) +\\|`)
        );
      }
    }
  );

  it('has a section for the link of every boot warning', () => {
    for (const item of EXPERIMENTAL_ITEMS) {
      const fragment = experimentalDocsUrl(item).split('#')[1];
      expect(headingAnchor(item.id)).toBe(fragment);
      expect(page).toContain(`\n### ${item.id}\n`);
    }
  });

  it('lists the four conditions of ADR-018 §5', () => {
    expect(page).toContain(
      PROMOTION_CONDITIONS.map((condition, index) => `${index + 1}. ${condition.text}`).join('\n')
    );
  });
});

describe('evidenceLink', () => {
  it.each([
    ['RFC 9449', '[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)'],
    ['#476', '[#476](https://github.com/qauth-labs/qauth/issues/476)'],
    ['https://example.com/spec', '<https://example.com/spec>'],
    [
      'docs/security/audit.md#wallet',
      '[`docs/security/audit.md#wallet`](https://github.com/qauth-labs/qauth/blob/main/docs/security/audit.md#wallet)',
    ],
  ])('links %s', (evidence, link) => {
    expect(evidenceLink(evidence)).toBe(link);
  });
});
