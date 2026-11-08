import { beforeAll, describe, expect, it } from 'vitest';

import { headingAnchor, markdownHeadingAnchors } from './anchor';
import { evidenceLink, renderExperimentalFeaturesPage } from './docs-page';
import { experimentalDocsUrl } from './enabled';
import { PROMOTION_CONDITIONS } from './item';
import { EXPERIMENTAL_ITEMS } from './items';

/**
 * The docs page `reference/experimental-features.md` is generated from the
 * registry. These tests check what the registry renders. The check that the
 * committed page is that rendering, formatted with Oxfmt, lives in the
 * `docs-checks` project (apps/docs-checks), beside the docs it reads:
 * `pnpm nx test docs-checks -- -u` rewrites the page (#1044).
 */

let page = '';
beforeAll(() => {
  page = renderExperimentalFeaturesPage(EXPERIMENTAL_ITEMS);
});

/** `text` as a regular expression that matches it literally. */
function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** The section of one item: from its heading to the next. */
function sectionOf(id: string): string {
  const start = page.indexOf(`\n### ${id}\n`);
  if (start === -1) return '';
  const next = page.indexOf('\n### ', start + 1);
  return page.slice(start, next === -1 ? undefined : next);
}

describe('the experimental features page', () => {
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
          new RegExp(`\\| \\d\\. ${escapeRegExp(condition.text)} +\\| (yes|no) +\\|`)
        );
      }
    }
  );

  // The boot warning links an item's section by its anchor; the page's own
  // headings, read back from the rendered Markdown, must carry that anchor.
  it('has a heading for the link of every boot warning', () => {
    const anchors = markdownHeadingAnchors(page);
    for (const item of EXPERIMENTAL_ITEMS) {
      const fragment = experimentalDocsUrl(item).split('#')[1];
      expect(anchors.has(fragment), `${item.id} links #${fragment}`).toBe(true);
    }
    expect(anchors.has('oid4vp-10-base')).toBe(true);
  });

  // #477: the page names what each server item adds to discovery, and the
  // page that documents it.
  it.each(EXPERIMENTAL_ITEMS.map((item) => [item.id, item] as const))(
    'names the discovery members and the docs page of %s',
    (id, item) => {
      const section = sectionOf(id);
      for (const member of item.discoveryMembers) expect(section).toContain(`\`${member}\``);
      if (item.surface === 'server' && item.discoveryMembers.length === 0) {
        expect(section).toContain('- Discovery members: none.');
      }
      expect(section).toContain(
        item.docsPage === null
          ? '- Documented in: no page yet.'
          : `- Documented in: [\`${item.docsPage}\`](${item.docsPage}).`
      );
    }
  );

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
