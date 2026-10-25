import type { APIContext } from 'astro';
import { describe, expect, it } from 'vitest';

import { EXPERIMENTAL_BANNER, onRequest } from './experimental-banner';

/** Run the middleware over a page with frontmatter `data`, and return its banner. */
async function bannerOf(data: Record<string, unknown>): Promise<unknown> {
  const context = { locals: { starlightRoute: { entry: { data } } } } as unknown as APIContext;
  await onRequest(context, () => Promise.resolve());
  return data['banner'];
}

describe('the experimental banner (ADR-018 §5, #477)', () => {
  it('shows the Experimental banner on a page flagged experimental: true', async () => {
    expect(await bannerOf({ experimental: true })).toEqual({ content: EXPERIMENTAL_BANNER });
    expect(EXPERIMENTAL_BANNER).toContain('<strong>Experimental.</strong>');
    expect(EXPERIMENTAL_BANNER).toContain('href="/reference/experimental-features/"');
  });

  it('leaves a page that is not flagged as it is', async () => {
    expect(await bannerOf({ experimental: false })).toBeUndefined();
    expect(await bannerOf({ experimental: false, banner: { content: 'News.' } })).toEqual({
      content: 'News.',
    });
  });

  it("puts a flagged page's own banner after the Experimental one", async () => {
    expect(await bannerOf({ experimental: true, banner: { content: 'News.' } })).toEqual({
      content: `${EXPERIMENTAL_BANNER} News.`,
    });
  });
});
