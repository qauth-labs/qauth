import { defineRouteMiddleware } from '@astrojs/starlight/route-data';

/**
 * The banner of a page flagged `experimental: true` (ADR-018 §5, #477): the
 * page documents an item of the experimental-feature registry, which is off
 * until its switch is on and may change in a minor release. Starlight's own
 * `Banner` component renders it, as it renders a page's `banner` frontmatter.
 */
export const EXPERIMENTAL_BANNER =
  '<strong>Experimental.</strong> This page documents an experimental feature: it is off until its switch is on, and it may change in a minor release without a deprecation window. See <a href="/reference/experimental-features/">Experimental features</a>.';

export const onRequest = defineRouteMiddleware((context) => {
  const { data } = context.locals.starlightRoute.entry;
  if (!data.experimental) return;
  // A banner the page sets itself follows the experimental one.
  data.banner = {
    content:
      data.banner === undefined
        ? EXPERIMENTAL_BANNER
        : `${EXPERIMENTAL_BANNER} ${data.banner.content}`,
  };
});
