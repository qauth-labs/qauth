import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { UI_ASSET_FILES, UI_STYLESHEET_URL, uiAsset, uiStylesheetLink } from './ui-assets';
import { UI_PAGE_CSS } from './ui-page-css';

/**
 * The /ui pages' stylesheet and fonts (#472): what the set holds and how its
 * files are named.
 */

/** The first 8 hex digits of the SHA-256 of `content`. */
function hashOf(content: Buffer): string {
  return createHash('sha256').update(content).digest('hex').slice(0, 8);
}

function stylesheet(): string {
  const name = UI_ASSET_FILES[0];
  const asset = uiAsset(name);
  if (asset === undefined) throw new Error(`no stylesheet ${name}`);
  return asset.body.toString('utf8');
}

describe('the /ui pages’ asset set (#472)', () => {
  it('names the stylesheet by its content and links it from every page’s head', () => {
    const [name] = UI_ASSET_FILES;
    expect(name).toMatch(/^qauth-[0-9a-f]{8}\.css$/);
    expect(UI_STYLESHEET_URL).toBe(`/ui/assets/${name}`);
    expect(name).toBe(`qauth-${hashOf(Buffer.from(stylesheet(), 'utf8'))}.css`);
    expect(uiAsset(name)?.contentType).toBe('text/css; charset=utf-8');
    expect(uiStylesheetLink().value).toBe(`<link rel="stylesheet" href="${UI_STYLESHEET_URL}" />`);
  });

  it('serves each font as woff2 under a name that carries the hash of its bytes', () => {
    const fonts = UI_ASSET_FILES.slice(1);
    expect(fonts.length).toBeGreaterThan(0);
    for (const name of fonts) {
      const asset = uiAsset(name);
      const match = /^([a-z0-9-]+)-([0-9a-f]{8})\.woff2$/.exec(name);
      expect(match, name).not.toBeNull();
      expect(asset?.contentType, name).toBe('font/woff2');
      expect(match?.[2], name).toBe(hashOf(asset?.body ?? Buffer.alloc(0)));
      // A woff2 file starts with its signature, `wOF2`.
      expect(asset?.body.subarray(0, 4).toString('latin1'), name).toBe('wOF2');
    }
  });

  it('names in the stylesheet exactly the fonts it serves, and nothing from elsewhere', () => {
    const css = stylesheet();
    const urls = [...css.matchAll(/url\(([^)]*)\)/g)].map(([, url]) => url);
    expect(new Set(urls)).toEqual(new Set(UI_ASSET_FILES.slice(1)));
    expect(css).not.toContain('@import');
    expect(css).not.toMatch(/\/\/[a-z0-9.-]+\.[a-z]{2,}\//i);
  });

  it('loads the design system’s three faces, with their subsets, and no italic', () => {
    const css = stylesheet();
    for (const family of ['DM Sans Variable', 'Instrument Serif', 'JetBrains Mono Variable']) {
      expect(css, family).toContain(`font-family: '${family}';`);
    }
    expect(css).toMatch(/unicode-range: U\+0000-00FF/);
    expect(css).not.toContain('font-style: italic');
  });

  it('carries the theme in light and dark, then base.css, then the pages’ own rules', () => {
    const css = stylesheet();
    const theme = css.indexOf('--primary-foreground:');
    const dark = css.indexOf('@media (prefers-color-scheme: dark)');
    const base = css.indexOf('@layer base');
    const pages = css.indexOf(UI_PAGE_CSS);
    expect(theme).toBeGreaterThan(css.lastIndexOf('@font-face'));
    expect(dark).toBeGreaterThan(theme);
    expect(base).toBeGreaterThan(dark);
    expect(pages).toBeGreaterThan(base);
  });

  it.each(['qauth-00000000.css', 'dm-sans-latin-wght-normal.woff2', '../package.json', ''])(
    'has no file named %j',
    (name) => {
      expect(uiAsset(name)).toBeUndefined();
    }
  );

  it.each(['constructor', '__proto__', 'toString', 'hasOwnProperty'])(
    'has no file for the object key %s',
    (name) => {
      expect(uiAsset(name)).toBeUndefined();
    }
  );

  it('names every file as the reference proxy caches content-hashed /ui assets', () => {
    // Rule 6 of apps/docs-site/src/content/docs/operate/reverse-proxy.md, as
    // deploy/reference/proxy/nginx.conf writes it; nginx's `\z` is `$` here,
    // which without the `m` flag matches only at the end.
    const cacheable =
      /^\/ui\/assets\/(?:[A-Za-z0-9._-]+-)?[A-Za-z0-9_-]{8,}\.(?:js|mjs|css|woff2|woff|svg|png|jpg|jpeg|gif|webp|avif|ico)$/;
    for (const name of UI_ASSET_FILES) {
      expect(`/ui/assets/${name}`, name).toMatch(cacheable);
    }
  });
});
