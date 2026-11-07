import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  UI_ASSET_FILES,
  UI_ASSET_NAME,
  UI_ASSET_NAME_MAX_LENGTH,
  UI_STYLESHEET_URL,
  uiAsset,
  uiStylesheetLink,
} from './ui-assets';
import { UI_PAGE_CSS } from './ui-page-css';

/**
 * The /ui pages' stylesheet and fonts (#472): what the set holds, how its
 * files are named, and that no page draws a colour, a font or a shadow of
 * its own.
 */

const APP_DIR = join(__dirname, '..');

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
    expect(UI_STYLESHEET_URL).toBe(`/assets/ui/${name}`);
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

  it('names every file in the shape the asset route accepts', () => {
    for (const name of UI_ASSET_FILES) {
      expect(name, name).toMatch(UI_ASSET_NAME);
      expect(name.length, name).toBeLessThanOrEqual(UI_ASSET_NAME_MAX_LENGTH);
    }
  });

  it('serves them outside /ui/, which the ceremony app holds once a proxy splits the two', () => {
    // ADR-019 Decision 5: `/ui/*`, `/ui/assets/` with it, goes to the ceremony
    // app, and pages outside `/ui/` (GET /auth/verify) link these files too.
    expect(UI_STYLESHEET_URL.startsWith('/assets/ui/')).toBe(true);
    expect(UI_STYLESHEET_URL.startsWith('/ui/')).toBe(false);
  });
});

/**
 * A colour, a font stack, a corner or a shadow written into a page's styles
 * instead of taken from a token. The QR code box's white is the one literal,
 * and it lives in `ui-page-css.ts`.
 */
const LITERAL_STYLE =
  /#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?|oklch|oklab|lab|lch|color)\(|system-ui|-apple-system|box-shadow|font-family:(?!\s*var\()|border-radius:(?!\s*var\()|(?<![\w-])(?:white|black)(?![\w-])/g;

/** The inline `<style nonce="…">` blocks of a source file's pages. */
function inlineStyles(source: string): string[] {
  return [...source.matchAll(/<style nonce="[^"]*">([\s\S]*?)<\/style>/g)].map(([, css]) => css);
}

/** The app's non-test sources. */
function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sources(path);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [path] : [];
  });
}

describe('no page draws a colour of its own (#472)', () => {
  it('takes every colour, font, corner and shadow in its inline styles from a token', () => {
    const found = sources(APP_DIR).flatMap((file) =>
      inlineStyles(readFileSync(file, 'utf8')).flatMap((css) =>
        [...css.matchAll(LITERAL_STYLE)].map(
          ([literal]) => `${relative(APP_DIR, file)}: ${literal}`
        )
      )
    );
    expect(found).toEqual([]);
  });

  it('finds the inline styles it checks', () => {
    // Non-vacuity: the sign-in page and the consent screen keep one each.
    const pages = sources(APP_DIR).filter(
      (file) => inlineStyles(readFileSync(file, 'utf8')).length
    );
    expect(pages.map((file) => relative(APP_DIR, file))).toEqual(
      expect.arrayContaining([join('routes', 'ui', 'login.ts'), join('routes', 'ui', 'consent.ts')])
    );
  });

  it('keeps the shared rules on tokens, but for the QR code box’s white', () => {
    const literals = [...UI_PAGE_CSS.matchAll(LITERAL_STYLE)].map(([literal]) => literal);
    expect(literals).toEqual(['#fff']);
    expect(UI_PAGE_CSS).toMatch(/\.qr \{[^}]*background-color: #fff;/);
  });

  it('never takes the focus ring away', () => {
    const css = [
      UI_PAGE_CSS,
      ...sources(APP_DIR).flatMap((f) => inlineStyles(readFileSync(f, 'utf8'))),
    ];
    for (const block of css) expect(block).not.toMatch(/outline\s*:/);
  });
});
