import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

import { html, type SafeHtml } from './html';
import { UI_PAGE_CSS } from './ui-page-css';

/**
 * THE /ui PAGES' STYLESHEET AND FONTS (#472): QAuth's design system
 * (`@qauth-labs/ui`) on the pages the auth server renders.
 *
 * - One stylesheet: the fonts' `@font-face` rules, the design system's
 *   `theme.css` (its tokens, light and dark) and `base.css`, then the pages'
 *   own rules (`ui-page-css.ts`).
 * - The fonts' woff2 files: DM Sans and JetBrains Mono (variable) and
 *   Instrument Serif (regular, upright), from the `@fontsource` packages the
 *   design system depends on. Self-hosted: no page loads anything from another
 *   origin, which the CSP's `style-src 'self'` and `font-src 'self'` require.
 *
 * Every file is read once, when this module loads, and kept in memory; a file
 * that is missing fails the boot, not a page. Each is served under a name that
 * carries the first 8 hex digits of its content's SHA-256, such as
 * `qauth-1a2b3c4d.css` or `dm-sans-latin-wght-normal-1a2b3c4d.woff2`, so a
 * name never changes meaning and `routes/ui/assets.ts` serves it with a year's
 * immutable cache. The names also match the rule the reference proxy caches
 * content-hashed files under `/ui/assets/` by (`deploy/reference/proxy`).
 *
 * The `@font-face` rules are fontsource's own, with their `unicode-range` per
 * subset, so a browser fetches only the subsets a page's text needs. Only the
 * woff2 source of each is kept, renamed to its served file.
 */

/** Where the files are served: `routes/ui/assets.ts` under the `/ui` prefix. */
export const UI_ASSETS_PREFIX = '/ui/assets/';

/** One file of the set, as the asset route sends it. */
export interface UiAsset {
  readonly body: Buffer;
  readonly contentType: string;
}

/**
 * The fonts, as `libs/ui/src/styles/fonts.css` loads them for the apps with a
 * bundler, less Instrument Serif's italic, which no page sets.
 */
const FONT_STYLESHEETS = [
  '@fontsource-variable/dm-sans/index.css',
  '@fontsource/instrument-serif/400.css',
  '@fontsource-variable/jetbrains-mono/index.css',
] as const;

/** One `@font-face` rule of a fontsource stylesheet. */
const FONT_FACE_RULE = /@font-face\s*\{([^}]*)\}/g;

/** The woff2 source of a rule: the file beside the stylesheet, and its format. */
const WOFF2_SOURCE = /url\(\.\/files\/([a-z0-9-]+)\.woff2\)\s*format\('(woff2(?:-variations)?)'\)/;

/** The rule's `src` declaration, which the served one replaces. */
const SRC_DECLARATION = /\bsrc\s*:[^;]*;/;

/** The first 8 hex digits of the SHA-256 of `content`. */
function contentHash(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex').slice(0, 8);
}

/**
 * Read the design system's files and build the set: the stylesheet's served
 * name, and every file by its served name.
 */
function buildUiAssets(): { stylesheet: string; files: ReadonlyMap<string, UiAsset> } {
  // From this app, the design system's exported stylesheets; from the design
  // system, the font packages it depends on (pnpm links them beside it only).
  const fromServer = createRequire(__filename);
  const themeCss = fromServer.resolve('@qauth-labs/ui/theme.css');
  const baseCss = fromServer.resolve('@qauth-labs/ui/base.css');
  const fromDesignSystem = createRequire(themeCss);

  const files = new Map<string, UiAsset>();
  const fontFaces: string[] = [];
  for (const specifier of FONT_STYLESHEETS) {
    const stylesheet = fromDesignSystem.resolve(specifier);
    for (const [, declarations] of readFileSync(stylesheet, 'utf8').matchAll(FONT_FACE_RULE)) {
      const source = WOFF2_SOURCE.exec(declarations);
      if (source === null || !SRC_DECLARATION.test(declarations)) {
        throw new Error(`${specifier}: an @font-face rule with no woff2 source`);
      }
      const [, file, format] = source;
      const body = readFileSync(join(dirname(stylesheet), 'files', `${file}.woff2`));
      const served = `${file}-${contentHash(body)}.woff2`;
      files.set(served, { body, contentType: 'font/woff2' });
      fontFaces.push(
        `@font-face {${declarations.replace(SRC_DECLARATION, `src: url(${served}) format('${format}');`)}}`
      );
    }
  }
  if (fontFaces.length === 0) throw new Error('the design system names no font files');

  const css = [
    "/* QAuth /ui pages: the design system (@qauth-labs/ui) and the pages' own rules. */",
    ...fontFaces,
    readFileSync(themeCss, 'utf8'),
    readFileSync(baseCss, 'utf8'),
    UI_PAGE_CSS,
  ].join('\n');
  const stylesheet = `qauth-${contentHash(css)}.css`;
  files.set(stylesheet, { body: Buffer.from(css, 'utf8'), contentType: 'text/css; charset=utf-8' });
  return { stylesheet, files };
}

const UI_ASSETS = buildUiAssets();

/** The stylesheet's URL, which every page links. */
export const UI_STYLESHEET_URL = `${UI_ASSETS_PREFIX}${UI_ASSETS.stylesheet}`;

/** The served names of the set, the stylesheet's first. */
export const UI_ASSET_FILES: readonly string[] = [
  UI_ASSETS.stylesheet,
  ...[...UI_ASSETS.files.keys()].filter((name) => name !== UI_ASSETS.stylesheet),
];

/**
 * The file served under `name`, or `undefined` for any other name. The name
 * is only a key of the set built at load: no request value reaches a path.
 */
export function uiAsset(name: string): UiAsset | undefined {
  return UI_ASSETS.files.get(name);
}

/**
 * The `<link>` to the stylesheet, for a page's `<head>`, before any inline
 * `<style>` of its own so that its rules win. A same-origin file, so it needs
 * no CSP nonce.
 */
export function uiStylesheetLink(): SafeHtml {
  return html`<link rel="stylesheet" href="${UI_STYLESHEET_URL}" />`;
}
