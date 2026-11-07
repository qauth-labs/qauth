/**
 * Turns the tokens into stylesheets: the CSS custom properties for light and dark
 * (`styles/theme.css`) and the Tailwind v4 theme that maps utilities onto them
 * (`styles/tailwind-theme.css`). Both files are this module's output, checked in, and compared
 * with it by a test, so they cannot drift from `tokens.json`.
 */
import { COLOR_TOKENS, type ColorMode, oklchCss, STATIC_TOKENS } from './read-tokens';

const HEADER = (what: string) =>
  `/* ${what} Generated from libs/ui/src/tokens/tokens.json: do not edit by hand. Change the tokens, then run \`pnpm nx test ui -u\`. */\n`;

/** Values that replace the token defaults, as CSS text keyed by custom property. */
export interface ThemeOverrides {
  /** Colours per mode, e.g. `{ light: { '--primary': '#1d4ed8' } }`. */
  colors?: Partial<Record<ColorMode, Readonly<Record<string, string>>>>;
  /** Mode-independent values, e.g. `{ '--font-sans': 'system-ui, sans-serif' }`. */
  statics?: Readonly<Record<string, string>>;
  /**
   * With `false`, the stylesheet has no dark set: the page stays light whatever the system prefers
   * and whatever `data-theme` says. Defaults to `true`.
   */
  darkMode?: boolean;
}

function block(selector: string, lines: string[], indent = ''): string {
  return `${indent}${selector} {\n${lines.map((l) => `${indent}  ${l}\n`).join('')}${indent}}\n`;
}

function colorLines(mode: ColorMode, overrides: ThemeOverrides): string[] {
  const replaced = overrides.colors?.[mode] ?? {};
  return [
    `color-scheme: ${mode};`,
    ...COLOR_TOKENS.map((t) => `${t.cssVar}: ${replaced[t.cssVar] ?? oklchCss(t[mode])};`),
  ];
}

/**
 * The theme as plain CSS. The light set is on `:root`; the dark set applies when the system
 * prefers dark, unless the root says `data-theme="light"`, and wherever `data-theme="dark"` is set.
 * Any element may carry `data-theme` to fix its subtree to one mode.
 */
export function themeCss(overrides: ThemeOverrides = {}): string {
  const darkMode = overrides.darkMode ?? true;
  const statics = overrides.statics ?? {};
  const parts = [HEADER('QAuth design tokens as CSS custom properties.')];

  parts.push(
    block(
      darkMode
        ? ":root,\n[data-theme='light']"
        : ":root,\n[data-theme='light'],\n[data-theme='dark']",
      colorLines('light', overrides)
    )
  );
  parts.push(
    block(
      ':root',
      STATIC_TOKENS.map((t) => `${t.cssVar}: ${statics[t.cssVar] ?? t.css};`)
    )
  );
  if (darkMode) {
    parts.push(
      `@media (prefers-color-scheme: dark) {\n${block(":root:not([data-theme='light'])", colorLines('dark', overrides), '  ')}}\n`
    );
    parts.push(block("[data-theme='dark']", colorLines('dark', overrides)));
  }
  const durations = STATIC_TOKENS.filter((t) => t.cssVar.startsWith('--duration-'));
  parts.push(
    `@media (prefers-reduced-motion: reduce) {\n${block(
      ':root',
      durations.map((t) => `${t.cssVar}: 0ms;`),
      '  '
    )}}\n`
  );
  return parts.join('\n');
}

/**
 * The Tailwind v4 theme. Colours are `inline`, so a utility reads the variable itself and a
 * `data-theme` subtree switches it; the other tokens register Tailwind's own theme names, whose
 * values `theme.css` (or a brand stylesheet) sets on `:root`.
 */
export function tailwindThemeCss(): string {
  const colors = COLOR_TOKENS.map((t) => `--color-${t.cssVar.slice(2)}: var(${t.cssVar});`);
  const statics = STATIC_TOKENS.filter((t) => t.tailwindVar).map(
    (t) => `${t.tailwindVar}: ${t.css};`
  );
  return [
    HEADER('The Tailwind v4 theme of the QAuth design tokens.'),
    block('@theme inline', colors),
    block('@theme', statics),
  ].join('\n');
}
