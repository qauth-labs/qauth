/**
 * A realm's brand settings. Only four inputs may change a token: the primary colour, the accent
 * colour, a font from a fixed list, and whether dark mode is on. The logo, per-locale strings and
 * links are data, not tokens, and are not handled here.
 *
 * {@link applyBrand} validates the settings and returns the whole theme stylesheet with them
 * applied. Serve it in place of `styles/theme.css`, never beside it: with `darkMode: false` it
 * leaves out the dark set, which `theme.css` would bring back.
 */
import { contrastRatio, oklchToRgb, parseHex, type Rgb, toHex } from './color';
import { themeCss } from './theme-css';
import {
  COLOR_TOKENS,
  type ColorMode,
  type ColorToken,
  contrastFailures,
  oklchCss,
} from './tokens';

/**
 * The fonts a brand may pick. Each is self-hosted by `libs/ui` or is the system's own, so a brand
 * never loads a font from elsewhere. Adding one means shipping its files first.
 */
export const BRAND_FONTS = {
  /** The design system's pair: DM Sans for text, Instrument Serif for headings. */
  qauth: null,
  /** The operating system's interface font, for text and headings. */
  system: "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
} as const;

export type BrandFont = keyof typeof BRAND_FONTS;

/** One colour for both modes, or one per mode. Colours are `#rrggbb`. */
export type BrandColor = string | { light: string; dark?: string };

export interface Brand {
  /** The fill of primary actions. Its text is the theme's `primary-foreground`. */
  primary?: BrandColor;
  /** The brand accent (`highlight`): emphasis and selected states, drawn as text on the page. */
  accent?: BrandColor;
  font?: BrandFont;
  /** `false` keeps the realm's pages light. Defaults to `true`. */
  darkMode?: boolean;
}

/** Thrown by {@link applyBrand} with every problem it found, so an admin sees them all at once. */
export class BrandError extends Error {
  readonly issues: readonly string[];
  constructor(issues: string[]) {
    super(`Invalid brand settings: ${issues.join('; ')}`);
    this.name = 'BrandError';
    this.issues = issues;
  }
}

/** Fragments that could end a declaration or pull in a resource, refused in every value. */
const FORBIDDEN = ['url(', ';', '{', '}'] as const;

const KEYS = new Set(['primary', 'accent', 'font', 'darkMode']);

/** The hover fill: the primary darkened, so the text on it keeps at least its contrast. */
const HOVER_SHADE = 0.88;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function forbiddenIn(value: unknown, path: string, issues: string[]): void {
  if (typeof value === 'string') {
    const lower = value.toLowerCase();
    for (const fragment of FORBIDDEN) {
      if (lower.includes(fragment)) issues.push(`${path} contains "${fragment}"`);
    }
  } else if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) forbiddenIn(child, `${path}.${key}`, issues);
  }
}

/** Reads a brand colour into one sRGB value per mode, or records why it cannot. */
function readColor(
  value: unknown,
  path: string,
  issues: string[]
): Record<ColorMode, Rgb> | undefined {
  const hex = (v: unknown, at: string): Rgb | undefined => {
    const rgb = typeof v === 'string' ? parseHex(v) : null;
    if (!rgb) issues.push(`${at} must be a colour written #rrggbb`);
    return rgb ?? undefined;
  };
  if (typeof value === 'string') {
    const rgb = hex(value, path);
    return rgb && { light: rgb, dark: rgb };
  }
  if (isRecord(value)) {
    for (const key of Object.keys(value)) {
      if (key !== 'light' && key !== 'dark') issues.push(`${path}.${key} is not a mode`);
    }
    const light = hex(value['light'], `${path}.light`);
    const dark = value['dark'] === undefined ? light : hex(value['dark'], `${path}.dark`);
    return light && dark && { light, dark };
  }
  issues.push(`${path} must be a colour written #rrggbb, or { light, dark }`);
  return undefined;
}

function token(cssVar: string): ColorToken {
  const found = COLOR_TOKENS.find((t) => t.cssVar === cssVar);
  if (!found) throw new Error(`No colour token ${cssVar}`);
  return found;
}

function shade({ r, g, b }: Rgb, factor: number): Rgb {
  return { r: r * factor, g: g * factor, b: b * factor, alpha: 1 };
}

/**
 * Validates a realm's brand settings and returns the theme stylesheet with them applied.
 *
 * It refuses, with a {@link BrandError} listing every problem:
 * - a setting other than the four above, or a value of the wrong type;
 * - any value containing `url(`, `;`, `{` or `}`;
 * - a colour not written `#rrggbb`;
 * - a font outside {@link BRAND_FONTS};
 * - a colour below the contrast its tokens declare against their backgrounds (4.5:1 for text), in
 *   any mode the stylesheet will have.
 *
 * Links and text buttons use the primary colour where it reaches 4.5:1 on the page in that mode,
 * and the text colour where it does not.
 */
export function applyBrand(input: unknown): string {
  const issues: string[] = [];
  const brand = input ?? {};
  if (!isRecord(brand)) throw new BrandError(['the brand settings must be an object']);

  for (const key of Object.keys(brand)) {
    if (!KEYS.has(key)) issues.push(`brand.${key} is not a brand setting`);
  }
  forbiddenIn(brand, 'brand', issues);

  const darkMode = brand['darkMode'] ?? true;
  if (typeof darkMode !== 'boolean') issues.push('brand.darkMode must be true or false');

  const font = brand['font'];
  if (font !== undefined && !(typeof font === 'string' && Object.hasOwn(BRAND_FONTS, font))) {
    issues.push(`brand.font must be one of: ${Object.keys(BRAND_FONTS).join(', ')}`);
  }

  const primary =
    brand['primary'] === undefined
      ? undefined
      : readColor(brand['primary'], 'brand.primary', issues);
  const accent =
    brand['accent'] === undefined ? undefined : readColor(brand['accent'], 'brand.accent', issues);
  if (issues.length > 0) throw new BrandError(issues);

  const modes: ColorMode[] = darkMode === false ? ['light'] : ['light', 'dark'];
  const values: Record<ColorMode, Map<string, Rgb>> = { light: new Map(), dark: new Map() };
  for (const mode of modes) {
    const set = values[mode];
    if (primary) {
      set.set('--primary', primary[mode]);
      set.set('--primary-hover', shade(primary[mode], HOVER_SHADE));
      const onPage = token('--primary-text').contrast.every((rule) =>
        rule.on.every((bgPath) => {
          const bg = COLOR_TOKENS.find((t) => t.path === bgPath);
          return bg && contrastRatio(primary[mode], oklchToRgb(bg[mode])) >= rule.min;
        })
      );
      set.set('--primary-text', onPage ? primary[mode] : oklchToRgb(token('--foreground')[mode]));
    }
    if (accent) set.set('--highlight', accent[mode]);
  }

  const changed = new Set([...values.light.keys(), ...values.dark.keys()]);
  const failures = contrastFailures(
    COLOR_TOKENS,
    modes,
    (t, mode) => values[mode].get(t.cssVar) ?? oklchToRgb(t[mode])
  ).filter((f) => {
    const fg = COLOR_TOKENS.find((t) => t.path === f.foreground);
    const bg = COLOR_TOKENS.find((t) => t.path === f.background);
    return changed.has(fg?.cssVar ?? '') || changed.has(bg?.cssVar ?? '');
  });
  for (const f of failures) {
    const name = (path: string) => COLOR_TOKENS.find((t) => t.path === path)?.cssVar.slice(2);
    const setting = name(f.foreground) === 'highlight' ? 'brand.accent' : 'brand.primary';
    issues.push(
      `${setting}: ${name(f.foreground)} on ${name(f.background)} is ${f.ratio.toFixed(2)}:1 in ${f.mode} mode, below ${f.min}:1`
    );
  }
  if (issues.length > 0) throw new BrandError([...new Set(issues)]);

  const css = (set: Map<string, Rgb>) =>
    Object.fromEntries([...set].map(([cssVar, rgb]) => [cssVar, toHex(rgb)]));
  const fontStack = typeof font === 'string' ? BRAND_FONTS[font as BrandFont] : null;
  return themeCss({
    colors: { light: css(values.light), dark: css(values.dark) },
    statics: fontStack ? { '--font-sans': fontStack, '--font-display': fontStack } : {},
    darkMode: darkMode !== false,
  });
}

/** The CSS text of a token's default value in a mode, for callers that show the defaults. */
export function defaultColor(cssVar: string, mode: ColorMode): string {
  return oklchCss(token(cssVar)[mode]);
}
