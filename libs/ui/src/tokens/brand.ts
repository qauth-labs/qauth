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
import {
  COLOR_TOKENS,
  type ColorMode,
  type ColorToken,
  contrastFailures,
  oklchCss,
} from './read-tokens';
import { themeCss } from './theme-css';

/**
 * The fonts a brand may pick. Each is self-hosted by `libs/ui` or is the system's own, so a brand
 * never loads a font from elsewhere. Adding one means shipping its files first. Frozen: the stack
 * reaches the stylesheet as written.
 */
export const BRAND_FONTS = Object.freeze({
  /** The design system's pair: DM Sans for text, Instrument Serif for headings. */
  qauth: null,
  /** The operating system's interface font, for text and headings. */
  system: "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
} as const);

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

const WHITE: Rgb = { r: 1, g: 1, b: 1, alpha: 1 };
const BLACK: Rgb = { r: 0, g: 0, b: 0, alpha: 1 };

/** A plain JSON-like object: not an array, a Map, a Date or a class instance. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function forbiddenIn(value: string, path: string, issues: string[]): void {
  const lower = value.toLowerCase();
  for (const fragment of FORBIDDEN) {
    if (lower.includes(fragment)) issues.push(`${path} contains "${fragment}"`);
  }
}

/**
 * Reads a brand colour into one sRGB value per mode, or records why it cannot. Only the two shapes
 * a colour may have are looked at, so a deep or cyclic value is refused, never walked.
 */
function readColor(
  value: unknown,
  path: string,
  issues: string[]
): Record<ColorMode, Rgb> | undefined {
  const hex = (v: unknown, at: string): Rgb | undefined => {
    if (typeof v !== 'string') {
      issues.push(`${at} must be a colour written #rrggbb`);
      return undefined;
    }
    forbiddenIn(v, at, issues);
    const rgb = parseHex(v);
    if (!rgb) issues.push(`${at} must be a colour written #rrggbb`);
    return rgb ?? undefined;
  };
  if (typeof value === 'string') {
    const rgb = hex(value, path);
    return rgb && { light: rgb, dark: rgb };
  }
  if (isPlainObject(value)) {
    for (const key of Object.keys(value)) {
      if (key !== 'light' && key !== 'dark') issues.push(`${path}.${key} is not a mode`);
    }
    const light = hex(value['light'], `${path}.light`);
    const dark = Object.hasOwn(value, 'dark') ? hex(value['dark'], `${path}.dark`) : light;
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

function byPath(path: string): ColorToken | undefined {
  return COLOR_TOKENS.find((t) => t.path === path);
}

function mix(from: Rgb, to: Rgb, amount: number): Rgb {
  const at = (a: number, b: number) => a + (b - a) * amount;
  return { r: at(from.r, to.r), g: at(from.g, to.g), b: at(from.b, to.b), alpha: 1 };
}

/**
 * The brand colour as link text in a mode: the colour itself where it reaches the floors of
 * `primary-text`, otherwise the nearest shade of it, toward white on a dark page and toward black
 * on a light one, that does. Links keep the brand's hue rather than turning into body text.
 */
function linkShade(color: Rgb, mode: ColorMode): Rgb {
  const rules = token('--primary-text').contrast;
  const passes = (c: Rgb) =>
    rules.every((rule) =>
      rule.on.every((path) => {
        const bg = byPath(path);
        return bg !== undefined && contrastRatio(c, oklchToRgb(bg[mode])) >= rule.min;
      })
    );
  const toward = mode === 'dark' ? WHITE : BLACK;
  for (let step = 0; step <= 50; step++) {
    const shade = mix(color, toward, step / 50);
    if (passes(shade)) return shade;
  }
  return toward;
}

function shade({ r, g, b }: Rgb, factor: number): Rgb {
  return { r: r * factor, g: g * factor, b: b * factor, alpha: 1 };
}

/**
 * Validates a realm's brand settings and returns the theme stylesheet with them applied.
 *
 * It refuses, with a {@link BrandError} listing every problem:
 * - settings that are not a plain object, a setting other than the four above, or a value of the
 *   wrong type (`null` included);
 * - any value containing `url(`, `;`, `{` or `}`;
 * - a colour not written `#rrggbb`;
 * - a font outside {@link BRAND_FONTS};
 * - a colour below the contrast its tokens declare against their backgrounds (4.5:1 for text), in
 *   any mode the stylesheet will have.
 *
 * Links and text buttons use the primary colour where it reaches 4.5:1 on the page in that mode,
 * and the nearest shade of it that does where it does not.
 */
export function applyBrand(input: unknown): string {
  const issues: string[] = [];
  const brand = input === undefined ? {} : input;
  if (!isPlainObject(brand)) throw new BrandError(['the brand settings must be an object']);

  for (const key of Object.keys(brand)) {
    if (!KEYS.has(key)) issues.push(`brand.${key} is not a brand setting`);
  }

  const darkMode = Object.hasOwn(brand, 'darkMode') ? brand['darkMode'] : true;
  if (typeof darkMode !== 'boolean') issues.push('brand.darkMode must be true or false');

  const font = Object.hasOwn(brand, 'font') ? brand['font'] : undefined;
  if (font !== undefined) {
    if (typeof font === 'string') forbiddenIn(font, 'brand.font', issues);
    if (!(typeof font === 'string' && Object.hasOwn(BRAND_FONTS, font))) {
      issues.push(`brand.font must be one of: ${Object.keys(BRAND_FONTS).join(', ')}`);
    }
  }

  const color = (key: 'primary' | 'accent') =>
    Object.hasOwn(brand, key) ? readColor(brand[key], `brand.${key}`, issues) : undefined;
  const primary = color('primary');
  const accent = color('accent');
  if (issues.length > 0) throw new BrandError([...new Set(issues)]);

  const modes: ColorMode[] = darkMode === false ? ['light'] : ['light', 'dark'];
  const values: Record<ColorMode, Map<string, Rgb>> = { light: new Map(), dark: new Map() };
  for (const mode of modes) {
    const set = values[mode];
    if (primary) {
      set.set('--primary', primary[mode]);
      set.set('--primary-hover', shade(primary[mode], HOVER_SHADE));
      set.set('--primary-text', linkShade(primary[mode], mode));
    }
    if (accent) set.set('--highlight', accent[mode]);
  }

  const changed = new Set([...values.light.keys(), ...values.dark.keys()]);
  const failures = contrastFailures(
    COLOR_TOKENS,
    modes,
    (t, mode) => values[mode].get(t.cssVar) ?? oklchToRgb(t[mode])
  ).filter(
    (f) =>
      changed.has(byPath(f.foreground)?.cssVar ?? '') ||
      changed.has(byPath(f.background)?.cssVar ?? '')
  );
  for (const f of failures) {
    const name = (path: string) => byPath(path)?.cssVar.slice(2);
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
