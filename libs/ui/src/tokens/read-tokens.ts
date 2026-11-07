/**
 * Reads the design token file (Design Tokens Community Group format 2025.10) into flat lists the
 * stylesheet generator and the contrast check use. The file is the one source of the values;
 * nothing here holds a colour or a size of its own.
 */
import { contrastRatio, type Oklch, oklchToRgb, type Rgb } from './color';
import tokenFile from './tokens.json';

/** The colour modes a token can have. Light is `$value`; dark sits under `$extensions`. */
export type ColorMode = 'light' | 'dark';

/** A colour value as the token file writes it. */
interface DtcgColor {
  colorSpace: 'oklch';
  components: [number, number, number];
  alpha?: number;
}

/** A contrast floor a foreground token declares against the backgrounds it is drawn on. */
export interface ContrastRule {
  min: number;
  /** Paths of the background tokens, e.g. `color.surface.card`. */
  on: string[];
}

/** One colour token, flattened. */
export interface ColorToken {
  /** Dotted path in the token file, e.g. `color.text.muted-foreground`. */
  path: string;
  /** The CSS custom property it becomes, e.g. `--muted-foreground`. */
  cssVar: string;
  light: Oklch;
  dark: Oklch;
  contrast: ContrastRule[];
}

/** One token that is the same in every mode (a font, a size, a duration). */
export interface StaticToken {
  path: string;
  cssVar: string;
  /** The value as CSS text. */
  css: string;
  /** The Tailwind theme variable it registers, or `null` when it registers none. */
  tailwindVar: string | null;
}

const EXT = 'dev.qauth.ui';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toOklch(value: unknown, path: string): Oklch {
  const v = value as DtcgColor;
  if (!isRecord(value) || v.colorSpace !== 'oklch' || v.components?.length !== 3) {
    throw new Error(
      `Token ${path}: a colour must be { colorSpace: "oklch", components: [L, C, H] }`
    );
  }
  const [l, c, h] = v.components;
  const alpha = v.alpha ?? 1;
  // A DTCG "none" component or a string would turn into NaN, and NaN passes every comparison
  // the contrast check makes, so only finite numbers are taken.
  if (![l, c, h, alpha].every((n) => typeof n === 'number' && Number.isFinite(n))) {
    throw new Error(`Token ${path}: colour components and alpha must be finite numbers`);
  }
  return { l, c, h, alpha };
}

/** Walks the token tree and calls `visit` on every token (a node with `$value`). */
function walk(
  node: Record<string, unknown>,
  path: string[],
  inheritedType: string | undefined,
  visit: (path: string[], type: string, token: Record<string, unknown>) => void
): void {
  const type = typeof node['$type'] === 'string' ? (node['$type'] as string) : inheritedType;
  if ('$value' in node) {
    if (!type) throw new Error(`Token ${path.join('.')} has no $type`);
    visit(path, type, node);
    return;
  }
  for (const [key, child] of Object.entries(node)) {
    if (key.startsWith('$') || !isRecord(child)) continue;
    walk(child, [...path, key], type, visit);
  }
}

function colorTokens(file: Record<string, unknown>): ColorToken[] {
  const out: ColorToken[] = [];
  walk(file, [], undefined, (path, type, token) => {
    if (type !== 'color') return;
    const dotted = path.join('.');
    const ext = isRecord(token['$extensions']) ? token['$extensions'] : {};
    // Modes in the form Terrazzo reads: `$extensions.mode.{light,dark}`, light equal to `$value`.
    const mode = ext['mode'];
    if (!isRecord(mode) || !('dark' in mode)) {
      throw new Error(`Colour token ${dotted} has no dark value under $extensions.mode.dark`);
    }
    if (JSON.stringify(mode['light']) !== JSON.stringify(token['$value'])) {
      throw new Error(`Colour token ${dotted}: $extensions.mode.light must equal $value`);
    }
    const own = ext[EXT];
    const contrast =
      isRecord(own) && Array.isArray(own['contrast'])
        ? (own['contrast'] as { min: number; on: string[] }[]).map((rule) => ({
            min: rule.min,
            on: rule.on.map((ref) => ref.replace(/^\{|\}$/g, '')),
          }))
        : [];
    out.push({
      path: dotted,
      // Colours keep the design system's short names (`--card`, `--muted-foreground`), which the
      // qauth.dev website uses too.
      cssVar: `--${path[path.length - 1]}`,
      light: toOklch(token['$value'], dotted),
      dark: toOklch(mode['dark'], dotted),
      contrast,
    });
  });
  return out;
}

/**
 * How each static token group becomes a CSS variable. The names are Tailwind's theme names where
 * Tailwind has one, so a Tailwind app's utilities (`font-sans`, `text-sm`, `rounded-control`,
 * `ease-standard`) read the same variable as a plain stylesheet does.
 */
const STATIC_GROUPS: { prefix: string; cssPrefix: string; tailwind: boolean }[] = [
  { prefix: 'font.family.', cssPrefix: '--font-', tailwind: true },
  { prefix: 'font.weight.', cssPrefix: '--font-weight-', tailwind: true },
  { prefix: 'font.size.', cssPrefix: '--text-', tailwind: true },
  { prefix: 'font.line-height.', cssPrefix: '--leading-', tailwind: true },
  { prefix: 'radius.', cssPrefix: '--radius-', tailwind: true },
  { prefix: 'motion.easing.', cssPrefix: '--ease-', tailwind: true },
  { prefix: 'motion.duration.', cssPrefix: '--duration-', tailwind: false },
  { prefix: 'focus.', cssPrefix: '--focus-', tailwind: false },
];

function cssValue(type: string, value: unknown, path: string): string {
  switch (type) {
    case 'fontFamily': {
      const names = Array.isArray(value) ? value : [value];
      const generic = new Set(['serif', 'sans-serif', 'monospace', 'system-ui', 'cursive']);
      return names.map((n: string) => (generic.has(n) ? n : `'${n}'`)).join(', ');
    }
    case 'fontWeight':
    case 'number':
      return String(value);
    case 'dimension':
    case 'duration': {
      const v = value as { value: number; unit: string };
      return `${v.value}${v.unit}`;
    }
    case 'cubicBezier':
      return `cubic-bezier(${(value as number[]).join(', ')})`;
    default:
      throw new Error(`Token ${path}: type ${type} has no CSS form here`);
  }
}

function staticTokens(file: Record<string, unknown>): StaticToken[] {
  const out: StaticToken[] = [];
  walk(file, [], undefined, (path, type, token) => {
    if (type === 'color') return;
    const dotted = path.join('.');
    if (dotted === 'space.unit') {
      out.push({
        path: dotted,
        cssVar: '--spacing',
        css: cssValue(type, token['$value'], dotted),
        tailwindVar: '--spacing',
      });
      return;
    }
    const group = STATIC_GROUPS.find((g) => dotted.startsWith(g.prefix));
    if (!group) throw new Error(`Token ${dotted} belongs to no known group`);
    const cssVar = group.cssPrefix + dotted.slice(group.prefix.length);
    out.push({
      path: dotted,
      cssVar,
      css: cssValue(type, token['$value'], dotted),
      tailwindVar: group.tailwind ? cssVar : null,
    });
  });
  return out;
}

/** Every colour token in the file, in file order. */
export const COLOR_TOKENS: readonly ColorToken[] = colorTokens(
  tokenFile as Record<string, unknown>
);

/** Every token that does not change with the mode, in file order. */
export const STATIC_TOKENS: readonly StaticToken[] = staticTokens(
  tokenFile as Record<string, unknown>
);

/** Reads the token file given (for tests that alter a value); the exports above read the real one. */
export function readTokens(file: unknown): { colors: ColorToken[]; statics: StaticToken[] } {
  if (!isRecord(file)) throw new Error('A token file is a JSON object');
  return { colors: colorTokens(file), statics: staticTokens(file) };
}

/** Formats an OKLCH colour as CSS. */
export function oklchCss({ l, c, h, alpha }: Oklch): string {
  const base = `${round(l)} ${round(c)} ${round(h)}`;
  return alpha < 1 ? `oklch(${base} / ${round(alpha)})` : `oklch(${base})`;
}

function round(n: number): string {
  return String(Math.round(n * 10000) / 10000);
}

/** A failed contrast floor: which foreground, on which background, in which mode. */
export interface ContrastFailure {
  mode: ColorMode;
  foreground: string;
  background: string;
  ratio: number;
  min: number;
}

/**
 * Checks every contrast floor the tokens declare and returns the pairs that fall short. `valueOf`
 * gives a token's colour in a mode; by default it is the token's own value, and the brand check
 * passes one that puts the brand's colours in their place.
 */
export function contrastFailures(
  colors: readonly ColorToken[],
  modes: readonly ColorMode[] = ['light', 'dark'],
  valueOf: (token: ColorToken, mode: ColorMode) => Rgb = (token, mode) => oklchToRgb(token[mode])
): ContrastFailure[] {
  const byPath = new Map(colors.map((t) => [t.path, t]));
  const failures: ContrastFailure[] = [];
  for (const mode of modes) {
    for (const fg of colors) {
      for (const rule of fg.contrast) {
        for (const bgPath of rule.on) {
          const bg = byPath.get(bgPath);
          if (!bg)
            throw new Error(`Token ${fg.path}: contrast background ${bgPath} does not exist`);
          const background = valueOf(bg, mode);
          if (background.alpha < 1) {
            // A see-through background's contrast depends on what lies under it.
            throw new Error(`Token ${fg.path}: contrast background ${bgPath} is translucent`);
          }
          const ratio = contrastRatio(valueOf(fg, mode), background);
          if (!(ratio >= rule.min)) {
            failures.push({ mode, foreground: fg.path, background: bgPath, ratio, min: rule.min });
          }
        }
      }
    }
  }
  return failures;
}
