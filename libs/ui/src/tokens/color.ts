/**
 * Colour maths for the token checks: parse the two colour forms the tokens and brand settings use
 * (OKLCH and `#rrggbb`), convert to sRGB, and compute the WCAG 2.2 contrast ratio.
 */

/** A colour in the OKLCH space: lightness 0–1, chroma ≥ 0, hue in degrees, alpha 0–1. */
export interface Oklch {
  l: number;
  c: number;
  h: number;
  alpha: number;
}

/** A colour in sRGB with channels 0–1, gamma-encoded, and alpha 0–1. */
export interface Rgb {
  r: number;
  g: number;
  b: number;
  alpha: number;
}

const HEX = /^#([0-9a-f]{6})$/i;

/** Parses `#rrggbb`. Returns `null` for anything else, including the short and alpha forms. */
export function parseHex(value: string): Rgb | null {
  const match = HEX.exec(value);
  if (!match) return null;
  const n = Number.parseInt(match[1], 16);
  return { r: ((n >> 16) & 255) / 255, g: ((n >> 8) & 255) / 255, b: (n & 255) / 255, alpha: 1 };
}

/** Formats an sRGB colour as `#rrggbb`, dropping alpha. */
export function toHex({ r, g, b }: Rgb): string {
  const channel = (v: number) =>
    Math.round(clamp01(v) * 255)
      .toString(16)
      .padStart(2, '0');
  return `#${channel(r)}${channel(g)}${channel(b)}`;
}

function clamp01(v: number): number {
  return Math.min(1, Math.max(0, v));
}

function encode(linear: number): number {
  return linear <= 0.0031308 ? 12.92 * linear : 1.055 * linear ** (1 / 2.4) - 0.055;
}

function decode(encoded: number): number {
  return encoded <= 0.04045 ? encoded / 12.92 : ((encoded + 0.055) / 1.055) ** 2.4;
}

/**
 * Converts OKLCH to gamma-encoded sRGB (Björn Ottosson's OKLab matrices). Channels outside the
 * sRGB gamut are clamped, which is what a browser shows for such a colour.
 */
export function oklchToRgb({ l, c, h, alpha }: Oklch): Rgb {
  const rad = (h * Math.PI) / 180;
  const a = c * Math.cos(rad);
  const b = c * Math.sin(rad);
  const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s_ = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const r = 4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_;
  const g = -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_;
  const bl = -0.0041960863 * l_ - 0.7034186147 * m_ + 1.707614701 * s_;
  return { r: clamp01(encode(r)), g: clamp01(encode(g)), b: clamp01(encode(bl)), alpha };
}

/** Paints `top` over the opaque `bottom`, as a translucent colour shows on its background. */
export function composite(top: Rgb, bottom: Rgb): Rgb {
  const a = top.alpha;
  return {
    r: top.r * a + bottom.r * (1 - a),
    g: top.g * a + bottom.g * (1 - a),
    b: top.b * a + bottom.b * (1 - a),
    alpha: 1,
  };
}

/** WCAG 2.2 relative luminance of an opaque sRGB colour. */
export function relativeLuminance({ r, g, b }: Rgb): number {
  return 0.2126 * decode(r) + 0.7152 * decode(g) + 0.0722 * decode(b);
}

/**
 * WCAG 2.2 contrast ratio of `foreground` on `background`, from 1 to 21. A translucent foreground
 * is first painted over the background; the background must be opaque.
 */
export function contrastRatio(foreground: Rgb, background: Rgb): number {
  const fg = foreground.alpha < 1 ? composite(foreground, background) : foreground;
  const lf = relativeLuminance(fg);
  const lb = relativeLuminance(background);
  return (Math.max(lf, lb) + 0.05) / (Math.min(lf, lb) + 0.05);
}
