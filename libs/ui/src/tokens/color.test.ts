import { describe, expect, it } from 'vitest';

import {
  composite,
  contrastRatio,
  oklchToRgb,
  parseHex,
  relativeLuminance,
  type Rgb,
  toHex,
} from './color';

function hex(value: string): Rgb {
  const rgb = parseHex(value);
  if (!rgb) throw new Error(`not #rrggbb: ${value}`);
  return rgb;
}

describe('colour maths', () => {
  it('parses and formats #rrggbb, and refuses other spellings', () => {
    expect(parseHex('#b44723')).toEqual({ r: 180 / 255, g: 71 / 255, b: 35 / 255, alpha: 1 });
    expect(toHex(hex('#B44723'))).toBe('#b44723');
    for (const bad of ['b44723', '#b44', '#b44723ff', 'red', '#gggggg', '', ' #b44723']) {
      expect(parseHex(bad)).toBeNull();
    }
  });

  it('converts OKLCH white, black and a hue to sRGB', () => {
    expect(toHex(oklchToRgb({ l: 1, c: 0, h: 0, alpha: 1 }))).toBe('#ffffff');
    expect(toHex(oklchToRgb({ l: 0, c: 0, h: 0, alpha: 1 }))).toBe('#000000');
    // The design system's primary, as its artifact lists it.
    expect(toHex(oklchToRgb({ l: 0.54, c: 0.15, h: 38, alpha: 1 }))).toBe('#b44723');
  });

  it('computes the WCAG ratios of known pairs', () => {
    const white = hex('#ffffff');
    const black = hex('#000000');
    expect(contrastRatio(black, white)).toBeCloseTo(21, 5);
    expect(contrastRatio(white, white)).toBe(1);
    // #767676 is the lightest grey that reaches 4.5:1 on white.
    expect(contrastRatio(hex('#767676'), white)).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(hex('#777777'), white)).toBeLessThan(4.5);
    expect(relativeLuminance(white)).toBe(1);
  });

  it('paints a translucent foreground over its background first', () => {
    const black = hex('#000000');
    const halfWhite = { r: 1, g: 1, b: 1, alpha: 0.5 };
    expect(composite(halfWhite, black)).toEqual({ r: 0.5, g: 0.5, b: 0.5, alpha: 1 });
    expect(contrastRatio(halfWhite, black)).toBeCloseTo(
      contrastRatio(composite(halfWhite, black), black),
      10
    );
  });
});
