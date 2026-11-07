import { describe, expect, it } from 'vitest';

import { COLOR_TOKENS, contrastFailures, readTokens, STATIC_TOKENS } from './tokens';
import tokenFile from './tokens.json';

describe('the token file', () => {
  it('gives every token its own CSS variable', () => {
    const names = [...COLOR_TOKENS, ...STATIC_TOKENS].map((t) => t.cssVar);
    expect(new Set(names).size).toBe(names.length);
  });

  it('covers the semantic groups, the type scale, spacing, radius, focus and motion', () => {
    const paths = [...COLOR_TOKENS, ...STATIC_TOKENS].map((t) => t.path);
    for (const prefix of [
      'color.surface.',
      'color.text.',
      'color.primary.',
      'color.feedback.',
      'font.family.',
      'font.size.',
      'space.unit',
      'radius.',
      'focus.',
      'motion.duration.',
      'motion.easing.',
    ]) {
      expect(
        paths.some((p) => p.startsWith(prefix)),
        prefix
      ).toBe(true);
    }
  });

  it('names only backgrounds that exist in its contrast rules', () => {
    const paths = new Set(COLOR_TOKENS.map((t) => t.path));
    for (const token of COLOR_TOKENS) {
      for (const rule of token.contrast) {
        for (const bg of rule.on) expect(paths.has(bg), `${token.path} on ${bg}`).toBe(true);
      }
    }
  });

  it('declares a contrast floor for every text colour', () => {
    const text = COLOR_TOKENS.filter((t) => t.path.startsWith('color.text.'));
    expect(text.length).toBeGreaterThan(0);
    for (const token of text) expect(token.contrast.length, token.path).toBeGreaterThan(0);
  });
});

describe('contrast', () => {
  it('meets every declared floor in light and dark', () => {
    const failures = contrastFailures(COLOR_TOKENS).map(
      (f) =>
        `${f.mode}: ${f.foreground} on ${f.background} is ${f.ratio.toFixed(2)}, below ${f.min}`
    );
    expect(failures).toEqual([]);
  });

  it('fails when one pair is lowered below AA', () => {
    const lowered = structuredClone(tokenFile) as typeof tokenFile;
    // Muted text at L 0.7 is about 2.6:1 on white.
    lowered.color.text['muted-foreground'].$value.components = [0.7, 0.013, 58.071];
    const failures = contrastFailures(readTokens(lowered).colors);
    expect(failures.length).toBeGreaterThan(0);
    expect(
      failures.every((f) => f.mode === 'light' && f.foreground === 'color.text.muted-foreground')
    ).toBe(true);
  });

  it('fails in dark mode alone when only the dark value is lowered', () => {
    const lowered = structuredClone(tokenFile) as typeof tokenFile;
    lowered.color.brand.highlight.$extensions['dev.qauth.ui'].dark.components = [0.3, 0.15, 195];
    const failures = contrastFailures(readTokens(lowered).colors);
    expect(failures.map((f) => `${f.mode} ${f.foreground}`)).toContain(
      'dark color.brand.highlight'
    );
    expect(failures.some((f) => f.mode === 'light')).toBe(false);
  });
});
