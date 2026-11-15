import { MAIL_COLOR_TOKENS, MAIL_COLORS } from '@qauth-labs/fastify-plugin-email';
import { COLOR_TOKENS, oklchToRgb } from '@qauth-labs/ui';
import { describe, expect, it } from 'vitest';

/**
 * The mail's colours are the design system's (`libs/server/email`,
 * `templates/theme.ts`): mail clients read no OKLCH, so the email library
 * holds each light-mode token as `#rrggbb`. It may not import the design
 * system; the auth server may import both, so the check lives here, and a
 * token change marks this app affected.
 */

/** `#rrggbb` of an sRGB colour, rounded as the design system's own `toHex`. */
function hexOf({ r, g, b }: { r: number; g: number; b: number }): string {
  const channel = (v: number) =>
    Math.round(Math.min(1, Math.max(0, v)) * 255)
      .toString(16)
      .padStart(2, '0');
  return `#${channel(r)}${channel(g)}${channel(b)}`;
}

describe('the mail colours', () => {
  it.each(Object.entries(MAIL_COLOR_TOKENS))('%s is the light value of %s', (name, cssVar) => {
    const token = COLOR_TOKENS.find((candidate) => candidate.cssVar === cssVar);
    if (token === undefined) throw new Error(`${cssVar}: no such colour token`);
    expect(MAIL_COLORS[name as keyof typeof MAIL_COLORS]).toBe(hexOf(oklchToRgb(token.light)));
  });
});
