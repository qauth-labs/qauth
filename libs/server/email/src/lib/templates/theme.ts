/**
 * THE MAIL'S LOOK: QAuth's design system (`@qauth-labs/ui`) in the form a mail
 * client reads.
 *
 * The design system's tokens (`libs/ui/src/tokens/tokens.json`) are OKLCH
 * colours and self-hosted web fonts; most mail clients read neither. So each
 * colour here is the light-mode token as `#rrggbb`, and each font is the
 * token's face first, then the faces a mail client has: a reader whose client
 * cannot load DM Sans, Instrument Serif or JetBrains Mono gets the nearest
 * system sans, serif and monospace. Mail is light only: dark-mode support in
 * mail clients is a client's own inversion, which no stylesheet controls.
 *
 * The look is the qauth.dev website's, as the design system states it: square
 * corners, flat surfaces with a hairline edge and no shadow, Instrument Serif
 * for the heading, DM Sans for text, JetBrains Mono for a code.
 *
 * A test in the auth server (`mail-theme.test.ts`), which may import both this
 * library and the design system, checks every colour here against its token,
 * so a token change that is not carried here fails CI.
 */

/** The design system's light-mode colours, by the CSS variable each one is. */
export const MAIL_COLORS = Object.freeze({
  /** `--muted`: the page around the card. */
  muted: '#f5f5f4',
  /** `--card`. */
  card: '#ffffff',
  /** `--foreground`: the heading, the name and a code. */
  foreground: '#0c0a09',
  /** `--body`: running text. */
  body: '#534b46',
  /** `--muted-foreground`: the footer. */
  mutedForeground: '#726a65',
  /** `--border`: the hairline edges. */
  border: '#e7e5e4',
  /** `--primary`: a button. */
  primary: '#b44723',
  /** `--primary-foreground`: a button's label. */
  primaryForeground: '#fff7ed',
});

/** The CSS variable of each {@link MAIL_COLORS} entry, for the test that checks them. */
export const MAIL_COLOR_TOKENS: Readonly<Record<keyof typeof MAIL_COLORS, string>> = Object.freeze({
  muted: '--muted',
  card: '--card',
  foreground: '--foreground',
  body: '--body',
  mutedForeground: '--muted-foreground',
  border: '--border',
  primary: '--primary',
  primaryForeground: '--primary-foreground',
});

/** The design system's three faces, each followed by what a mail client has instead. */
export const MAIL_FONTS = Object.freeze({
  sans: '"DM Sans","DM Sans Variable",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif',
  display: '"Instrument Serif",Georgia,"Times New Roman",Times,serif',
  mono: '"JetBrains Mono","JetBrains Mono Variable","SFMono-Regular",Menlo,Consolas,"Liberation Mono",monospace',
});
