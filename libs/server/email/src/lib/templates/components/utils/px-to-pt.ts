/**
 * Vendored from `@react-email/button@0.2.1` (resend/react-email), MIT licensed.
 * See `../LICENSE` and `../README.md`. Changed from upstream: this header only.
 */
export const pxToPt = (px: number | undefined): number | undefined =>
  typeof px === 'number' && !Number.isNaN(Number(px)) ? (px * 3) / 4 : undefined;
