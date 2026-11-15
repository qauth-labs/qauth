import type { EmailInlineImage } from '../../types';

/**
 * QAUTH'S MARK IN A MAIL: the Q of `logos/qauth-logo.svg` (the terracotta
 * ring and the cyan square, without the wordmark's letters) as a PNG the mail
 * carries itself, shown through `cid:` (RFC 2392) before the brand's name.
 * Nothing is fetched when the mail is opened, so an open tells no server
 * anything, and the mark shows on a development stack that no mail client can
 * reach.
 *
 * Only the mark is an image: the name beside it is text. A mail client's dark
 * mode recolours text but not images, and the wordmark's black letters on a
 * transparent ground vanished on a dark background (Gmail on Android). The
 * mark has no black, so it reads on a light page and a dark one alike.
 *
 * 84 × 84 pixels, drawn at 28 × 28: three pixels to a point, sharp on a
 * high-density screen. Generated with sharp from the SVG's circle and rect
 * alone, in a viewBox of `0 146 1000 1000`:
 * `sharp(markSvg, { density: 72 }).resize(84, 84)
 * .png({ palette: true, compressionLevel: 9 })`.
 * Kept in this module rather than as a file so that the bundled server needs
 * no path to it.
 */
const QAUTH_MARK_PNG_BASE64 =
  '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';

/** The mark as the mail carries it. */
export const QAUTH_MAIL_LOGO_IMAGE: EmailInlineImage = Object.freeze({
  contentId: 'qauth-mark@qauth.mail',
  filename: 'qauth-mark.png',
  contentType: 'image/png',
  content: Buffer.from(QAUTH_MARK_PNG_BASE64, 'base64'),
});

/** The size the mark is drawn at, in CSS pixels: a third of the PNG's. */
export const QAUTH_MAIL_LOGO_SIZE = Object.freeze({ width: 28, height: 28 });
