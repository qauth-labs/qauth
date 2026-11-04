/**
 * THE BRAND OF A REALM'S MAIL (PRO-14, #637; ADR-020 fork C, ADR-019
 * Decision 7).
 *
 * The engine's mail templates are fixed English text. A realm changes only
 * their look and their name: the logo, the colours, the service's name and a
 * footer notice, from its brand settings (the admin console's brand screen).
 * Brand settings never form or replace a mail's link, code or pass, which the
 * server builds from the realm row (ADR-019 Decision 7), and a mail carries no
 * brand link.
 *
 * {@link resolveMailBrand} reads the settings as the store holds them and
 * keeps only what is safe to put in a mail: a value out of shape falls back to
 * the default rather than reaching the template, so a mail is always sent.
 */

/** The realm's logo, as the brand settings name it: a path the realm origin serves. */
export interface MailBrandLogo {
  /**
   * An absolute path on the realm origin (`/assets/brand/logo.png`), never a
   * URL: the template puts it after the realm's issuer, so the image always
   * comes from the realm's own host.
   */
  readonly path: string;
  readonly width: number;
  readonly height: number;
}

/** What a mail's look is built from. */
export interface MailBrand {
  /** The service's display name, in the heading and as the logo's text alternative. */
  readonly name: string;
  /** The logo an admin uploaded, served from the realm origin. Absent, the name stands in. */
  readonly logo?: MailBrandLogo;
  readonly colors: {
    /** Buttons and links. */
    readonly primary: string;
    /** The mail's background. */
    readonly background: string;
  };
  /** A short notice at the foot of every mail, as plain text. */
  readonly footer?: string;
}

/** The brand settings as a store holds them: any member may be missing or out of shape. */
export interface MailBrandSettings {
  readonly name?: unknown;
  readonly logo?: unknown;
  readonly colors?: { readonly primary?: unknown; readonly background?: unknown };
  readonly footer?: unknown;
}

/** The look of a realm that set no brand. */
export const DEFAULT_MAIL_BRAND: MailBrand = Object.freeze({
  name: 'QAuth',
  colors: Object.freeze({ primary: '#2563eb', background: '#f6f9fc' }),
});

/** The longest service name, as the brand screen bounds it. */
const NAME_MAX_LENGTH = 64;
/** The longest footer notice. */
const FOOTER_MAX_LENGTH = 280;
/** The longest logo path. */
const LOGO_PATH_MAX_LENGTH = 512;
/** The largest logo side, in pixels. */
const LOGO_MAX_SIDE = 2048;

/** A colour as the brand screen stores it: `#` and six lower-case hex digits. */
const HEX_COLOR = /^#[0-9a-f]{6}$/;

/**
 * An absolute path with no authority, query, fragment, backslash, dot segment
 * or percent escape: `//host`, `/\host` and `/%2e%2e/` cannot leave the realm
 * origin's path space or reach another host once joined to the issuer.
 */
const SAME_ORIGIN_PATH = /^\/(?!\/)[A-Za-z0-9._~\-/]*$/;

/** C0 and C1 controls, and the bidirectional overrides and isolates (ADR-019 Decision 6). */
// eslint-disable-next-line no-control-regex
const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g;

/** Plain text with its controls removed and its spaces collapsed, or `undefined` when nothing is left. */
function safeText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const text = value.replace(UNSAFE_TEXT, ' ').replace(/\s+/g, ' ').trim();
  if (text.length === 0 || text.length > maxLength) return undefined;
  return text;
}

function safeColor(value: unknown, fallback: string): string {
  return typeof value === 'string' && HEX_COLOR.test(value) ? value : fallback;
}

function safeSide(value: unknown): number | undefined {
  return typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= LOGO_MAX_SIDE
    ? value
    : undefined;
}

/** Whether `path` is a path on the realm origin that a mail may name. */
export function isSameOriginPath(path: unknown): path is string {
  return (
    typeof path === 'string' &&
    path.length <= LOGO_PATH_MAX_LENGTH &&
    SAME_ORIGIN_PATH.test(path) &&
    !path.split('/').some((segment) => segment === '.' || segment === '..')
  );
}

function safeLogo(value: unknown): MailBrandLogo | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const { path, width, height } = value as Record<string, unknown>;
  const w = safeSide(width);
  const h = safeSide(height);
  if (!isSameOriginPath(path) || w === undefined || h === undefined) return undefined;
  return Object.freeze({ path, width: w, height: h });
}

/**
 * The brand a realm's mail is rendered with: each member of `settings` that is
 * in shape, and the default for every other. Never throws.
 */
export function resolveMailBrand(settings?: MailBrandSettings | null): MailBrand {
  if (settings === undefined || settings === null) return DEFAULT_MAIL_BRAND;
  const name = safeText(settings.name, NAME_MAX_LENGTH) ?? DEFAULT_MAIL_BRAND.name;
  const logo = safeLogo(settings.logo);
  const footer = safeText(settings.footer, FOOTER_MAX_LENGTH);
  return Object.freeze({
    name,
    ...(logo === undefined ? {} : { logo }),
    colors: Object.freeze({
      primary: safeColor(settings.colors?.primary, DEFAULT_MAIL_BRAND.colors.primary),
      background: safeColor(settings.colors?.background, DEFAULT_MAIL_BRAND.colors.background),
    }),
    ...(footer === undefined ? {} : { footer }),
  });
}
