/**
 * URL scheme inspection for link/`href` safety.
 *
 * ## Why a DENYLIST lives here next to the allowlists elsewhere
 *
 * The usual rule — and the one `apps/auth-server`'s `html.ts#safeUrl()` applies
 * to anything built from client-supplied metadata — is an ALLOWLIST of
 * `http/https/mailto`. That rule cannot be applied everywhere: some links are
 * built from operator-supplied deployment configuration whose whole purpose is a
 * vendor custom scheme (`openid4vp://`, `haip://`, `eudi-wallet://` — OID4VP 1.0
 * §5 wallet Authorization Endpoints, issue #239). Enumerating every wallet
 * scheme in the world is not possible.
 *
 * It does not have to be. The set of schemes that EXECUTE when a browser
 * navigates to them is small, closed and well known, so the open-ended side can
 * be handled by refusing that set rather than by admitting the rest.
 *
 * ## Why this is not `new URL(value).protocol`
 *
 * `new URL()` is a fine scheme extractor for a well-formed URL and a poor filter
 * for a hostile string: it throws on `&#106;avascript:alert(1)`, which an HTML
 * parser decodes to `javascript:alert(1)` before the URL parser ever sees it.
 * Scheme filters are bypassed in practice by exactly these shapes — mixed case,
 * embedded TAB/LF/CR/NUL inside the scheme, and HTML character references — so
 * {@link extractUrlScheme} undoes each of them before deciding, in the same
 * order a browser would.
 */

/**
 * Schemes whose content a browser executes, or renders as an attacker-authored
 * document, when it navigates to them from an `href`/`src`/form action.
 *
 * `javascript:` is the classic; `vbscript:`, `livescript:` and `mocha:` are the
 * legacy engine-specific spellings that filters routinely forget. `data:`,
 * `blob:` and `filesystem:` do not run a script engine directly but deliver a
 * document body of the author's choosing into a navigable context, which is the
 * same outcome by another route.
 *
 * Compared LOWERCASE, without the trailing colon.
 */
export const SCRIPT_CAPABLE_URL_SCHEMES: ReadonlySet<string> = new Set([
  'javascript',
  'vbscript',
  'livescript',
  'mocha',
  'data',
  'blob',
  'filesystem',
]);

/**
 * The named HTML character references that can smuggle a scheme past a naive
 * filter. Deliberately NOT the full ~2200-entry HTML entity table: a named
 * reference only matters here if it decodes to a character that is stripped
 * before navigation (TAB/LF) or that terminates the scheme (`:`). Everything
 * else decodes to a character RFC 3986 forbids in a scheme, which makes the
 * whole value a relative reference — harmless by construction.
 */
const NAMED_CHARACTER_REFERENCES: ReadonlyMap<string, string> = new Map([
  ['colon', ':'],
  ['Tab', '\t'],
  ['NewLine', '\n'],
]);

/**
 * One HTML character reference: hexadecimal numeric, decimal numeric, or named.
 * The trailing `;` is optional because HTML parsers accept it missing.
 */
const HTML_CHARACTER_REFERENCE = /&(?:#[xX]([0-9a-fA-F]+)|#([0-9]+)|([a-zA-Z][a-zA-Z0-9]*));?/g;

/**
 * ASCII whitespace, C0 controls and DEL. HTML strips TAB/LF/CR from attribute
 * values and the URL parser strips leading/trailing C0-or-space, which is why
 * `java&#9;script:`, `\njavascript:` and `java\0script:` all reach the
 * navigation as `javascript:`.
 */
// eslint-disable-next-line no-control-regex -- matching control characters is the entire purpose of this pattern; the rule guards against them appearing by accident, which is the opposite of the case here
const IGNORABLE_CHARACTERS = /[\u0000-\u0020\u007f]/g;

/** A syntactically valid RFC 3986 scheme, already lowercased. */
const WELL_FORMED_SCHEME = /^[a-z][a-z0-9+.-]*$/;

/** Highest Unicode code point `String.fromCodePoint` accepts. */
const MAX_CODE_POINT = 0x10ffff;

/**
 * Decode HTML character references ONCE, left to right, exactly as a browser
 * does. Single-pass matters: `&amp;#106;avascript:` must decode to the literal
 * `&#106;avascript:` (a relative reference — harmless) and must NOT be
 * re-scanned into `javascript:`, or this function would disagree with the parser
 * it is modelling.
 */
function decodeCharacterReferences(value: string): string {
  return value.replace(
    HTML_CHARACTER_REFERENCE,
    (match: string, hex?: string, dec?: string, name?: string) => {
      if (hex !== undefined) {
        const code = Number.parseInt(hex, 16);
        return Number.isNaN(code) || code > MAX_CODE_POINT ? match : String.fromCodePoint(code);
      }
      if (dec !== undefined) {
        const code = Number.parseInt(dec, 10);
        return Number.isNaN(code) || code > MAX_CODE_POINT ? match : String.fromCodePoint(code);
      }
      return (name !== undefined ? NAMED_CHARACTER_REFERENCES.get(name) : undefined) ?? match;
    }
  );
}

/**
 * Extract the scheme a browser would actually navigate with, normalised to
 * lowercase and without its colon.
 *
 * @param value - a raw URL string as it would be written into an `href`.
 * @returns the lowercase scheme, or `undefined` when the value carries no
 * well-formed scheme — a relative reference, or a string whose "scheme" contains
 * characters RFC 3986 does not allow (a browser treats both as relative, so
 * neither can select a script-capable handler).
 *
 * @example
 * ```typescript
 * extractUrlScheme('OpenID4VP://request?x=1'); // 'openid4vp'
 * extractUrlScheme('java\tscript:alert(1)');   // 'javascript'
 * extractUrlScheme('&#106;avascript:alert(1)'); // 'javascript'
 * extractUrlScheme('/relative/path');          // undefined
 * ```
 */
export function extractUrlScheme(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0) return undefined;

  const normalized = decodeCharacterReferences(value).replace(IGNORABLE_CHARACTERS, '');
  const colon = normalized.indexOf(':');
  if (colon <= 0) return undefined;

  const scheme = normalized.slice(0, colon).toLowerCase();
  return WELL_FORMED_SCHEME.test(scheme) ? scheme : undefined;
}

/**
 * Whether rendering `value` as a link would hand its author script execution —
 * or an attacker-authored document — in this origin.
 *
 * Use for URLs that MUST keep an open-ended scheme: operator-configured deep
 * links into native apps, for instance. Anything built from CLIENT-supplied data
 * belongs behind an allowlist instead (`html.ts#safeUrl()`), because "not
 * obviously executable" is a far weaker property than "one of three schemes we
 * chose".
 *
 * @param value - a raw URL string as it would be written into an `href`.
 * @returns `true` when the value's effective scheme is in
 * {@link SCRIPT_CAPABLE_URL_SCHEMES}.
 */
export function isScriptCapableUrl(value: unknown): boolean {
  const scheme = extractUrlScheme(value);
  return scheme !== undefined && SCRIPT_CAPABLE_URL_SCHEMES.has(scheme);
}
