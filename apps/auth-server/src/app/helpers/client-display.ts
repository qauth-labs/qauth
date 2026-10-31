import { InvalidRequestError } from '@qauth-labs/shared-errors';
import type { ClientDisplay } from '@qauth-labs/shared-interaction-client';
import { DISPLAY_TEXT_PATTERN } from '@qauth-labs/shared-interaction-contract';
import {
  DISPLAY_HOST_MAX_LENGTH,
  DISPLAY_HOST_PATTERN,
  isVerifiedDomain,
  redirectTarget,
} from '@qauth-labs/shared-validation';
import { parse as parseHost } from 'tldts';

import { isCimdClient } from './client-resolution';
import { isDynamicClientWithinBadgeWindow } from './consent';

/**
 * Who a client is, as the auth server's own records say (ADR-019 Decision 6,
 * issue #593).
 *
 * Every screen that names a client renders this data and computes none of it.
 * Today that is the consent page; device-code entry, the logout confirmation
 * and the account console's list of apps take it from here when they are
 * built. It is the Interaction API's `ClientDisplay` (the contract of #590), so
 * the screens served by the ceremony app and the pages the auth server still
 * renders itself show a client the same way.
 *
 * What a screen shows first is what the server verified, by client class:
 *
 * - `cimd`: the host of the client id URL, which the server fetched the
 *   client's metadata document from, in ASCII (punycode) form;
 * - `admin_registered`: the domain an admin set on a client the operator
 *   provisioned (`oauth_clients.verified_domain`);
 * - `federation`: the entity id and its validated trust marks. Reserved for
 *   the federation beta: no client is of this class yet, so it is never
 *   returned;
 * - `unverified`: everything else, a dynamically registered or
 *   developer-portal client included. Nothing about it is verified, so the
 *   screen says so and shows where the code goes.
 *
 * Everything a client supplied about itself is data: the name it declares is
 * length-capped, stripped of control, format (bidirectional, zero-width),
 * markup and blank-rendering characters and of stacked combining marks,
 * carried as `declaredName` after the verified members, and the contract marks
 * it as declared. A client's link and description are not
 * display data at all, and no logo ever comes from a URL a client supplied: a
 * logo appears only when an admin uploaded one, and no such upload exists
 * yet, so none is returned.
 */

/** A client row, as much of it as the display rules read. */
export interface ClientDisplaySource {
  clientId: string;
  /** The name the client declared (registration, metadata document or owner). */
  name: string;
  /** `registrationType` says how the client was registered (`cimd`, `dynamic`). */
  metadata: Record<string, unknown> | null;
  dynamicRegisteredAt: number | null;
  /** `oauth_clients.provisioned_by_operator`: only such a client's verified domain counts. */
  provisionedByOperator?: boolean | null;
  /** `oauth_clients.verified_domain`, set by an admin (#593). */
  verifiedDomain?: string | null;
}

export interface ClientDisplayOptions {
  /**
   * The redirect URI the request was bound to, already matched against the
   * client's registered ones. Omit it where no code goes (logout, the account
   * console's list of apps).
   */
  redirectUri?: string;
}

type VerifiedDomain = NonNullable<ClientDisplay['verifiedDomain']>;

/** The cap on a declared name: the contract's `ClientDisplay.declaredName` `maxLength`. */
export const DECLARED_NAME_MAX_LENGTH = 64;

const DISPLAY_HOST = new RegExp(DISPLAY_HOST_PATTERN);
const DISPLAY_TEXT = new RegExp(DISPLAY_TEXT_PATTERN, 'u');

/** Characters that break a line: shown as one space, so words do not run together. */
const LINE_BREAKS = /[\t\n\v\f\r\u0085\u2028\u2029]/gu;

/**
 * Characters a declared value never carries: markup brackets, every character
 * of the Unicode category Other (controls, format characters such as the
 * bidirectional embeddings, overrides and isolates and the zero-width ones,
 * surrogates, private use, unassigned), the Hangul fillers, which are letters
 * that render as nothing, and the blank braille pattern, a symbol that renders
 * as nothing.
 */
const REMOVED = /[<>\p{C}\u115F\u1160\u2800\u3164\uFFA0]/gu;

/**
 * Combining marks kept on one character. Natural text needs a few (a Vietnamese
 * vowel with two marks, an Indic consonant with a virama and a vowel sign); a
 * stack of dozens draws over the lines around the name, which would put the
 * declared text above the verified data in the literal sense.
 */
const MAX_MARKS_PER_GRAPHEME = 4;

const MARK = /\p{M}/u;
const LEADING_MARKS = /^\p{M}+/u;

/** A run of space separators: one ordinary space. */
const SPACES = /\p{Zs}+/gu;

const ELLIPSIS = '\u2026';

const graphemes = new Intl.Segmenter(undefined, { granularity: 'grapheme' });

/** The number of code points in `text`, which is what a JSON Schema `maxLength` counts. */
function codePointLength(text: string): number {
  let count = 0;
  for (const _ of text) count += 1;
  return count;
}

/**
 * `text` with at most {@link MAX_MARKS_PER_GRAPHEME} combining marks on each
 * grapheme and none before the first base character, which would otherwise
 * attach to the label in front of the name.
 */
function limitMarks(text: string): string {
  let out = '';
  for (const { segment } of graphemes.segment(text.replace(LEADING_MARKS, ''))) {
    let marks = 0;
    for (const char of segment) {
      if (MARK.test(char)) {
        marks += 1;
        if (marks > MAX_MARKS_PER_GRAPHEME) continue;
      }
      out += char;
    }
  }
  return out;
}

/**
 * A value a client declared, made fit to show as plain text: line breaks
 * become spaces; control, format, private-use and unassigned characters,
 * markup brackets and blank-rendering characters are removed; the text is
 * put in NFC; a character keeps at most four combining marks; runs of spaces
 * become one and the ends are trimmed. A value longer than
 * `maxLength` code points is cut at a grapheme boundary and ends in an
 * ellipsis, so the result is never longer than `maxLength`.
 *
 * @returns the text, or `undefined` when nothing showable is left (or the
 * value is not a string).
 */
export function declaredText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== 'string' || maxLength < 2) return undefined;
  // Bound the work before any per-character step: nothing past this point can
  // reach the result. A surrogate pair split here is removed below.
  const bounded = value.length > maxLength * 8 ? value.slice(0, maxLength * 8) : value;
  let text = bounded
    .replace(LINE_BREAKS, ' ')
    .replace(REMOVED, '')
    .normalize('NFC')
    .replace(SPACES, ' ')
    .trim();
  text = limitMarks(text).trim();

  if (codePointLength(text) > maxLength) {
    let kept = '';
    let count = 0;
    for (const { segment } of graphemes.segment(text)) {
      const size = codePointLength(segment);
      if (count + size > maxLength - 1) break;
      kept += segment;
      count += size;
    }
    kept = kept.trimEnd();
    text = kept === '' ? '' : `${kept}${ELLIPSIS}`;
  }

  if (text === '' || !DISPLAY_TEXT.test(text)) return undefined;
  return text;
}

/**
 * The verified domain of a host in the contract's form: the host, its
 * registrable domain (the part a screen highlights) and whether it sits under
 * a shared-hosting suffix, from the private section of the Public Suffix List,
 * where unrelated parties get names next to each other.
 *
 * With the private section on, the registrable domain under such a suffix is
 * the name its owner holds (`alice.eu.org`), not the suffix's own registrable
 * domain (`eu.org`), which would point at the hosting service instead. A host
 * that is itself a suffix, or an IP address, is its own registrable domain.
 */
function verifiedDomainOf(host: string): VerifiedDomain {
  const info = parseHost(host, { allowPrivateDomains: true, extractHostname: false });
  return {
    host,
    registrableDomain: info.domain ?? host,
    sharedHosting: info.isPrivate === true,
  };
}

/** True when `host` has a registrable domain: it is not itself a public suffix. */
function isRegistrable(host: string): boolean {
  return parseHost(host, { allowPrivateDomains: true, extractHostname: false }).domain !== null;
}

/** The host of a CIMD client id URL, in the contract's form; `undefined` when it has none. */
function cimdHost(clientId: string): string | undefined {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:') return undefined;
  // The URL parser writes the host lower case, with an IDN in `xn--` form. A
  // trailing dot names the same DNS name.
  const host = url.hostname.replace(/\.$/, '');
  return host.length <= DISPLAY_HOST_MAX_LENGTH && DISPLAY_HOST.test(host) ? host : undefined;
}

/**
 * Where the authorization code goes, from the redirect URI the request was
 * bound to (`redirectTarget` in shared-validation): a web host, "this device"
 * for a loopback address, or a native app's own URI scheme.
 *
 * @throws InvalidRequestError when the URI cannot be shown in the contract's
 * form. Every registration path refuses such a URI since #593, so only a
 * client registered before it can hold one. The screen of an unverified
 * client has nothing else the user can check, so it is not shown without it.
 */
function redirectOf(redirectUri: string): NonNullable<ClientDisplay['redirect']> {
  const target = redirectTarget(redirectUri);
  if (target === undefined) throw new InvalidRequestError('redirect_uri cannot be shown');
  return target;
}

/**
 * The display data of a client: what the server verified first, then where
 * the code goes, then what the client declared.
 *
 * @param client - the client's row, from the auth server's own records.
 * @param options - the redirect URI the request was bound to, where a code goes.
 */
export function clientDisplay(
  client: ClientDisplaySource,
  options: ClientDisplayOptions = {}
): ClientDisplay {
  let kind: ClientDisplay['kind'] = 'unverified';
  let verifiedDomain: VerifiedDomain | undefined;

  if (isCimdClient({ metadata: client.metadata })) {
    // A CIMD client's metadata document was fetched from its client id URL,
    // so the host of that URL is what the server verified. Never the
    // `verified_domain` column, which only an operator-provisioned client's
    // admin sets. A row whose client id is not an https URL with a host the
    // contract can carry is shown as unverified: nothing was verified.
    const host = cimdHost(client.clientId);
    if (host !== undefined) {
      kind = 'cimd';
      verifiedDomain = verifiedDomainOf(host);
    }
  } else if (client.provisionedByOperator === true && isVerifiedDomain(client.verifiedDomain)) {
    // The admin's domain counts only while the operator vouches for the row:
    // an owner who changes the redirect URIs clears `provisioned_by_operator`,
    // and with it the verified domain. A value written by hand in any other
    // form than the stored one reads as none, and so does a public suffix
    // (`co.uk`), which `normaliseVerifiedDomain` refuses on every write path
    // but the database's own CHECK cannot tell.
    if (isRegistrable(client.verifiedDomain)) {
      kind = 'admin_registered';
      verifiedDomain = verifiedDomainOf(client.verifiedDomain);
    }
  }

  const redirect = options.redirectUri !== undefined ? redirectOf(options.redirectUri) : undefined;
  const declaredName = declaredText(client.name, DECLARED_NAME_MAX_LENGTH);

  // Built in the order a screen shows it: verified data first, the client's
  // own declaration last. No `logo`: only an admin-uploaded one may appear,
  // and none exists yet.
  return {
    kind,
    ...(verifiedDomain !== undefined ? { verifiedDomain } : {}),
    ...(redirect !== undefined ? { redirect } : {}),
    ...(declaredName !== undefined ? { declaredName } : {}),
    newClient: isDynamicClientWithinBadgeWindow(client),
  };
}
