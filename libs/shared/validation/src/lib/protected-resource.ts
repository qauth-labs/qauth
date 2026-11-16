import { z } from 'zod';

import { isReservedAudience } from './reserved-audiences';
import { isReservedQauthScope } from './reserved-scopes';

/**
 * THE RULES OF A PROTECTED RESOURCE (#1087): what the admin API and the seed
 * manifest accept as a realm's protected resource, so neither stores what the
 * other refuses, nor what the consent step could not show.
 *
 * A protected resource is a resource indicator (RFC 8707), the scopes it
 * defines, each with its consent text by BCP 47 locale (English always among
 * them: the fallback), and who may ask for them: every client of the realm
 * (`any_client`) or a list of `client_id`s.
 */

/** The bounds of a protected resource. */
export const PROTECTED_RESOURCE_LIMITS = Object.freeze({
  /** The longest resource indicator, as `/oauth/authorize` bounds `resource`. */
  resourceMaxLength: 2048,
  /** The most scopes one resource defines: as many as the consent step lists. */
  scopes: 64,
  /** The longest scope value the consent step shows. */
  scopeMaxLength: 128,
  /** The most locales one scope's text is given in. */
  locales: 16,
  /** The longest consent text, as the consent step bounds a scope's `text`. */
  textMaxLength: 280,
  /** The most clients one resource is open to by name. */
  clients: 100,
  /** The longest `client_id`, as the client table stores it. */
  clientIdMaxLength: 255,
});

/** The locale every scope's consent text is given in, and the one shown when no other matches. */
export const PROTECTED_RESOURCE_FALLBACK_LOCALE = 'en';

/** Who may ask for a resource's scopes when it is open to every client of the realm. */
export const ANY_CLIENT = 'any_client';

/**
 * RFC 6749 §3.3 scope characters (%x21 / %x23-5B / %x5D-7E), without `<` and
 * `>`: the consent step's scope alphabet, spelled out character by character.
 */
const SCOPE_TOKEN = /^[!#$%&'()*+,\-./0-9:;=?@A-Z[\]^_`a-z{|}~]+$/;

/** A BCP 47 language tag, as the Interaction API's `uiLocales` carries one. */
export const LOCALE_TAG_PATTERN = /^[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*$/;

/** The longest BCP 47 tag a text is keyed by. */
const LOCALE_TAG_MAX_LENGTH = 35;

/**
 * A display value, as the Interaction API's `DISPLAY_TEXT_PATTERN` holds it:
 * no `<` or `>`, no Unicode Other character (controls, bidirectional
 * overrides, zero-width spaces), no line or paragraph separator and no Hangul
 * filler, spaces only between other characters. The auth server's tests hold
 * it equal to the contract's, so a stored text is one the consent step shows.
 */
export const CONSENT_TEXT_PATTERN =
  '^[^<>\\p{C}\\p{Z}\\u115F\\u1160\\u3164\\uFFA0](?:[^<>\\p{C}\\p{Zl}\\p{Zp}\\u115F\\u1160\\u3164\\uFFA0]*[^<>\\p{C}\\p{Z}\\u115F\\u1160\\u3164\\uFFA0])?$';

const CONSENT_TEXT = new RegExp(CONSENT_TEXT_PATTERN, 'u');

/** QAuth's own OpenID Connect and refresh scopes, which a resource never defines. */
const QAUTH_STANDARD_SCOPES: ReadonlySet<string> = new Set([
  'openid',
  'profile',
  'email',
  'offline_access',
]);

/**
 * Whether `scope` is one of QAuth's own: `openid`, `profile`, `email`,
 * `offline_access`, an agent mode (`agent:*`) or one of the reserved `qauth:`
 * namespace, its ASCII letters in any case. A protected resource never
 * defines one: their meaning and their consent text are QAuth's, and the
 * rules that grant them (the agent scope cap, the admin grants) are not a
 * resource's to widen.
 */
export function isQauthOwnScope(scope: string): boolean {
  const folded = scope.toLowerCase();
  return (
    QAUTH_STANDARD_SCOPES.has(folded) || folded.startsWith('agent:') || isReservedQauthScope(scope)
  );
}

/** Printable ASCII without the space: every character RFC 3986 allows in a URI. */
const URI_CHARACTERS = /^[\x21-\x7E]+$/;

/**
 * What is wrong with `value` as a protected resource's indicator, or
 * `undefined`: an absolute URI (RFC 8707 §2) of printable ASCII, with no
 * fragment, at most {@link PROTECTED_RESOURCE_LIMITS.resourceMaxLength}
 * characters, and never a QAuth API audience (`urn:qauth:aud:`), whose
 * tokens a client gets only when its own `audience` lists it. It is matched
 * exactly against the authorization request's `resource`, so it is stored as
 * written.
 */
export function protectedResourceIndicatorProblem(value: string): string | undefined {
  if (value.length === 0) return 'is empty';
  if (value.length > PROTECTED_RESOURCE_LIMITS.resourceMaxLength) {
    return `is longer than ${PROTECTED_RESOURCE_LIMITS.resourceMaxLength} characters`;
  }
  if (!URI_CHARACTERS.test(value)) return 'holds a character a URI does not, such as a space';
  if (value.includes('#'))
    return 'has a fragment, which a resource indicator never has (RFC 8707 §2)';
  try {
    new URL(value);
  } catch {
    return 'is not an absolute URI (RFC 8707 §2)';
  }
  if (isReservedAudience(value)) {
    return 'is a QAuth API audience (urn:qauth:aud:), which a client gets only when its own audience lists it';
  }
  return undefined;
}

/** A protected resource's indicator ({@link protectedResourceIndicatorProblem}). */
export const protectedResourceIndicatorSchema = z.string().superRefine((value, ctx) => {
  const problem = protectedResourceIndicatorProblem(value);
  if (problem !== undefined) ctx.addIssue({ code: 'custom', message: `resource ${problem}` });
});

/** One scope's consent text by locale: at least English, each one a display value. */
export const protectedResourceScopeTextSchema = z
  .record(
    z
      .string()
      .max(LOCALE_TAG_MAX_LENGTH)
      .regex(LOCALE_TAG_PATTERN, 'a locale is a BCP 47 language tag, such as en or pt-BR'),
    z
      .string()
      .min(1)
      .max(PROTECTED_RESOURCE_LIMITS.textMaxLength)
      .regex(
        CONSENT_TEXT,
        'a consent text holds no < or >, no control or invisible character, and no space at its start or end'
      )
  )
  .refine((text) => Object.hasOwn(text, PROTECTED_RESOURCE_FALLBACK_LOCALE), {
    message: `a scope's consent text is given in English (${PROTECTED_RESOURCE_FALLBACK_LOCALE}) at least: it is shown when no other locale matches`,
  })
  .refine((text) => Object.keys(text).length <= PROTECTED_RESOURCE_LIMITS.locales, {
    message: `a scope's consent text is given in at most ${PROTECTED_RESOURCE_LIMITS.locales} locales`,
  });

/** One scope a protected resource defines. */
export const protectedResourceScopeSchema = z.strictObject({
  scope: z
    .string()
    .min(1)
    .max(PROTECTED_RESOURCE_LIMITS.scopeMaxLength)
    .regex(SCOPE_TOKEN, 'a scope is printable ASCII with no space, ", <, > or \\ (RFC 6749 §3.3)')
    .refine((scope) => !isQauthOwnScope(scope), {
      error: (issue) =>
        `"${String(issue.input)}" is one of QAuth's own scopes (openid, profile, email, offline_access, agent:*, qauth:*), which a protected resource never defines`,
    }),
  text: protectedResourceScopeTextSchema,
  sensitive: z.boolean().optional(),
});

/** The scopes a protected resource defines: one entry per scope value. */
export const protectedResourceScopesSchema = z
  .array(protectedResourceScopeSchema)
  .min(1, { message: 'a protected resource defines one scope at least' })
  .max(PROTECTED_RESOURCE_LIMITS.scopes)
  .superRefine((entries, ctx) => {
    const seen = new Set<string>();
    entries.forEach((entry, index) => {
      if (seen.has(entry.scope)) {
        ctx.addIssue({
          code: 'custom',
          message: `"${entry.scope}" is listed twice`,
          path: [index, 'scope'],
        });
      }
      seen.add(entry.scope);
    });
  });

/**
 * Who may ask for a protected resource's scopes: `any_client`, every client
 * of the realm (CIMD and dynamically registered ones included), or the
 * `client_id`s listed, one at least, each once.
 */
export const protectedResourceClientsSchema = z.union([
  z.literal(ANY_CLIENT),
  z
    .array(z.string().min(1).max(PROTECTED_RESOURCE_LIMITS.clientIdMaxLength))
    .min(1, {
      message: `list one client at least, or "${ANY_CLIENT}": a resource open to no client grants nothing`,
    })
    .max(PROTECTED_RESOURCE_LIMITS.clients)
    .refine((ids) => new Set(ids).size === ids.length, { message: 'a client is listed twice' }),
]);

/** A scope a protected resource defines, as the schemas above take it. */
export type ProtectedResourceScopeInput = z.infer<typeof protectedResourceScopeSchema>;

/** Who may ask for the scopes, as {@link protectedResourceClientsSchema} takes it. */
export type ProtectedResourceClients = z.infer<typeof protectedResourceClientsSchema>;

/**
 * The text of a scope for the first of `locales` (in order) it holds, by its
 * exact tag and then by its language alone (`pt-BR` falls back to `pt`), and
 * otherwise its English text. Case is ignored, as BCP 47 tags compare.
 */
export function consentTextFor(
  text: Readonly<Record<string, string>>,
  locales: readonly string[]
): string | undefined {
  const byTag = new Map<string, string>();
  for (const [tag, value] of Object.entries(text)) byTag.set(tag.toLowerCase(), value);
  for (const locale of locales) {
    const tag = locale.toLowerCase();
    const exact = byTag.get(tag);
    if (exact !== undefined) return exact;
    const language = byTag.get(tag.split('-')[0]);
    if (language !== undefined) return language;
  }
  return byTag.get(PROTECTED_RESOURCE_FALLBACK_LOCALE);
}
