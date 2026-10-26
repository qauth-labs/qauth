/**
 * Building blocks for the contract's JSON Schema (draft 2020-12, the dialect of
 * OpenAPI 3.1).
 *
 * The display rule of ADR-019 Decision 6 is written into these helpers: the
 * API returns typed data from the auth server's own records and never HTML, so
 * every string a response carries is an enum, a constant, or a bounded value
 * with a pattern. A value that reaches a screen as text is a display value
 * ({@link displayText}): length-capped, and with no markup bracket, control,
 * format (bidirectional, zero-width) or line-separator character, so a page can
 * show it as plain text and a client-supplied name cannot reorder or hide the
 * text around it. `display-rules.test.ts` checks every response schema against
 * this rule.
 *
 * Patterns use only syntax that ECMAScript (with the `u` flag, as JSON Schema
 * requires) and RE2 both read: no lookaround, no backreference, `\p{..}` with
 * general categories only.
 */

/** A JSON Schema object. Loose on purpose: the contract tests compile every one. */
export type JsonSchema = { readonly [keyword: string]: unknown };

/**
 * Hangul filler characters: letters by category, but they render as nothing,
 * so a name made of them looks blank.
 */
const FILLERS = '\\u115F\\u1160\\u3164\\uFFA0';

/**
 * A display value: no `<` or `>`, no character of the Unicode category Other
 * (controls, format characters such as the bidirectional overrides and
 * zero-width spaces, surrogates, private use, unassigned), no line or
 * paragraph separator and no Hangul filler; spaces only between other
 * characters, so a value is never blank or padded.
 */
export const DISPLAY_TEXT_PATTERN = `^[^<>\\p{C}\\p{Z}${FILLERS}](?:[^<>\\p{C}\\p{Zl}\\p{Zp}${FILLERS}]*[^<>\\p{C}\\p{Z}${FILLERS}])?$`;

/**
 * Where a display value comes from, as the `x-qauth-display` annotation says:
 *
 * - `realm`: set by an admin of the realm (brand strings, a scope's consent text);
 * - `server`: derived by the auth server from its own data (a region from an
 *   address lookup);
 * - `account`: the signed-in or selected account's own data (an identifier),
 *   returned only by the personal-data read;
 * - `declared`: declared by a client, a device or a registrant (a client's
 *   name, a device's user agent, a network's registered name). A screen marks
 *   it as declared and never shows it above or instead of the verified data.
 */
export type DisplaySource = 'realm' | 'server' | 'account' | 'declared';

export const DISPLAY_SOURCES: readonly DisplaySource[] = ['realm', 'server', 'account', 'declared'];

/** A bounded display value; see the module comment. */
export function displayText(
  source: DisplaySource,
  maxLength: number,
  description: string
): JsonSchema {
  return {
    type: 'string',
    minLength: 1,
    maxLength,
    pattern: DISPLAY_TEXT_PATTERN,
    'x-qauth-display': source,
    description,
  };
}

/** A base64url string (RFC 4648 §5, no padding) of `min` to `max` characters. */
export function base64url(min: number, max: number, description: string): JsonSchema {
  return {
    type: 'string',
    minLength: min,
    maxLength: max,
    pattern: min === max ? `^[A-Za-z0-9_-]{${min}}$` : `^[A-Za-z0-9_-]{${min},${max}}$`,
    description,
  };
}

/** An RFC 3339 UTC time, such as `2026-10-26T09:30:00Z` (the API conventions' time rule). */
export function dateTime(description: string): JsonSchema {
  return {
    type: 'string',
    format: 'date-time',
    maxLength: 30,
    pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?Z$',
    description,
  };
}

/** A DNS host name in its ASCII form (IDNs as `xn--` labels), lower case. */
export function host(description: string): JsonSchema {
  return {
    type: 'string',
    minLength: 1,
    maxLength: 253,
    pattern: '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
    description,
  };
}

/** Printable ASCII without space, `"`, `<`, `>` and `\`: the characters a URI may carry unescaped. */
const URI_CHARACTERS = '[!#-;=?-\\[\\]-~]';

/** An `https` URL. */
export function httpsUrl(maxLength: number, description: string): JsonSchema {
  return {
    type: 'string',
    format: 'uri',
    maxLength,
    pattern: `^https://${URI_CHARACTERS}+$`,
    description,
  };
}

/**
 * An absolute URI of any scheme (a redirect to a native app uses its own
 * scheme), except the schemes a browser runs or reads locally. The scheme is
 * lower case, so `JavaScript:` is refused by the pattern and `javascript:` by
 * the `not`.
 */
export function absoluteUri(maxLength: number, description: string): JsonSchema {
  return {
    type: 'string',
    format: 'uri',
    maxLength,
    pattern: `^[a-z][a-z0-9+.-]*:${URI_CHARACTERS}+$`,
    not: { type: 'string', pattern: '^(?:javascript|data|vbscript|file|blob):' },
    description,
  };
}

/**
 * Mark a value that a client or a device declared, which is not text but must
 * still be shown as declared (a resource URL the request named). Text a client
 * declared is a {@link displayText} with the `declared` source.
 */
export function declared(schema: JsonSchema): JsonSchema {
  return { ...schema, 'x-qauth-declared': true };
}

/**
 * A path on the realm origin, such as `/ui/assets/logo-3f9a1c2e.svg`. Never
 * `//…`, which a browser reads as another host, and no `.` or `..` segment.
 */
export function sameOriginPath(description: string): JsonSchema {
  return {
    type: 'string',
    minLength: 2,
    maxLength: 255,
    pattern: '^(?:/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+$',
    description,
  };
}

/** A string from a closed set. */
export function closedEnum(values: readonly string[], description: string): JsonSchema {
  return { type: 'string', enum: [...values], description };
}

/**
 * A string from a set that grows within a major version (step names, problem
 * codes, fonts). Published as `x-extensible-enum`, not `enum`: a client accepts
 * a value it does not know, and adding one is not a break for the
 * stable-surface check (`stable-surface/README.md`). The pattern bounds it.
 */
export function extensibleEnum(
  values: readonly string[],
  pattern: string,
  maxLength: number,
  description: string
): JsonSchema {
  return { type: 'string', maxLength, pattern, 'x-extensible-enum': [...values], description };
}

/**
 * An object with the given members, closed (`additionalProperties: false`):
 * a response schema lists every member that version of the contract sends, so
 * no value can reach a screen past the display rule, and a request with a
 * member it does not declare is refused. A later version may add members,
 * which a client ignores (the versioning rules). `required` lists the members
 * that are always present; `rules` are conditions between members
 * ({@link whenEquals}), which constrain the object without changing its type.
 */
export function object(
  properties: Record<string, JsonSchema>,
  required: readonly string[],
  description?: string,
  rules: readonly JsonSchema[] = []
): JsonSchema {
  return { ...openObject(properties, required, description, rules), additionalProperties: false };
}

/**
 * An object that may carry members it does not declare. Only for a value the
 * contract does not own: a WebAuthn response a browser serialises, and a
 * problem document, whose type may define extension members (RFC 9457 §3.2).
 */
export function openObject(
  properties: Record<string, JsonSchema>,
  required: readonly string[],
  description?: string,
  rules: readonly JsonSchema[] = []
): JsonSchema {
  for (const name of required) {
    if (!(name in properties)) throw new Error(`required member ${name} is not declared`);
  }
  return {
    type: 'object',
    ...(description === undefined ? {} : { description }),
    properties,
    ...(required.length === 0 ? {} : { required: [...required] }),
    ...(rules.length === 0 ? {} : { allOf: [...rules] }),
  };
}

/** A schema no value matches: a member that is never present. */
export const NEVER: JsonSchema = { not: {} };

/**
 * A rule of an object: when `member` holds one of `values`, the object also
 * matches `then` (more required members, or members that must be absent).
 */
export function whenEquals(
  member: string,
  values: readonly string[],
  then: JsonSchema
): JsonSchema {
  return {
    if: {
      properties: { [member]: values.length === 1 ? { const: values[0] } : { enum: [...values] } },
      required: [member],
    },
    then,
  };
}

/**
 * A request object: closed, as the API conventions require of every request
 * body, like every {@link object}. A request with a member it does not
 * declare is refused.
 */
export function closedObject(
  properties: Record<string, JsonSchema>,
  required: readonly string[],
  description?: string
): JsonSchema {
  return object(properties, required, description);
}

/** An array of `items`, `min` to `max` long. */
export function array(
  items: JsonSchema,
  min: number,
  max: number,
  description: string
): JsonSchema {
  return { type: 'array', description, items, minItems: min, maxItems: max };
}

/** An object with no members: a step that has no params, or no personal data. */
export const EMPTY_OBJECT: JsonSchema = {
  type: 'object',
  properties: {},
  additionalProperties: false,
};

/** A request object with no members. */
export const EMPTY_CLOSED_OBJECT: JsonSchema = {
  type: 'object',
  properties: {},
  additionalProperties: false,
};
