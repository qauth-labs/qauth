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

/** The characters a display value may hold: anything but `<`, `>`, controls, format and line/paragraph separators. */
export const DISPLAY_TEXT_PATTERN = '^[^<>\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}]+$';

/**
 * Where a display value comes from, as the `x-qauth-display` annotation says:
 *
 * - `realm`: set by an admin of the realm (brand strings, a scope's consent text);
 * - `server`: derived by the auth server from its own data (a network name from
 *   an address lookup);
 * - `account`: the signed-in or selected account's own data (an identifier),
 *   returned only by the personal-data read;
 * - `declared`: declared by a client or a device (a client's name, a device's
 *   user agent). A screen marks it as declared and never shows it above or
 *   instead of the verified data.
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

/** An absolute URI of any scheme (a redirect to a native app uses its own scheme). */
export function absoluteUri(maxLength: number, description: string): JsonSchema {
  return {
    type: 'string',
    format: 'uri',
    maxLength,
    pattern: `^[a-z][a-z0-9+.-]*:${URI_CHARACTERS}+$`,
    description,
  };
}

/**
 * A path on the realm origin, such as `/ui/assets/logo-3f9a1c2e.svg`. Never
 * `//…`, which a browser reads as another host.
 */
export function sameOriginPath(description: string): JsonSchema {
  return {
    type: 'string',
    minLength: 2,
    maxLength: 255,
    pattern: '^/[A-Za-z0-9._~-][A-Za-z0-9._~/-]*$',
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

/** An object with the given members. `required` lists the members that are always present. */
export function object(
  properties: Record<string, JsonSchema>,
  required: readonly string[],
  description?: string
): JsonSchema {
  for (const name of required) {
    if (!(name in properties)) throw new Error(`required member ${name} is not declared`);
  }
  return {
    type: 'object',
    ...(description === undefined ? {} : { description }),
    properties,
    ...(required.length === 0 ? {} : { required: [...required] }),
  };
}

/**
 * A request object: closed (`additionalProperties: false`), as the API
 * conventions require of every request body. A request with a member it does
 * not declare is refused.
 */
export function closedObject(
  properties: Record<string, JsonSchema>,
  required: readonly string[],
  description?: string
): JsonSchema {
  return { ...object(properties, required, description), additionalProperties: false };
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

/** An object with no members: a step that has no params, or no answer fields. */
export const EMPTY_OBJECT: JsonSchema = { type: 'object', properties: {} };

/** A request object with no members. */
export const EMPTY_CLOSED_OBJECT: JsonSchema = {
  type: 'object',
  properties: {},
  additionalProperties: false,
};
