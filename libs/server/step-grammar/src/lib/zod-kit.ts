import { DISPLAY_TEXT_PATTERN, type DisplaySource } from '@qauth-labs/shared-interaction-contract';
import { z } from 'zod';

import { isDateTime, isUri } from './formats';
import { toJsonSchemaPart } from './json-schema';

/**
 * Zod builders for the step grammar, one for each JSON Schema builder of the
 * Interaction API contract (`schema-kit.ts` in
 * `@qauth-labs/shared-interaction-contract`). Each builds the same rule as a
 * runtime check, and its JSON Schema (`json-schema.ts`) is the one the
 * contract publishes; `json-schema.test.ts` compares every step file.
 *
 * A `format` is checked as the published schemas' validator checks it
 * (`formats.ts`, ajv-formats in full mode), beside the `pattern`.
 *
 * Zod counts a string's length in UTF-16 code units where JSON Schema counts
 * code points, so a character outside the Basic Multilingual Plane counts
 * twice. Against a maximum that is stricter. Against a minimum it would be
 * laxer, but every string here with a minimum above one is held to ASCII by
 * its pattern or is parsed as JSON (`jsonString`), so no value is affected.
 */

/**
 * A string that matches `pattern`, read with the `u` flag as JSON Schema
 * reads every pattern. The published `pattern` is the string itself:
 * `RegExp#source` would write `/` as `\/`.
 */
export function matching(schema: z.ZodString, pattern: string): z.ZodString {
  return schema.regex(new RegExp(pattern, 'u')).meta({ pattern });
}

/** A display value (the contract's display rule): bounded, no markup, control or format character. */
export function displayText(source: DisplaySource, maxLength: number, description: string) {
  return matching(z.string().min(1).max(maxLength), DISPLAY_TEXT_PATTERN).meta({
    'x-qauth-display': source,
    description,
  });
}

/** A base64url string (RFC 4648 §5, no padding) of `min` to `max` characters. */
export function base64url(min: number, max: number, description: string) {
  const pattern = min === max ? `^[A-Za-z0-9_-]{${min}}$` : `^[A-Za-z0-9_-]{${min},${max}}$`;
  return matching(z.string().min(min).max(max), pattern).meta({ description });
}

/** An RFC 3339 UTC time, such as `2026-10-26T09:30:00Z`: a real date and time. */
export function dateTime(description: string) {
  return matching(
    z.string().max(30),
    '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?Z$'
  )
    .refine(isDateTime)
    .meta({ format: 'date-time', description });
}

/** A DNS host name in its ASCII form (IDNs as `xn--` labels), lower case. */
export function host(description: string) {
  return matching(
    z.string().min(1).max(253),
    '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  ).meta({ description });
}

/** Printable ASCII without space, `"`, `<`, `>` and `\`: the characters a URI may carry unescaped. */
export const URI_CHARACTERS = '[!#-;=?-\\[\\]-~]';

/** The schemes a browser runs or reads locally, which no absolute URI here may have. */
const BROWSER_LOCAL_SCHEME = '^(?:javascript|data|vbscript|file|blob):';

/** An absolute URI of any scheme except those a browser runs or reads locally. */
export function absoluteUri(maxLength: number, description: string) {
  const browserLocal = new RegExp(BROWSER_LOCAL_SCHEME, 'u');
  return matching(z.string().max(maxLength), `^[a-z][a-z0-9+.-]*:${URI_CHARACTERS}+$`)
    .refine((value) => !browserLocal.test(value))
    .refine(isUri)
    .meta({
      format: 'uri',
      not: { type: 'string', pattern: BROWSER_LOCAL_SCHEME },
      description,
    });
}

/** A URI that matches `pattern`: `format: uri`, checked as RFC 3986 reads it. */
export function uriMatching(maxLength: number, pattern: string, description: string) {
  return matching(z.string().max(maxLength), pattern)
    .refine(isUri)
    .meta({ format: 'uri', description });
}

/** Mark a value that a client or a device declared (the contract's `declared`). */
export function declared<T extends z.ZodType>(schema: T): T {
  return schema.meta({ 'x-qauth-declared': true });
}

/** A string from a closed set. */
export function closedEnum<const T extends readonly [string, ...string[]]>(
  values: T,
  description: string
) {
  return z.enum(values).meta({ description });
}

/** An integer from a closed set: `{ "type": "integer", "enum": [...] }`. */
export function integerEnum<const T extends readonly [number, ...number[]]>(
  values: T,
  description: string
) {
  return z.literal(values).meta({ description });
}

/** An integer from `min` to `max`. */
export function integer(min: number, max: number, description: string) {
  return z.int().min(min).max(max).meta({ description });
}

/** A string that is always `value`: `{ "const": value }`. */
export function constant<const T extends string | boolean>(value: T, description?: string) {
  const schema = z.literal(value);
  return description === undefined ? schema : schema.meta({ description });
}

/**
 * An object with the given members, closed: a member it does not declare is
 * refused, as the contract's `object` closes every object it publishes. A
 * member is required unless its schema is `.optional()`.
 */
export function object<T extends z.core.$ZodLooseShape>(shape: T, description?: string) {
  const schema = z.strictObject(shape);
  return description === undefined ? schema : schema.meta({ description });
}

/**
 * An object that may carry members it does not declare. Only for a value the
 * contract does not own: a WebAuthn response a browser serialises.
 */
export function openObject<T extends z.core.$ZodLooseShape>(shape: T) {
  return z.looseObject(shape);
}

/** An object with no members: a step that has no params, or no personal data. */
export const EMPTY_OBJECT = z.strictObject({});

/** An array of `items`, `min` to `max` long. */
export function array<T extends z.ZodType>(
  items: T,
  min: number,
  max: number,
  description?: string
) {
  const schema = z.array(items).min(min).max(max);
  return description === undefined ? schema : schema.meta({ description });
}

/** An array of `min` to `max` distinct items. */
export function distinctArray<T extends z.ZodType>(
  items: T,
  min: number,
  max: number,
  description: string
) {
  return z
    .array(items)
    .min(min)
    .max(max)
    .refine(
      (values) => new Set(values.map((value) => JSON.stringify(value))).size === values.length
    )
    .meta({ uniqueItems: true, description });
}

/**
 * A string that carries a JSON document matching `content`: JSON Schema's
 * `contentMediaType` and `contentSchema`. JSON Schema leaves both as
 * annotations; here the server parses the string and checks it, so a value
 * that is not such a document is refused at the answer, before any verifier
 * reads it.
 */
export function jsonString<T extends z.ZodType>(
  content: T,
  minLength: number,
  maxLength: number,
  description: string
) {
  return z
    .string()
    .min(minLength)
    .max(maxLength)
    .refine((value) => {
      try {
        return content.safeParse(JSON.parse(value)).success;
      } catch {
        return false;
      }
    })
    .meta({
      contentMediaType: 'application/json',
      contentSchema: toJsonSchemaPart(content),
      description,
    });
}
