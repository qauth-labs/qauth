import { z } from 'zod';

import { OAUTH_CLIENT_ID_MAX_LENGTH, OAUTH_URI_PARAM_MAX_LENGTH } from '../constants/security';

/**
 * Error response schema (matches error handler output)
 */
export const errorResponseSchema = z.object({
  error: z.string(),
  statusCode: z.number(),
});

/**
 * Error response type
 */
export type ErrorResponse = z.infer<typeof errorResponseSchema>;

/** An ASCII tab, line feed or carriage return. */
const TAB_OR_NEWLINE = /[\t\n\r]/;

/**
 * Whether `value` holds an ASCII tab, LF or CR outside the leading and
 * trailing whitespace that `z.url()` trims.
 */
export function hasInteriorTabOrNewline(value: string): boolean {
  return TAB_OR_NEWLINE.test(value.trim());
}

/** Printable ASCII without the space: every character RFC 3986 allows in a URI. */
const URI_CHARACTERS = /^[\x21-\x7E]*$/;

/**
 * Whether `value` holds only characters RFC 3986 allows in a URI.
 *
 * Checked before a URL parser sees a caller's value. `new URL()` does work
 * quadratic in the number of distinct non-ASCII characters in a host (IDNA
 * mapping), so a 2048-character CJK host is still milliseconds of blocked event
 * loop per parse, and a single request carries dozens of them. A URI is ASCII
 * by definition: an internationalised host is written in its `xn--` form and
 * any other non-ASCII character percent-encoded.
 */
export function hasOnlyUriCharacters(value: string): boolean {
  return URI_CHARACTERS.test(value);
}

/**
 * `z.url()` for every URL QAuth compares as a string: `redirect_uri`, RFC 8707
 * `resource`, and the redirect URIs registered through `/api/clients`. A value
 * that passes comes out exactly as it went in, with only its ends trimmed.
 *
 * BOUNDED BEFORE IT IS PARSED. The length (`maxLength`, 2048 by default) and
 * the character set ({@link hasOnlyUriCharacters}) are checked first and abort
 * the pipeline, so the URL parser never sees a value that fails either. A cap
 * chained after this schema (`exactUrl().max(n)`) would run only after the
 * parse and bound nothing.
 *
 * Plain `z.url()` cannot be used for these. Since Zod 4.5 it returns its input
 * with every ASCII tab, LF and CR removed, which is what the WHATWG URL parser
 * does before it parses. `https://app.exa\nmple.com/cb` would come out as
 * `https://app.example.com/cb` and match a registered URI it does not equal.
 * That puts a URL parser's rewrite into the redirect_uri decision, which must
 * stay an exact string comparison (RFC 9700 §2.1, `redirectUriMatchesRegistered`).
 * It would also split /authorize from /token, whose `redirect_uri` is a plain
 * string. RFC 3986 allows none of these characters in a URI, so a value with
 * one inside it is rejected before the URL check runs (the character-set check
 * covers them). Nothing is left for Zod to remove from a value that passes, so
 * the output is the trimmed input, as it was with Zod 4.4.
 *
 * Built as `z.string()` plus checks rather than `z.url().refine()`: a format
 * schema runs its own check before any check chained onto it, so a refinement
 * on `z.url()` would only ever see the stripped value, and only after the
 * parse. `abort: true` on the two guards is what keeps the URL check from
 * running after either fails. The URL check still sets `format: "uri"` in the
 * generated OpenAPI document, next to `maxLength`.
 */
export function exactUrl(maxLength: number = OAUTH_URI_PARAM_MAX_LENGTH) {
  return z
    .string()
    .max(maxLength, { abort: true })
    .refine((value) => hasOnlyUriCharacters(value.trim()), {
      message: 'Invalid URL',
      abort: true,
    })
    .check(z.url());
}

/** RFC 6749 Appendix A.1: `client-id = *VSCHAR`, `VSCHAR = %x20-7E`. */
const CLIENT_ID_CHARACTERS = /^[\x20-\x7E]*$/;

/**
 * `client_id` as a request parameter: 1 to {@link OAUTH_CLIENT_ID_MAX_LENGTH}
 * characters of RFC 6749 VSCHAR, the length checked first.
 *
 * Bounded like every other pre-authentication string: a refused `client_id` is
 * written to `audit_logs`, and an unknown one is parsed as a URL on the Client
 * ID Metadata Document path, where a long non-ASCII host is expensive. 2048
 * leaves room for a CIMD URL `client_id`.
 */
export const clientIdParamSchema = z
  .string()
  .min(1)
  .max(OAUTH_CLIENT_ID_MAX_LENGTH, { abort: true })
  .regex(CLIENT_ID_CHARACTERS, { message: 'client_id must be printable ASCII' });

/**
 * Bound a request array to `max` elements, checking its length BEFORE any of
 * its elements.
 *
 * `z.array(element).max(max)` alone does not bound the work. Zod parses every
 * element first and runs the array's own checks afterwards, and each failing
 * element is an issue of its own, so the caller rather than the schema chooses
 * how many issues a request produces: a 1 MB body of two-byte elements yields
 * ~490 000, seconds of event-loop time on an unauthenticated route before the
 * error handler copies them again. An issue raised in a `preprocess` step stops
 * the pipe, so an oversized array costs one length comparison and raises the
 * same single `too_big` issue that `.max()` reports.
 *
 * Every array in a request schema goes through this. `.max()` stays on the
 * inner array so the published JSON Schema keeps its `maxItems`. Give a
 * default with `.prefault()`, not `.default()`: Zod leaves a `.default()` set
 * on a preprocessed schema out of the input JSON Schema.
 */
export function boundedArray<T extends z.ZodArray>(array: T, max: number) {
  return z.preprocess((value, ctx) => {
    if (Array.isArray(value) && value.length > max) {
      ctx.addIssue({ code: 'too_big', origin: 'array', maximum: max, inclusive: true });
      return z.NEVER;
    }
    return value;
  }, array.max(max));
}
