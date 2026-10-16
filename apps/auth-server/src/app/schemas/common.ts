import { z } from 'zod';

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

/**
 * `z.url()` for every URL QAuth compares as a string: `redirect_uri`, RFC 8707
 * `resource`, and the redirect URIs registered through `/api/clients`. A value
 * that passes comes out exactly as it went in, with only its ends trimmed.
 *
 * Plain `z.url()` cannot be used for these. Since Zod 4.5 it returns its input
 * with every ASCII tab, LF and CR removed, which is what the WHATWG URL parser
 * does before it parses. `https://app.exa\nmple.com/cb` would come out as
 * `https://app.example.com/cb` and match a registered URI it does not equal.
 * That puts a URL parser's rewrite into the redirect_uri decision, which must
 * stay an exact string comparison (RFC 9700 §2.1, `redirectUriMatchesRegistered`).
 * It would also split /authorize from /token, whose `redirect_uri` is a plain
 * string. RFC 3986 allows none of these characters in a URI, so a value with
 * one inside it is rejected before the URL check runs. Nothing is left for Zod
 * to remove from a value that passes, so the output is the trimmed input, as it
 * was with Zod 4.4.
 *
 * Built as `z.string()` plus checks rather than `z.url().refine()`: a format
 * schema runs its own check before any check chained onto it, so a refinement
 * on `z.url()` would only ever see the stripped value. The URL check still
 * sets `format: "uri"` in the generated OpenAPI document.
 */
export function exactUrl() {
  return z
    .string()
    .refine((value) => !hasInteriorTabOrNewline(value), { message: 'Invalid URL' })
    .check(z.url());
}

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
