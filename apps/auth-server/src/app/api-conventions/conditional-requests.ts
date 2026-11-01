import { createHash } from 'node:crypto';

import { PreconditionRequiredError } from '@qauth-labs/shared-errors';
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';

import { UnsupportedMediaTypeError } from '../helpers/api-request-errors';

/**
 * Optimistic concurrency for the admin, account and developer APIs (RFC 9110
 * §13.1.1, #506): a read of one resource answers an `ETag`, and an update
 * names the version it replaces in `If-Match`. Without one the update is
 * refused with 428 (RFC 6585 §3), with another version with 412.
 *
 * The admin listener checks `If-Match` in its pipeline (`plugins/admin-operations.ts`);
 * a route of the public listener checks it with {@link requireIfMatch} before
 * validation and compares it in its handler, under a row lock, with
 * {@link ifMatchAllows}.
 */

/**
 * The strong entity tag of a representation (RFC 9110 §8.8.3): the SHA-256 of
 * its JSON, base64url, quoted. Two representations that serialize alike get
 * the same tag, and any change to one member changes it. `value` is built by
 * the route, with its members in a fixed order, so the JSON is stable.
 */
export function entityTagOf(value: unknown): string {
  return `"${createHash('sha256').update(JSON.stringify(value)).digest('base64url')}"`;
}

/** The opaque value inside a strong entity tag: `"abc"` gives `abc`. */
export function entityTagValue(tag: string): string {
  return tag.startsWith('"') && tag.endsWith('"') ? tag.slice(1, -1) : tag;
}

/**
 * The `If-Match` request header as an update route declares it, so the
 * OpenAPI document marks it required. A request without it is answered 428
 * by {@link requireIfMatch} before this schema is checked, not 400.
 */
export const ifMatchHeadersSchema = z.looseObject({
  'if-match': z.string().meta({
    description: 'The ETag of the representation this update replaces (RFC 9110 §13.1.1).',
  }),
});

/** RFC 7396 §4: the media type of a JSON Merge Patch. */
export const MERGE_PATCH_MEDIA_TYPE = 'application/merge-patch+json';

/**
 * A `preValidation` hook: refuse a `PATCH` body that is not a JSON Merge
 * Patch with 415 `unsupported_media_type`. A JSON body would parse as one,
 * but the API conventions take only the merge patch media type, so a client
 * says which semantics it means.
 */
export async function requireMergePatch(request: FastifyRequest): Promise<void> {
  const mediaType = (request.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (mediaType !== MERGE_PATCH_MEDIA_TYPE) {
    throw new UnsupportedMediaTypeError();
  }
}

/**
 * A `preValidation` hook: refuse an update that names no version with 428
 * `precondition_required`, before its body and headers are validated.
 */
export async function requireIfMatch(request: FastifyRequest): Promise<void> {
  if (request.headers['if-match'] === undefined) {
    throw new PreconditionRequiredError();
  }
}

/** Whether `code` is an `etagc` (RFC 9110 §8.8.3): `%x21 / %x23-7E / obs-text`. */
function isEntityTagChar(code: number): boolean {
  return code === 0x21 || (code >= 0x23 && code <= 0x7e) || (code >= 0x80 && code <= 0xff);
}

/** Whether `char` is optional whitespace (RFC 9110 §5.6.3). */
function isOws(char: string | undefined): boolean {
  return char === ' ' || char === '\t';
}

/**
 * Whether an `If-Match` field (RFC 9110 §13.1.1) lets a request act on the
 * state of version `stateVersion`: absent, `*`, or a list holding the strong
 * entity-tag `"stateVersion"`. A weak tag never matches (strong comparison),
 * empty list elements are skipped, and a field that does not parse matches
 * nothing.
 *
 * Parsed in one pass, without a regular expression: a pattern with repeated
 * whitespace and comma groups is polynomial on a long run of either.
 */
export function ifMatchAllows(field: string | string[] | undefined, stateVersion: string): boolean {
  if (field === undefined) return true;
  const value = (Array.isArray(field) ? field.join(', ') : field).trim();
  if (value === '*') return true;
  if (value === '') return false;
  let matched = false;
  let i = 0;
  while (i < value.length) {
    // Optional whitespace and empty list elements before the next tag.
    while (i < value.length && (isOws(value[i]) || value[i] === ',')) i++;
    if (i >= value.length) break;
    const weak = value.startsWith('W/', i);
    if (weak) i += 2;
    if (value[i] !== '"') return false;
    const start = ++i;
    while (i < value.length && isEntityTagChar(value.charCodeAt(i))) i++;
    if (value[i] !== '"') return false;
    const opaque = value.slice(start, i);
    i++;
    while (i < value.length && isOws(value[i])) i++;
    if (i < value.length && value[i] !== ',') return false;
    if (!weak && opaque === stateVersion) matched = true;
  }
  return matched;
}
