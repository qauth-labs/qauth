/**
 * The operation tag of a wire test title (#535, ADR-018 §5).
 *
 * `[POST /oauth/token]` in a `describe` or `it` title of `apps/wire-suite`
 * marks that test as a wire test of the operation: an upper-case method, one
 * space, and the path exactly as the OpenAPI document lists it, path templates
 * included (`[GET /developer/v1-rc.0/clients/{clientId}]`). A title may carry
 * several tags.
 *
 * Shared by two scripts, so the grammar has one home:
 *
 *   - `scripts/wire-coverage.mjs` counts the tags of the passing wire tests and
 *     fails when a stable operation has none;
 *   - `scripts/spec-matrix.mjs` blanks the tags out before it reads spec
 *     citations, because a path such as `/oauth/token` or
 *     `/.well-known/openid-configuration` holds a word (`oauth`, `openid`) that
 *     the joiner treats as a spec name, which would otherwise take the bare
 *     `§` references after it away from the spec the title cites.
 *
 * Node's standard library only, like both scripts.
 */

/** The methods an OpenAPI path item holds operations under, spelled as a tag spells them. */
export const TAG_METHODS = Object.freeze([
  'GET',
  'PUT',
  'POST',
  'DELETE',
  'OPTIONS',
  'HEAD',
  'PATCH',
  'TRACE',
]);

/** `[METHOD /path]`. The path is `/` and then anything but whitespace and brackets. */
const OPERATION_TAG_SOURCE = `\\[(${TAG_METHODS.join('|')}) (/[^\\s\\[\\]]*)\\]`;

/** A fresh global matcher for the tag, so no caller shares `lastIndex` with another. */
export function operationTagPattern() {
  return new RegExp(OPERATION_TAG_SOURCE, 'g');
}

/**
 * Every operation a title tags, as `METHOD /path`, in the order they appear.
 *
 * @param {string} title
 * @returns {string[]}
 */
export function operationTags(title) {
  return [...title.matchAll(operationTagPattern())].map((match) => `${match[1]} ${match[2]}`);
}

/**
 * The title with every tag replaced by as many spaces, so the positions of the
 * rest of the text do not move.
 *
 * @param {string} title
 * @returns {string}
 */
export function blankOperationTags(title) {
  return title.replace(operationTagPattern(), (tag) => ' '.repeat(tag.length));
}
