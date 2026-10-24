import { z } from 'zod';

import { classifyFieldName, type PayloadFinding, scanValues } from './payload-rules';

/**
 * The diff an admin event carries (ADR-020 §3, ADR-019 Decision 7, issue
 * #459): what an admin operation changed in one resource, field by field,
 * with every secret value masked.
 *
 * A diff is a list of changes. Each names one field by a JSON Pointer
 * (RFC 6901) into the resource and holds its value before and after the
 * operation:
 *
 * - Only changed fields are listed; an unchanged field is absent.
 * - A nested object present on both sides is diffed member by member, so a
 *   change inside it is listed at its own path.
 * - Any other value, an array included, is shown whole.
 * - `before` is absent when the field did not exist, and `after` when it no
 *   longer does. `null` means the field held `null`.
 *
 * The field names of a diff are the resource's own, not the event's, so the
 * payload rules read its values and not its names. In their place the
 * masking rule holds: a secret never enters a diff.
 *
 * ## Masking
 *
 * A field is secret, and holds {@link ADMIN_DIFF_SECRET_MARKER} whatever its
 * value, when the caller marks it, or when its name looks like a secret by the
 * payload rules (`classifyFieldName`), marked or not. A string shaped like a
 * token or a key is masked wherever it sits. A secret field is masked whole
 * and never diffed inside, and a change of its value is still listed, so a
 * rotated secret shows as changed without showing either value.
 */

/**
 * What a secret field holds once masked. One marker for every secret and
 * every value, so a stored diff tells nothing about a secret, not even its
 * length.
 */
export const ADMIN_DIFF_SECRET_MARKER = '***';

/** The most changes one diff lists. */
export const ADMIN_DIFF_MAX_CHANGES = 1024;

/** The longest path a change names, in UTF-16 units. */
export const ADMIN_DIFF_MAX_PATH = 1024;

/** A JSON value, as `jsonb` stores it. */
export type JsonValue = string | number | boolean | null | JsonValue[] | JsonObject;

/** A JSON object. */
export type JsonObject = { [member: string]: JsonValue };

/** One changed field of a diff. */
export interface AdminDiffChange {
  /** The field, as a JSON Pointer into the resource, such as `/smtp/host`. */
  path: string;
  /** The value before; absent when the field did not exist. */
  before?: JsonValue;
  /** The value after; absent when the field no longer exists. */
  after?: JsonValue;
}

/** A JSON Pointer of one or more segments; `~` only as `~0` or `~1`. */
const POINTER_PATTERN = /^(?:\/(?:[^~/]|~[01])*)+$/;

const jsonValueSchema = z.json();

/** The schema of one change. */
export const adminDiffChangeSchema = z
  .strictObject({
    path: z
      .string()
      .max(ADMIN_DIFF_MAX_PATH)
      .regex(POINTER_PATTERN)
      .describe(
        'The changed field, as a JSON Pointer (RFC 6901) into the resource, such as `/smtp/host`.'
      ),
    before: jsonValueSchema
      .optional()
      .describe(
        'The value before the operation. Absent when the field did not exist. A secret field holds `***`.'
      ),
    after: jsonValueSchema
      .optional()
      .describe(
        'The value after the operation. Absent when the field no longer exists. A secret field holds `***`.'
      ),
  })
  .describe('One changed field.');

/**
 * The schema of a diff. An event type that carries one names the member in
 * its registry entry (`diff`), and uses this schema for it as it is.
 */
export const adminDiffSchema = z
  .array(adminDiffChangeSchema)
  .max(ADMIN_DIFF_MAX_CHANGES)
  .describe(
    'What the operation changed in the target, field by field. Only changed fields are listed. A nested object is diffed member by member; any other value, an array included, is shown whole. Every secret value is `***`.'
  );

/** Options of {@link buildAdminDiff}. */
export interface AdminDiffOptions {
  /**
   * Fields the caller marks secret, by their path inside the resource:
   * member names or array indexes joined by `.`, where `*` matches any member
   * or element. For example `clientSecretHash`, `smtp.password` or
   * `webhooks.*.signingSecret`. A field whose name looks like a secret is
   * masked without a mark.
   */
  readonly secretFields?: readonly string[];
}

/** A lone UTF-16 surrogate: not well-formed Unicode, and refused by `jsonb`. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** The members of an object that hold a value; `undefined` is absent, as in `JSON.stringify`. */
function presentKeys(value: Record<string, unknown>): string[] {
  return Object.keys(value).filter((key) => value[key] !== undefined);
}

/** Throw unless `value` is plain JSON: what `jsonb` stores and reads back unchanged. */
function assertJson(value: unknown, at: string): asserts value is JsonValue {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`buildAdminDiff: ${at} is not a JSON number`);
    return;
  }
  if (typeof value === 'string') {
    if (LONE_SURROGATE.test(value)) {
      throw new TypeError(`buildAdminDiff: ${at} holds a lone surrogate`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index) || value[index] === undefined) {
        throw new TypeError(`buildAdminDiff: ${at}[${index}] is not a JSON value`);
      }
      assertJson(value[index], `${at}[${index}]`);
    }
    return;
  }
  if (!isPlainObject(value)) {
    throw new TypeError(`buildAdminDiff: ${at} is not a JSON value`);
  }
  for (const key of presentKeys(value)) assertJson(value[key], `${at}.${key}`);
}

function jsonEqual(a: JsonValue, b: JsonValue): boolean {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((item, index) => jsonEqual(item, b[index]))
    );
  }
  if (!isPlainObject(a) || !isPlainObject(b)) return false;
  const keys = presentKeys(a);
  const other = presentKeys(b);
  return (
    keys.length === other.length &&
    keys.every((key) => Object.hasOwn(b, key) && jsonEqual(a[key], b[key] as JsonValue))
  );
}

const escapeSegment = (segment: string) => segment.replace(/~/g, '~0').replace(/\//g, '~1');
const unescapeSegment = (segment: string) => segment.replace(/~1/g, '/').replace(/~0/g, '~');

/** The JSON Pointer of a path. */
const pointer = (segments: readonly string[]) =>
  segments.map((segment) => `/${escapeSegment(segment)}`).join('');

/** A path's segments from its JSON Pointer. */
function pointerSegments(path: string): string[] {
  return path.split('/').slice(1).map(unescapeSegment);
}

function parseMarks(fields: readonly string[]): string[][] {
  return fields.map((field) => {
    const segments = field.split('.');
    if (segments.some((segment) => segment === '')) {
      throw new TypeError(`buildAdminDiff: secret field "${field}" has an empty segment`);
    }
    return segments;
  });
}

const marked = (marks: readonly string[][], at: readonly string[]) =>
  marks.some(
    (mark) =>
      mark.length === at.length &&
      mark.every((segment, index) => segment === '*' || segment === at[index])
  );

/** Whether a member's name looks like a secret by the payload rules. */
export function namesASecret(name: string): boolean {
  return classifyFieldName(name) === 'secret_field';
}

/** Whether a string is shaped like a token, a signed or encrypted object, or a key. */
const tokenShaped = (value: string) => scanValues(value).length > 0;

/**
 * A whole value, as a change shows it: each member that is secret by name or
 * by mark, and each string shaped like a token, replaced by the marker.
 */
function maskWithin(
  value: JsonValue,
  at: readonly string[],
  marks: readonly string[][]
): JsonValue {
  if (typeof value === 'string') return tokenShaped(value) ? ADMIN_DIFF_SECRET_MARKER : value;
  if (Array.isArray(value)) {
    return value.map((item, index) => {
      const path = [...at, String(index)];
      return marked(marks, path) ? ADMIN_DIFF_SECRET_MARKER : maskWithin(item, path, marks);
    });
  }
  if (value === null || typeof value !== 'object') return value;
  // `Object.fromEntries` defines own properties, so a member named
  // `__proto__` stays a member and never becomes a prototype.
  return Object.fromEntries(
    presentKeys(value).map((key) => {
      const path = [...at, key];
      const member = value[key];
      return [
        key,
        namesASecret(key) || marked(marks, path)
          ? ADMIN_DIFF_SECRET_MARKER
          : maskWithin(member, path, marks),
      ];
    })
  );
}

function diffObjects(
  before: JsonObject,
  after: JsonObject,
  at: readonly string[],
  marks: readonly string[][],
  changes: AdminDiffChange[]
): void {
  // Sorted, so one change gives one diff whatever order the members came in.
  const keys = [...new Set([...presentKeys(before), ...presentKeys(after)])].sort();
  for (const key of keys) {
    const path = [...at, key];
    const hasBefore = Object.hasOwn(before, key) && before[key] !== undefined;
    const hasAfter = Object.hasOwn(after, key) && after[key] !== undefined;
    const old = before[key];
    const now = after[key];
    const secret = namesASecret(key) || marked(marks, path);

    if (hasBefore && hasAfter && !secret && isPlainObject(old) && isPlainObject(now)) {
      diffObjects(old, now, path, marks, changes);
      continue;
    }
    if (hasBefore && hasAfter && jsonEqual(old, now)) continue;

    const change: AdminDiffChange = { path: pointer(path) };
    if (hasBefore) change.before = secret ? ADMIN_DIFF_SECRET_MARKER : maskWithin(old, path, marks);
    if (hasAfter) change.after = secret ? ADMIN_DIFF_SECRET_MARKER : maskWithin(now, path, marks);
    changes.push(change);
  }
}

/**
 * The masked diff between a resource before and after an admin operation.
 * See the module comment for what it lists and what it masks.
 *
 * @param before - The resource before the operation, or `null` when the
 *   operation created it.
 * @param after - The resource after the operation, or `null` when the
 *   operation deleted it.
 * @returns The changes, ordered by path; empty when nothing changed.
 * @throws TypeError when a side is not a plain JSON object or `null`, when a
 *   value is not plain JSON (a `Date`, a `Buffer`, `NaN`, a lone surrogate, a
 *   hole in an array), when a secret field mark has an empty segment, or when
 *   the diff would list more than {@link ADMIN_DIFF_MAX_CHANGES} changes.
 */
export function buildAdminDiff(
  before: JsonObject | null,
  after: JsonObject | null,
  options: AdminDiffOptions = {}
): AdminDiffChange[] {
  for (const [side, value] of [
    ['before', before],
    ['after', after],
  ] as const) {
    if (value !== null && !isPlainObject(value)) {
      throw new TypeError(`buildAdminDiff: ${side} must be a plain object or null`);
    }
    if (value !== null) assertJson(value, side);
  }
  const changes: AdminDiffChange[] = [];
  diffObjects(before ?? {}, after ?? {}, [], parseMarks(options.secretFields ?? []), changes);
  if (changes.length > ADMIN_DIFF_MAX_CHANGES) {
    throw new TypeError(
      `buildAdminDiff: ${changes.length} changes, more than one diff lists (${ADMIN_DIFF_MAX_CHANGES})`
    );
  }
  const longPath = changes.find((change) => change.path.length > ADMIN_DIFF_MAX_PATH);
  if (longPath) {
    throw new TypeError(
      `buildAdminDiff: a changed field's path is longer than ${ADMIN_DIFF_MAX_PATH}`
    );
  }
  return changes;
}

function unmasked(path: string, name: string): PayloadFinding {
  return {
    path,
    rule: 'secret_field',
    message: `"${name}" names a secret; in an admin diff it must hold "${ADMIN_DIFF_SECRET_MARKER}"`,
  };
}

const escapePointer = escapeSegment;

/** Every member under `value` named like a secret that does not hold the marker. */
function unmaskedWithin(value: unknown, at: string): PayloadFinding[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => unmaskedWithin(item, `${at}/${index}`));
  }
  if (value === null || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, member]) => {
    const path = `${at}/${escapePointer(key)}`;
    if (!namesASecret(key)) return unmaskedWithin(member, path);
    return member === ADMIN_DIFF_SECRET_MARKER ? [] : [unmasked(path, key)];
  });
}

/**
 * Check a diff against the masking rule: a change whose path names a secret
 * holds the marker on each side it has, and so does every member named like
 * a secret inside a value. The payload rules run this over a type's `diff`
 * member in place of reading its names. It cannot know what a caller marked:
 * the marks are {@link buildAdminDiff}'s to apply.
 *
 * @param diff - The diff, as the event carries it.
 * @param at - The JSON Pointer of the diff inside the payload, for findings.
 * @returns Every finding; empty when the diff is masked.
 */
export function scanAdminDiff(diff: unknown, at = ''): PayloadFinding[] {
  if (!Array.isArray(diff)) return [];
  return diff.flatMap((change: unknown, index) => {
    if (!isPlainObject(change) || typeof change['path'] !== 'string') return [];
    const base = `${at}/${index}`;
    const secretName = pointerSegments(change['path']).find(namesASecret);
    return (['before', 'after'] as const).flatMap((side) => {
      if (!Object.hasOwn(change, side)) return [];
      const value = change[side];
      if (secretName !== undefined) {
        return value === ADMIN_DIFF_SECRET_MARKER ? [] : [unmasked(`${base}/${side}`, secretName)];
      }
      return unmaskedWithin(value, `${base}/${side}`);
    });
  });
}
