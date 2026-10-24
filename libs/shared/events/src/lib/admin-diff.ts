import { z } from 'zod';

import { fieldNameWords, type PayloadFinding, scanValues } from './payload-rules';

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
 * masking rule holds: a secret never enters a diff. Personal data does: an
 * admin event shows an admin's change to a user's contact address as it is.
 *
 * ## Masking
 *
 * A field is secret, and holds {@link ADMIN_DIFF_SECRET_MARKER} whatever its
 * value, when the caller marks it, or when its name holds a secret
 * ({@link namesASecret}), marked or not. A secret field is masked whole and
 * never diffed inside, and a change of its value is still listed, so a
 * rotated secret shows as changed without showing either value. A boolean is
 * never masked: a flag holds no secret. In a name and value pair, such as a
 * custom header `{ name: 'X-Api-Key', value: '…' }`, the `value` is secret
 * when the name holds a secret.
 *
 * A value shaped like a secret is masked wherever it sits
 * ({@link isSecretShaped}): a token, a signed or encrypted object, a key, a
 * URL with a password, an `Authorization` header value, or a private JWK
 * (an AKP key's `priv` or `seed` included). A member name shaped like a
 * token, a key or a URL with a password cannot be masked without changing
 * the resource's shape, so it is refused.
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

/**
 * Words that name a value which is itself a secret. Wider than the payload
 * rules' list where a resource names secrets in ways an event never does
 * (`smtp.auth.pass`, `bindPw`, `dsn`, `connectionString`), and narrower where
 * a resource field only mentions one (see {@link DESCRIBING_WORDS}).
 */
export const DIFF_SECRET_WORDS: ReadonlySet<string> = new Set([
  'password',
  'passwords',
  'passwd',
  'passphrase',
  'passcode',
  'pwd',
  'pass',
  'pw',
  'pin',
  'pins',
  'secret',
  'secrets',
  'token',
  'tokens',
  'otp',
  'otps',
  'totp',
  'hotp',
  'seed',
  'salt',
  'key',
  'keys',
  'apikey',
  'cookie',
  'cookies',
  'assertion',
  'assertions',
  'signature',
  'signatures',
  'jwt',
  'jwts',
  'bearer',
  'credential',
  'credentials',
  'auth',
  'authorization',
  'code',
  'codes',
  'dsn',
  'connection',
]);

/** Secret words also caught inside a longer word written without a separator. */
export const DIFF_SECRET_STEMS: readonly string[] = [
  'password',
  'passwd',
  'passphrase',
  'passcode',
  'secret',
  'token',
  'apikey',
  'privatekey',
  'signingkey',
  'jwt',
];

/** Words that name a link, which is a secret only when it is a one-time link. */
const LINK_WORDS: ReadonlySet<string> = new Set([
  'link',
  'links',
  'url',
  'urls',
  'uri',
  'uris',
  'href',
]);

/** What a set-up, reset or other one-time link is called (ADR-019 Decision 7). */
const ONE_TIME_LINK_STEMS: readonly string[] = [
  'reset',
  'setup',
  'enrol',
  'enroll',
  'invit',
  'magic',
  'recover',
  'verif',
  'confirm',
  'activat',
  'onetime',
];

/**
 * Last words that say a field describes a secret rather than holds it: its
 * id, type, method, lifetime, policy or address. `accessTokenTtl`,
 * `tokenEndpointAuthMethod`, `passwordMinScore`, `jwksUri` and
 * `signingKeyId` are shown; `clientSecretHash` and `signingKey` are not.
 */
export const DESCRIBING_WORDS: ReadonlySet<string> = new Set([
  'id',
  'ids',
  'type',
  'types',
  'count',
  'method',
  'methods',
  'alg',
  'algorithm',
  'algorithms',
  'lifespan',
  'lifetime',
  'ttl',
  'timeout',
  'expiry',
  'expires',
  'expiration',
  'at',
  'seconds',
  'minutes',
  'hours',
  'days',
  'interval',
  'length',
  'min',
  'max',
  'limit',
  'size',
  'bits',
  'reuse',
  'score',
  'policy',
  'policies',
  'enabled',
  'required',
  'rotated',
  'rotation',
  'mode',
  'format',
  'version',
  'endpoint',
  'endpoints',
  'uri',
  'uris',
  'url',
  'urls',
]);

/**
 * Whether a member's name says it holds a secret (see the module comment):
 * a one-time link (`resetLink`, `setupUrl`); otherwise, unless its last word
 * only describes the secret, a name with a secret word (`smtpPassword`,
 * `pass`, `signingKey`, `connectionString`) or a secret stem (`clientsecret`).
 */
export function namesASecret(name: string): boolean {
  const words = fieldNameWords(name);
  if (words.length === 0) return false;
  const joined = words.join('');
  if (
    words.some((word) => LINK_WORDS.has(word)) &&
    ONE_TIME_LINK_STEMS.some((stem) => joined.includes(stem))
  ) {
    return true;
  }
  if (words.length > 1 && DESCRIBING_WORDS.has(words[words.length - 1])) return false;
  return words.some(
    (word) => DIFF_SECRET_WORDS.has(word) || DIFF_SECRET_STEMS.some((stem) => word.includes(stem))
  );
}

/** A URL with a password in it: `scheme://user:password@host`. */
const URL_WITH_PASSWORD = /^[a-z][a-z0-9+.-]*:\/\/[^\s/@:]*:[^\s/@]*@/i;

/**
 * An `Authorization` header value: a scheme that carries a credential and one
 * token68 after it (RFC 9110 §11.4), so prose such as "Basic plan for teams"
 * or "Bearer of record" stays visible.
 */
const AUTHORIZATION_VALUE =
  /^\s*(?:basic|bearer|token|dpop|ssws|apikey|api-key)\s+[A-Za-z0-9._~+/-]+=*\s*$/i;

/** A `Digest` header value: the scheme and its first parameter. */
const DIGEST_VALUE = /^\s*digest\s+[a-z][a-z0-9-]*\s*=/i;

/**
 * The members a JWK holds only when it is a private or a symmetric key: RFC
 * 7518 §6's, and `priv` and `seed`, which hold the private key of an AKP
 * (ML-DSA) key, as QAuth's own ML-DSA-65 keys do.
 */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth', 'priv', 'seed'] as const;

/**
 * The members that name the other half of a name and value pair, as a list of
 * headers or settings holds them: `{ name: 'X-Api-Key', value: '…' }`.
 */
const PAIR_NAME_MEMBERS = ['name', 'key', 'header', 'field', 'variable'] as const;

/**
 * Whether an object is a name and value pair whose name holds a secret, so
 * its `value` member is secret: `{ name: 'Authorization', value: 'Token …' }`
 * or `{ key: 'SMTP_PASSWORD', value: '…' }`.
 */
function isSecretPair(value: unknown): boolean {
  return (
    isPlainObject(value) &&
    Object.hasOwn(value, 'value') &&
    PAIR_NAME_MEMBERS.some((member) => {
      const name = value[member];
      return typeof name === 'string' && namesASecret(name);
    })
  );
}

/**
 * Whether a value is shaped like a secret whatever its name: a string shaped
 * like a token, a signed or encrypted object or a key (the payload rules'
 * value scan), a URL with a password, or an `Authorization` header value; or
 * an object that is a private or symmetric JWK.
 */
export function isSecretShaped(value: unknown): boolean {
  if (typeof value === 'string') {
    return isSecretShapedName(value) || AUTHORIZATION_VALUE.test(value) || DIGEST_VALUE.test(value);
  }
  if (isPlainObject(value)) {
    return (
      typeof value['kty'] === 'string' &&
      PRIVATE_JWK_MEMBERS.some((member) => Object.hasOwn(value, member))
    );
  }
  return false;
}

/** Whether a value is a JWK, or a non-empty array of JWKs: an object with a `kty`. */
function isJwkValue(value: unknown): boolean {
  const isJwk = (item: unknown) => isPlainObject(item) && typeof item['kty'] === 'string';
  return isJwk(value) || (Array.isArray(value) && value.length > 0 && value.every(isJwk));
}

/**
 * Whether a member's name hides its value: a name that holds a secret, unless
 * the value is a JWK or JWKs, which the value rule judges instead (a private
 * key is masked, a public key shown, a JWK Set's `keys` read through).
 */
const hiddenByName = (key: string, value: unknown) => namesASecret(key) && !isJwkValue(value);

/**
 * Whether a member name is shaped like a secret: a token, a signed or
 * encrypted object, a key, or a URL with a password. An `Authorization` value
 * is not looked for here: a name such as "Basic tier" is a name.
 */
function isSecretShapedName(name: string): boolean {
  return scanValues(name).length > 0 || URL_WITH_PASSWORD.test(name);
}

/** Refuse a member name shaped like a secret, which no mask can hide. */
function checkMemberName(key: string, at: readonly string[]): void {
  if (isSecretShapedName(key)) {
    throw new TypeError(
      `buildAdminDiff: a member name under ${pointer(at) || '/'} is shaped like a secret`
    );
  }
}

/** What a secret field holds in a diff: the marker, or a flag as it is. */
const masked = (value: JsonValue): JsonValue =>
  typeof value === 'boolean' ? value : ADMIN_DIFF_SECRET_MARKER;

/**
 * A whole value, as a change shows it: each member that is secret by name or
 * by mark, and each value shaped like a secret, replaced by the marker.
 */
function maskWithin(
  value: JsonValue,
  at: readonly string[],
  marks: readonly string[][]
): JsonValue {
  if (isSecretShaped(value)) return ADMIN_DIFF_SECRET_MARKER;
  if (Array.isArray(value)) {
    return value.map((item, index) => {
      const path = [...at, String(index)];
      return marked(marks, path) ? masked(item) : maskWithin(item, path, marks);
    });
  }
  if (value === null || typeof value !== 'object') return value;
  const pair = isSecretPair(value);
  // `Object.fromEntries` defines own properties, so a member named
  // `__proto__` stays a member and never becomes a prototype.
  return Object.fromEntries(
    presentKeys(value).map((key) => {
      checkMemberName(key, at);
      const path = [...at, key];
      const member = value[key];
      return [
        key,
        marked(marks, path) || hiddenByName(key, member) || (pair && key === 'value')
          ? masked(member)
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
  // A pair's value is secret when either side names a secret.
  const pair = isSecretPair(before) || isSecretPair(after);
  for (const key of keys) {
    checkMemberName(key, at);
    const path = [...at, key];
    const hasBefore = Object.hasOwn(before, key) && before[key] !== undefined;
    const hasAfter = Object.hasOwn(after, key) && after[key] !== undefined;
    const old = before[key];
    const now = after[key];
    const byMark = marked(marks, path) || (pair && key === 'value');
    const secret = byMark || namesASecret(key);
    const side = (value: JsonValue) =>
      byMark || hiddenByName(key, value) ? masked(value) : maskWithin(value, path, marks);

    if (hasBefore && hasAfter && !secret && isPlainObject(old) && isPlainObject(now)) {
      diffObjects(old, now, path, marks, changes);
      continue;
    }
    if (hasBefore && hasAfter && jsonEqual(old, now)) continue;

    const change: AdminDiffChange = { path: pointer(path) };
    if (hasBefore) change.before = side(old);
    if (hasAfter) change.after = side(now);
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

function secretShaped(path: string): PayloadFinding {
  return {
    path,
    rule: 'secret_value',
    message: 'the value or member name is shaped like a secret; in an admin diff it must be masked',
  };
}

const escapePointer = escapeSegment;

/**
 * Whether a field named like a secret holds what {@link buildAdminDiff}
 * leaves there: the marker, a flag, or JWKs with no private member.
 */
const holdsMask = (value: unknown) =>
  value === ADMIN_DIFF_SECRET_MARKER ||
  typeof value === 'boolean' ||
  (isJwkValue(value) && unmaskedWithin(value, '').length === 0);

/** Every unmasked secret under `value`: by member name, by value shape, or in a member name. */
function unmaskedWithin(value: unknown, at: string): PayloadFinding[] {
  if (isSecretShaped(value)) return [secretShaped(at)];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => unmaskedWithin(item, `${at}/${index}`));
  }
  if (value === null || typeof value !== 'object') return [];
  const pair = isSecretPair(value);
  return Object.entries(value).flatMap(([key, member]) => {
    const path = `${at}/${escapePointer(key)}`;
    if (isSecretShapedName(key)) return [secretShaped(path)];
    if (pair && key === 'value') return holdsMask(member) ? [] : [unmasked(path, key)];
    if (!namesASecret(key)) return unmaskedWithin(member, path);
    return holdsMask(member) ? [] : [unmasked(path, key)];
  });
}

/**
 * Check a diff against the masking rule: a change whose path names a secret
 * holds the marker (or a flag) on each side it has, and so does every member
 * named like a secret inside a value; no value and no member name is shaped
 * like a secret. The payload rules run this over a type's `diff` member in
 * place of reading its names. It cannot know what a caller marked:
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
    const segments = pointerSegments(change['path']);
    if (segments.some(isSecretShapedName)) return [secretShaped(`${base}/path`)];
    const secretName = segments.find(namesASecret);
    return (['before', 'after'] as const).flatMap((side) => {
      if (!Object.hasOwn(change, side)) return [];
      const value = change[side];
      if (secretName !== undefined) {
        return holdsMask(value) ? [] : [unmasked(`${base}/${side}`, secretName)];
      }
      return unmaskedWithin(value, `${base}/${side}`);
    });
  });
}
