import type { AdminAuditDiff, FieldAnnotations, JsonObject, JsonValue } from './types';

/**
 * What a secret field holds once masked. It is the same for every secret and
 * every value, so a stored diff tells nothing about a secret, not even its
 * length or whether it is set.
 */
export const ADMIN_AUDIT_SECRET_MARKER = '***';

/**
 * What is left of one annotation path below the current value. `wild` records
 * whether a `*` was taken on the way down: a path that named every step and
 * meets an array has forgotten a `*`, while one that went through a `*` merely
 * meets a member without the field.
 */
interface PathRest {
  segments: string[];
  wild: boolean;
}

/** The annotation paths that mark a field secret, split into segments. */
function secretPaths(annotations: FieldAnnotations): PathRest[] {
  return Object.entries(annotations)
    .filter(([, annotation]) => annotation === 'secret')
    .map(([path]) => {
      const segments = path.split('.');
      if (segments.some((segment) => segment === '')) {
        throw new TypeError(`maskSecrets: annotation path "${path}" has an empty segment`);
      }
      return { segments, wild: false };
    });
}

/**
 * The paths that continue below a member: for each path whose first segment
 * matches `key` (or is `*`), the rest of it. An empty rest means the member
 * itself is secret.
 */
function descend(paths: PathRest[], key: string): PathRest[] {
  return paths
    .filter(({ segments: [head] }) => head === '*' || head === key)
    .map(({ segments: [head, ...rest], wild }) => ({
      segments: rest,
      wild: wild || head === '*',
    }));
}

const ARRAY_INDEX = /^(0|[1-9][0-9]*)$/;

function mask(value: JsonValue, paths: PathRest[], at: string): JsonValue {
  if (paths.length === 0 || value === null || typeof value !== 'object') return value;

  const maskMember = (key: string, member: JsonValue): JsonValue => {
    const below = descend(paths, key);
    return below.some(({ segments }) => segments.length === 0)
      ? ADMIN_AUDIT_SECRET_MARKER
      : mask(member, below, `${at}.${key}`);
  };

  if (Array.isArray(value)) {
    // A path that named every step and finds an array where it names a member
    // has forgotten a `*`: it would mask nothing, so it is refused.
    const misplaced = paths.find(
      ({ segments: [head], wild }) => !wild && head !== '*' && !ARRAY_INDEX.test(head)
    );
    if (misplaced) {
      throw new TypeError(
        `maskSecrets: annotation segment "${misplaced.segments[0]}" meets an array at ${at}; use "*"`
      );
    }
    return value.map((item, index) => maskMember(String(index), item));
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`maskSecrets: ${at} is not a plain object`);
  }
  // `Object.fromEntries` defines own properties, so a member named
  // `__proto__` stays a member and never becomes a prototype.
  return Object.fromEntries(
    Object.entries(value).map(([key, member]) => [key, maskMember(key, member)])
  );
}

function maskSide(side: JsonObject | null, paths: PathRest[], at: string): JsonObject | null {
  return side === null ? null : (mask(side, paths, at) as JsonObject);
}

/**
 * Replace every field annotated as secret by {@link ADMIN_AUDIT_SECRET_MARKER},
 * on both sides of a diff (ADR-020 §3: admin events show a diff with secret
 * values masked).
 *
 * A secret field is replaced whatever it holds, `null` and nested objects
 * included, so no part of its value survives. Fields that are not annotated
 * are copied unchanged. The input is not modified.
 *
 * A set-up or reset link, code or token is a secret field in every diff that
 * carries one: ADR-019 Decision 7 keeps them out of every log.
 *
 * A path segment is a member name, an array index, or `*`. A member whose own
 * name holds a `.` or is `*` is masked through a `*` on its parent.
 *
 * @param diff - The resource before and after the operation.
 * @param annotations - The resource's field annotations, by path inside the
 *   resource (not inside the diff): `clientSecretHash` masks
 *   `before.clientSecretHash` and `after.clientSecretHash`.
 * @returns A new diff, safe to store.
 * @throws TypeError on an annotation path with an empty segment, a member name
 *   where the diff holds an array, or a value that is not plain JSON.
 */
export function maskSecrets(diff: AdminAuditDiff, annotations: FieldAnnotations): AdminAuditDiff {
  const paths = secretPaths(annotations);
  return {
    before: maskSide(diff.before, paths, 'before'),
    after: maskSide(diff.after, paths, 'after'),
  };
}
