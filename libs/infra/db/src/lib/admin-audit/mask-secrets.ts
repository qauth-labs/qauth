import type { AdminAuditDiff, FieldAnnotations, JsonObject, JsonValue } from './types';

/**
 * What a secret field holds once masked. It is the same for every secret and
 * every value, so a stored diff tells nothing about a secret, not even its
 * length or whether it is set.
 */
export const ADMIN_AUDIT_SECRET_MARKER = '***';

/** The annotation paths that mark a field secret, split into segments. */
function secretPaths(annotations: FieldAnnotations): string[][] {
  return Object.entries(annotations)
    .filter(([, annotation]) => annotation === 'secret')
    .map(([path]) => {
      const segments = path.split('.');
      if (segments.some((segment) => segment === '')) {
        throw new TypeError(`maskSecrets: annotation path "${path}" has an empty segment`);
      }
      return segments;
    });
}

/**
 * The paths that continue below a member: for each path whose first segment
 * matches `key` (or is `*`), the rest of it. An empty rest means the member
 * itself is secret.
 */
function descend(paths: string[][], key: string): string[][] {
  return paths.filter(([head]) => head === '*' || head === key).map(([, ...rest]) => rest);
}

function mask(value: JsonValue, paths: string[][]): JsonValue {
  if (paths.length === 0 || value === null || typeof value !== 'object') return value;

  const maskMember = (key: string, member: JsonValue): JsonValue => {
    const below = descend(paths, key);
    return below.some((rest) => rest.length === 0)
      ? ADMIN_AUDIT_SECRET_MARKER
      : mask(member, below);
  };

  if (Array.isArray(value)) {
    return value.map((item, index) => maskMember(String(index), item));
  }
  // `Object.fromEntries` defines own properties, so a member named
  // `__proto__` stays a member and never becomes a prototype.
  return Object.fromEntries(
    Object.entries(value).map(([key, member]) => [key, maskMember(key, member)])
  );
}

function maskSide(side: JsonObject | null, paths: string[][]): JsonObject | null {
  return side === null ? null : (mask(side, paths) as JsonObject);
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
 * @param diff - The resource before and after the operation.
 * @param annotations - The resource's field annotations, by path inside the
 *   resource (not inside the diff): `clientSecretHash` masks
 *   `before.clientSecretHash` and `after.clientSecretHash`.
 * @returns A new diff, safe to store.
 */
export function maskSecrets(diff: AdminAuditDiff, annotations: FieldAnnotations): AdminAuditDiff {
  const paths = secretPaths(annotations);
  return { before: maskSide(diff.before, paths), after: maskSide(diff.after, paths) };
}
