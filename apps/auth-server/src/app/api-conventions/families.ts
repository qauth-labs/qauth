/**
 * The three API families of ADR-019 Decision 7, and the path each one is
 * served under (#506).
 *
 * The major version is part of the path. Until QAuth 1.0.0 it is a release
 * candidate, `v1-rc.<M>` (ADR-018 §5): nothing is promised yet, a breaking
 * change raises `<M>`, and the release that ships 1.0.0 serves `/admin/v1`.
 * A later major release serves `/admin/v2` beside `/admin/v1` for the overlap
 * window, so code that asks "is this a family route?" matches any
 * `v<major>`, with or without the suffix. The rules every family route follows are on
 * the docs site's API conventions page
 * (`apps/docs-site/src/content/docs/reference/api-conventions.md`), and
 * `openapi-conventions.ts` enforces them over the generated OpenAPI document.
 */

/** The callers of ADR-019 Decision 7: operators, end users, developers. */
export const API_FAMILIES = ['admin', 'account', 'developer'] as const;

export type ApiFamily = (typeof API_FAMILIES)[number];

/** The path prefix of each family: its first major version, still a release candidate. */
export const API_FAMILY_PREFIXES: Readonly<Record<ApiFamily, string>> = {
  admin: '/admin/v1-rc.0',
  account: '/account/v1-rc.0',
  developer: '/developer/v1-rc.0',
};

/**
 * The audience of each family's access tokens (ADR-019 Decision 7, #509). A
 * family accepts a token whose `aud` holds exactly its own audience and no
 * other value, so a token for one family never works on another.
 *
 * The version is the path's release candidate (ADR-018 §5): the release that
 * ships 1.0.0 issues `urn:qauth:aud:admin:v1`, and a breaking change before it
 * raises both together. The token endpoint issues an audience only to a client
 * whose `audience` lists it, and the client asks for it with the RFC 8707
 * `resource` parameter, whose value is the audience itself.
 */
export const API_FAMILY_AUDIENCES: Readonly<Record<ApiFamily, string>> = {
  admin: 'urn:qauth:aud:admin:v1-rc.0',
  account: 'urn:qauth:aud:account:v1-rc.0',
  developer: 'urn:qauth:aud:developer:v1-rc.0',
};

/**
 * The namespace of the audiences QAuth defines (#509). No client registers a
 * value in it for itself: dynamic registration and Client ID Metadata
 * Documents refuse it as an `audience` or a `resource`, and the token endpoint
 * issues one only to a client whose `audience` an operator set to list it.
 */
export const RESERVED_AUDIENCE_PREFIX = 'urn:qauth:aud:';

/**
 * `urn:qauth:aud:` at the start, after any leading whitespace, ASCII letters in
 * any case. RFC 8141 makes `urn` and the namespace id case-insensitive, and
 * QAuth owns the rest of the prefix, so `URN:QAuth:aud:` is the same reserved
 * name. Without the `u` flag, `i` folds no character outside ASCII onto an
 * ASCII letter.
 */
const RESERVED_AUDIENCE = /^\s*urn:qauth:aud:/i;

/** Whether `value` is an audience in QAuth's reserved namespace, in any case. */
export function isReservedAudience(value: string): boolean {
  return RESERVED_AUDIENCE.test(value);
}

/**
 * The reserved audiences in a client metadata value: a string, or a list whose
 * string entries are checked. Any other value holds none. For metadata a
 * client wrote about itself (`audience`, `resource`), which QAuth otherwise
 * ignores, so its shape is not validated here.
 */
export function reservedAudiencesIn(value: unknown): string[] {
  const values: unknown[] = Array.isArray(value) ? value : [value];
  return values.filter(
    (entry): entry is string => typeof entry === 'string' && isReservedAudience(entry)
  );
}

/**
 * `/<family>/v<major>` or `/<family>/v<major>-rc.<M>` at the start of a path,
 * followed by `/` or the end.
 */
const FAMILY_PATH = /^\/(admin|account|developer)\/v([1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?(?:\/|$)/;

/** A path whose first segment is a family name, versioned or not. */
const FAMILY_SEGMENT = /^\/(admin|account|developer)(?:\/|$)/;

/** Where a path sits among the API families. */
export interface ApiFamilyPath {
  family: ApiFamily;
  /** The major version from the path: `1` for `/admin/v1-rc.0/...`. */
  major: number;
  /**
   * The release candidate number, `0` for `/admin/v1-rc.0/...`; absent once
   * the major version is promised (`/admin/v1/...`).
   */
  rc?: number;
}

/**
 * The family and major version a route path belongs to, or `undefined` for a
 * path outside the three families (`/oauth/token`, `/api/clients`, `/consents`).
 *
 * Takes a route pattern (Fastify's `/admin/v1-rc.0/realms/:realmId`) or an
 * OpenAPI path (`/admin/v1-rc.0/realms/{realmId}`); only the first two segments
 * are read.
 */
export function apiFamilyOf(path: string): ApiFamilyPath | undefined {
  const match = FAMILY_PATH.exec(path);
  if (!match) return undefined;
  const family = match[1] as ApiFamily;
  const major = Number(match[2]);
  return match[3] === undefined ? { family, major } : { family, major, rc: Number(match[3]) };
}

/**
 * Whether a path starts with a family name but no `v<major>` segment after it,
 * such as `/admin/realms` or `/admin/v1-rc/realms`. Such a path breaks the rule
 * that the major version is in the path.
 */
export function isUnversionedFamilyPath(path: string): boolean {
  return FAMILY_SEGMENT.test(path) && !FAMILY_PATH.test(path);
}
