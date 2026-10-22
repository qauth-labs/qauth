/**
 * The three API families of ADR-019 Decision 7, and the path each one is
 * served under (#506).
 *
 * The major version is part of the path: `/admin/v1`, `/account/v1`,
 * `/developer/v1`. A later major release serves `/admin/v2` beside `/admin/v1`
 * for the overlap window, so code that asks "is this a family route?" matches
 * any `v<major>`, not only `v1`. The rules every family route follows are on
 * the docs site's API conventions page
 * (`apps/docs-site/src/content/docs/reference/api-conventions.md`), and
 * `openapi-conventions.ts` enforces them over the generated OpenAPI document.
 */

/** The callers of ADR-019 Decision 7: operators, end users, developers. */
export const API_FAMILIES = ['admin', 'account', 'developer'] as const;

export type ApiFamily = (typeof API_FAMILIES)[number];

/** The path prefix of each family in its first major version. */
export const API_FAMILY_PREFIXES: Readonly<Record<ApiFamily, string>> = {
  admin: '/admin/v1',
  account: '/account/v1',
  developer: '/developer/v1',
};

/** `/<family>/v<major>` at the start of a path, followed by `/` or the end. */
const FAMILY_PATH = /^\/(admin|account|developer)\/v([1-9][0-9]*)(?:\/|$)/;

/** A path whose first segment is a family name, versioned or not. */
const FAMILY_SEGMENT = /^\/(admin|account|developer)(?:\/|$)/;

/** Where a path sits among the API families. */
export interface ApiFamilyPath {
  family: ApiFamily;
  /** The major version from the path: `1` for `/admin/v1/...`. */
  major: number;
}

/**
 * The family and major version a route path belongs to, or `undefined` for a
 * path outside the three families (`/oauth/token`, `/api/clients`, `/consents`).
 *
 * Takes a route pattern (Fastify's `/admin/v1/realms/:realmId`) or an OpenAPI
 * path (`/admin/v1/realms/{realmId}`); only the first two segments are read.
 */
export function apiFamilyOf(path: string): ApiFamilyPath | undefined {
  const match = FAMILY_PATH.exec(path);
  if (!match) return undefined;
  return { family: match[1] as ApiFamily, major: Number(match[2]) };
}

/**
 * Whether a path starts with a family name but no `v<major>` segment after it,
 * such as `/admin/realms`. Such a path breaks the rule that the major version
 * is in the path.
 */
export function isUnversionedFamilyPath(path: string): boolean {
  return FAMILY_SEGMENT.test(path) && !FAMILY_PATH.test(path);
}
