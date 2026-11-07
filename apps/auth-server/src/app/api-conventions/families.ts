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

import { DEVELOPER_API_AUDIENCE } from '@qauth-labs/shared-validation';

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
 * `resource` parameter, whose value is the audience itself. Each lies in the
 * reserved `urn:qauth:aud:` namespace (`isReservedAudience` in
 * `@qauth-labs/shared-validation`).
 */
export const API_FAMILY_AUDIENCES: Readonly<Record<ApiFamily, string>> = {
  admin: 'urn:qauth:aud:admin:v1-rc.0',
  account: 'urn:qauth:aud:account:v1-rc.0',
  developer: DEVELOPER_API_AUDIENCE,
};

/** The families a token reaches by scope alone: the account and developer APIs (#933). */
export type ScopedApiFamily = Exclude<ApiFamily, 'admin'>;

/**
 * The class of an account or developer operation, its `x-qauth-class`.
 * `security` belongs to the admin API alone.
 */
export type FamilyOperationClass = 'read' | 'write';

/**
 * The scopes of the account and developer APIs (#933), one per operation
 * class, in QAuth's reserved `qauth:` namespace beside the admin API's
 * (ADR-019 Decision 7).
 *
 * An operation needs the scope of its class (`x-qauth-class`), which is the
 * class of its permission (`x-qauth-permission`): `qauth:developer:read` to
 * list or read, `qauth:developer:write` to create, change, delete or revoke.
 * The two are independent, as the admin scopes are: the write scope does not
 * reach a read. A token needs its family's audience as well, and the scope of
 * one family reaches nothing in another.
 *
 * The token endpoint issues one only to a client whose `audience` lists that
 * family's audience, which only an operator sets, for a token that names a
 * user (`helpers/admin-issuance.ts`). The developer portal's token carries
 * both developer scopes (`SYSTEM_CLIENT_SCOPES`). Unlike the admin scopes, no
 * role is intersected with them: the family's operations act on the token's
 * own user, its account or the clients it owns.
 */
export const API_FAMILY_SCOPES: Readonly<
  Record<ScopedApiFamily, Readonly<Record<FamilyOperationClass, string>>>
> = Object.freeze({
  account: Object.freeze({ read: 'qauth:account:read', write: 'qauth:account:write' }),
  developer: Object.freeze({ read: 'qauth:developer:read', write: 'qauth:developer:write' }),
});

/** A scope of {@link API_FAMILY_SCOPES}: its family and the class it reaches. */
export interface FamilyScope {
  readonly family: ScopedApiFamily;
  readonly operationClass: FamilyOperationClass;
}

const FAMILY_SCOPE_BY_NAME: ReadonlyMap<string, FamilyScope> = new Map(
  (Object.keys(API_FAMILY_SCOPES) as ScopedApiFamily[]).flatMap((family) =>
    (Object.keys(API_FAMILY_SCOPES[family]) as FamilyOperationClass[]).map(
      (operationClass) =>
        [API_FAMILY_SCOPES[family][operationClass], { family, operationClass }] as const
    )
  )
);

/**
 * The family and class a scope of {@link API_FAMILY_SCOPES} reaches, or
 * `undefined` for any other string. Exact match only, as a scope is
 * case-sensitive (RFC 6749 §3.3): `QAuth:developer:read` reaches nothing.
 */
export function familyScopeOf(scope: string): FamilyScope | undefined {
  return FAMILY_SCOPE_BY_NAME.get(scope);
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
