import type { RealmRow } from './request-realm';

/**
 * Absolute URLs from the realm row (ADR-019 Decision 1, issue #490).
 *
 * No URL is built from the request: the issuer, every endpoint URL, the links
 * in mail and the URLs a wallet is handed all start at the issuer of the realm
 * the request was resolved to (`requestRealm(request)`). The `Host` header,
 * `X-Forwarded-*`, `JWT_ISSUER` and `EMAIL_BASE_URL` decide none of them; the
 * lint configuration refuses the request's authority outside the realm
 * resolver (`.oxlintrc.json`).
 */

/** The column of a realm row its URLs are built from. */
export type RealmUrlSource = Pick<RealmRow, 'issuer'>;

/**
 * The realm's issuer identifier, exactly as its discovery documents publish it
 * as `issuer` (RFC 8414 §2).
 *
 * The row stores it in that form already: a CHECK refuses a trailing slash, and
 * the default realm's boot step drops the one `JWT_ISSUER` may end with. So it
 * is returned as stored, byte for byte, which is what a client compares the
 * RFC 9207 `iss` parameter with.
 *
 * @throws Error when the realm has no issuer. The realm resolver answers a
 * request to such a realm with `421`, so a handler reaching this is a bug.
 */
export function realmIssuer(realm: RealmUrlSource): string {
  if (realm.issuer === null) {
    throw new Error(
      'The realm has no issuer, so no URL can be built for it: the realm resolver refuses requests to such a realm'
    );
  }
  return realm.issuer;
}

/**
 * The absolute URL of `path` on the realm's issuer: the issuer identifier
 * followed by `path`, as discovery builds every endpoint URL.
 *
 * Joined as strings, never through `new URL(path, issuer)`, which would drop a
 * path the issuer carries (the default realm's issuer keeps the path of
 * `JWT_ISSUER`) and normalise the authority.
 *
 * @param path - an absolute path such as `/oauth/token`, with a query when the
 * URL needs one.
 * @throws Error when `path` does not start with a single `/`, which would join
 * into another host (`//evil.example`) or into the issuer's last label.
 */
export function buildRealmUrl(realm: RealmUrlSource, path: string): string {
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new Error(`A realm URL path must start with a single "/": ${JSON.stringify(path)}`);
  }
  return `${realmIssuer(realm)}${path}`;
}

/**
 * Where the links in a realm's mail point: the realm's issuer, so a link
 * opens the auth server of the realm the account belongs to (ADR-019
 * Decisions 1 and 6), never a `/ui/*` path and never `EMAIL_BASE_URL`.
 */
export function realmMailLink(realm: RealmUrlSource): { readonly baseUrl: string } {
  return { baseUrl: realmIssuer(realm) };
}

/**
 * The realm a token is signed for or verified in, as the JWT plugin takes it
 * (ADR-019 Decisions 1 and 9, #491): its id, whose keys sign and verify the
 * token, and its issuer, the `iss` the signer puts in the token and every
 * verification pins (RFC 9700 §4.4 mix-up defence). A token another realm
 * issued names another issuer and verifies with none of this realm's keys.
 *
 * @throws Error when the realm has no issuer, as {@link realmIssuer} does
 */
export function tokenRealm(realm: Pick<RealmRow, 'id' | 'issuer'>): {
  readonly id: string;
  readonly issuer: string;
} {
  return { id: realm.id, issuer: realmIssuer(realm) };
}
