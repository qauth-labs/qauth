import type { FastifyInstance, FastifyRequest } from 'fastify';

/**
 * A single `realms` row as returned by the repository. Derived from the
 * decorator type so we stay decoupled from `@qauth-labs/infra-db`
 * (auth-server depends on it only transitively via
 * `@qauth-labs/fastify-plugin-db`), matching the boundary that
 * `routes/clients/index.ts` keeps with its `OAuthClientRow` type.
 *
 * The type is spelled out rather than inferred where it is returned:
 * TypeScript 7 rejects the inferred form with TS2883, because naming it would
 * require a reference to `PasswordPolicy` from a package auth-server does not
 * depend on directly.
 */
export type RealmRow = NonNullable<
  Awaited<ReturnType<FastifyInstance['repositories']['realms']['findById']>>
>;

/**
 * The realm a request belongs to (ADR-019 Decision 1, issue #487): the one the
 * realm resolver (`plugins/realm-resolver.ts`) found through the host the
 * request named. Every handler and helper takes its realm from here; none
 * picks one by name.
 *
 * The row is the resolver's, read at most its cache time ago (30 seconds by
 * default). A disabled realm, a realm with no issuer and an unknown host never
 * reach a handler: the resolver answers them with `421`.
 *
 * @throws Error when the request carries no realm. Only a `none` route, such
 * as `/health`, has none, and such a route must not read one; reaching this
 * from one is a bug, so it fails the request rather than guess a realm.
 */
export function requestRealm(request: FastifyRequest): RealmRow {
  const realm = request.realm;
  if (realm === null || realm === undefined) {
    // The route pattern, never the URL: a query string can carry a token.
    throw new Error(
      `${request.method} ${request.routeOptions.url ?? '(no route)'} has no resolved realm: only a route on a realm surface may read one`
    );
  }
  return realm;
}
