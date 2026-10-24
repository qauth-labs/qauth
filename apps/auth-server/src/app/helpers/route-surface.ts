/**
 * Route surfaces (ADR-019 Decisions 1 and 8, issue #486): which hosts a route
 * answers on.
 *
 * Every route of the auth server names its surface in `config.surface`. The
 * realm resolver (`plugins/realm-resolver.ts`) reads it on every request and
 * refuses to boot when a route has none, so a new route cannot ship without a
 * decision about where it may answer.
 *
 * - `browser` — reads or sets the browser session cookie: `/oauth/authorize`,
 *   the `/ui/*` ceremony pages, `/consents` and `/auth/link/wallet`. Answers
 *   on the realm's primary host only; on an endpoint host it is `421`, because
 *   the session belongs to the realm host (ADR-019 Decision 3).
 * - `api` — called by a client or a server with its own credentials: token,
 *   introspection, revocation, userinfo, registration, the OID4VP request and
 *   response endpoints a wallet calls, the management and legacy `/auth/*`
 *   routes, and `/metrics` until it moves to the internal listener. Answers on
 *   the realm's primary host and on its endpoint hosts. `/auth/logout` is one:
 *   it is a bearer-token call, and the session cookie it clears when a request
 *   carries one never reaches an endpoint host, since a `__Host-` cookie stays
 *   on the host that set it.
 * - `meta` — a document any caller may read about the realm or the server:
 *   discovery, JWKS, the passkey association files and the root greeting.
 *   Answers on the primary host and the endpoint hosts, like `api`.
 * - `none` — not routed by host. Answers on any host, with no realm resolved,
 *   and must carry no realm data. Only `/health` is `none`.
 */
export const ROUTE_SURFACES = ['browser', 'api', 'meta', 'none'] as const;

export type RouteSurface = (typeof ROUTE_SURFACES)[number];

declare module 'fastify' {
  interface FastifyContextConfig {
    /**
     * Which hosts the route answers on; see {@link RouteSurface}. Optional in
     * the type so a route outside this app is not forced to carry it, required
     * at boot by the realm resolver for every route of the app.
     */
    surface?: RouteSurface;
  }
}

/** Whether `value` is one of the {@link ROUTE_SURFACES}. */
export function isRouteSurface(value: unknown): value is RouteSurface {
  return typeof value === 'string' && (ROUTE_SURFACES as readonly string[]).includes(value);
}

/** The parts of a route's options {@link routeSurfaceProblem} reads. */
export interface RouteSurfaceSubject {
  readonly method: string | readonly string[];
  readonly url: string;
  readonly config?: { readonly surface?: unknown };
}

/**
 * Why a route cannot be served: it names no surface, or names a value that is
 * not one. `undefined` when the route is classified.
 */
export function routeSurfaceProblem(route: RouteSurfaceSubject): string | undefined {
  const surface = route.config?.surface;
  if (isRouteSurface(surface)) return undefined;
  const method = Array.isArray(route.method) ? route.method.join(',') : String(route.method);
  const expected = ROUTE_SURFACES.map((value) => `'${value}'`).join(', ');
  return surface === undefined
    ? `Route ${method} ${route.url} has no config.surface; set one of ${expected}`
    : `Route ${method} ${route.url} has an unknown config.surface; set one of ${expected}`;
}
