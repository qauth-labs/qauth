import type { RepositoryName } from '@qauth-labs/fastify-plugin-db';
import { SERVICE_ROLE_NAMES, type ServiceRole } from '@qauth-labs/server-config';
import type { FastifyPluginAsync } from 'fastify';

/**
 * THE ROUTE MANIFEST (ADR-019 Decision 8, issue #495).
 *
 * Every route module of the auth server, with the service roles that register
 * it, the plugins its routes call and the repositories they read or write. It
 * replaces the folder autoload: a module that is not listed here is never
 * registered, and a module without a role cannot be listed.
 *
 * - `web` registers the browser-session endpoints, the `browser` routes of
 *   #486: authorize, the ceremony pages (the email verification page
 *   `GET /auth/verify` among them), `/consents` and wallet linking.
 * - `api` registers the routes a client or a server calls with its own
 *   credentials, and the documents about the realm: token, introspection,
 *   revocation, userinfo, registration, discovery, JWKS, the OID4VP endpoints
 *   a wallet calls, the account and developer APIs, the SSF transmitter and
 *   the legacy `/auth/*` routes (the `api` and `meta` surfaces).
 * - Every role registers `/health` and `/metrics`: each process answers for
 *   itself, whatever else it serves.
 * - `admin`, `signer` and `delivery` have no route here. The admin API runs
 *   on its own listener (#511, `admin/listener.ts`), the signer service
 *   (#497) on the internal listener, whose routes have a manifest of their
 *   own (#496, `internal/route-manifest.ts`), and delivery serves no inbound
 *   request.
 *
 * `route-manifest.test.ts` checks each entry against its module: the plugins
 * and repositories its code reaches, its prefix (the directory's name, or the
 * module's `autoPrefix`, as the autoload gave it), and that every module under
 * `routes/` is listed. The process builds its repository list and its plugin
 * set from the entries of its roles (`service-roles.ts`).
 */

/**
 * A plugin a process registers only when a role it holds needs it. The others
 * (database, Redis, metrics, rate limits, realm resolution, error handling)
 * every process registers.
 *
 * - `dpop`: `fastify.dpop`; `jwt` needs it too.
 * - `jwt`: `fastify.jwtUtils` and `fastify.requireJwt`.
 * - `password`: `fastify.passwordHasher` and `fastify.passwordValidator`.
 * - `pkce`: `fastify.pkceUtils`.
 * - `federation`: `fastify.providerRegistry`, with the wallet configuration's
 *   boot checks.
 * - `email`: `fastify.emailService` and `fastify.emailVerificationTokenUtils`.
 * - `sessions`: `fastify.sessionService`.
 * - `ssf`: `fastify.ssf`, the SSF transmitter.
 * - `eventDelivery`: the delivery role's reader.
 * - `egress`: `fastify.egress`, the SSRF-safe client of the outbound calls a
 *   route makes for a configuration value or a request (CIMD documents,
 *   client and issuer JWKS, ID-JAG discovery; ADR-019 Decision 8, #481).
 */
export const ROLE_PLUGINS = [
  'dpop',
  'jwt',
  'password',
  'pkce',
  'federation',
  'email',
  'sessions',
  'ssf',
  'eventDelivery',
  'egress',
] as const;

/** One of {@link ROLE_PLUGINS}. */
export type RolePlugin = (typeof ROLE_PLUGINS)[number];

/** One route module and where it runs. */
export interface RouteModule {
  /** The module's path under `routes/`, without its extension. */
  readonly module: string;
  /** The URL prefix its routes are registered under. */
  readonly prefix?: string;
  /** The roles whose processes register it. Never empty. */
  readonly roles: readonly ServiceRole[];
  /** The plugins its routes call, beyond those every process registers. */
  readonly plugins: readonly RolePlugin[];
  /** The repositories its routes read or write. */
  readonly repositories: readonly RepositoryName[];
  /**
   * Import the module. Only a process that registers it imports it, so a role
   * never loads the code of another role's routes.
   */
  readonly load: () => Promise<{ readonly default: FastifyPluginAsync }>;
}

/** `/health` and `/metrics`: every process answers for itself. */
const EVERY_ROLE: readonly ServiceRole[] = SERVICE_ROLE_NAMES;

/** The signed-in user's wallet linking and wallet sign-in. */
const WALLET_FLOW_REPOSITORIES: readonly RepositoryName[] = [
  'events',
  'oid4vpRequestStates',
  'realms',
  'userAttributes',
  'userCredentials',
  'users',
];

/**
 * Every route module of the auth server, in the order the folder autoload
 * registered them: the files of `routes/` and then its directories, each
 * alphabetically. The order reaches the OpenAPI document's paths.
 */
export const ROUTE_MANIFEST: readonly RouteModule[] = [
  {
    module: 'app-association',
    roles: ['api'],
    plugins: [],
    repositories: [],
    load: () => import('./routes/app-association'),
  },
  {
    module: 'health',
    roles: EVERY_ROLE,
    plugins: [],
    repositories: [],
    load: () => import('./routes/health'),
  },
  {
    module: 'interaction-document',
    roles: ['api'],
    plugins: [],
    repositories: [],
    load: () => import('./routes/interaction-document'),
  },
  {
    module: 'metrics',
    roles: EVERY_ROLE,
    plugins: [],
    repositories: [],
    load: () => import('./routes/metrics'),
  },
  {
    module: 'root',
    roles: ['api'],
    plugins: [],
    repositories: [],
    load: () => import('./routes/root'),
  },
  {
    module: 'well-known',
    roles: ['api'],
    plugins: ['dpop', 'jwt', 'ssf'],
    repositories: ['oauthClients', 'realms'],
    load: () => import('./routes/well-known'),
  },
  {
    module: 'account',
    prefix: '/account/v1-rc.0',
    roles: ['api'],
    plugins: ['jwt'],
    repositories: [
      'authorizationCodes',
      'events',
      'oauthClients',
      'oauthConsents',
      'refreshTokens',
      'users',
    ],
    load: () => import('./routes/account'),
  },
  {
    module: 'auth/link-wallet',
    prefix: '/auth',
    roles: ['web'],
    plugins: ['sessions'],
    repositories: WALLET_FLOW_REPOSITORIES,
    load: () => import('./routes/auth/link-wallet'),
  },
  {
    module: 'auth/login',
    prefix: '/auth',
    roles: ['api'],
    plugins: ['egress', 'federation', 'jwt', 'password'],
    repositories: ['events', 'oauthClients', 'refreshTokens', 'userCredentials', 'users'],
    load: () => import('./routes/auth/login'),
  },
  {
    module: 'auth/logout',
    prefix: '/auth',
    roles: ['api'],
    plugins: ['jwt', 'sessions'],
    repositories: ['authorizationCodes', 'events', 'oauthClients', 'refreshTokens', 'users'],
    load: () => import('./routes/auth/logout'),
  },
  {
    module: 'auth/register',
    prefix: '/auth',
    roles: ['api'],
    plugins: ['email', 'federation', 'password'],
    repositories: [
      'emailVerificationTokens',
      'events',
      'userAttributes',
      'userCredentials',
      'users',
    ],
    load: () => import('./routes/auth/register'),
  },
  {
    module: 'auth/resend-verification',
    prefix: '/auth',
    roles: ['api'],
    plugins: ['email'],
    repositories: ['emailVerificationTokens', 'userCredentials', 'users'],
    load: () => import('./routes/auth/resend-verification'),
  },
  {
    module: 'auth/verify-page',
    prefix: '/auth',
    roles: ['web'],
    plugins: [],
    repositories: [],
    load: () => import('./routes/auth/verify-page'),
  },
  {
    module: 'auth/verify',
    prefix: '/auth',
    roles: ['api'],
    plugins: ['email', 'password'],
    repositories: ['emailVerificationTokens', 'userAttributes', 'userCredentials', 'users'],
    load: () => import('./routes/auth/verify'),
  },
  {
    module: 'clients',
    prefix: '/api/clients',
    roles: ['api'],
    plugins: ['jwt', 'password'],
    repositories: ['apiKeys', 'events', 'oauthClients', 'realms', 'users'],
    load: () => import('./routes/clients'),
  },
  {
    module: 'consents',
    prefix: '/consents',
    roles: ['web'],
    plugins: ['sessions'],
    repositories: ['authorizationCodes', 'events', 'oauthConsents', 'refreshTokens', 'users'],
    load: () => import('./routes/consents'),
  },
  {
    module: 'consents-api',
    prefix: '/api/consents',
    roles: ['api'],
    plugins: ['jwt'],
    repositories: [
      'authorizationCodes',
      'events',
      'oauthClients',
      'oauthConsents',
      'refreshTokens',
      'users',
    ],
    load: () => import('./routes/consents-api'),
  },
  {
    module: 'developer',
    prefix: '/developer/v1-rc.0',
    roles: ['api'],
    plugins: ['jwt', 'password'],
    repositories: [
      'apiKeys',
      'authorizationCodes',
      'events',
      'oauthClients',
      'oauthConsents',
      'realms',
      'refreshTokens',
      'users',
    ],
    load: () => import('./routes/developer'),
  },
  {
    module: 'oauth/authorize',
    prefix: '/oauth',
    roles: ['web'],
    plugins: ['dpop', 'egress', 'password', 'sessions'],
    repositories: [
      'authorizationCodes',
      'events',
      'oauthClients',
      'oauthConsents',
      'sessions',
      'users',
    ],
    load: () => import('./routes/oauth/authorize'),
  },
  {
    module: 'oauth/introspect',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['egress', 'jwt', 'password'],
    repositories: ['events', 'oauthClients', 'users'],
    load: () => import('./routes/oauth/introspect'),
  },
  {
    module: 'oauth/register',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['jwt', 'password'],
    repositories: ['events', 'oauthClients', 'realms', 'users'],
    load: () => import('./routes/oauth/register'),
  },
  {
    module: 'oauth/revoke',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['egress', 'jwt', 'password'],
    repositories: ['events', 'oauthClients', 'refreshTokens', 'users'],
    load: () => import('./routes/oauth/revoke'),
  },
  {
    module: 'oauth/token',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['dpop', 'egress', 'jwt', 'password', 'pkce'],
    repositories: [
      'adminGrants',
      'authorizationCodes',
      'events',
      'oauthClients',
      'oauthConsents',
      'realms',
      'refreshTokens',
      'userAttributes',
      'userCredentials',
      'users',
    ],
    load: () => import('./routes/oauth/token'),
  },
  {
    module: 'oauth/userinfo',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['jwt'],
    repositories: ['events', 'oauthClients', 'realms', 'userAttributes', 'users'],
    load: () => import('./routes/oauth/userinfo'),
  },
  {
    module: 'oid4vp/request-object',
    prefix: '/oid4vp',
    roles: ['api'],
    plugins: [],
    repositories: [],
    load: () => import('./routes/oid4vp/request-object'),
  },
  {
    module: 'oid4vp/response',
    prefix: '/oid4vp',
    roles: ['api'],
    plugins: [],
    repositories: ['events', 'oid4vpRequestStates'],
    load: () => import('./routes/oid4vp/response'),
  },
  {
    module: 'ssf',
    prefix: '/ssf',
    roles: ['api'],
    plugins: ['jwt', 'ssf'],
    repositories: ['events', 'oauthClients', 'realms', 'ssfStreams'],
    load: () => import('./routes/ssf'),
  },
  {
    module: 'ui/consent',
    prefix: '/ui',
    roles: ['web'],
    plugins: ['dpop', 'egress', 'password', 'sessions'],
    repositories: [
      'authorizationCodes',
      'events',
      'oauthClients',
      'oauthConsents',
      'sessions',
      'users',
    ],
    load: () => import('./routes/ui/consent'),
  },
  {
    module: 'ui/login',
    prefix: '/ui',
    roles: ['web'],
    plugins: ['federation', 'password', 'sessions'],
    repositories: ['events', 'userCredentials', 'users'],
    load: () => import('./routes/ui/login'),
  },
  {
    module: 'ui/resume',
    prefix: '/ui',
    roles: ['web'],
    plugins: [],
    repositories: [],
    load: () => import('./routes/ui/resume'),
  },
  {
    module: 'ui/verify',
    prefix: '/ui',
    roles: ['web'],
    plugins: ['email', 'password'],
    repositories: ['emailVerificationTokens', 'userAttributes', 'userCredentials', 'users'],
    load: () => import('./routes/ui/verify'),
  },
  {
    module: 'ui/wallet-link',
    prefix: '/ui',
    roles: ['web'],
    plugins: ['sessions'],
    repositories: WALLET_FLOW_REPOSITORIES,
    load: () => import('./routes/ui/wallet-link'),
  },
  {
    module: 'ui/wallet-login',
    prefix: '/ui',
    roles: ['web'],
    plugins: ['sessions'],
    repositories: WALLET_FLOW_REPOSITORIES,
    load: () => import('./routes/ui/wallet-login'),
  },
];

/** The route modules a process with `roles` registers, in manifest order. */
export function routeModulesFor(roles: readonly ServiceRole[]): readonly RouteModule[] {
  return ROUTE_MANIFEST.filter((entry) => entry.roles.some((role) => roles.includes(role)));
}
