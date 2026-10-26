import type { RepositoryName } from '@qauth-labs/fastify-plugin-db';
import { SERVICE_ROLE_NAMES, type ServiceRole } from '@qauth-labs/server-config';
import type { FastifyPluginAsync } from 'fastify';

import appAssociationRoutes from './routes/app-association';
import linkWalletRoutes from './routes/auth/link-wallet';
import loginRoutes from './routes/auth/login';
import logoutRoutes from './routes/auth/logout';
import registerRoutes from './routes/auth/register';
import resendVerificationRoutes from './routes/auth/resend-verification';
import verifyRoutes from './routes/auth/verify';
import clientsRoutes, { autoPrefix as clientsPrefix } from './routes/clients';
import consentsRoutes from './routes/consents';
import consentsApiRoutes, { autoPrefix as consentsApiPrefix } from './routes/consents-api';
import healthRoutes from './routes/health';
import metricsRoutes from './routes/metrics';
import authorizeRoutes from './routes/oauth/authorize';
import introspectRoutes from './routes/oauth/introspect';
import clientRegistrationRoutes from './routes/oauth/register';
import revokeRoutes from './routes/oauth/revoke';
import tokenRoutes from './routes/oauth/token';
import userinfoRoutes from './routes/oauth/userinfo';
import requestObjectRoutes from './routes/oid4vp/request-object';
import walletResponseRoutes from './routes/oid4vp/response';
import rootRoutes from './routes/root';
import ssfRoutes, { autoPrefix as ssfPrefix } from './routes/ssf';
import uiConsentRoutes from './routes/ui/consent';
import uiLoginRoutes from './routes/ui/login';
import uiResumeRoutes from './routes/ui/resume';
import uiWalletLinkRoutes from './routes/ui/wallet-link';
import uiWalletLoginRoutes from './routes/ui/wallet-login';
import wellKnownRoutes from './routes/well-known';

/**
 * THE ROUTE MANIFEST (ADR-019 Decision 8, issue #495).
 *
 * Every route module of the auth server, with the service roles that register
 * it, the plugins its routes call and the repositories they read or write. It
 * replaces the folder autoload: a module that is not listed here is never
 * registered, and a module without a role cannot be listed.
 *
 * - `web` registers the browser-session endpoints, the `browser` routes of
 *   #486: authorize, the ceremony pages, `/consents` and wallet linking.
 * - `api` registers the routes a client or a server calls with its own
 *   credentials, and the documents about the realm: token, introspection,
 *   revocation, userinfo, registration, discovery, JWKS, the OID4VP endpoints
 *   a wallet calls, the account and developer APIs, the SSF transmitter and
 *   the legacy `/auth/*` routes (the `api` and `meta` surfaces).
 * - Every role registers `/health` and `/metrics`: each process answers for
 *   itself, whatever else it serves.
 * - `admin`, `signer` and `delivery` have no route of their own yet. The admin
 *   API (#511) and the signer service (#497) arrive on the internal listener
 *   (#496); delivery serves no inbound request.
 *
 * `route-manifest.test.ts` checks each entry against its module: the plugins
 * and repositories its code reaches, and the roles its routes' surfaces call
 * for. The process builds its repository list and its plugin set from the
 * entries of its roles (`service-roles.ts`).
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
  readonly plugin: FastifyPluginAsync;
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

/** Every route module of the auth server. */
export const ROUTE_MANIFEST: readonly RouteModule[] = [
  { module: 'health', roles: EVERY_ROLE, plugins: [], repositories: [], plugin: healthRoutes },
  { module: 'metrics', roles: EVERY_ROLE, plugins: [], repositories: [], plugin: metricsRoutes },
  { module: 'root', roles: ['api'], plugins: [], repositories: [], plugin: rootRoutes },
  {
    module: 'app-association',
    roles: ['api'],
    plugins: [],
    repositories: [],
    plugin: appAssociationRoutes,
  },
  {
    module: 'well-known',
    roles: ['api'],
    plugins: ['dpop', 'jwt', 'ssf'],
    repositories: ['oauthClients', 'realms'],
    plugin: wellKnownRoutes,
  },
  {
    module: 'oauth/authorize',
    prefix: '/oauth',
    roles: ['web'],
    plugins: ['dpop', 'jwt', 'password', 'sessions'],
    repositories: ['authorizationCodes', 'events', 'oauthClients', 'oauthConsents', 'users'],
    plugin: authorizeRoutes,
  },
  {
    module: 'oauth/token',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['dpop', 'jwt', 'password', 'pkce'],
    repositories: [
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
    plugin: tokenRoutes,
  },
  {
    module: 'oauth/introspect',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['jwt', 'password'],
    repositories: ['events', 'oauthClients', 'users'],
    plugin: introspectRoutes,
  },
  {
    module: 'oauth/revoke',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['jwt', 'password'],
    repositories: ['events', 'oauthClients', 'refreshTokens'],
    plugin: revokeRoutes,
  },
  {
    module: 'oauth/userinfo',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['jwt'],
    repositories: ['events', 'realms', 'userAttributes', 'users'],
    plugin: userinfoRoutes,
  },
  {
    module: 'oauth/register',
    prefix: '/oauth',
    roles: ['api'],
    plugins: ['jwt', 'password'],
    repositories: ['events', 'oauthClients', 'realms', 'users'],
    plugin: clientRegistrationRoutes,
  },
  {
    module: 'oid4vp/request-object',
    prefix: '/oid4vp',
    roles: ['api'],
    plugins: [],
    repositories: [],
    plugin: requestObjectRoutes,
  },
  {
    module: 'oid4vp/response',
    prefix: '/oid4vp',
    roles: ['api'],
    plugins: [],
    repositories: ['events', 'oid4vpRequestStates'],
    plugin: walletResponseRoutes,
  },
  {
    module: 'ui/login',
    prefix: '/ui',
    roles: ['web'],
    plugins: ['federation', 'password', 'sessions'],
    repositories: ['events', 'userCredentials', 'users'],
    plugin: uiLoginRoutes,
  },
  {
    module: 'ui/consent',
    prefix: '/ui',
    roles: ['web'],
    plugins: ['dpop', 'jwt', 'password', 'sessions'],
    repositories: ['authorizationCodes', 'events', 'oauthClients', 'oauthConsents', 'users'],
    plugin: uiConsentRoutes,
  },
  {
    module: 'ui/resume',
    prefix: '/ui',
    roles: ['web'],
    plugins: [],
    repositories: [],
    plugin: uiResumeRoutes,
  },
  {
    module: 'ui/wallet-login',
    prefix: '/ui',
    roles: ['web'],
    plugins: ['sessions'],
    repositories: WALLET_FLOW_REPOSITORIES,
    plugin: uiWalletLoginRoutes,
  },
  {
    module: 'ui/wallet-link',
    prefix: '/ui',
    roles: ['web'],
    plugins: ['sessions'],
    repositories: WALLET_FLOW_REPOSITORIES,
    plugin: uiWalletLinkRoutes,
  },
  {
    module: 'consents',
    prefix: '/consents',
    roles: ['web'],
    plugins: ['sessions'],
    repositories: ['authorizationCodes', 'events', 'oauthConsents', 'refreshTokens', 'users'],
    plugin: consentsRoutes,
  },
  {
    module: 'auth/link-wallet',
    prefix: '/auth',
    roles: ['web'],
    plugins: ['sessions'],
    repositories: WALLET_FLOW_REPOSITORIES,
    plugin: linkWalletRoutes,
  },
  {
    module: 'auth/login',
    prefix: '/auth',
    roles: ['api'],
    plugins: ['federation', 'jwt', 'password'],
    repositories: ['events', 'oauthClients', 'refreshTokens', 'userCredentials', 'users'],
    plugin: loginRoutes,
  },
  {
    module: 'auth/logout',
    prefix: '/auth',
    roles: ['api'],
    plugins: ['jwt', 'password', 'sessions'],
    repositories: ['authorizationCodes', 'events', 'oauthClients', 'refreshTokens', 'users'],
    plugin: logoutRoutes,
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
    plugin: registerRoutes,
  },
  {
    module: 'auth/verify',
    prefix: '/auth',
    roles: ['api'],
    plugins: ['email', 'password'],
    repositories: ['emailVerificationTokens', 'userAttributes', 'userCredentials', 'users'],
    plugin: verifyRoutes,
  },
  {
    module: 'auth/resend-verification',
    prefix: '/auth',
    roles: ['api'],
    plugins: ['email'],
    repositories: ['emailVerificationTokens', 'userCredentials', 'users'],
    plugin: resendVerificationRoutes,
  },
  {
    module: 'clients',
    prefix: clientsPrefix,
    roles: ['api'],
    plugins: ['jwt', 'password'],
    repositories: ['apiKeys', 'events', 'oauthClients', 'realms', 'users'],
    plugin: clientsRoutes,
  },
  {
    module: 'consents-api',
    prefix: consentsApiPrefix,
    roles: ['api'],
    plugins: ['jwt', 'password'],
    repositories: [
      'authorizationCodes',
      'events',
      'oauthClients',
      'oauthConsents',
      'refreshTokens',
      'users',
    ],
    plugin: consentsApiRoutes,
  },
  {
    module: 'ssf',
    prefix: ssfPrefix,
    roles: ['api'],
    plugins: ['jwt', 'ssf'],
    repositories: ['events', 'oauthClients', 'realms', 'ssfStreams'],
    plugin: ssfRoutes,
  },
];

/** The route modules a process with `roles` registers, in manifest order. */
export function routeModulesFor(roles: readonly ServiceRole[]): readonly RouteModule[] {
  return ROUTE_MANIFEST.filter((entry) => entry.roles.some((role) => roles.includes(role)));
}
