import { randomUUID } from 'node:crypto';
import type { Server as TlsServer, TLSSocket } from 'node:tls';

import type { InternalPeerRoles, ServiceRole } from '@qauth-labs/server-config';
import { ForbiddenError } from '@qauth-labs/shared-errors';
import Fastify, {
  type FastifyBaseLogger,
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
  LogController,
  type RouteOptions,
} from 'fastify';
import fp from 'fastify-plugin';
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';

import { env } from '../../config/env';
import { closeWithApp } from '../helpers/listener-close';
import {
  answerClientError,
  answerFrameworkError,
  answerRouteNotFound,
  answerUnknownRouteBeforeBody,
  requestDeadlineOptions,
} from '../helpers/request-bounds';
import errorHandler from '../plugins/error-handler';
import { requestIdPlugin } from '../plugins/request-id';
import { describeServiceRoles, routeRolesProblem } from '../service-roles';
import {
  certificateSans,
  loggableSans,
  type PeerRoleResolution,
  resolvePeerRole,
} from './peer-certificate';
import {
  internalModuleProblem,
  type InternalRouteModule,
  internalRouteModulesFor,
  internalRouteProblem,
} from './route-manifest';
import {
  describeCertificate,
  internalSecureContextOptions,
  type InternalTlsFiles,
  type InternalTlsMaterial,
  watchInternalTlsFiles,
} from './tls-files';

/**
 * THE INTERNAL LISTENER (ADR-019 Decision 8, issue #496).
 *
 * The roles of a distributed deployment call one another on a second HTTP
 * server of the process, bound to INTERNAL_HOST and INTERNAL_PORT, apart from
 * the public listener: the signer service first (#497). `main.ts` builds it
 * with {@link createInternalServer} on a process whose roles need it
 * (`servesInternalListener`), the app installs its routes and shares its
 * decorators with {@link installInternalApi}, and `main.ts` listens on it
 * once the app is ready. It closes with the public listener.
 *
 * With the internal TLS files it serves mutual TLS, TLS 1.3 only: the
 * handshake fails for a client that presents no certificate or one the CA
 * file did not issue. A peer that passes is known by a subject alternative
 * name of its certificate: INTERNAL_PEER_ROLES maps it to the role it calls
 * as, `request.peerRole`, and a request from a peer with no role is refused
 * with 403 before any route, or the 404 of a path no route serves, is
 * reached. A route module names the peer roles that may call it, and a peer
 * of another role gets 403 on its routes. The certificate files are read
 * again when they change, so a rotated certificate is served with no restart.
 *
 * The handshake checks the peer's certificate once per connection, so each
 * request checks again what may have changed since: a request after the
 * certificate's `notAfter`, or on a connection made before the TLS files were
 * last reloaded (a CA replaced among them), is refused with 403. Every 403
 * closes its connection, so the peer connects again under the files served
 * then.
 *
 * Without the TLS files it serves plain HTTP, which no boot reaches: the
 * listener runs only while the roles are split, and then the boot refuses a
 * process without the files (`service-roles.ts`). No request there has a
 * peer role, so every one is refused.
 *
 * The listener is not routed by host (ADR-019 Decision 1): a route takes the
 * realm from the request body or from what the caller's role may do, never
 * from the `Host` header. The admin API keeps its own listener and its own
 * rule (Decision 7): a peer's certificate grants nothing there, and every
 * admin call still needs its admin token.
 *
 * HTTP/1.1 only, as the public listener (`main.ts`): `find-my-way`'s HTTP/2
 * advisory stays inert only while no listener serves HTTP/2.
 */

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * The service role the peer's certificate maps to in INTERNAL_PEER_ROLES:
     * set on every request of the internal listener that reaches a route
     * (#496), and never on the public or the admin listener. Read it with
     * {@link requestPeerRole}.
     */
    peerRole?: ServiceRole;
  }
}

/**
 * The role the caller of an internal route calls as. Every request that
 * reaches a route of the internal listener has one.
 *
 * @throws Error on a request of another listener: a route that reads it
 *   belongs on the internal listener only
 */
export function requestPeerRole(request: FastifyRequest): ServiceRole {
  const role = request.peerRole;
  if (role === undefined) {
    throw new Error('requestPeerRole: the request did not come through the internal listener');
  }
  return role;
}

/** The internal listener's TLS files and what they hold at boot. */
export interface InternalServerTls {
  readonly files: InternalTlsFiles;
  /** The files' contents, read and checked at boot (`readInternalTlsFiles`). */
  readonly material: InternalTlsMaterial;
  /** How often the files are read again; the default of `tls-files.ts` unless set. */
  readonly reloadIntervalMs?: number;
}

/** Options for {@link createInternalServer}. */
export interface InternalServerOptions {
  /** The logger the listener writes to: in `main.ts`, the public server's, as a child. */
  readonly loggerInstance?: FastifyBaseLogger;
  /** Serve mutual TLS with these files; unset, plain HTTP. */
  readonly tls?: InternalServerTls;
  /** The role each known peer SAN calls as: INTERNAL_PEER_ROLES. */
  readonly peerRoles: InternalPeerRoles;
}

/** The parts of a connection the peer check reads: a TLS socket's, when it is one. */
type PeerSocket = Partial<Pick<TLSSocket, 'authorized' | 'getPeerX509Certificate'>>;

/** What the listener knows of a connection's peer, resolved at its first request. */
type SocketPeer = PeerRoleResolution & {
  readonly sans: string[];
  /** When the peer's certificate stops being valid, in ms since the epoch: never without one. */
  readonly notAfterMs: number;
};

/**
 * The role of the peer on `socket`: none on a plain-HTTP connection or one
 * whose certificate did not verify, and otherwise the role its SANs map to.
 */
function resolveSocketPeer(socket: PeerSocket, peerRoles: InternalPeerRoles): SocketPeer {
  const none: SocketPeer = {
    refused: 'no-certificate',
    sans: [],
    notAfterMs: Number.POSITIVE_INFINITY,
  };
  if (typeof socket.getPeerX509Certificate !== 'function' || socket.authorized !== true) {
    return none;
  }
  const certificate = socket.getPeerX509Certificate();
  if (certificate === undefined) return none;
  const sans = certificateSans(certificate.subjectAltName);
  // An unreadable date counts as expired.
  const notAfterMs = certificate.validToDate.getTime();
  return {
    ...resolvePeerRole(sans, peerRoles),
    sans: loggableSans(sans),
    notAfterMs: Number.isNaN(notAfterMs) ? 0 : notAfterMs,
  };
}

/**
 * Which TLS files each connection's handshake ran under: a generation the
 * listener bumps on every reload of its files, and the one each connection
 * was made in, stamped when its handshake completes.
 */
class TlsGenerations {
  private generation = 0;
  private readonly sockets = new WeakMap<object, number>();

  /** The generation of the files served now. */
  get current(): number {
    return this.generation;
  }

  /** The files changed: every connection made before now is of an older generation. */
  bump(): void {
    this.generation += 1;
  }

  /** `socket` completed its handshake under the files served now. */
  stamp(socket: object): void {
    this.sockets.set(socket, this.generation);
  }

  /** The generation `socket` was made in: the current one for a socket never stamped (plain HTTP). */
  of(socket: object): number {
    return this.sockets.get(socket) ?? this.generation;
  }
}

/**
 * Refuse an internal request with 403 and close its connection once the
 * answer is sent: the peer connects again, and its next handshake checks its
 * certificate under the TLS files served then.
 */
function refuseInternalRequest(reply: FastifyReply, message: string): never {
  reply.header('connection', 'close');
  throw new ForbiddenError(message);
}

/**
 * The peer check: an `onRequest` hook of the listener's root, registered
 * after the request id (so a refusal carries it) and before the answer to an
 * unknown path (so a peer with no role learns nothing of the routes).
 *
 * A connection's peer cannot change, TLS 1.3 having no renegotiation, so its
 * role is resolved once per connection. What the handshake checked can stop
 * holding while the connection lives, kept alive or resumed: each request is
 * refused once the certificate's `notAfter` has passed, or once the TLS files
 * the handshake ran under were replaced.
 */
const peerRolePlugin = fp<{
  readonly peerRoles: InternalPeerRoles;
  readonly generations: TlsGenerations;
}>(
  async (fastify, { peerRoles, generations }) => {
    const resolved = new WeakMap<object, SocketPeer & { readonly generation: number }>();
    fastify.decorateRequest('peerRole', undefined);
    fastify.addHook('onRequest', async (request, reply) => {
      const socket = request.raw.socket;
      let peer = resolved.get(socket);
      if (peer === undefined) {
        peer = {
          ...resolveSocketPeer(socket as PeerSocket, peerRoles),
          generation: generations.of(socket),
        };
        resolved.set(socket, peer);
      }
      if (peer.generation < generations.current) {
        request.log.debug(
          'Refused an internal request on a connection made before the TLS files were reloaded'
        );
        refuseInternalRequest(
          reply,
          'The internal TLS files changed since this connection was made: connect again'
        );
      }
      if (Date.now() >= peer.notAfterMs) {
        request.log.warn(
          { sans: peer.sans, notAfter: new Date(peer.notAfterMs).toISOString() },
          'Refused an internal request: the peer certificate has expired'
        );
        refuseInternalRequest(reply, 'The peer certificate has expired');
      }
      if ('role' in peer) {
        request.peerRole = peer.role;
        return;
      }
      request.log.warn(
        { refused: peer.refused, sans: peer.sans },
        'Refused an internal request: the peer certificate maps to no role in INTERNAL_PEER_ROLES'
      );
      refuseInternalRequest(reply, 'The peer has no role on the internal listener');
    });
  },
  { name: '@qauth-labs/internal-peer-role' }
);

/** The listener's answer to a path no route serves, as an `onRequest` hook after the peer check. */
const unknownRoutePlugin = fp(
  async (fastify) => {
    fastify.addHook('onRequest', answerUnknownRouteBeforeBody);
  },
  { name: '@qauth-labs/internal-unknown-route' }
);

/** How long a connection may take to complete its TLS handshake. */
export const INTERNAL_HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * The most connections the internal listener holds open at once; past it, a
 * new connection is closed before its handshake. Room for 32 peer processes
 * with the internal client's default pool of 32 connections each
 * (`client.ts`), while a flood of connections that never complete a
 * handshake cannot take the process's file descriptors from the public
 * listener and the database pool.
 */
export const INTERNAL_MAX_CONNECTIONS = 1_024;

/** The shortest time between two log lines about refused handshakes. */
const REFUSAL_LOG_INTERVAL_MS = 60_000;

/** The most refusal reasons {@link LogSampler} keeps a count for. */
const MAX_SAMPLED_REASONS = 32;

/**
 * Lets one event per reason through per interval and counts the others, so
 * a stream of the same refusal writes one line a minute, with how many it
 * stands for, while a new reason is still logged at once. The reasons are
 * the TLS layer's error codes, a closed set; past {@link MAX_SAMPLED_REASONS}
 * they share one count.
 */
class LogSampler {
  private readonly reasons = new Map<string, { last: number; skipped: number }>();

  constructor(private readonly intervalMs: number) {}

  /** The count of events of `reason` skipped since the last one let through, or `undefined` to skip this one. */
  take(reason: string, now: number): number | undefined {
    const key =
      this.reasons.has(reason) || this.reasons.size < MAX_SAMPLED_REASONS ? reason : 'other';
    const entry = this.reasons.get(key) ?? { last: Number.NEGATIVE_INFINITY, skipped: 0 };
    this.reasons.set(key, entry);
    if (now - entry.last < this.intervalMs) {
      entry.skipped += 1;
      return undefined;
    }
    const skipped = entry.skipped;
    entry.last = now;
    entry.skipped = 0;
    return skipped;
  }
}

/**
 * A refused connection about the client's certificate, rather than a dropped
 * one: no certificate, or one the CA file did not issue. For the second,
 * Node.js completes the handshake, then closes the connection before any
 * request is read, and the reason is the socket's `authorizationError`.
 */
function isCertificateRefusal(
  error: Error,
  socket: Pick<TLSSocket, 'authorizationError'>
): boolean {
  const code = (error as NodeJS.ErrnoException).code ?? '';
  return (
    socket.authorizationError !== undefined ||
    /CERTIFICATE|UNKNOWN_CA|VERIFY/.test(code) ||
    /certificate/i.test(error.message)
  );
}

/**
 * Build the internal listener's Fastify instance, with the server-wide rules
 * of `main.ts`'s public instance and the admin listener's:
 *
 * - the Zod validator and serializer compilers, set before any route, so ajv
 *   (and with it `fast-uri`) never validates an internal request;
 * - HTTP/1.1 only;
 * - REQUEST_TIMEOUT_MS bounds an unfinished request;
 * - the router's refusals, unreadable requests and unknown paths answer
 *   problem documents, an unknown path before its body is read;
 * - every request has an id the server made;
 * - no proxy is trusted, and no route is chosen by host;
 * - with `tls`, a client certificate the CA file issued is required at the
 *   handshake, and the files are read again while the listener listens;
 * - every request is checked for its peer's role before anything else, and
 *   for a certificate that expired or TLS files replaced since its connection
 *   was made; each 403 closes its connection;
 * - at most {@link INTERNAL_MAX_CONNECTIONS} connections are open at once.
 */
export function createInternalServer(options: InternalServerOptions): FastifyInstance {
  const { tls } = options;
  const deadline = requestDeadlineOptions(env.REQUEST_TIMEOUT_MS);
  const server = Fastify({
    ...(options.loggerInstance === undefined
      ? { logger: false }
      : { loggerInstance: options.loggerInstance }),
    ...(tls === undefined
      ? {}
      : {
          https: {
            ...internalSecureContextOptions(tls.material),
            requestCert: true,
            rejectUnauthorized: true,
            // Node's default is 120 s: a connection that never completes its
            // handshake is dropped within this.
            handshakeTimeout: INTERNAL_HANDSHAKE_TIMEOUT_MS,
            // With `https` set, Fastify reads the headers timeout here, not
            // from `http` (`requestDeadlineOptions`).
            headersTimeout: deadline.http.headersTimeout,
          },
        }),
    requestIdHeader: false,
    genReqId: () => randomUUID(),
    logController: new LogController({ requestIdLogLabel: 'reqId' }),
    trustProxy: false,
    routerOptions: { ignoreTrailingSlash: true },
    exposeHeadRoutes: false,
    ...deadline,
    frameworkErrors: answerFrameworkError,
    clientErrorHandler: answerClientError,
  }).withTypeProvider<ZodTypeProvider>() as unknown as FastifyInstance;

  // The listener makes every request id itself, so Fastify's
  // `requestIdHeader` stays unset: the root's own answers echo the id in
  // this header instead.
  server.decorate('requestIdEchoHeader', env.REQUEST_ID_HEADER);
  server.setValidatorCompiler(validatorCompiler);
  server.setSerializerCompiler(serializerCompiler);
  server.setNotFoundHandler(answerRouteNotFound);
  server.server.maxConnections = INTERNAL_MAX_CONNECTIONS;
  const generations = new TlsGenerations();
  void server.register(errorHandler);
  void server.register(requestIdPlugin);
  void server.register(peerRolePlugin, { peerRoles: options.peerRoles, generations });
  void server.register(unknownRoutePlugin);

  if (tls !== undefined) {
    const tlsServer = server.server as unknown as TlsServer;
    // Registered after the HTTP layer's own listener, and run in the same
    // emit, so before the connection's first request is read.
    tlsServer.on('secureConnection', (socket) => generations.stamp(socket));
    const refusalLog = new LogSampler(REFUSAL_LOG_INTERVAL_MS);
    tlsServer.on('tlsClientError', (error, socket) => {
      const fields = {
        err: { code: (error as NodeJS.ErrnoException).code, message: error.message },
        ...(socket.authorizationError === undefined
          ? {}
          : { authorizationError: String(socket.authorizationError) }),
      };
      if (isCertificateRefusal(error, socket)) {
        // At most one line a minute per reason: a TLS health check that
        // presents no certificate would otherwise write one per probe.
        const reason = String(
          socket.authorizationError ?? (error as NodeJS.ErrnoException).code ?? 'unknown'
        );
        const suppressed = refusalLog.take(reason, Date.now());
        if (suppressed !== undefined) {
          server.log.warn(
            { ...fields, suppressed },
            'Refused an internal TLS connection at the handshake'
          );
        }
      } else {
        server.log.debug(fields, 'An internal TLS connection failed at the handshake');
      }
    });
    let watcher: { stop(): void } | undefined;
    server.addHook('onListen', async () => {
      watcher ??= watchInternalTlsFiles(
        tls.files,
        tls.material,
        (material) => {
          // A new context for new connections, with new session ticket keys
          // (`setSecureContext` makes them), so no session made before
          // resumes after. Every connection made before is of an older
          // generation now: the idle ones close, and the next request on a
          // busy one is refused with 403 and closes it, so each peer
          // connects again under the new files.
          tlsServer.setSecureContext(internalSecureContextOptions(material));
          generations.bump();
          server.server.closeIdleConnections();
          server.log.info(
            { certificate: describeCertificate(material.cert) },
            'Reloaded the internal TLS files'
          );
        },
        {
          ...(tls.reloadIntervalMs === undefined ? {} : { intervalMs: tls.reloadIntervalMs }),
          onError: (error) => {
            server.log.warn(
              { err: { message: error.message } },
              'The internal TLS files changed but cannot be used yet; the listener keeps the files it serves'
            );
          },
          onWarning: (message) => {
            server.log.warn(message);
          },
        }
      );
    });
    server.addHook('onClose', async () => {
      watcher?.stop();
    });
  }

  return server;
}

/** Options for {@link installInternalApi}. */
export interface InternalApiOptions {
  /** The roles of this process: the modules of these roles register. */
  readonly roles: readonly ServiceRole[];
  /**
   * TEST SUPPORT — the route modules to register in place of the manifest's
   * (`INTERNAL_ROUTE_MODULES`), such as a fixture route. `main.ts` never
   * sets it.
   */
  readonly modules?: readonly InternalRouteModule[];
}

/**
 * How long the internal listener waits for its calls in flight when the
 * server closes, before it closes their connections: under the 10 s Fastify
 * gives a `preClose` hook. It closes at the same time as the admin listener
 * (`helpers/listener-close.ts`), so a process with both stops within the
 * longer of their two graces.
 */
export const INTERNAL_CLOSE_GRACE_MS = 8_000;

/** How often a closing internal listener closes the connections that went idle. */
const IDLE_SWEEP_MS = 50;

/**
 * Close the internal listener: it takes no new call, lets each call in
 * flight finish, and closes each keep-alive connection as soon as it is idle,
 * and any still open after {@link INTERNAL_CLOSE_GRACE_MS}.
 */
export async function closeInternalServer(internal: FastifyInstance): Promise<void> {
  const closing = internal.close();
  const sweep = setInterval(() => internal.server.closeIdleConnections(), IDLE_SWEEP_MS);
  const deadline = setTimeout(() => internal.server.closeAllConnections(), INTERNAL_CLOSE_GRACE_MS);
  try {
    await closing;
  } finally {
    clearInterval(sweep);
    clearTimeout(deadline);
  }
}

/**
 * Install the internal listener's routes on `internal`, the instance
 * {@link createInternalServer} built, from `source`, the app scope that
 * registered the database, cache and signer plugins: the listener shares
 * their decorators, so one pool, one Redis client and one signer serve every
 * listener of the process.
 *
 * Each module of the process's roles registers in its own scope, under its
 * prefix, its routes tagged with the module's roles, and refuses with 403 a
 * peer whose role is not among the module's `peerRoles`. The boot is refused
 * for a module that names no peer role, and for a route outside `/internal/`
 * or with no role this process holds.
 *
 * `internal` stops accepting requests when `source` begins to close, before
 * the database closes, and while any other listener of the app closes.
 */
export async function installInternalApi(
  internal: FastifyInstance,
  source: FastifyInstance,
  options: InternalApiOptions
): Promise<void> {
  internal.decorate('db', source.db);
  internal.decorate('dbPool', source.dbPool);
  internal.decorate('repositories', source.repositories);
  internal.decorate('redis', source.redis);
  internal.decorate('signer', source.signer);
  // Never routed by host: no request of the listener has a realm until a
  // route takes it from the request body or from the caller's role.
  internal.decorateRequest('realm', null);
  internal.decorateRequest('realmHost', null);

  const registered: RouteOptions[] = [];
  internal.addHook('onRoute', (route) => {
    registered.push(route);
  });

  const modules = internalRouteModulesFor(options.roles, options.modules);
  const unguarded = modules
    .map((entry) => internalModuleProblem(entry))
    .filter((problem) => problem !== undefined);
  if (unguarded.length > 0) throw new Error(unguarded.join('\n'));
  for (const entry of modules) {
    const plugin = (await entry.load()).default;
    await internal.register(async (scope) => {
      scope.addHook('onRoute', (route) => {
        route.config = { ...route.config, serviceRoles: entry.roles };
      });
      // After the root's peer check: every request here has a peer role.
      scope.addHook('onRequest', async (request, reply) => {
        const role = request.peerRole;
        if (role !== undefined && entry.peerRoles.includes(role)) return;
        request.log.warn(
          { peerRole: role, module: entry.module },
          "Refused an internal request: the module does not admit the peer's role"
        );
        refuseInternalRequest(reply, "The peer's role may not call this route");
      });
      await scope.register(plugin, { prefix: entry.prefix });
    });
  }
  await internal.after();

  const unplaced = registered
    .map((route) => internalRouteProblem(route) ?? routeRolesProblem(route, options.roles))
    .filter((problem) => problem !== undefined);
  if (unplaced.length > 0) throw new Error(unplaced.join('\n'));

  internal.log.info(
    {
      serviceRoles: describeServiceRoles(options.roles),
      modules: modules.map((entry) => entry.module),
    },
    'Installed the internal listener'
  );

  closeWithApp(source, () => closeInternalServer(internal));
}
