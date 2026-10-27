import { createHash, randomBytes } from 'node:crypto';

import type { DeliveryRoute } from '@qauth-labs/fastify-plugin-event-delivery';
import { bootRealmKeysWithKekEnv } from '@qauth-labs/fastify-plugin-signer';
import {
  applyQauthMigrations,
  type StartedPostgres,
  type StartedRedis,
  startPostgresContainer,
  startRedisContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance, type InjectOptions, type RouteOptions } from 'fastify';
import fp from 'fastify-plugin';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';

import type { AppOptions } from '../app/app';
import { WALLET_LOGIN_FLOW_TTL_MS } from '../app/constants';
import type { EventLogQueueLimits } from '../app/helpers/event-log-queue';
import { encodeQrCode, renderQrCodeSvg } from '../app/helpers/qr-code';
import {
  answerFrameworkError,
  answerRouteNotFound,
  answerUnknownRouteBeforeBody,
} from '../app/helpers/request-bounds';

/**
 * TEST SUPPORT — booting the REAL auth-server against throwaway containers
 * (issue #240).
 *
 * The E2E suites in this app need the whole server, not a slice of it: the
 * wallet flow crosses an unauthenticated `direct_post` endpoint, a Redis-backed
 * flow record, a Postgres-backed account store, the OAuth authorization
 * endpoint and the token endpoint, and the properties worth asserting (a new
 * user is created, `acr` reaches the ID token, a password login does not grow
 * one) are only observable across all of them.
 *
 * ## Why the app is imported dynamically
 *
 * `src/config/env.ts` parses `process.env` at MODULE LOAD. A suite that wants a
 * deployment with — say — no `VerifierProfile` therefore has to set the
 * environment first and import the app after, with the module registry reset in
 * between. {@link bootAuthServer} does exactly that, which is also what makes
 * the fail-closed test (#296 Q1) expressible at all: it is a different
 * deployment, not a different request.
 *
 * ## Containers are shared, databases are not
 *
 * One Postgres and one Redis per FILE (`vitest.integration.config.ts` runs files
 * serially). Between tests the domain tables are truncated and Redis is flushed,
 * so a leaked row or a stale flow record cannot make the next test pass.
 */

/** A running QAuth server plus everything needed to reset and stop it. */
export interface BootedAuthServer {
  /**
   * The Fastify instance, ready for `.inject(options)`. A request that names
   * no host is sent to the realm host, the host of `JWT_ISSUER` (#486); a test
   * that sets `headers.host` sends that one instead. The chain form,
   * `.inject().get(…)`, is not covered and goes to `localhost`.
   */
  readonly app: FastifyInstance;
  /** Close the server (and its pools). Containers survive. */
  close(): Promise<void>;
}

/** Containers shared by every deployment a suite boots. */
export interface E2eInfrastructure {
  readonly postgres: StartedPostgres;
  readonly redis: StartedRedis;
  /** Stop and remove both containers. */
  teardown(): Promise<void>;
}

/**
 * Start Postgres + Redis and apply QAuth's generated migrations.
 *
 * Call from `beforeAll` behind `requireDockerOrSkip()`.
 */
export async function startE2eInfrastructure(): Promise<E2eInfrastructure> {
  const postgres = await startPostgresContainer();
  const redis = await startRedisContainer();

  await applyQauthMigrations(postgres.connectionString);

  return {
    postgres,
    redis,

    async teardown(): Promise<void> {
      await redis.stop();
      await postgres.stop();
    },
  };
}

/** Per booted server: run its default realm boot step and key boot step again. */
const defaultRealmReboots = new WeakMap<FastifyInstance, () => Promise<unknown>>();

/** Per booted server: run the key boot step for a realm, by name, with no key variables. */
const realmKeyBoots = new WeakMap<FastifyInstance, (realmName: string) => Promise<unknown>>();

/**
 * Give a realm the server created after its boot (`realms.createWithPrimaryHost`)
 * its standard keys, as the key boot step gives the default realm, RS256
 * included (#485): the server signs a realm's tokens only with that realm's
 * keys (#491), and creating a realm row creates none.
 */
export async function provisionRealmKeys(app: FastifyInstance, realmName: string): Promise<void> {
  const boot = realmKeyBoots.get(app);
  if (boot === undefined) {
    throw new Error('provisionRealmKeys: the server was not booted by bootAuthServer');
  }
  await boot(realmName);
}

/**
 * Truncate every domain table and flush Redis, through the SERVER's own
 * connections, then put the default realm and its keys back as the boot steps
 * made them.
 *
 * Deliberately not a second pool: the app already holds the only clients this
 * needs, and opening another would mean a test could reset a database the
 * server is not looking at.
 */
export async function resetE2eState(app: FastifyInstance): Promise<void> {
  await app.dbPool.query(truncateDomainTablesStatement());
  await app.redis.flushall();
  // The truncation took the default realm and its hosts with it, and every
  // request is routed by host (#486): put back what the boot step made, and
  // forget the hosts the resolver cached.
  await defaultRealmReboots.get(app)?.();
  app.realmHostCache.clear();
}

/** An Ed25519 key pair, PEM-encoded, for `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY`. */
export interface PemKeyPair {
  readonly privateKey: string;
  readonly publicKey: string;
}

/** Mint the Ed25519 signing key the server issues tokens with. */
export async function generateJwtPem(): Promise<PemKeyPair> {
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

/**
 * The name of the default realm every booted deployment creates
 * (`DEFAULT_REALM_NAME` below), for a suite that seeds rows in it. Named here
 * so no test reads the setting: only the boot step does (#487).
 */
export const E2E_REALM_NAME = 'master';

/**
 * The environment every deployment needs regardless of what it is testing.
 *
 * Exported so the HAIP suite can build a deployment with no containers behind it
 * and still fail for the reason it is asserting rather than for a missing
 * variable.
 */
export const REQUIRED_TEST_ENVIRONMENT: Record<string, string> = Object.freeze({
  NODE_ENV: 'test',
  JWT_ISSUER: 'https://auth.example.com',
  SESSION_COOKIE_SECRET: 'e2e-session-cookie-secret-of-at-least-32-characters',
  // The key-encryption key (#462). The key boot step (#485) refuses to import
  // the key variables under the published development KEK.
  KEK: Buffer.alloc(32, 0xe2).toString('base64'),
  EMAIL_PROVIDER: 'mock',
  EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
  EMAIL_BASE_URL: 'https://auth.example.com',
  DEFAULT_REALM_NAME: E2E_REALM_NAME,
  ENABLE_SWAGGER: 'false',
  LOG_LEVEL: 'fatal',
});

/** The environment every booted deployment starts from. */
export function baseEnvironment(infra: E2eInfrastructure, jwt: PemKeyPair): Record<string, string> {
  return {
    ...REQUIRED_TEST_ENVIRONMENT,
    DATABASE_URL: infra.postgres.connectionString,
    REDIS_URL: infra.redis.connectionUrl,
    JWT_PRIVATE_KEY: jwt.privateKey,
    JWT_PUBLIC_KEY: jwt.publicKey,
    // The rate limits are sized for humans; an E2E drives dozens of requests a
    // second from one IP, and a 429 would look like a security refusal.
    LOGIN_RATE_LIMIT: '10000',
    OID4VP_RESPONSE_RATE_LIMIT: '10000',
    RATE_LIMIT_MAX: '10000',
  };
}

/** What {@link bootAuthServer} may vary beyond the environment. */
export interface BootAuthServerOptions {
  /**
   * Receive the server's own log lines (pino NDJSON, level `warn` and up), for a
   * suite that asserts what the server logged — e.g. that a refusal raised no
   * database error. Without it the server is silent unless `E2E_DEBUG_LOG=1`.
   */
  readonly logStream?: { write(line: string): void };
  /**
   * Run the default realm's boot step (#484), which needs the database. On by
   * default. A suite that boots against a database URL it never dials, to test
   * what registration accepts or refuses, turns it off.
   */
  readonly defaultRealmBoot?: boolean;
  /**
   * Routes to add beside the app's, for a suite that reads request state no
   * route shows, such as the realm the resolver put on the request (#486).
   * Each one needs a `config.surface`, as every route of the app does. It may
   * be async, to import an app module after the boot reset the registry, so
   * the module is the instance the app loaded.
   */
  readonly routes?: (app: FastifyInstance) => void | Promise<void>;
  /**
   * The event telemetry queue's sizes and times (#541), for a suite that
   * fills the queue or waits for a batch.
   */
  readonly eventTelemetryLimits?: Partial<EventLogQueueLimits>;
  /** Event delivery routes for the delivery role (#460), for a suite that watches it. */
  readonly eventDeliveryRoutes?: readonly DeliveryRoute[];
  /**
   * Called with each route as the app registers it, for a suite that lists
   * the routes a set of service roles registers (#495).
   */
  readonly onRoute?: (route: RouteOptions) => void;
  /**
   * Build the egress client with this factory (#481): `createTestEgressClient`
   * from `@qauth-labs/fastify-plugin-egress`, for a suite that serves a CIMD
   * document, a JWKS or an issuer from a local fixture server. Unset, the
   * server uses the production client, which refuses localhost.
   */
  readonly egressClientFactory?: AppOptions['egressClientFactory'];
}

/**
 * Make `inject()` send `host` when a request names none (#486). Without it a
 * request goes to light-my-request's `localhost`, which names no realm, and
 * every route but `/health` answers 421. A `host` header still wins.
 */
function injectToRealmHost(server: FastifyInstance, host: string): void {
  const inject = server.inject.bind(server) as (...args: unknown[]) => unknown;
  const withHost = (options: InjectOptions | string): InjectOptions => {
    const given = typeof options === 'string' ? { url: options } : options;
    return { ...given, authority: given.authority ?? host };
  };
  server.inject = ((options?: InjectOptions | string, callback?: unknown) => {
    if (options === undefined) return inject();
    return callback === undefined ? inject(withHost(options)) : inject(withHost(options), callback);
  }) as FastifyInstance['inject'];
}

/**
 * Boot the real auth-server under a given environment.
 *
 * Every variable NOT named in `environment` is cleared from `process.env` first,
 * so a deployment cannot inherit a previous test's configuration — which is the
 * failure mode that would make the fail-closed suite pass for the wrong reason.
 */
export async function bootAuthServer(
  environment: Record<string, string>,
  options: BootAuthServerOptions = {}
): Promise<BootedAuthServer> {
  const vitest = await import('vitest');

  for (const key of Object.keys(process.env)) {
    if (
      key.startsWith('OID4VP_') ||
      key.startsWith('WALLET_') ||
      key.startsWith('ACR_') ||
      key.startsWith('WEBAUTHN_') ||
      key === 'KEK' ||
      key.startsWith('KEK_') ||
      key.startsWith('DEFAULT_REALM_') ||
      key.startsWith('OTEL_') ||
      key.startsWith('EVENT_RETENTION_') ||
      key.startsWith('DPOP_') ||
      key.startsWith('SSF_') ||
      key.startsWith('EGRESS_') ||
      key.startsWith('EVENT_DELIVERY_') ||
      key.startsWith('JWT_') ||
      key.startsWith('PQC_') ||
      key === 'HYBRID_SIGNING_ENABLED' ||
      key === 'SIGNING_ALGORITHM_MODE' ||
      key === 'TRUST_PROXY' ||
      // The role switch (#495): a process without the signer refuses a key
      // variable another boot left behind, one more reason the JWT keys go.
      key === 'SERVICE_ROLES' ||
      key === 'SIGNER_URL' ||
      key.startsWith('INTERNAL_TLS_')
    ) {
      delete process.env[key];
    }
  }
  for (const [key, value] of Object.entries(environment)) process.env[key] = value;

  // The app and its env module are re-imported per deployment; without this the
  // first import's parsed `env` would be reused for every later boot.
  vitest.vi.resetModules();

  const { app, defaultRealmBootSettings } = await import('../app/app');
  const { bootDefaultRealm } = await import('../app/helpers/default-realm-boot');
  const { keyVariableSettings } = await import('../app/helpers/key-variables');
  // The same module instance the app just loaded, since the registry was reset.
  const { env } = await import('../config/env');

  // Silent by default: these suites drive dozens of requests and every refusal
  // logs its reason. `E2E_DEBUG_LOG=1` turns the server's own log back on, which
  // is the only way to see WHY a uniform refusal was returned — the wire says
  // the same thing for every cause, by design.
  const server = Fastify({
    logger:
      options.logStream !== undefined
        ? { level: 'warn', stream: options.logStream }
        : process.env['E2E_DEBUG_LOG'] === '1',
    routerOptions: { ignoreTrailingSlash: true },
    // As in `main.ts`: `request.host` reads `X-Forwarded-Host` only from a
    // TRUST_PROXY hop, and `request.ip` reads `X-Forwarded-For` likewise.
    trustProxy: env.TRUST_PROXY,
    // As in `main.ts`: the router's own refusals answer problem documents (#513).
    frameworkErrors: answerFrameworkError,
    // As in `main.ts`: the request id travels in REQUEST_ID_HEADER, which the
    // root's own answers echo too.
    requestIdHeader: env.REQUEST_ID_HEADER,
  });
  server.setValidatorCompiler(validatorCompiler);
  server.setSerializerCompiler(serializerCompiler);
  // As in `main.ts`: a path no route serves is answered before its body is
  // read, with the `not_found` problem document (#513).
  server.addHook('onRequest', answerUnknownRouteBeforeBody);
  // As in `main.ts`: `reply.callNotFound()` answers that document too.
  server.setNotFoundHandler(answerRouteNotFound);
  // `fp()` only lifts ENCAPSULATION: the same plugins register in the same order
  // and every route is identical, but `db`/`dbPool`/`redis` land on the root
  // instance instead of inside the app's own scope, which is what lets
  // `resetE2eState` truncate the database the server is actually looking at.
  // Nothing under test observes the difference.
  const defaultRealmBoot = options.defaultRealmBoot ?? true;
  if (options.onRoute !== undefined) server.addHook('onRoute', options.onRoute);
  await server.register(fp(app), {
    defaultRealmBoot,
    ...(options.eventTelemetryLimits === undefined
      ? {}
      : { eventTelemetryLimits: options.eventTelemetryLimits }),
    ...(options.eventDeliveryRoutes === undefined
      ? {}
      : { eventDeliveryRoutes: options.eventDeliveryRoutes }),
    ...(options.egressClientFactory === undefined
      ? {}
      : { egressClientFactory: options.egressClientFactory }),
  });
  const { routes } = options;
  if (routes !== undefined) {
    await server.register(async (scope) => routes(scope));
  }
  await server.ready();
  injectToRealmHost(server, new URL(env.JWT_ISSUER).host);
  if (defaultRealmBoot) {
    // The environment as this server booted with it: a later boot of another
    // server rewrites `process.env`.
    const bootEnvironment = { ...process.env };
    const quiet = { info: () => undefined, warn: () => undefined };
    const bootRealmKeys = (realmName: string, withVariables: boolean) =>
      bootRealmKeysWithKekEnv(
        {
          db: server.db,
          kekEnv: bootEnvironment,
          warn: () => undefined,
          enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
          hybridSigning: env.HYBRID_SIGNING_ENABLED,
          log: quiet,
        },
        {
          realmName,
          environmentKeys: withVariables ? keyVariableSettings(env, bootEnvironment) : {},
        }
      );
    defaultRealmReboots.set(server, async () => {
      await bootDefaultRealm(
        { db: server.db, realms: server.repositories.realms, log: server.log },
        defaultRealmBootSettings()
      );
      await bootRealmKeys(defaultRealmBootSettings().realmName, true);
    });
    realmKeyBoots.set(server, (realmName) => bootRealmKeys(realmName, false));
  }

  return {
    app: server,
    async close(): Promise<void> {
      await server.close();
    },
  };
}

/**
 * A browser's cookie jar.
 *
 * The wallet flow spans four requests carrying three different `__Host-`
 * cookies (login CSRF, wallet-flow binder, session). Driving them by hand is how
 * a test ends up asserting a flow that no browser could actually complete, so
 * the suite keeps a jar and replays whatever the server set.
 */
export class CookieJar {
  private readonly cookies = new Map<string, string>();

  /** Absorb every `set-cookie` on a reply. */
  absorb(setCookie: string | string[] | undefined): void {
    if (setCookie === undefined) return;
    const headers = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const header of headers) {
      const [pair] = header.split(';');
      if (pair === undefined) continue;
      const separator = pair.indexOf('=');
      if (separator <= 0) continue;
      const name = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      if (value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  /** The `cookie` request header, or `undefined` when the jar is empty. */
  header(): string | undefined {
    if (this.cookies.size === 0) return undefined;
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  }

  /** Read one cookie's raw value. */
  get(name: string): string | undefined {
    return this.cookies.get(name);
  }

  /** Drop one cookie — used to prove a flow cannot advance without its binder. */
  drop(name: string): void {
    this.cookies.delete(name);
  }
}

/** Pull the hidden CSRF token out of a server-rendered form. */
export function extractCsrfToken(html: string): string {
  const match = /name="csrf_token"\s+value="([^"]+)"/.exec(html);
  if (match?.[1] === undefined) {
    throw new Error('no csrf_token field in the rendered form');
  }
  return match[1];
}

/**
 * Pull the wallet invocation URI out of a SAME-DEVICE pending page (#405).
 *
 * The same-device page renders the "Open my wallet" anchor and nothing else
 * that carries the URI, so the href is the one place to read it. A
 * cross-device page has no such anchor — by design, see
 * {@link extractInvocationUriFromQr} — and this throws for it.
 */
export function extractInvocationUri(html: string): string {
  const match = /href="(openid4vp:[^"]+)"/.exec(html);
  if (match?.[1] === undefined) {
    throw new Error('no wallet invocation link in the rendered page');
  }
  return decodeHtmlEntities(match[1]);
}

/** Pull the flow handle out of the pending page's poll URL. */
export function extractFlowHandle(html: string): string {
  const match = /\/ui\/wallet-(?:login|link)\/([A-Za-z0-9_-]{43})/.exec(html);
  if (match?.[1] === undefined) {
    throw new Error('no wallet flow handle in the rendered page');
  }
  return match[1];
}

/** The regex the harness uses to find a same-device "Open my wallet" anchor. */
const INVOCATION_ANCHOR = /href="openid4vp:/;

/** One rendered QR symbol, as `renderQrCodeSvg` emits it — single line, no nesting. */
const QR_SVG = /<svg [^>]*aria-label="([^"]*)"[^>]*>.*?<\/svg>/g;

/**
 * The Redis key (inside the app's session namespace) of a wallet flow record.
 *
 * The literal is `WALLET_FLOW_KEY_PREFIX` in `helpers/wallet-login-flow.ts`,
 * which keeps it private. It is repeated here rather than imported so the
 * harness reads the store the way an operator with `redis-cli` would — and so
 * that a renamed namespace fails these suites loudly ("no wallet flow record")
 * instead of being papered over by a shared constant.
 */
const WALLET_FLOW_SESSION_KEY = (handle: string): string => `wallet-login:${handle}`;

/** Likewise for the wallet-side signal record, keyed by the request `state` digest. */
const WALLET_SIGNAL_SESSION_KEY = (stateHash: string): string => `wallet-login-signal:${stateHash}`;

/** The fields of a flow record these helpers read. The record holds more. */
interface WalletFlowRecordView {
  readonly stateHash: string;
  readonly invocationUri: string;
  readonly sameDevice?: boolean;
  readonly mode?: string;
}

/**
 * Read a wallet flow record straight out of the booted server's session store.
 *
 * The same path `resetE2eState` uses to flush it: the app's own Redis client,
 * not a second connection, so the record read is the one the server is
 * looking at.
 *
 * @throws Error when no record exists under `handle`, or it has no
 * `invocationUri` / `stateHash`.
 */
export async function readWalletFlowRecord(
  app: FastifyInstance,
  handle: string
): Promise<WalletFlowRecordView> {
  const record = await app.sessionUtils.getSession<Record<string, unknown>>(
    WALLET_FLOW_SESSION_KEY(handle)
  );
  if (record === null) {
    throw new Error(`no wallet flow record in the session store for handle ${handle}`);
  }
  const { stateHash, invocationUri, sameDevice, mode } = record;
  if (typeof stateHash !== 'string' || typeof invocationUri !== 'string') {
    throw new Error('the wallet flow record carries no stateHash / invocationUri');
  }
  return {
    stateHash,
    invocationUri,
    ...(typeof sameDevice === 'boolean' ? { sameDevice } : {}),
    ...(typeof mode === 'string' ? { mode } : {}),
  };
}

/**
 * Obtain the wallet invocation URI behind a CROSS-DEVICE pending page (#405).
 *
 * ## A harness shortcut, and why
 *
 * Since #405 a cross-device pending page deliberately exposes the invocation
 * URI ONLY as a QR code: the "Open my wallet" anchor is the same-device
 * affordance, and rendering it for a device that is about to scan would
 * offer a link the scanning device cannot use. A real wallet decodes the QR
 * with a camera. This harness has no QR decoder (`helpers/qr-code.ts` is a
 * hand-rolled ENCODER, and pulling a decoder in for one helper would be a
 * dependency the product never needs), so it reads the URI where the server
 * keeps it — the flow record in the app's own session store, the record the
 * pending page was rendered FROM.
 *
 * ## What keeps it honest
 *
 * Reading the store alone would prove nothing about the page. So the helper
 * re-encodes the stored URI with the app's own `encodeQrCode` +
 * `renderQrCodeSvg` and requires the resulting SVG markup to be BYTE-EQUAL to
 * the one `<svg>` in the page. The encoder is deterministic (byte mode, level
 * M, lowest-penalty mask), so equality of the markup is equality of the
 * modules, and equality of the modules is what a camera would establish: the
 * QR on screen encodes exactly the URI the wallet is then driven with. A page
 * that rendered a different request, a stale one, or two symbols fails here,
 * loudly, before any wallet response is built.
 *
 * @throws Error when the page carries no QR, more than one, or one that does
 * not encode the flow record's invocation URI.
 */
export async function extractInvocationUriFromQr(
  page: string,
  app: FastifyInstance
): Promise<string> {
  const rendered = [...page.matchAll(QR_SVG)];
  if (rendered.length !== 1) {
    throw new Error(`expected exactly one QR code in the rendered page, found ${rendered.length}`);
  }
  const [svg, escapedLabel] = rendered[0] as RegExpMatchArray;

  const flow = await readWalletFlowRecord(app, extractFlowHandle(page));

  const qr = encodeQrCode(flow.invocationUri);
  if (qr === undefined) {
    throw new Error("the flow record's invocation URI does not fit a QR code");
  }
  // `renderQrCodeSvg` escapes the label with `&amp; &lt; &gt; &quot;` only.
  const label = (escapedLabel ?? '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&');

  if (renderQrCodeSvg(qr, label) !== svg) {
    throw new Error(
      "the rendered QR code does not encode the flow record's invocation URI — the page and the store disagree"
    );
  }

  return flow.invocationUri;
}

/** Which device the user said the wallet is on (#405, the sign-in form's `device` field). */
export type WalletDeviceChoice = 'this' | 'other';

/** What {@link startWalletLogin} may vary. */
export interface StartWalletLoginOptions {
  /**
   * The `device` form field. Omitted → the field is NOT posted, which is the
   * cross-device default every client built before #405 gets; `'other'` posts
   * it explicitly and lands on the same path; `'this'` starts a same-device
   * flow that completes on the return leg.
   */
  readonly device?: WalletDeviceChoice;
}

/** What a started wallet sign-in flow gives the browser. */
export interface StartedWalletFlow {
  readonly jar: CookieJar;
  readonly handle: string;
  /** The wallet invocation URI, read the way the page's affordance allows (see below). */
  readonly invocationUri: string;
  /** Whether the flow was started with `device=this`. */
  readonly sameDevice: boolean;
  /** The rendered pending page, for assertions about what it shows. */
  readonly page: string;
}

/**
 * Drive `GET /ui/wallet-login` then `POST /ui/wallet-login` exactly as a
 * browser would, cookies and CSRF included, and read the invocation URI back
 * the way the rendered page allows (#405):
 *
 * - same-device (`device: 'this'`): from the "Open my wallet" anchor's href,
 *   and the page must carry NO QR;
 * - cross-device (field absent or `'other'`): via
 *   {@link extractInvocationUriFromQr}, and the page must carry NO anchor.
 *
 * Exactly one affordance is the page's contract, so the helper refuses a page
 * that shows both or neither rather than reading whichever it finds.
 */
export async function startWalletLogin(
  app: FastifyInstance,
  identifier: string,
  options: StartWalletLoginOptions = {}
): Promise<StartedWalletFlow> {
  const jar = new CookieJar();

  const form = await app.inject({ method: 'GET', url: '/ui/wallet-login' });
  if (form.statusCode !== 200) {
    throw new Error(`GET /ui/wallet-login answered ${form.statusCode}: ${form.body}`);
  }
  jar.absorb(form.headers['set-cookie']);

  const started = await app.inject({
    method: 'POST',
    url: '/ui/wallet-login',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(jar.header() === undefined ? {} : { cookie: jar.header() as string }),
    },
    payload: new URLSearchParams({
      identifier,
      csrf_token: extractCsrfToken(form.body),
      ...(options.device === undefined ? {} : { device: options.device }),
    }).toString(),
  });
  if (started.statusCode !== 200) {
    throw new Error(`POST /ui/wallet-login answered ${started.statusCode}: ${started.body}`);
  }
  jar.absorb(started.headers['set-cookie']);

  const page = started.body;
  const sameDevice = options.device === 'this';
  const invocationUri = await readInvocationUriFromPendingPage(app, page, sameDevice);

  return { jar, handle: extractFlowHandle(page), invocationUri, sameDevice, page };
}

/**
 * Read the invocation URI off a pending page through the ONE affordance the
 * page is supposed to render for its device choice, refusing the other.
 *
 * Shared by the login and the link flows: both pending pages have the same
 * contract (#405).
 */
export async function readInvocationUriFromPendingPage(
  app: FastifyInstance,
  page: string,
  sameDevice: boolean
): Promise<string> {
  const hasAnchor = INVOCATION_ANCHOR.test(page);
  const hasQr = /<svg /.test(page);

  if (sameDevice) {
    if (hasQr) throw new Error('a same-device pending page rendered a QR code');
    if (!hasAnchor) throw new Error('a same-device pending page rendered no wallet anchor');
    return extractInvocationUri(page);
  }

  if (hasAnchor) throw new Error('a cross-device pending page rendered a wallet anchor');
  if (!hasQr) throw new Error('a cross-device pending page rendered no QR code');
  return extractInvocationUriFromQr(page, app);
}

/** The password every E2E password account is registered with. */
export const E2E_PASSWORD = 'Correct-Horse-Battery-Staple-42!';

/**
 * Register a password account through the real `POST /auth/register` route and
 * verify it through the real `POST /auth/verify`, as its owner would from the
 * mailed link.
 *
 * Since ANT-2026-SPEMY9GU registration answers every address with the same
 * `202` and no user id, and `REQUIRE_VERIFIED_ACCOUNT` is on by default, so an
 * unverified account cannot sign in. The verification token is read from the
 * mail the server hands its provider (the mail goes out off the request path),
 * and the id from the account's password credential.
 *
 * `options.host` registers the account in the realm of that host (#487); by
 * default the requests go to the default realm's host.
 *
 * @returns the new account's `users.id`.
 * @throws Error when registration, the mail or the verification fails.
 */
export async function registerPasswordAccount(
  app: FastifyInstance,
  email: string,
  password = E2E_PASSWORD,
  options: { readonly host?: string } = {}
): Promise<string> {
  const headers = options.host === undefined ? {} : { host: options.host };
  const emailService = app.emailService;
  const original = emailService.sendVerificationEmail;
  const tokens: string[] = [];
  emailService.sendVerificationEmail = async (to, token, link, options) => {
    if (to === email) tokens.push(token);
    return original.call(emailService, to, token, link, options);
  };
  try {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      headers,
      payload: { email, password },
    });
    if (response.statusCode !== 202) {
      throw new Error(`POST /auth/register answered ${response.statusCode}: ${response.body}`);
    }
    const deadline = Date.now() + 5_000;
    while (tokens.length === 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  } finally {
    emailService.sendVerificationEmail = original;
  }
  const token = tokens.at(-1);
  if (token === undefined) {
    throw new Error(`registration of ${email} sent no verification mail`);
  }

  const verified = await app.inject({
    method: 'POST',
    url: '/auth/verify',
    headers,
    payload: { token, password },
  });
  if (verified.statusCode !== 200) {
    throw new Error(`POST /auth/verify answered ${verified.statusCode}: ${verified.body}`);
  }

  const realm =
    options.host === undefined
      ? await app.repositories.realms.findByName(E2E_REALM_NAME)
      : (await app.repositories.realms.findByHost(options.host))?.realm;
  const credential =
    realm &&
    (await app.repositories.userCredentials.findByRealmProviderSub(realm.id, 'password', email));
  if (!credential) {
    throw new Error(`registration of ${email} left no password credential`);
  }
  return credential.userId;
}

/**
 * Sign a password account in through the real `/ui/login` form, CSRF included.
 *
 * @returns the browser's cookie jar, holding the session cookie.
 * @throws Error when the form does not redirect (a refused sign-in re-renders).
 */
export async function signInWithPassword(
  app: FastifyInstance,
  email: string,
  password = E2E_PASSWORD
): Promise<CookieJar> {
  const jar = new CookieJar();
  const loginPage = await app.inject({ method: 'GET', url: '/ui/login' });
  jar.absorb(loginPage.headers['set-cookie']);

  const login = await app.inject({
    method: 'POST',
    url: '/ui/login',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(jar.header() === undefined ? {} : { cookie: jar.header() as string }),
    },
    payload: new URLSearchParams({
      email,
      password,
      csrf_token: extractCsrfToken(loginPage.body),
    }).toString(),
  });
  if (login.statusCode !== 302) {
    throw new Error(`POST /ui/login answered ${login.statusCode}, not a redirect`);
  }
  jar.absorb(login.headers['set-cookie']);
  return jar;
}

/** What a started wallet LINK flow gives the signed-in browser. */
export interface StartedWalletLink {
  readonly handle: string;
  /** The wallet invocation URI, read through the page's one affordance. */
  readonly invocationUri: string;
  /** The rendered pending page. */
  readonly page: string;
}

/**
 * Start a linking flow through the server-rendered screens (#238), as the
 * signed-in browser holding `jar`, choosing where the wallet is (#405) — or
 * not choosing, which is the cross-device default.
 *
 * @throws Error when either screen does not answer 200.
 */
export async function startWalletLink(
  app: FastifyInstance,
  jar: CookieJar,
  device?: WalletDeviceChoice
): Promise<StartedWalletLink> {
  const confirm = await app.inject({
    method: 'GET',
    url: '/ui/wallet-link',
    headers: { cookie: jar.header() as string },
  });
  if (confirm.statusCode !== 200) {
    throw new Error(`GET /ui/wallet-link answered ${confirm.statusCode}`);
  }
  jar.absorb(confirm.headers['set-cookie']);

  const started = await app.inject({
    method: 'POST',
    url: '/ui/wallet-link',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: jar.header() as string,
    },
    payload: new URLSearchParams({
      csrf_token: extractCsrfToken(confirm.body),
      ...(device === undefined ? {} : { device }),
    }).toString(),
  });
  if (started.statusCode !== 200) {
    throw new Error(`POST /ui/wallet-link answered ${started.statusCode}: ${started.body}`);
  }
  jar.absorb(started.headers['set-cookie']);

  return {
    handle: extractFlowHandle(started.body),
    invocationUri: await readInvocationUriFromPendingPage(app, started.body, device === 'this'),
    page: started.body,
  };
}

/** The heading `walletLinkedPage` renders (`WALLET_LINKED_TITLE` in `helpers/wallet-ui.ts`). */
const WALLET_LINKED_TITLE = 'Wallet credential linked';

/**
 * Give a wallet credential an account the one way QAuth allows since ADR-009
 * §1's 2026-10-19 amendment: wallet SIGN-IN never creates an account, so the
 * account is registered with a password, signed in, and the wallet is linked
 * from that session (#238) — cross-device, completed by the link page's
 * no-JavaScript refresh.
 *
 * `answer` IS the wallet: it receives the invocation URI and returns the form
 * body to post to `/oid4vp/response`. Each suite passes its own, so the link
 * runs under the suite's profile (an inline request, or a signed JAR and an
 * encrypted response).
 *
 * @returns the account's `users.id` and the password-signed-in browser's jar.
 * @throws Error when any step of the registration, sign-in or link fails.
 */
export async function linkWalletToNewAccount(
  app: FastifyInstance,
  email: string,
  answer: (invocationUri: string) => Promise<Record<string, string>>
): Promise<{ readonly userId: string; readonly jar: CookieJar }> {
  const userId = await registerPasswordAccount(app, email);
  const jar = await signInWithPassword(app, email);
  const link = await startWalletLink(app, jar);

  const posted = await app.inject({
    method: 'POST',
    url: '/oid4vp/response',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams(await answer(link.invocationUri)).toString(),
  });
  if (posted.statusCode !== 200) {
    throw new Error(
      `the wallet's link response was refused (${posted.statusCode}): ${posted.body}`
    );
  }

  const completed = await app.inject({
    method: 'GET',
    url: `/ui/wallet-link/${link.handle}`,
    headers: { cookie: jar.header() as string },
  });
  jar.absorb(completed.headers['set-cookie']);
  // The pending page also answers 200, so the heading is what says "linked".
  if (completed.statusCode !== 200 || !completed.body.includes(WALLET_LINKED_TITLE)) {
    throw new Error(`the wallet link did not complete (${completed.statusCode})`);
  }

  return { userId, jar };
}

/** What a followed `redirect_uri` answered. */
export interface FollowedRedirect {
  readonly statusCode: number;
  readonly body: string;
  readonly headers: Record<string, string | string[] | number | undefined>;
}

/**
 * Follow a `redirect_uri` the Response Endpoint handed the wallet, as the
 * BROWSER holding `jar` (#405, OID4VP 1.0 §8.2 / HAIP 1.0 §5.1).
 *
 * The URI is absolute and under `JWT_ISSUER`; the server is in-process, so
 * only its path and query are injected — asserting the origin is the suite's
 * job, and it is worth asserting separately (a `redirect_uri` under any other
 * host would be a wallet sent elsewhere). The jar's cookies go with the
 * request and whatever the landing sets (the session cookie, on success) is
 * absorbed, so the SAME jar can then poll and mint tokens as the original tab
 * would. A fresh jar models the wallet opening a different browser.
 */
export async function followRedirect(
  app: FastifyInstance,
  jar: CookieJar,
  redirectUri: string
): Promise<FollowedRedirect> {
  const target = new URL(redirectUri);
  const response = await app.inject({
    method: 'GET',
    url: `${target.pathname}${target.search}`,
    headers: { ...(jar.header() === undefined ? {} : { cookie: jar.header() as string }) },
  });
  jar.absorb(response.headers['set-cookie']);
  return { statusCode: response.statusCode, body: response.body, headers: response.headers };
}

/**
 * Move a flow's wallet-side signal `at` timestamp INTO THE PAST by `byMs`,
 * in the app's own Redis (#405).
 *
 * The login state machine rejects a same-device presentation whose redirect
 * was never followed once `Date.now() > signal.at + WALLET_RETURN_CODE_TTL_MS`
 * (HAIP 1.0 §5.1). That deadline is three minutes, which no E2E should wait
 * for; rewriting the stored timestamp is the deterministic way to reach it,
 * and it is the SAME record the poll reads, so the outcome asserted is the
 * server's own decision and not a clock the harness faked into the process.
 * Written back through the app's own session utilities with the TTL the
 * server publishes the signal under, so nothing about the record but `at`
 * changes.
 *
 * @throws Error when the flow or its signal record does not exist.
 */
export async function backdateWalletPresentationSignal(
  app: FastifyInstance,
  handle: string,
  byMs: number
): Promise<void> {
  const flow = await readWalletFlowRecord(app, handle);
  const key = WALLET_SIGNAL_SESSION_KEY(flow.stateHash);

  const record = await app.sessionUtils.getSession<Record<string, unknown>>(key);
  if (record === null) {
    throw new Error('no wallet presentation signal has been published for the flow');
  }
  if (typeof record['at'] !== 'number') throw new Error('the signal record carries no timestamp');

  await app.sessionUtils.setSession(
    key,
    { ...record, at: record['at'] - byMs },
    Math.floor(WALLET_LOGIN_FLOW_TTL_MS / 1000)
  );
}

/**
 * The five entities `helpers/html.ts` escapes, reversed — for asserting page
 * COPY (an apostrophe renders as `&#39;`) rather than wire bytes.
 *
 * `&amp;` is decoded LAST, and that order is load-bearing: decoding it first
 * would turn an escaped `&amp;lt;` into `&lt;` and then into `<`, unescaping a
 * literal the page had deliberately escaped (CodeQL `js/double-escaping`).
 */
export function decodeHtmlEntities(value: string): string {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}

/**
 * A page with its per-request CSP nonces blanked, for byte-comparing two
 * renders of what must be ONE refusal page (#405).
 *
 * Every server-rendered page here carries `nonce="…"` on its `<style>` and
 * `<script>`, minted per request; two renders of the same page therefore
 * differ in exactly those values and nothing else. Comparing with the nonces
 * blanked is the strongest statement the wire allows: identical markup,
 * identical copy, identical links.
 */
export function withoutNonces(html: string): string {
  return html.replace(/nonce="[^"]*"/g, 'nonce=""');
}

/** A PKCE pair, S256 — the only method QAuth accepts. */
export function pkcePair(): { readonly verifier: string; readonly challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  return {
    verifier,
    challenge: createHash('sha256').update(verifier).digest('base64url'),
  };
}

/** Decode a JWT payload without verifying — for asserting CLAIMS, never trust. */
export function decodeJwtClaims(token: string): Record<string, unknown> {
  const payload = token.split('.')[1];
  if (payload === undefined) throw new Error('not a compact JWS');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
}
