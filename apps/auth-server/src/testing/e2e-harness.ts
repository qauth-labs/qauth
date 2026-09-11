import { createHash, randomBytes } from 'node:crypto';

import {
  applyQauthMigrations,
  type StartedPostgres,
  type StartedRedis,
  startPostgresContainer,
  startRedisContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';

import { WALLET_LOGIN_FLOW_TTL_MS } from '../app/constants';
import { encodeQrCode, renderQrCodeSvg } from '../app/helpers/qr-code';

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
  /** The Fastify instance, ready for `.inject()`. */
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

/**
 * Truncate every domain table and flush Redis, through the SERVER's own
 * connections.
 *
 * Deliberately not a second pool: the app already holds the only clients this
 * needs, and opening another would mean a test could reset a database the
 * server is not looking at.
 */
export async function resetE2eState(app: FastifyInstance): Promise<void> {
  await app.dbPool.query(truncateDomainTablesStatement());
  await app.redis.flushall();
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
  EMAIL_PROVIDER: 'mock',
  EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
  EMAIL_BASE_URL: 'https://auth.example.com',
  DEFAULT_REALM_NAME: 'master',
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

/**
 * Boot the real auth-server under a given environment.
 *
 * Every variable NOT named in `environment` is cleared from `process.env` first,
 * so a deployment cannot inherit a previous test's configuration — which is the
 * failure mode that would make the fail-closed suite pass for the wrong reason.
 */
export async function bootAuthServer(
  environment: Record<string, string>
): Promise<BootedAuthServer> {
  const vitest = await import('vitest');

  for (const key of Object.keys(process.env)) {
    if (key.startsWith('OID4VP_') || key.startsWith('WALLET_') || key.startsWith('ACR_')) {
      delete process.env[key];
    }
  }
  for (const [key, value] of Object.entries(environment)) process.env[key] = value;

  // The app and its env module are re-imported per deployment; without this the
  // first import's parsed `env` would be reused for every later boot.
  vitest.vi.resetModules();

  const { app } = await import('../app/app');

  // Silent by default: these suites drive dozens of requests and every refusal
  // logs its reason. `E2E_DEBUG_LOG=1` turns the server's own log back on, which
  // is the only way to see WHY a uniform refusal was returned — the wire says
  // the same thing for every cause, by design.
  const server = Fastify({
    logger: process.env['E2E_DEBUG_LOG'] === '1',
    routerOptions: { ignoreTrailingSlash: true },
  });
  server.setValidatorCompiler(validatorCompiler);
  server.setSerializerCompiler(serializerCompiler);
  // `fp()` only lifts ENCAPSULATION: the same plugins register in the same order
  // and every route is identical, but `db`/`dbPool`/`redis` land on the root
  // instance instead of inside the app's own scope, which is what lets
  // `resetE2eState` truncate the database the server is actually looking at.
  // Nothing under test observes the difference.
  await server.register(fp(app));
  await server.ready();

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
