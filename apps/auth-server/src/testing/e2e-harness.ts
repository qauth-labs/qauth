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

/** Pull the wallet invocation URI out of the rendered pending page. */
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

/**
 * The five entities `helpers/html.ts` escapes, reversed.
 *
 * `&amp;` is decoded LAST, and that order is load-bearing: decoding it first
 * would turn an escaped `&amp;lt;` into `&lt;` and then into `<`, unescaping a
 * literal the page had deliberately escaped (CodeQL `js/double-escaping`).
 */
function decodeHtmlEntities(value: string): string {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
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
