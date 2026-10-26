import { type CryptoKey, SignJWT } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createExpiringRedis,
  createFakeIdJagIssuer,
  type ExpiringRedis,
  type FakeIdJagIssuer,
  strangerKey,
} from '../../testing/fake-id-jag-issuer';

/**
 * How often an ID-JAG issuer is dialled (#433), end to end: assertions go
 * through `validateIdJagAssertion` with the REAL key resolver, against a fake
 * issuer that counts every discovery and JWKS fetch, over a Redis whose expiry
 * runs on a clock the test moves.
 *
 * The acceptance criteria, one block each:
 *  - N assertions with unknown `kid` values inside the cooldown cause at most
 *    one refresh;
 *  - while an issuer is unreachable, at most one attempt per negative-cache
 *    window;
 *  - a rotated key is still picked up after the cooldown.
 * Each also holds for requests that arrive together, against an issuer that
 * hangs until its fetch timeout rather than failing at once.
 * The TTL ceiling is a config rule, tested with the schema
 * (`libs/server/config`).
 */

const { ENV, ssrfSafeGet } = vi.hoisted(() => ({
  ENV: {
    ID_JAG_ENABLED: true,
    ID_JAG_TRUSTED_ISSUERS: [] as string[],
    ID_JAG_FETCH_TIMEOUT_MS: 5000,
    ID_JAG_JWKS_CACHE_TTL: 300,
    ID_JAG_JWKS_REFRESH_COOLDOWN: 30,
    ID_JAG_JWKS_NEGATIVE_CACHE_TTL: 30,
    ID_JAG_MAX_DOCUMENT_BYTES: 65536,
    ID_JAG_ALLOW_PRIVATE_ADDRESSES: false,
    ID_JAG_CLOCK_SKEW_LEEWAY: 60,
    ID_JAG_MAX_ASSERTION_LIFETIME: 300,
  },
  ssrfSafeGet: vi.fn(),
}));

vi.mock('../../config/env', () => ({ env: ENV }));

vi.mock('./ssrf-safe-fetch', async () => {
  const actual = await vi.importActual<typeof import('./ssrf-safe-fetch')>('./ssrf-safe-fetch');
  return { ...actual, ssrfSafeGet };
});

import { ID_JAG_TYP, IdJagValidationError, validateIdJagAssertion } from './id-jag';

const AS_ISSUER = 'https://auth.example.com';
const CLIENT_ID = 'mcp-client-1';
const MCP_SERVER = 'https://mcp.example.com/';

let idp: FakeIdJagIssuer;
let redis: ExpiringRedis;
/**
 * One server instance for every request of a test, as the token route passes
 * its own instance on each request: fetches in flight are shared per instance.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let fastify: any;
let jtiCounter = 0;

beforeEach(async () => {
  idp = await createFakeIdJagIssuer();
  redis = createExpiringRedis();
  fastify = {
    redis,
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  ssrfSafeGet.mockReset();
  ssrfSafeGet.mockImplementation((url: string) => idp.fetch(url));
  ENV.ID_JAG_TRUSTED_ISSUERS = [idp.issuer];
  ENV.ID_JAG_JWKS_CACHE_TTL = 300;
  ENV.ID_JAG_JWKS_REFRESH_COOLDOWN = 30;
  ENV.ID_JAG_JWKS_NEGATIVE_CACHE_TTL = 30;
});

/** An ID-JAG for this AS, signed by `signer` and naming its `kid`. */
async function assertion(signer: { kid: string; privateKey: CryptoKey }): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    jti: `refresh-jti-${++jtiCounter}`,
    iss: idp.issuer,
    sub: 'U019488227',
    aud: AS_ISSUER,
    client_id: CLIENT_ID,
    resource: MCP_SERVER,
    iat: now,
    exp: now + 120,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: ID_JAG_TYP, kid: signer.kid })
    .sign(signer.privateKey);
}

/** Validate one assertion; the IdJagValidationError reason, or `'accepted'`. */
async function present(signer: { kid: string; privateKey: CryptoKey }): Promise<string> {
  try {
    await validateIdJagAssertion(
      fastify,
      { issuer: AS_ISSUER },
      {
        assertion: await assertion(signer),
        expectedClientId: CLIENT_ID,
      }
    );
    return 'accepted';
  } catch (err) {
    if (err instanceof IdJagValidationError) return err.reason;
    throw err;
  }
}

/**
 * Present `count` assertions at once while the issuer hangs, and release it
 * only once every request is waiting on it, so none can have missed the fetch
 * that is in flight.
 */
async function presentTogetherWhileHanging(
  count: number,
  signer: () => Promise<{ kid: string; privateKey: CryptoKey }>
): Promise<string[]> {
  const signers = await Promise.all(Array.from({ length: count }, signer));
  idp.hang();
  const outcomes = Promise.all(signers.map((s) => present(s)));
  // Every request reads the discovery cache before it reaches the fetch.
  await vi.waitFor(() => {
    const reads = redis.get.mock.calls.filter(([key]) => key.startsWith('id-jag:discovery:'));
    expect(reads.length).toBeGreaterThanOrEqual(count);
  });
  await new Promise((resolve) => setImmediate(resolve));
  idp.release();
  return outcomes;
}

/** The issuer's current key, as a signer. */
function issuerKey() {
  return { kid: idp.kid, privateKey: idp.privateKey };
}

describe('refresh cooldown — unknown `kid` values', () => {
  it('N assertions with unknown kids inside the cooldown cause one refresh', async () => {
    expect(await present(issuerKey())).toBe('accepted');
    idp.resetFetches();

    for (let i = 0; i < 25; i += 1) {
      expect(await present(await strangerKey())).toBe('unresolvable_key');
    }

    // One refresh: one discovery and one JWKS fetch, for 25 forced retries.
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 1 });
  });

  it('holds when the N assertions arrive at once', async () => {
    expect(await present(issuerKey())).toBe('accepted');
    idp.resetFetches();

    const strangers = await Promise.all(Array.from({ length: 25 }, () => strangerKey()));
    const outcomes = await Promise.all(strangers.map((signer) => present(signer)));

    expect(new Set(outcomes)).toEqual(new Set(['unresolvable_key']));
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 1 });
  });

  it('allows one more refresh once the cooldown has passed', async () => {
    expect(await present(issuerKey())).toBe('accepted');
    idp.resetFetches();

    expect(await present(await strangerKey())).toBe('unresolvable_key');
    redis.advance(29);
    expect(await present(await strangerKey())).toBe('unresolvable_key');
    expect(idp.totalFetches()).toBe(2);

    redis.advance(1);
    expect(await present(await strangerKey())).toBe('unresolvable_key');
    expect(idp.fetches).toEqual({ discovery: 2, jwks: 2 });
  });

  it('keeps verifying the cached key while the cooldown is held', async () => {
    expect(await present(issuerKey())).toBe('accepted');
    expect(await present(await strangerKey())).toBe('unresolvable_key');
    idp.resetFetches();

    expect(await present(issuerKey())).toBe('accepted');
    expect(idp.totalFetches()).toBe(0);
  });
});

describe('refresh cooldown — key rotation', () => {
  it('picks up a rotated key at once when no refresh is in its cooldown', async () => {
    expect(await present(issuerKey())).toBe('accepted');
    await idp.rotate();
    idp.resetFetches();

    expect(await present(issuerKey())).toBe('accepted');
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 1 });
  });

  it('picks up a rotated key after the cooldown when forged kids spent it', async () => {
    expect(await present(issuerKey())).toBe('accepted');
    // A forged kid spends the cooldown; the issuer then rotates inside it.
    expect(await present(await strangerKey())).toBe('unresolvable_key');
    await idp.rotate();
    idp.resetFetches();

    // Inside the cooldown the new kid is refused like any unknown kid, unfetched.
    expect(await present(issuerKey())).toBe('unresolvable_key');
    expect(idp.totalFetches()).toBe(0);

    // The cache TTL (300 s) is far off: the cooldown alone lets the refresh run.
    redis.advance(30);
    expect(await present(issuerKey())).toBe('accepted');
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 1 });

    // The refreshed key set is cached: the next assertion costs nothing.
    expect(await present(issuerKey())).toBe('accepted');
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 1 });
  });

  it('stops accepting the withdrawn key once the refreshed set is cached', async () => {
    const withdrawn = issuerKey();
    expect(await present(withdrawn)).toBe('accepted');
    await idp.rotate();
    expect(await present(issuerKey())).toBe('accepted');

    expect(await present(withdrawn)).toBe('unresolvable_key');
  });
});

describe('concurrent cache misses', () => {
  it('share one fetch of each document and all succeed', async () => {
    const outcomes = await presentTogetherWhileHanging(25, async () => issuerKey());

    expect(new Set(outcomes)).toEqual(new Set(['accepted']));
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 1 });
  });
});

describe('negative cache — an unreachable issuer', () => {
  it('costs one attempt per window, not two fetches per request', async () => {
    idp.goDown();

    for (let i = 0; i < 10; i += 1) {
      expect(await present(issuerKey())).toBe('unresolvable_key');
    }
    // The first request's discovery fetch fails; its forced retry and the next
    // nine requests fetch nothing.
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 0 });

    redis.advance(29);
    expect(await present(issuerKey())).toBe('unresolvable_key');
    expect(idp.totalFetches()).toBe(1);

    redis.advance(1);
    expect(await present(issuerKey())).toBe('unresolvable_key');
    expect(idp.fetches).toEqual({ discovery: 2, jwks: 0 });
  });

  it('counts a failing JWKS endpoint the same way', async () => {
    idp.goDown(['jwks']);

    for (let i = 0; i < 10; i += 1) {
      expect(await present(issuerKey())).toBe('unresolvable_key');
    }
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 1 });

    // Discovery succeeded and is cached, so the next window's attempt is the
    // JWKS fetch alone.
    redis.advance(30);
    expect(await present(issuerKey())).toBe('unresolvable_key');
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 2 });
  });

  it('serves the issuer again once the window has lapsed', async () => {
    idp.goDown();
    expect(await present(issuerKey())).toBe('unresolvable_key');
    idp.comeBack();

    // Remembered until the window lapses, then the first request succeeds.
    expect(await present(issuerKey())).toBe('unresolvable_key');
    redis.advance(30);
    expect(await present(issuerKey())).toBe('accepted');
  });

  it('costs one attempt when the requests arrive together and the issuer hangs', async () => {
    idp.goDown();

    const outcomes = await presentTogetherWhileHanging(25, async () => issuerKey());

    expect(new Set(outcomes)).toEqual(new Set(['unresolvable_key']));
    expect(idp.fetches).toEqual({ discovery: 1, jwks: 0 });

    expect(await present(issuerKey())).toBe('unresolvable_key');
    expect(idp.totalFetches()).toBe(1);
  });

  it('keeps verifying a cached key through the outage', async () => {
    expect(await present(issuerKey())).toBe('accepted');
    idp.goDown();
    // A forged kid drives a refresh into the outage: it fails and is remembered.
    expect(await present(await strangerKey())).toBe('unresolvable_key');
    idp.resetFetches();

    expect(await present(issuerKey())).toBe('accepted');
    expect(idp.totalFetches()).toBe(0);
  });
});
