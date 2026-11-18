import { generateSigningKeyPair, type SigningKey } from '@qauth-labs/core-crypto';
import { exportJWK, type JWK, SignJWT } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const { egressGet } = vi.hoisted(() => ({ egressGet: vi.fn() }));

vi.mock('./egress-get', () => ({ egressGet }));

import { createExpiringRedis } from '../../testing/fake-id-jag-issuer';
import { REDIS_KEYS } from '../constants/redis-keys';
import type { AllowlistedIssuerKeyResolver } from './allowlisted-issuer-keys';
import {
  matchWorkloadEntry,
  validateWorkloadToken,
  WORKLOAD_TOKEN_MAX_AGE_SECONDS,
  type WorkloadIssuerEntry,
  workloadSubjectMatches,
  WorkloadTokenError,
} from './workload-token';

const ISSUER = 'https://ci.example.com';
const AUDIENCE = 'https://auth.example.com';
const SUBJECT = 'repo:acme/infra:ref:refs/heads/main';
const REALM = 'master';

const ENTRY: WorkloadIssuerEntry = {
  issuer: ISSUER,
  audience: AUDIENCE,
  subject: SUBJECT,
  serviceAccount: 'ci-realm-import',
};

let signingKey: SigningKey;
let verificationKey: SigningKey;
let publicJwk: JWK;

beforeAll(async () => {
  const pair = await generateSigningKeyPair('EdDSA', { extractable: true });
  signingKey = pair.privateKey;
  verificationKey = pair.publicKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: 'ci-1' };
});

/** A resolver that knows the one test key, for `ISSUER` alone, as the shared one would answer. */
const resolver: AllowlistedIssuerKeyResolver = vi.fn(async (request) =>
  request.issuer === ISSUER ? { key: verificationKey, identifier: ISSUER } : undefined
);

/** A workload token of `ISSUER`, with `claims` over the defaults; `null` drops a claim. */
async function workloadToken(
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: ISSUER,
    sub: SUBJECT,
    aud: AUDIENCE,
    iat: now,
    exp: now + 300,
    jti: crypto.randomUUID(),
    repository: 'acme/infra',
    ...claims,
  };
  for (const [name, value] of Object.entries(payload)) if (value === null) delete payload[name];
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'ci-1', ...header })
    .sign(signingKey);
}

function fastifyStub() {
  const redis = createExpiringRedis();
  return {
    redis,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fastify: {
      redis,
      log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    } as any,
  };
}

async function refusal(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof WorkloadTokenError) return err.reason;
    throw err;
  }
  throw new Error('the token was accepted');
}

beforeEach(() => {
  egressGet.mockReset();
  vi.mocked(resolver).mockClear();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('validateWorkloadToken (#526)', () => {
  it('accepts a token of a listed issuer, audience and subject, and names the service account', async () => {
    const { fastify, redis } = fastifyStub();
    const token = await workloadToken({ jti: 'run-1' });

    const validated = await validateWorkloadToken(fastify, {
      token,
      entries: [ENTRY],
      realm: REALM,
      resolver,
    });

    expect(validated).toMatchObject({
      issuer: ISSUER,
      subject: SUBJECT,
      audience: AUDIENCE,
      serviceAccount: 'ci-realm-import',
      jti: 'run-1',
    });
    expect(redis.set).toHaveBeenCalledWith(
      REDIS_KEYS.WORKLOAD_JTI(ISSUER, 'run-1'),
      '1',
      'EX',
      WORKLOAD_TOKEN_MAX_AGE_SECONDS + 60,
      'NX'
    );
  });

  it('refuses an issuer the policy does not list, before any key is looked up', async () => {
    const { fastify } = fastifyStub();
    const token = await workloadToken({ iss: 'https://other-ci.example.com' });

    expect(
      await refusal(
        validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
      )
    ).toBe('issuer_not_listed');
    expect(resolver).not.toHaveBeenCalled();
  });

  it('matches the issuer exactly: no trailing slash, case or path is forgiven', async () => {
    const { fastify } = fastifyStub();
    for (const iss of [`${ISSUER}/`, 'https://CI.example.com', `${ISSUER}/oidc`]) {
      const token = await workloadToken({ iss });
      expect(
        await refusal(
          validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
        ),
        iss
      ).toBe('issuer_not_listed');
    }
  });

  it('fetches nothing for an unlisted issuer with the real resolver', async () => {
    const { fastify } = fastifyStub();
    const token = await workloadToken({ iss: 'https://other-ci.example.com' });

    await refusal(validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM }));
    await refusal(validateWorkloadToken(fastify, { token, entries: [], realm: REALM }));
    expect(egressGet).not.toHaveBeenCalled();
  });

  it('refuses a subject the entry does not name', async () => {
    const { fastify } = fastifyStub();
    for (const sub of [
      'repo:acme/infra:ref:refs/heads/feature',
      'repo:acme/infra:ref:refs/heads/main2',
      'repo:acme/infra:ref:refs/heads/mai',
    ]) {
      const token = await workloadToken({ sub });
      expect(
        await refusal(
          validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
        ),
        sub
      ).toBe('subject_not_listed');
    }
  });

  it('refuses a token whose aud does not hold the entry audience', async () => {
    const { fastify } = fastifyStub();
    for (const aud of ['https://other.example.com', ['https://a.example', 'https://b.example']]) {
      const token = await workloadToken({ aud });
      expect(
        await refusal(
          validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
        ),
        JSON.stringify(aud)
      ).toBe('audience_invalid');
    }
  });

  it('accepts an aud list that holds the entry audience', async () => {
    const { fastify } = fastifyStub();
    const token = await workloadToken({ aud: ['https://other.example.com', AUDIENCE] });
    await expect(
      validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
    ).resolves.toMatchObject({ audience: AUDIENCE });
  });

  it('refuses a token older than ten minutes since iat, even before its exp', async () => {
    const { fastify } = fastifyStub();
    const now = Math.floor(Date.now() / 1000);
    const token = await workloadToken({
      iat: now - WORKLOAD_TOKEN_MAX_AGE_SECONDS - 1,
      exp: now + 3600,
    });
    expect(
      await refusal(
        validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
      )
    ).toBe('too_old');
  });

  it('accepts a token ten minutes old', async () => {
    const { fastify } = fastifyStub();
    const now = Math.floor(Date.now() / 1000);
    const token = await workloadToken({ iat: now - WORKLOAD_TOKEN_MAX_AGE_SECONDS + 5 });
    await expect(
      validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
    ).resolves.toBeDefined();
  });

  it('refuses a token issued in the future, expired, or not yet valid', async () => {
    const { fastify } = fastifyStub();
    const now = Math.floor(Date.now() / 1000);
    const cases: [Record<string, unknown>, string][] = [
      [{ iat: now + 120, exp: now + 400 }, 'issued_in_future'],
      [{ iat: now - 200, exp: now - 100 }, 'signature_invalid'],
      [{ nbf: now + 300 }, 'signature_invalid'],
    ];
    for (const [claims, reason] of cases) {
      const token = await workloadToken(claims);
      expect(
        await refusal(
          validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
        ),
        JSON.stringify(claims)
      ).toBe(reason);
    }
  });

  it('refuses a token without iat, exp, sub or jti', async () => {
    const { fastify } = fastifyStub();
    for (const claim of ['iat', 'exp', 'sub', 'jti']) {
      const token = await workloadToken({ [claim]: null });
      expect(
        await refusal(
          validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
        ),
        claim
      ).toBe('claims_invalid');
    }
  });

  it('refuses a replayed jti, and burns it only once the token passed every other check', async () => {
    const { fastify, redis } = fastifyStub();
    const token = await workloadToken({ jti: 'run-7' });
    const options = { token, entries: [ENTRY], realm: REALM, resolver };

    await validateWorkloadToken(fastify, options);
    expect(await refusal(validateWorkloadToken(fastify, options))).toBe('replayed');

    const refused = await workloadToken({ jti: 'run-8', sub: 'repo:acme/other:ref:main' });
    await refusal(validateWorkloadToken(fastify, { ...options, token: refused }));
    expect(await redis.get(REDIS_KEYS.WORKLOAD_JTI(ISSUER, 'run-8'))).toBeNull();
  });

  it('refuses when the replay store is unreachable', async () => {
    const { fastify, redis } = fastifyStub();
    redis.set.mockRejectedValueOnce(new Error('down'));
    const token = await workloadToken();
    expect(
      await refusal(
        validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
      )
    ).toBe('replay_store_unavailable');
  });

  it('refuses a token signed by another key, an unsupported alg, or a typ of another token kind', async () => {
    const { fastify } = fastifyStub();
    const other = await generateSigningKeyPair('EdDSA');
    const forged = await new SignJWT({
      iss: ISSUER,
      sub: SUBJECT,
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60,
      jti: 'forged',
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'ci-1' })
      .sign(other.privateKey);
    expect(
      await refusal(
        validateWorkloadToken(fastify, { token: forged, entries: [ENTRY], realm: REALM, resolver })
      )
    ).toBe('signature_invalid');

    const hmac = await new SignJWT({ iss: ISSUER })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new Uint8Array(32));
    expect(
      await refusal(
        validateWorkloadToken(fastify, { token: hmac, entries: [ENTRY], realm: REALM, resolver })
      )
    ).toBe('unsupported_algorithm');

    for (const typ of ['at+jwt', 'oauth-id-jag+jwt']) {
      const token = await workloadToken({}, { typ });
      expect(
        await refusal(
          validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver })
        ),
        typ
      ).toBe('unsupported_typ');
    }
    expect(
      await refusal(
        validateWorkloadToken(fastify, {
          token: 'not-a-jwt',
          entries: [ENTRY],
          realm: REALM,
          resolver,
        })
      )
    ).toBe('malformed');
  });

  it('refuses a token whose key does not resolve, after one forced refresh', async () => {
    const { fastify } = fastifyStub();
    const none: AllowlistedIssuerKeyResolver = vi.fn(async () => undefined);
    const token = await workloadToken();
    expect(
      await refusal(
        validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM, resolver: none })
      )
    ).toBe('unresolvable_key');
    expect(none).toHaveBeenCalledTimes(2);
    expect(vi.mocked(none).mock.calls[1][0]).toMatchObject({ forceRefresh: true });
  });

  it('resolves keys through discovery as an admin destination of the realm', async () => {
    const { fastify } = fastifyStub();
    egressGet.mockImplementation(async (_fastify: unknown, url: string) => {
      if (url === `${ISSUER}/.well-known/openid-configuration`) {
        return {
          status: 200,
          headers: {},
          body: JSON.stringify({ issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` }),
        };
      }
      if (url === `${ISSUER}/jwks`) {
        return { status: 200, headers: {}, body: JSON.stringify({ keys: [publicJwk] }) };
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    const token = await workloadToken();

    await expect(
      validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM })
    ).resolves.toMatchObject({ serviceAccount: 'ci-realm-import' });
    expect(egressGet).toHaveBeenCalledWith(
      fastify,
      `${ISSUER}/.well-known/openid-configuration`,
      expect.objectContaining({ source: 'admin', realm: REALM, purpose: 'workload-discovery' })
    );
    expect(egressGet).toHaveBeenCalledWith(
      fastify,
      `${ISSUER}/jwks`,
      expect.objectContaining({ source: 'remote_document', purpose: 'workload-jwks' })
    );
  });

  it('refuses a discovery document that names another issuer', async () => {
    const { fastify } = fastifyStub();
    egressGet.mockResolvedValue({
      status: 200,
      headers: {},
      body: JSON.stringify({ issuer: `${ISSUER}/`, jwks_uri: `${ISSUER}/jwks` }),
    });
    const token = await workloadToken();
    expect(
      await refusal(validateWorkloadToken(fastify, { token, entries: [ENTRY], realm: REALM }))
    ).toBe('unresolvable_key');
  });
});

describe('workloadSubjectMatches (#526)', () => {
  it('matches a prefix subject only for subjects that start with the prefix', () => {
    const pattern = 'repo:acme/infra:*';
    expect(workloadSubjectMatches(pattern, 'repo:acme/infra:ref:refs/heads/main')).toBe(true);
    expect(workloadSubjectMatches(pattern, 'repo:acme/infra:environment:prod')).toBe(true);
    expect(workloadSubjectMatches(pattern, 'repo:acme/infra-evil:ref:refs/heads/main')).toBe(false);
    expect(workloadSubjectMatches(pattern, 'repo:acme/infr')).toBe(false);
    expect(workloadSubjectMatches(pattern, 'xrepo:acme/infra:ref:main')).toBe(false);
    expect(workloadSubjectMatches(pattern, 'REPO:acme/infra:ref:main')).toBe(false);
  });

  it('takes no other character as a wildcard', () => {
    expect(workloadSubjectMatches('repo:acme/?nfra', 'repo:acme/infra')).toBe(false);
    expect(workloadSubjectMatches('repo:acme/.*', 'repo:acme/infra')).toBe(false);
    expect(workloadSubjectMatches('repo:*:main', 'repo:acme:main')).toBe(false);
    expect(workloadSubjectMatches('repo:acme/infra', 'repo:acme/infra')).toBe(true);
    expect(workloadSubjectMatches('repo:acme/infra', 'repo:acme/infra:x')).toBe(false);
  });

  it('never lets a pattern of a star alone match', () => {
    expect(workloadSubjectMatches('*', 'anything')).toBe(false);
    expect(workloadSubjectMatches(':*', ':anything')).toBe(false);
  });

  it('matches by a prefix only when it ends at a separator, so a name that only starts alike is refused', () => {
    expect(workloadSubjectMatches('repo:acme*', 'repo:acme-evil/infra:ref:main')).toBe(false);
    expect(workloadSubjectMatches('repo:acme*', 'repo:acme')).toBe(false);
    expect(workloadSubjectMatches('repo:acme/*', 'repo:acme/infra:ref:main')).toBe(true);
    expect(workloadSubjectMatches('repo:acme:*', 'repo:acme:main')).toBe(true);
  });

  it('applies through validation: a prefix entry exchanges a subject under it and refuses the rest', async () => {
    const { fastify } = fastifyStub();
    const entries = [{ ...ENTRY, subject: 'repo:acme/infra:*' }];
    const inside = await workloadToken({ sub: 'repo:acme/infra:environment:prod' });
    await expect(
      validateWorkloadToken(fastify, { token: inside, entries, realm: REALM, resolver })
    ).resolves.toMatchObject({ subjectPattern: 'repo:acme/infra:*' });

    const outside = await workloadToken({ sub: 'repo:acme/infra-evil:environment:prod' });
    expect(
      await refusal(
        validateWorkloadToken(fastify, { token: outside, entries, realm: REALM, resolver })
      )
    ).toBe('subject_not_listed');
  });
});

describe('matchWorkloadEntry (#526)', () => {
  const claims = { iss: ISSUER, sub: SUBJECT, aud: [AUDIENCE] };

  it('prefers an exact subject over a prefix, and a longer prefix over a shorter', () => {
    const entries: WorkloadIssuerEntry[] = [
      { ...ENTRY, subject: 'repo:acme/*', serviceAccount: 'broad' },
      { ...ENTRY, subject: 'repo:acme/infra:*', serviceAccount: 'narrow' },
      { ...ENTRY, subject: SUBJECT, serviceAccount: 'exact' },
    ];
    expect(matchWorkloadEntry(entries, claims)).toMatchObject({
      entry: { serviceAccount: 'exact' },
    });
    expect(matchWorkloadEntry(entries.slice(0, 2), claims)).toMatchObject({
      entry: { serviceAccount: 'narrow' },
    });
  });

  it('refuses two equally specific entries that name different service accounts', () => {
    const entries: WorkloadIssuerEntry[] = [
      { ...ENTRY, serviceAccount: 'one' },
      { ...ENTRY, audience: 'https://second.example', serviceAccount: 'two' },
    ];
    expect(
      matchWorkloadEntry(entries, { ...claims, aud: [AUDIENCE, 'https://second.example'] })
    ).toEqual({ refusal: 'ambiguous_service_account' });
    expect(matchWorkloadEntry(entries, claims)).toMatchObject({
      entry: { serviceAccount: 'one' },
    });
  });

  it('names the first check a token fails: issuer, then audience, then subject', () => {
    expect(matchWorkloadEntry([], claims)).toEqual({ refusal: 'issuer_not_listed' });
    expect(matchWorkloadEntry([ENTRY], { ...claims, aud: ['x'], sub: 'y' })).toEqual({
      refusal: 'audience_invalid',
    });
    expect(matchWorkloadEntry([ENTRY], { ...claims, sub: 'y' })).toEqual({
      refusal: 'subject_not_listed',
    });
  });
});
