import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AUTHORIZATION_CODE_TTL_MS } from '../constants';
import {
  type AuthorizationCodeGrant,
  type AuthorizationCodeTransaction,
  isMintableCodeChallenge,
  mintAuthorizationCode,
  PkceChallengeRequiredError,
} from './authorization-code';

type CodeRepository = FastifyInstance['repositories']['authorizationCodes'];
type CreateCode = CodeRepository['create'];

/** The RFC 7636 Appendix B challenge: 43 characters of base64url. */
const S256_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

const GRANT: AuthorizationCodeGrant = {
  oauthClientId: 'client-row-1',
  userId: 'user-1',
  redirectUri: 'https://app.example.com/callback',
  codeChallenge: S256_CHALLENGE,
  codeChallengeMethod: 'S256',
  scopes: ['openid', 'email'],
  resource: ['https://api.example.com'],
  nonce: 'n-0S6_WzA2Mj',
  state: 'af0ifjsldkj',
  authTime: 1_700_000_000_000,
  assuranceLevel: null,
  sessionExpiresAt: 1_700_086_400_000,
  dpopJkt: null,
};

/** A pg unique violation, wrapped the way drizzle-orm wraps driver errors. */
function uniqueViolation(): Error {
  return Object.assign(new Error('Failed query'), {
    cause: Object.assign(new Error('duplicate key'), {
      code: '23505',
      constraint: 'authorization_codes_code_unique',
    }),
  });
}

function stub(create: CreateCode = vi.fn<CreateCode>(async (row) => row as never)) {
  const fastify = {
    repositories: { authorizationCodes: { create } as unknown as CodeRepository },
  } as Pick<FastifyInstance, 'repositories'>;
  return { fastify, create: vi.mocked(create) };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('mintAuthorizationCode (ADR-017 Decision 10)', () => {
  it('writes a 32-byte base64url code that binds the whole grant and lives AUTHORIZATION_CODE_TTL_MS', async () => {
    vi.useFakeTimers({ now: 1_800_000_000_000, toFake: ['Date'] });
    const { fastify, create } = stub();

    const code = await mintAuthorizationCode(fastify, GRANT);

    expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(create).toHaveBeenCalledOnce();
    expect(create.mock.calls[0]).toEqual([
      {
        ...GRANT,
        code,
        codeChallengeMethod: 'S256',
        expiresAt: 1_800_000_000_000 + AUTHORIZATION_CODE_TTL_MS,
      },
    ]);
  });

  it('accepts a 128-character challenge of every unreserved character (RFC 7636 §4.2)', async () => {
    const { fastify, create } = stub();
    const challenge = `${'A'.repeat(124)}-._~`;

    await mintAuthorizationCode(fastify, { ...GRANT, codeChallenge: challenge });

    expect(create.mock.calls[0][0]).toMatchObject({ codeChallenge: challenge });
  });

  it.each([
    ['a missing challenge', { codeChallenge: '' }],
    ['an undefined challenge', { codeChallenge: undefined as unknown as string }],
    ['a 42-character challenge', { codeChallenge: S256_CHALLENGE.slice(0, 42) }],
    ['a 129-character challenge', { codeChallenge: 'A'.repeat(129) }],
    ['a challenge outside the unreserved set', { codeChallenge: `${'A'.repeat(42)}=` }],
    ['a challenge with whitespace', { codeChallenge: `${'A'.repeat(42)} ` }],
    ['the plain method', { codeChallengeMethod: 'plain' }],
    ['a lower-case method', { codeChallengeMethod: 's256' }],
    ['a missing method', { codeChallengeMethod: '' }],
  ])('refuses %s and writes nothing', async (_label, override) => {
    const { fastify, create } = stub();

    await expect(mintAuthorizationCode(fastify, { ...GRANT, ...override })).rejects.toBeInstanceOf(
      PkceChallengeRequiredError
    );
    expect(create).not.toHaveBeenCalled();
  });

  it('writes in the caller’s transaction under a savepoint', async () => {
    const { fastify, create } = stub();
    const savepoint = { savepoint: true } as unknown as AuthorizationCodeTransaction;
    const tx = {
      transaction: vi.fn(async (run: (inner: unknown) => Promise<unknown>) => run(savepoint)),
    } as unknown as AuthorizationCodeTransaction;

    await mintAuthorizationCode(fastify, GRANT, tx);

    expect(tx.transaction).toHaveBeenCalledOnce();
    expect(create.mock.calls[0][1]).toBe(savepoint);
  });

  it('retries a code collision with a fresh code', async () => {
    const create = vi
      .fn<CreateCode>()
      .mockRejectedValueOnce(uniqueViolation())
      .mockImplementation(async (row) => row as never);
    const { fastify } = stub(create);

    const code = await mintAuthorizationCode(fastify, GRANT);

    expect(create).toHaveBeenCalledTimes(2);
    const [first, second] = create.mock.calls.map(([row]) => row.code);
    expect(first).not.toBe(second);
    expect(code).toBe(second);
  });

  it('gives up after three collisions', async () => {
    const create = vi.fn<CreateCode>().mockRejectedValue(uniqueViolation());
    const { fastify } = stub(create);

    await expect(mintAuthorizationCode(fastify, GRANT)).rejects.toThrow('Failed query');
    expect(create).toHaveBeenCalledTimes(3);
  });

  it('does not retry any other failure', async () => {
    const create = vi.fn<CreateCode>().mockRejectedValue(new Error('connection lost'));
    const { fastify } = stub(create);

    await expect(mintAuthorizationCode(fastify, GRANT)).rejects.toThrow('connection lost');
    expect(create).toHaveBeenCalledOnce();
  });
});

describe('isMintableCodeChallenge', () => {
  it('holds for S256 only, in every environment: there is no policy argument', () => {
    expect(isMintableCodeChallenge(S256_CHALLENGE, 'S256')).toBe(true);
    expect(isMintableCodeChallenge(S256_CHALLENGE, 'plain')).toBe(false);
    expect(isMintableCodeChallenge(null, 'S256')).toBe(false);
    expect(isMintableCodeChallenge(42, 'S256')).toBe(false);
  });
});
