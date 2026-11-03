import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import { type CryptoKey, generateKeyPair, type JWTPayload, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { verifyIdTokenHint } from './id-token-hint';
import { signIdToken } from './jwt-service';

const ISSUER = 'https://auth.example.com';
const NOW = () => Math.floor(Date.now() / 1000);

interface Pair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

let ed: Pair;
let otherEd: Pair;
let rsa: Pair;

beforeAll(async () => {
  ed = await generateKeyPair('EdDSA');
  otherEd = await generateKeyPair('EdDSA');
  rsa = await generateKeyPair('RS256');
});

/** Sign a token by hand, so each test controls the header and every claim. */
function token(
  privateKey: CryptoKey,
  claims: JWTPayload,
  header: { alg?: string; typ?: string | null } = {}
): Promise<string> {
  const { alg = 'EdDSA', typ = 'JWT' } = header;
  return new SignJWT(claims)
    .setProtectedHeader({ alg, ...(typ === null ? {} : { typ }) })
    .sign(privateKey);
}

function idClaims(overrides: JWTPayload = {}): JWTPayload {
  const now = NOW();
  return { iss: ISSUER, sub: 'user-1', aud: 'client-1', iat: now, exp: now + 900, ...overrides };
}

function expiredClaims(overrides: JWTPayload = {}): JWTPayload {
  const now = NOW();
  return idClaims({ iat: now - 3600, exp: now - 1800, ...overrides });
}

async function refused(promise: Promise<unknown>): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught
  );
  expect(error).toBeInstanceOf(JWTInvalidError);
  expect(error).not.toBeInstanceOf(JWTExpiredError);
}

describe('verifyIdTokenHint (#675)', () => {
  it('accepts an EdDSA ID token this issuer signed', async () => {
    const idToken = await signIdToken(
      { sub: 'user-1', audience: 'client-1', sid: 'session-1' },
      ed.privateKey,
      ISSUER,
      900
    );
    const hint = await verifyIdTokenHint(idToken, ed.publicKey, { issuer: ISSUER });
    expect(hint).toMatchObject({
      sub: 'user-1',
      aud: ['client-1'],
      sid: 'session-1',
      expired: false,
    });
    expect(typeof hint.iat).toBe('number');
    expect(typeof hint.exp).toBe('number');
  });

  it('accepts an RS256 ID token this issuer signed', async () => {
    const idToken = await signIdToken(
      { sub: 'user-1', audience: 'client-1' },
      rsa.privateKey,
      ISSUER,
      900,
      'RS256'
    );
    const hint = await verifyIdTokenHint(idToken, rsa.publicKey, { issuer: ISSUER });
    expect(hint).toMatchObject({ sub: 'user-1', aud: ['client-1'], expired: false });
    expect(hint.sid).toBeUndefined();
  });

  it('accepts an expired ID token with expired: true', async () => {
    const claims = expiredClaims({ sid: 'session-1' });
    const hint = await verifyIdTokenHint(await token(ed.privateKey, claims), ed.publicKey, {
      issuer: ISSUER,
    });
    expect(hint).toEqual({
      sub: 'user-1',
      aud: ['client-1'],
      sid: 'session-1',
      iat: claims.iat,
      exp: claims.exp,
      expired: true,
    });
  });

  it('accepts an expired RS256 ID token', async () => {
    const hint = await verifyIdTokenHint(
      await token(rsa.privateKey, expiredClaims(), { alg: 'RS256' }),
      rsa.publicKey,
      { issuer: ISSUER }
    );
    expect(hint.expired).toBe(true);
  });

  it('refuses another issuer, expired or not', async () => {
    for (const claims of [
      idClaims({ iss: 'https://evil.example.com' }),
      expiredClaims({ iss: 'https://evil.example.com' }),
      idClaims({ iss: undefined }),
      expiredClaims({ iss: undefined }),
    ]) {
      await refused(
        verifyIdTokenHint(await token(ed.privateKey, claims), ed.publicKey, { issuer: ISSUER })
      );
    }
  });

  it('refuses a signature another key made, expired or not', async () => {
    for (const claims of [idClaims(), expiredClaims()]) {
      await refused(
        verifyIdTokenHint(await token(otherEd.privateKey, claims), ed.publicKey, {
          issuer: ISSUER,
        })
      );
    }
  });

  it('refuses a tampered payload, expired or not', async () => {
    for (const claims of [idClaims(), expiredClaims()]) {
      const [header, , signature] = (await token(ed.privateKey, claims)).split('.');
      const forged = Buffer.from(JSON.stringify({ ...claims, sub: 'admin' })).toString('base64url');
      await refused(
        verifyIdTokenHint(`${header}.${forged}.${signature}`, ed.publicKey, { issuer: ISSUER })
      );
    }
  });

  it('refuses alg none and HS256', async () => {
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = `${encode({ alg: 'none', typ: 'JWT' })}.${encode(expiredClaims())}.`;
    await refused(verifyIdTokenHint(unsigned, ed.publicKey, { issuer: ISSUER }));

    const secret = new TextEncoder().encode('a-shared-secret-of-at-least-32-bytes!');
    const hs256 = await new SignJWT(idClaims())
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .sign(secret);
    await refused(verifyIdTokenHint(hs256, ed.publicKey, { issuer: ISSUER }));
  });

  it('refuses an algorithm the options narrow away', async () => {
    const rs = await token(rsa.privateKey, idClaims(), { alg: 'RS256' });
    await refused(verifyIdTokenHint(rs, rsa.publicKey, { issuer: ISSUER, algorithms: ['EdDSA'] }));
    await refused(verifyIdTokenHint(rs, rsa.publicKey, { issuer: ISSUER, algorithms: [] }));
  });

  it('refuses a token whose typ is not JWT, expired or not', async () => {
    for (const typ of ['at+jwt', 'oauth-id-jag+jwt', 'logout+jwt', 'jwt', null]) {
      for (const claims of [idClaims(), expiredClaims()]) {
        await refused(
          verifyIdTokenHint(await token(ed.privateKey, claims, { typ }), ed.publicKey, {
            issuer: ISSUER,
          })
        );
      }
    }
  });

  it('refuses a token not yet valid', async () => {
    await refused(
      verifyIdTokenHint(await token(ed.privateKey, idClaims({ nbf: NOW() + 3600 })), ed.publicKey, {
        issuer: ISSUER,
      })
    );
  });

  it('refuses malformed claims, expired or not', async () => {
    const malformed: JWTPayload[] = [
      { sub: undefined },
      { sub: '' },
      { sub: 42 as unknown as string },
      { aud: undefined },
      { aud: '' },
      { aud: [] },
      { aud: ['client-1', ''] },
      { aud: [7] as unknown as string[] },
      { sid: 9 },
      { iat: 'yesterday' as unknown as number },
    ];
    for (const overrides of malformed) {
      for (const claims of [idClaims(overrides), expiredClaims(overrides)]) {
        await refused(
          verifyIdTokenHint(await token(ed.privateKey, claims), ed.publicKey, { issuer: ISSUER })
        );
      }
    }
  });

  it('reads aud as a list', async () => {
    const single = await verifyIdTokenHint(
      await token(ed.privateKey, idClaims({ aud: 'client-1' })),
      ed.publicKey,
      { issuer: ISSUER }
    );
    expect(single.aud).toEqual(['client-1']);
    const many = await verifyIdTokenHint(
      await token(ed.privateKey, idClaims({ aud: ['client-1', 'client-2'] })),
      ed.publicKey,
      { issuer: ISSUER }
    );
    expect(many.aud).toEqual(['client-1', 'client-2']);
  });

  it('returns sid only when the token carries one', async () => {
    const withSid = await verifyIdTokenHint(
      await token(ed.privateKey, idClaims({ sid: 'session-9' })),
      ed.publicKey,
      { issuer: ISSUER }
    );
    expect(withSid.sid).toBe('session-9');
    const withoutSid = await verifyIdTokenHint(
      await token(ed.privateKey, idClaims()),
      ed.publicKey,
      { issuer: ISSUER }
    );
    expect('sid' in withoutSid).toBe(false);
  });

  it('refuses a token that is not a JWT', async () => {
    await refused(verifyIdTokenHint('not-a-jwt', ed.publicKey, { issuer: ISSUER }));
  });
});
