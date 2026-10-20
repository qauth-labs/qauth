import { createLocalJWKSet, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { peekHeader, remoteKeySet, verifyJwt } from './jwt';
import { type LocalServer, startLocalServer } from './local-server';

const ISSUER = 'http://localhost:3000';

let publicJwk: JWK;
let privateKey: CryptoKey;
let otherPrivateKey: CryptoKey;
let jwksServer: LocalServer;
let jwksRequests = 0;

beforeAll(async () => {
  const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  privateKey = pair.privateKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'EdDSA', use: 'sig' };
  otherPrivateKey = (await generateKeyPair('EdDSA', { crv: 'Ed25519' })).privateKey;

  jwksServer = await startLocalServer((_request, response) => {
    jwksRequests++;
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ keys: [publicJwk] }));
  });
});

afterAll(async () => {
  await jwksServer.close();
});

function sign(
  claims: Record<string, unknown>,
  options: { key?: CryptoKey; kid?: string; typ?: string } = {}
) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA', kid: options.kid ?? 'k1', typ: options.typ ?? 'at+jwt' })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(options.key ?? privateKey);
}

describe('verifyJwt', () => {
  const localSet = () => createLocalJWKSet({ keys: [publicJwk] });

  it('returns the header and claims of a token signed by a published key', async () => {
    const token = await sign({ iss: ISSUER, aud: 'wire', sub: 'client-1' });
    const { header, payload } = await verifyJwt(token, localSet(), {
      issuer: ISSUER,
      audience: 'wire',
      typ: 'at+jwt',
    });

    expect(header).toMatchObject({ alg: 'EdDSA', kid: 'k1' });
    expect(payload).toMatchObject({ iss: ISSUER, sub: 'client-1' });
  });

  it.each([
    [
      'a token signed by a key the set does not publish',
      () => sign({ iss: ISSUER, aud: 'wire' }, { key: otherPrivateKey }),
    ],
    ['another issuer', () => sign({ iss: 'http://localhost:3001', aud: 'wire' })],
    ['another audience', () => sign({ iss: ISSUER, aud: 'someone-else' })],
    ['another typ', () => sign({ iss: ISSUER, aud: 'wire' }, { typ: 'JWT' })],
  ])('refuses %s', async (_label, makeToken) => {
    await expect(
      verifyJwt(await makeToken(), localSet(), { issuer: ISSUER, audience: 'wire', typ: 'at+jwt' })
    ).rejects.toThrow();
  });

  it('refuses an expired token', async () => {
    const token = await new SignJWT({ iss: ISSUER })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'k1' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 300)
      .sign(privateKey);

    await expect(verifyJwt(token, localSet(), { issuer: ISSUER })).rejects.toThrow(/exp/);
  });
});

describe('remoteKeySet', () => {
  it('fetches the key set over HTTP and verifies against it', async () => {
    const before = jwksRequests;
    const keySet = remoteKeySet(`${jwksServer.url}/.well-known/jwks.json`);
    const token = await sign({ iss: ISSUER });

    await expect(verifyJwt(token, keySet, { issuer: ISSUER })).resolves.toBeDefined();
    expect(jwksRequests).toBeGreaterThan(before);
  });

  it('returns the same key set for the same URI', () => {
    const uri = `${jwksServer.url}/same`;
    expect(remoteKeySet(uri)).toBe(remoteKeySet(uri));
  });
});

describe('peekHeader', () => {
  it('reads the protected header without verifying', async () => {
    const token = await sign({ iss: ISSUER }, { key: otherPrivateKey, kid: 'unknown' });
    expect(peekHeader(token)).toMatchObject({ alg: 'EdDSA', kid: 'unknown' });
  });
});
