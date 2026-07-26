import { describe, expect, it } from 'vitest';

import { createStaticIssuerAllowlist, DENY_ALL_TRUST_REGISTRY } from '../trust/trust-registry';
import { createStatusListTrustAnchors } from './status-list-chain';
import { STATUS_LIST_TOKEN_TYP } from './status-list-spec';
import { verifyStatusListToken } from './status-list-token';
import { encodeStatusList, signStatusListToken } from './test/status-list-fixtures';
import { createTestCertificate } from './test/x509-fixtures';

const now = new Date('2026-07-26T12:00:00.000Z');
const nowSeconds = Math.floor(now.getTime() / 1000);
const valid = {
  notBefore: new Date('2026-07-01T00:00:00.000Z'),
  notAfter: new Date('2026-08-31T00:00:00.000Z'),
};

const root = createTestCertificate({ subject: 'QAuth Test Root', ca: true, ...valid });
const intermediate = createTestCertificate({
  subject: 'QAuth Test Intermediate',
  ca: true,
  issuer: root,
  ...valid,
});
const signer = createTestCertificate({
  subject: 'status.issuer.example',
  issuer: intermediate,
  dnsNames: ['status.issuer.example'],
  ...valid,
});
const anchors = createStatusListTrustAnchors([root.pem]);

const ISSUER = 'https://status.issuer.example';
const URI = 'https://status.issuer.example/lists/1';
const LST = encodeStatusList([0, 1, 2, 3, 0, 0, 0, 0], 2);

const x5c = [signer.x5c, intermediate.x5c];

function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    sub: URI,
    iat: nowSeconds - 60,
    exp: nowSeconds + 600,
    ttl: 300,
    status_list: { bits: 2, lst: LST },
    ...overrides,
  };
}

function token(
  overrides: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
  tamper = false
): string {
  return signStatusListToken({
    signer,
    header: { typ: STATUS_LIST_TOKEN_TYP, x5c, ...header },
    claims: claims(overrides),
    tamper,
  });
}

async function verify(
  compact: string,
  extra: Partial<Parameters<typeof verifyStatusListToken>[0]> = {}
): ReturnType<typeof verifyStatusListToken> {
  return verifyStatusListToken({ token: compact, expectedUri: URI, anchors, now, ...extra });
}

describe('verifyStatusListToken (#297, draft-14 §5/§6)', () => {
  it('verifies a well-formed, anchored Status List Token', async () => {
    const result = await verify(token());

    expect(result.outcome).toBe('verified');
    if (result.outcome !== 'verified') return;
    expect(result.statusList).toMatchObject({
      bits: 2,
      lst: LST,
      issuer: ISSUER,
      ttlSeconds: 300,
      expiresAtMs: (nowSeconds + 600) * 1000,
    });
  });

  it('omits ttl and exp when the token carries none', async () => {
    const result = await verify(token({ ttl: undefined, exp: undefined }));

    expect(result.outcome).toBe('verified');
    if (result.outcome !== 'verified') return;
    expect(result.statusList.ttlSeconds).toBeUndefined();
    expect(result.statusList.expiresAtMs).toBeUndefined();
  });

  it('drops a non-positive ttl rather than honouring it', async () => {
    const result = await verify(token({ ttl: -5 }));
    expect(result.outcome).toBe('verified');
    if (result.outcome !== 'verified') return;
    expect(result.statusList.ttlSeconds).toBeUndefined();
  });

  describe('signature and algorithm', () => {
    it('refuses a tampered signature', async () => {
      expect(await verify(token({}, {}, true))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('refuses a token signed by a key other than the one in x5c', async () => {
      const impostor = createTestCertificate({
        subject: 'impostor.example',
        issuer: intermediate,
        dnsNames: ['impostor.example'],
        ...valid,
      });
      const forged = signStatusListToken({
        signer: impostor,
        header: { typ: STATUS_LIST_TOKEN_TYP, x5c },
        claims: claims(),
      });

      expect(await verify(forged)).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it.each(['none', 'HS256', 'EdDSA', 'RS256'])('refuses alg %s', async (alg) => {
      expect(await verify(token({}, { alg }))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('refuses a token with no x5c header at all', async () => {
      expect(await verify(token({}, { x5c: undefined }))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });
  });

  describe('type confusion', () => {
    it.each([
      ['a credential typ', 'dc+sd-jwt'],
      ['a plain JWT typ', 'JWT'],
      ['an access-token typ', 'at+jwt'],
      ['no typ at all', undefined],
    ])('refuses %s', async (_label, typ) => {
      // RFC 8725 §3.11: without this, any JWS the same key ever signed can be
      // replayed here as a status list.
      expect(await verify(token({}, { typ }))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });
  });

  describe('expiry', () => {
    it('refuses an expired Status List Token', async () => {
      expect(await verify(token({ exp: nowSeconds - 1 }))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('honours a configured clock tolerance', async () => {
      const result = await verify(token({ exp: nowSeconds - 10 }), {
        clockToleranceSeconds: 60,
      });
      expect(result.outcome).toBe('verified');
    });

    it('refuses a token with no iat', async () => {
      expect(await verify(token({ iat: undefined }))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('refuses a non-numeric iat', async () => {
      expect(await verify(token({ iat: 'yesterday' }))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });
  });

  describe('sub binding (draft-14 §6)', () => {
    it('refuses a token whose sub is a different list', async () => {
      // The attack: an attacker publishes an anchored status list of their own
      // and points every credential at it.
      expect(await verify(token({ sub: 'https://status.issuer.example/lists/2' }))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('refuses a token whose sub merely NORMALISES to the fetched uri', async () => {
      expect(await verify(token({ sub: `${URI}/` }))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('refuses a missing sub', async () => {
      expect(await verify(token({ sub: undefined }))).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });
  });

  describe('issuer trust', () => {
    it('refuses a chain that reaches no configured anchor', async () => {
      const foreignRoot = createTestCertificate({ subject: 'Attacker Root', ca: true, ...valid });
      const foreignSigner = createTestCertificate({
        subject: 'status.issuer.example',
        issuer: foreignRoot,
        dnsNames: ['status.issuer.example'],
        ...valid,
      });
      const foreign = signStatusListToken({
        signer: foreignSigner,
        header: { typ: STATUS_LIST_TOKEN_TYP, x5c: [foreignSigner.x5c] },
        claims: claims(),
      });

      expect(await verify(foreign)).toEqual({
        outcome: 'rejected',
        reason: 'issuer-untrusted',
      });
    });

    it('refuses an iss the signing certificate does not cover', async () => {
      // Anchored, correctly signed — and claiming to be somebody else. This is
      // the cross-issuer impersonation the SAN binding exists to stop.
      expect(await verify(token({ iss: 'https://other.issuer.example' }))).toEqual({
        outcome: 'rejected',
        reason: 'issuer-untrusted',
      });
    });

    it('refuses a missing iss', async () => {
      expect(await verify(token({ iss: undefined }))).toEqual({
        outcome: 'rejected',
        reason: 'issuer-untrusted',
      });
    });

    it('applies an optional issuer registry on top of the anchor path', async () => {
      expect(
        await verify(token(), { issuerTrustRegistry: createStaticIssuerAllowlist([ISSUER]) })
      ).toMatchObject({ outcome: 'verified' });

      expect(await verify(token(), { issuerTrustRegistry: DENY_ALL_TRUST_REGISTRY })).toEqual({
        outcome: 'rejected',
        reason: 'issuer-untrusted',
      });
    });
  });

  describe('status_list claim', () => {
    it.each([
      ['a missing status_list', { status_list: undefined }],
      ['a non-object status_list', { status_list: 'nope' }],
      ['a bits value of 3', { status_list: { bits: 3, lst: LST } }],
      ['a missing bits', { status_list: { lst: LST } }],
      ['a missing lst', { status_list: { bits: 2 } }],
      ['an empty lst', { status_list: { bits: 2, lst: '' } }],
      ['a non-string lst', { status_list: { bits: 2, lst: 42 } }],
    ])('refuses %s as unreadable', async (_label, overrides) => {
      expect(await verify(token(overrides))).toEqual({
        outcome: 'rejected',
        reason: 'list-unreadable',
      });
    });
  });

  describe('structural refusals', () => {
    it.each([
      ['an empty token', ''],
      ['a non-JWS string', 'not-a-token'],
      ['a two-segment token', 'aaa.bbb'],
      ['a four-segment token', 'aaa.bbb.ccc.ddd'],
      ['a header that is not base64url', '!!!.bbb.ccc'],
      ['a header that is not JSON', `${Buffer.from('nope').toString('base64url')}.bbb.ccc`],
      ['a header that is a JSON array', `${Buffer.from('[1,2]').toString('base64url')}.bbb.ccc`],
    ])('refuses %s', async (_label, compact) => {
      expect(await verify(compact)).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('refuses a non-string token without throwing', async () => {
      expect(await verify(undefined as unknown as string)).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });

    it('refuses an oversized token before parsing it', async () => {
      expect(await verify(`a.${'x'.repeat(7 * 1024 * 1024)}.c`)).toEqual({
        outcome: 'rejected',
        reason: 'token-unverifiable',
      });
    });
  });
});
