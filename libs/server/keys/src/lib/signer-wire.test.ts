import { describe, expect, it } from 'vitest';

import { KeyDecryptionError } from './errors';
import { SIGNER_OPERATIONS } from './signer';
import {
  DataDecryptionError,
  isSignerError,
  RealmIssuerNotFoundError,
  SIGNER_REFUSAL_REASONS,
  SignerAccessDeniedError,
  SignerKeyNotFoundError,
  SignerRequestRefusedError,
} from './signer-errors';
import {
  decodeSignerError,
  decodeSignerRequest,
  decodeSignerResult,
  decodeWireBytes,
  encodeSignerError,
  encodeSignerRequest,
  encodeSignerResult,
  encodeWireBytes,
  SIGNER_MAX_ANSWER_BYTES,
  SIGNER_REQUEST_BODY_LIMITS,
  SIGNER_SERVICE_PATH,
  SIGNER_SERVICE_ROUTES,
  SignerWireFormatError,
} from './signer-wire';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const MARKER = 'claim-value-77d0a1';

describe('the signer wire format (#497)', () => {
  it('names one POST route per operation, under a release-candidate version', () => {
    expect(SIGNER_SERVICE_PATH).toBe('/internal/signer/v1-rc.0');
    expect(Object.keys(SIGNER_SERVICE_ROUTES).sort()).toEqual([...SIGNER_OPERATIONS].sort());
    const routes = Object.values(SIGNER_SERVICE_ROUTES);
    expect(new Set(routes).size).toBe(routes.length);
    for (const route of routes) expect(route).toMatch(/^\/[a-z]+(?:-[a-z]+)*$/);
  });

  it('caps each request, and answers within the largest request', () => {
    expect(Object.keys(SIGNER_REQUEST_BODY_LIMITS).sort()).toEqual([...SIGNER_OPERATIONS].sort());
    for (const limit of Object.values(SIGNER_REQUEST_BODY_LIMITS)) {
      // Room for a cookie key id a cookie header carries, at the least.
      expect(limit).toBeGreaterThanOrEqual(64 * 1024);
      // An encryption of the largest plaintext, in base64url, fits an answer.
      expect(SIGNER_MAX_ANSWER_BYTES).toBeGreaterThan(Math.ceil((limit * 4) / 3) + 4096);
    }
  });

  it('carries bytes as base64url, and reads back only well-formed ones', () => {
    const bytes = Buffer.from([0, 1, 2, 250, 251, 252]);
    expect(decodeWireBytes(encodeWireBytes(bytes))?.equals(bytes)).toBe(true);
    expect(decodeWireBytes(encodeWireBytes(new Uint8Array()))?.length).toBe(0);
    for (const value of [
      'AAAA',
      { bytes: 'AA==' },
      { bytes: 'A' },
      { bytes: 'AA AA' },
      { bytes: 'AAAA', more: 1 },
      { bytes: 3 },
      null,
      ['AAAA'],
    ]) {
      expect(decodeWireBytes(value), JSON.stringify(value)).toBeUndefined();
    }
  });

  it('sends a webhook body as text or as bytes, and the service reads either back', () => {
    const request = { realmId: REALM, subscriptionId: 's', id: 'e', timestamp: 1 };
    const text = JSON.parse(encodeSignerRequest('signWebhook', [{ ...request, body: 'héllo' }]));
    expect(text.body).toBe('héllo');
    expect(decodeSignerRequest('signWebhook', text)).toEqual([{ ...request, body: 'héllo' }]);

    const bytes = JSON.parse(
      encodeSignerRequest('signWebhook', [{ ...request, body: Buffer.from('héllo') }])
    );
    expect(bytes.body).toEqual({ bytes: Buffer.from('héllo').toString('base64url') });
    const [decoded] = decodeSignerRequest('signWebhook', bytes);
    expect(Buffer.isBuffer(decoded.body)).toBe(true);
    expect(Buffer.from(decoded.body as Uint8Array).toString()).toBe('héllo');

    // A lone surrogate survives the trip, so the signer refuses it as it would in-process.
    const lone = JSON.parse(encodeSignerRequest('signWebhook', [{ ...request, body: '\ud800' }]));
    expect(decodeSignerRequest('signWebhook', lone)[0].body).toBe('\ud800');
  });

  it('sends the named arguments of a positional operation, and refuses another name unechoed', () => {
    expect(JSON.parse(encodeSignerRequest('getCookieSecrets', [REALM, undefined]))).toEqual({
      realmId: REALM,
    });
    expect(
      decodeSignerRequest('getCookieSecrets', { realmId: REALM, options: { kid: 'k' } })
    ).toEqual([REALM, { kid: 'k' }]);
    expect(decodeSignerRequest('getJwks', { realmId: REALM })).toEqual([REALM, undefined]);
    const refused = (() => {
      try {
        decodeSignerRequest('getJwks', { realmId: REALM, [MARKER]: true });
      } catch (error) {
        return error;
      }
      return undefined;
    })();
    expect(refused).toBeInstanceOf(SignerRequestRefusedError);
    expect((refused as SignerRequestRefusedError).reason).toBe('UNEXPECTED_FIELD');
    expect((refused as Error).message).not.toContain(MARKER);
    expect(() => decodeSignerRequest('signJws', [1])).toThrow(SignerRequestRefusedError);
  });

  it('refuses a request that does not serialize without quoting it', () => {
    const cyclic: Record<string, unknown> = { secret: MARKER };
    cyclic['self'] = cyclic;
    let caught: unknown;
    try {
      encodeSignerRequest('signJws', [
        { realmId: REALM, purpose: 'token_signing', typ: 'at+jwt', claims: cyclic },
      ]);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(SignerRequestRefusedError);
    expect((caught as SignerRequestRefusedError).reason).toBe('INVALID_CLAIMS');
    expect((caught as Error).message).not.toContain(MARKER);
    expect(() =>
      encodeSignerRequest('signJws', [
        { realmId: REALM, purpose: 'token_signing', typ: 'at+jwt', claims: { n: 1n } },
      ])
    ).toThrow(SignerRequestRefusedError);
  });

  it('zeroes the secrets it encodes, and the reader hands back buffers of its own', () => {
    const current = Buffer.alloc(32, 7);
    const encoded = encodeSignerResult('getCookieSecrets', {
      current: { kid: 'c1', secret: current },
      previous: null,
    });
    expect(current.every((byte) => byte === 0)).toBe(true);
    const decoded = decodeSignerResult('getCookieSecrets', JSON.parse(JSON.stringify(encoded)));
    expect(decoded.current.kid).toBe('c1');
    expect(decoded.current.secret.equals(Buffer.alloc(32, 7))).toBe(true);

    const plaintext = Buffer.from('s3cret');
    const sealed = encodeSignerResult('decrypt', plaintext);
    expect(plaintext.every((byte) => byte === 0)).toBe(true);
    expect(decodeSignerResult('decrypt', sealed).toString()).toBe('s3cret');
  });

  it('refuses an answer of another shape, and never passes a private JWK on', () => {
    expect(() => decodeSignerResult('signJws', '')).toThrow(SignerWireFormatError);
    expect(() => decodeSignerResult('signJws', { token: 'x' })).toThrow(SignerWireFormatError);
    expect(() =>
      decodeSignerResult('getCookieSecrets', { current: { kid: 'c', bytes: '' }, previous: null })
    ).toThrow(SignerWireFormatError);
    expect(() =>
      decodeSignerResult('getJwks', { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'x', d: 'd' }] })
    ).toThrow(SignerWireFormatError);
    expect(() =>
      decodeSignerResult('getVerificationKeys', [
        { kid: 'k', algorithm: 'EdDSA', status: 'next', publicJwk: { kty: 'OKP' } },
      ])
    ).toThrow(SignerWireFormatError);
    const jwks = decodeSignerResult('getUpstreamJwks', {
      keys: [{ kty: 'RSA', n: 'n', e: 'AQAB' }],
    });
    expect(Object.isFrozen(jwks.keys[0])).toBe(true);
  });

  it("sends an error's public fields and never its message", () => {
    const denied = encodeSignerError(
      new SignerAccessDeniedError('web', 'signJws', 'token_signing')
    );
    expect(denied).toEqual({
      status: 403,
      body: {
        error: {
          code: 'SIGNER_ACCESS_DENIED',
          caller: 'web',
          operation: 'signJws',
          purpose: 'token_signing',
        },
      },
    });
    expect(
      encodeSignerError(new SignerRequestRefusedError('RESERVED_CLAIM', `iss=${MARKER}`)).body
    ).toEqual({ error: { code: 'SIGNER_REQUEST_REFUSED', reason: 'RESERVED_CLAIM' } });
    expect(
      encodeSignerError(
        new SignerKeyNotFoundError(REALM, 'data_at_rest', { kid: MARKER, detail: MARKER })
      ).body
    ).toEqual({ error: { code: 'SIGNER_KEY_NOT_FOUND', purpose: 'data_at_rest' } });
    expect(encodeSignerError(new RealmIssuerNotFoundError(REALM)).status).toBe(422);
    expect(encodeSignerError(new DataDecryptionError(MARKER)).body).toEqual({
      error: { code: 'DATA_DECRYPTION_FAILED' },
    });
    const custody = encodeSignerError(new KeyDecryptionError({ detail: MARKER }));
    expect(custody.status).toBe(503);
    expect(JSON.stringify(custody)).not.toContain(MARKER);
    const fault = encodeSignerError(Object.assign(new Error(MARKER), { code: `${MARKER} x` }));
    expect(fault).toEqual({
      status: 500,
      body: { error: { code: 'SIGNER_FAULT' } },
      fault: { name: 'Error' },
    });
  });

  it('rebuilds each signer error with its class and a message of public fields only', () => {
    const context = { operation: 'signJws' as const, realmId: REALM.toUpperCase() };
    const denied = decodeSignerError(
      {
        code: 'SIGNER_ACCESS_DENIED',
        caller: 'api',
        operation: 'signJws',
        purpose: 'token_signing',
      },
      context
    );
    expect(denied).toBeInstanceOf(SignerAccessDeniedError);
    expect(denied).toMatchObject({ caller: 'api', operation: 'signJws', purpose: 'token_signing' });
    expect(
      decodeSignerError({ code: 'SIGNER_ACCESS_DENIED', caller: MARKER, purpose: MARKER }, context)
        ?.message
    ).not.toContain(MARKER);

    for (const reason of SIGNER_REFUSAL_REASONS) {
      const refused = decodeSignerError({ code: 'SIGNER_REQUEST_REFUSED', reason }, context);
      expect(refused).toBeInstanceOf(SignerRequestRefusedError);
      expect((refused as SignerRequestRefusedError).reason).toBe(reason);
    }
    expect(decodeSignerError({ code: 'SIGNER_REQUEST_REFUSED', reason: MARKER }, context)).toBe(
      undefined
    );
    const missing = decodeSignerError(
      { code: 'SIGNER_KEY_NOT_FOUND', purpose: 'token_signing', algorithm: 'RS256' },
      context
    );
    expect(missing).toBeInstanceOf(SignerKeyNotFoundError);
    expect(missing).toMatchObject({ realmId: REALM, purpose: 'token_signing', algorithm: 'RS256' });
    expect(isSignerError(decodeSignerError({ code: 'DATA_DECRYPTION_FAILED' }, context))).toBe(
      true
    );
    for (const code of ['SIGNER_UNAVAILABLE', 'SIGNER_FAULT', 'SOMETHING_ELSE', undefined]) {
      expect(decodeSignerError({ code }, context)).toBeUndefined();
    }
    expect(decodeSignerError('SIGNER_FAULT', context)).toBeUndefined();
  });
});
