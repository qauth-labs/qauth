import { describe, expect, it } from 'vitest';

import {
  DATA_DECRYPTION_ERROR_MESSAGE,
  DataDecryptionError,
  isSignerError,
  RealmIssuerNotFoundError,
  SignerAccessDeniedError,
  SignerError,
  SignerKeyNotFoundError,
  SignerRequestRefusedError,
  UpstreamClientNotFoundError,
} from './signer-errors';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';

describe('signer errors', () => {
  it.each([
    [new SignerAccessDeniedError('web', 'signJws', 'token_signing'), 'SIGNER_ACCESS_DENIED', 403],
    [new SignerRequestRefusedError('TYP_NOT_ALLOWED', 'no'), 'SIGNER_REQUEST_REFUSED', 400],
    [new RealmIssuerNotFoundError(REALM), 'SIGNER_ISSUER_NOT_FOUND', 500],
    [new UpstreamClientNotFoundError(REALM), 'SIGNER_UPSTREAM_CLIENT_NOT_FOUND', 500],
    [new SignerKeyNotFoundError(REALM, 'token_signing'), 'SIGNER_KEY_NOT_FOUND', 500],
    [new DataDecryptionError('detail'), 'DATA_DECRYPTION_FAILED', 500],
  ])('%s carries its code and status', (error, code, statusCode) => {
    expect(error).toBeInstanceOf(SignerError);
    expect(error).toBeInstanceOf(Error);
    expect(error).toMatchObject({ code, statusCode, name: error.constructor.name });
    expect(isSignerError(error)).toBe(true);
    expect(isSignerError(error, code as never)).toBe(true);
  });

  it('recognizes a signer error by its shape, as from another copy of the library', () => {
    const copy = Object.assign(new Error('x'), { code: 'SIGNER_KEY_NOT_FOUND' });

    expect(isSignerError(copy)).toBe(true);
    expect(isSignerError(copy, 'SIGNER_ACCESS_DENIED')).toBe(false);
    expect(isSignerError(Object.assign(new Error('x'), { code: 'OTHER' }))).toBe(false);
    expect(isSignerError({ code: 'SIGNER_KEY_NOT_FOUND' })).toBe(false);
  });

  it('names the role, the operation and the purpose of a refused call', () => {
    expect(new SignerAccessDeniedError('web', 'signJws', 'token_signing').message).toBe(
      "Signer caller 'web' may not call 'signJws' for 'token_signing'"
    );
    expect(new SignerAccessDeniedError(undefined, 'getJwks').message).toBe(
      "An unknown signer caller may not call 'getJwks'"
    );
  });

  it('names the key that was looked for', () => {
    expect(new SignerKeyNotFoundError(REALM, 'data_at_rest', { kid: 'k1' }).message).toBe(
      `Realm '${REALM}' has no key with kid 'k1' for purpose 'data_at_rest'`
    );
    expect(
      new SignerKeyNotFoundError(REALM, 'token_signing', {
        algorithm: 'EdDSA+ML-DSA-65',
        detail: 'no complete hybrid pair',
      }).message
    ).toBe(
      `Realm '${REALM}' has no active 'EdDSA+ML-DSA-65' key for purpose 'token_signing' ` +
        '(no complete hybrid pair)'
    );
  });

  it('names the realm of a missing upstream provider, and not the provider id it was given', () => {
    expect(new UpstreamClientNotFoundError(REALM).message).toBe(
      `Realm '${REALM}' has no configuration for the upstream provider`
    );
  });

  it('keeps the decryption detail out of the message', () => {
    const error = new DataDecryptionError('ciphertext did not authenticate');

    expect(error.message).toBe(DATA_DECRYPTION_ERROR_MESSAGE);
    expect(error.detail).toBe('ciphertext did not authenticate');
  });
});
