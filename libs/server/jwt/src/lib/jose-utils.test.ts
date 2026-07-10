import { JWTInvalidError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { decodeJwtUnsafe } from './jose-utils';
import { signAccessToken } from './jwt-service';
import { generateEdDSAKeyPair } from './key-management';

describe('decodeJwtUnsafe', () => {
  it('decodes a full user access token with email claims', async () => {
    const { privateKey } = await generateEdDSAKeyPair();
    const token = await signAccessToken(
      { sub: 'user-1', email: 'user@example.com', email_verified: true, clientId: 'client-1' },
      privateKey,
      'https://auth.example.com',
      900
    );

    const decoded = decodeJwtUnsafe(token);
    expect(decoded.sub).toBe('user-1');
    expect(decoded.email).toBe('user@example.com');
    expect(decoded.email_verified).toBe(true);
    expect(decoded.clientId).toBe('client-1');
  });

  it('decodes a client_credentials token that OMITS email/email_verified (F-09)', async () => {
    const { privateKey } = await generateEdDSAKeyPair();
    // client_credentials tokens have no end-user: signAccessToken omits
    // email/email_verified. decodeJwtUnsafe must still decode them.
    const token = await signAccessToken(
      { sub: 'service-client', clientId: 'service-client' },
      privateKey,
      'https://auth.example.com',
      900
    );

    const decoded = decodeJwtUnsafe(token);
    expect(decoded.sub).toBe('service-client');
    expect(decoded.email).toBeUndefined();
    expect(decoded.email_verified).toBeUndefined();
    expect(decoded.clientId).toBe('service-client');
  });

  it('throws JWTInvalidError when the token is structurally malformed', () => {
    expect(() => decodeJwtUnsafe('not.a.jwt')).toThrow(JWTInvalidError);
  });
});
