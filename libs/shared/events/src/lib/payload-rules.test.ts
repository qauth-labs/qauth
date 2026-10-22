import { describe, expect, it } from 'vitest';

import {
  classifyFieldName,
  fieldNameWords,
  scanJsonSchema,
  scanPayload,
  scanValues,
} from './payload-rules';

describe('fieldNameWords', () => {
  it.each([
    ['apiKeyId', ['api', 'key', 'id']],
    ['api_key_id', ['api', 'key', 'id']],
    ['token-type', ['token', 'type']],
    ['apiKeyID', ['api', 'key', 'id']],
    ['HTTPStatus', ['http', 'status']],
    ['oauth2Token', ['oauth2', 'token']],
  ])('splits %s', (name, words) => {
    expect(fieldNameWords(name)).toEqual(words);
  });
});

describe('the payload scanner', () => {
  // The acceptance criterion of #456: a field named like a password, code,
  // token, OTP, secret or link is refused.
  it.each([
    'password',
    'newPassword',
    'password_hash',
    'code',
    'authorizationCode',
    'code_verifier',
    'userCode',
    'token',
    'accessToken',
    'refresh_token',
    'idToken',
    'tokens',
    'otp',
    'emailOtp',
    'totp',
    'secret',
    'clientSecret',
    'client_secret',
    'link',
    'resetLink',
    'setupLink',
    'magic_link',
    'resetUrl',
    'redirectUri',
    'key',
    'privateKey',
    'signingKeys',
    'assertion',
    'clientAssertion',
    'signature',
    'webauthnSignature',
    'cookie',
    'sessionCookie',
    'pin',
    'accesstoken',
    'clientsecret',
    'passwordhash',
    'jwt',
    'idJwt',
    'sdJwt',
    'jwk',
    'privateJwk',
    'credential',
    'credentials',
    'presentation',
    'bearer',
    'mfaSeed',
    'dpopProof',
    'apikey',
    'privatekey',
    'signingkey',
  ])('refuses a field named %s', (name) => {
    expect(classifyFieldName(name)).toBe('secret_field');
    expect(scanPayload({ [name]: 'x' })).toEqual([
      expect.objectContaining({ path: `/${name}`, rule: 'secret_field' }),
    ]);
  });

  it.each([
    'apiKeyId',
    'keyId',
    'tokenType',
    'issuedTokenType',
    'tokenClientId',
    'rotatedFromTokenId',
    'revokedTokenCount',
    'authCodeId',
    'identifierHmac',
    'grantType',
    'reason',
    'error',
    'verifierProfile',
    'linkedAccountId',
    'consentId',
    'scopes',
    'typeHint',
    'encoded',
    'credentialId',
    'presentationCount',
    'idJagId',
  ])('allows a field named %s', (name) => {
    expect(classifyFieldName(name)).toBeNull();
    expect(scanPayload({ [name]: 'x' })).toEqual([]);
  });

  it.each([
    'email',
    'emailAddress',
    'ipAddress',
    'ip',
    'phone',
    'name',
    'displayName',
    'username',
    'identifier',
    'assertedIdentifier',
    'loginHint',
  ])('refuses personal data named %s unless the type declares it', (name) => {
    expect(classifyFieldName(name)).toBe('personal_data_field');
    expect(classifyFieldName(name, { personalData: [name] })).toBeNull();
  });

  it('allows an HMAC or an id of personal data', () => {
    expect(classifyFieldName('emailHmac')).toBeNull();
    expect(classifyFieldName('identifierHmac')).toBeNull();
    expect(classifyFieldName('addressId')).toBeNull();
  });

  it('never lets a type declare a secret field', () => {
    expect(classifyFieldName('password', { personalData: ['password'] })).toBe('secret_field');
  });

  it('reads nested objects and arrays, and reports JSON Pointers', () => {
    const findings = scanPayload({
      outer: { items: [{ ok: 1 }, { 'refresh/token': 'x' }] },
      list: [{ otp: '123456' }],
    });
    expect(findings.map((f) => f.path)).toEqual(['/outer/items/1/refresh~1token', '/list/0/otp']);
  });

  it.each([
    ['a JWT', 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl'],
    ['a JWE', 'eyJhbGciOiJSU0EtT0FFUCJ9.a2V5.aXY.Y2lwaGVy.dGFn'],
    ['a PEM key', '-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----'],
    ['an SD-JWT', 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln~WyJzYWx0IiwiYSIsMV0~'],
    ['a bearer header', 'Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl'],
    ['a JWT with whitespace around it', ' eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln\n'],
  ])('refuses a value shaped like %s, wherever it sits', (_label, value) => {
    expect(scanPayload({ reason: value })).toEqual([
      expect.objectContaining({ path: '/reason', rule: 'secret_value' }),
    ]);
    expect(scanPayload({ fields: ['ok', value] })[0]?.path).toBe('/fields/1');
  });

  it('passes a clean payload', () => {
    expect(
      scanPayload({ grantType: 'authorization_code', scopes: ['openid'], expiresIn: 3600 })
    ).toEqual([]);
  });
});

describe('the value-only scanner', () => {
  it('reads values and ignores names', () => {
    expect(scanValues({ ip: '203.0.113.7', password: 'x' })).toEqual([]);
    expect(scanValues({ actor: { id: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln' } })).toEqual([
      expect.objectContaining({ path: '/actor/id', rule: 'secret_value' }),
    ]);
  });
});

describe('the schema scanner', () => {
  it('reads the fixed keys of a record', () => {
    const schema = {
      properties: {
        byKind: { type: 'object', propertyNames: { enum: ['ok', 'accessToken'] } },
        single: { propertyNames: { const: 'clientSecret' } },
      },
    };
    expect(scanJsonSchema(schema).map((f) => f.message)).toEqual([
      expect.stringContaining('"accessToken"'),
      expect.stringContaining('"clientSecret"'),
    ]);
  });

  it('finds a declared secret field at any depth', () => {
    const schema = {
      type: 'object',
      properties: {
        ok: { type: 'string' },
        nested: {
          type: 'object',
          properties: { list: { type: 'array', items: { properties: { otp: {} } } } },
        },
        either: { anyOf: [{ properties: { resetLink: {} } }, { type: 'null' }] },
      },
      $defs: { Thing: { properties: { clientSecret: {} } } },
    };
    expect(scanJsonSchema(schema).map((f) => f.path)).toEqual([
      '/properties/nested/properties/list/items/properties/otp',
      '/properties/either/anyOf/0/properties/resetLink',
      '/$defs/Thing/properties/clientSecret',
    ]);
  });

  it('honours the declared personal data', () => {
    const schema = { properties: { email: { type: 'string' } } };
    expect(scanJsonSchema(schema)).toHaveLength(1);
    expect(scanJsonSchema(schema, { personalData: ['email'] })).toEqual([]);
  });
});
