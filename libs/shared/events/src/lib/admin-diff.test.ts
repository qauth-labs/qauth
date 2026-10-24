import { describe, expect, it } from 'vitest';

import {
  ADMIN_DIFF_MAX_CHANGES,
  ADMIN_DIFF_SECRET_MARKER,
  adminDiffSchema,
  buildAdminDiff,
  type JsonObject,
  scanAdminDiff,
} from './admin-diff';

const MASK = ADMIN_DIFF_SECRET_MARKER;

/** A compact JWS: three base64url segments, the first a JSON header. */
const COMPACT_JWS = 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1In0.c2lnbmF0dXJl';

describe('buildAdminDiff', () => {
  // The acceptance criterion of #459: changed fields with old and new values,
  // unchanged fields absent, nested objects diffed, arrays shown whole.
  it('lists the changed fields with their old and new values, and leaves unchanged ones out', () => {
    const diff = buildAdminDiff(
      { displayName: 'Notes', enabled: true, sessionTtl: 900 },
      { displayName: 'Team notes', enabled: true, sessionTtl: 600 }
    );
    expect(diff).toEqual([
      { path: '/displayName', before: 'Notes', after: 'Team notes' },
      { path: '/sessionTtl', before: 900, after: 600 },
    ]);
  });

  it('diffs a nested object member by member', () => {
    const diff = buildAdminDiff(
      { smtp: { host: 'mail.example', port: 25, tls: { required: false, minVersion: '1.2' } } },
      { smtp: { host: 'mail.example', port: 587, tls: { required: true, minVersion: '1.2' } } }
    );
    expect(diff).toEqual([
      { path: '/smtp/port', before: 25, after: 587 },
      { path: '/smtp/tls/required', before: false, after: true },
    ]);
  });

  it('shows an array whole, even when one element changed', () => {
    const diff = buildAdminDiff(
      { allowedScopes: ['openid', 'profile'], hosts: [{ host: 'a.example', primary: true }] },
      { allowedScopes: ['openid', 'email'], hosts: [{ host: 'a.example', primary: false }] }
    );
    expect(diff).toEqual([
      { path: '/allowedScopes', before: ['openid', 'profile'], after: ['openid', 'email'] },
      {
        path: '/hosts',
        before: [{ host: 'a.example', primary: true }],
        after: [{ host: 'a.example', primary: false }],
      },
    ]);
  });

  it('leaves an equal array, or an equal nested object in another member order, out', () => {
    expect(
      buildAdminDiff(
        { allowedScopes: ['openid'], branding: { colour: '#000', logo: 'a.svg' } },
        { allowedScopes: ['openid'], branding: { logo: 'a.svg', colour: '#000' } }
      )
    ).toEqual([]);
  });

  it('tells a field that was added or removed from one that held null', () => {
    const diff = buildAdminDiff(
      { description: null, legacyFlag: true },
      { description: 'Now described', locale: 'en' }
    );
    expect(diff).toEqual([
      { path: '/description', before: null, after: 'Now described' },
      { path: '/legacyFlag', before: true },
      { path: '/locale', after: 'en' },
    ]);
  });

  it('treats an undefined member as absent, as JSON does', () => {
    expect(buildAdminDiff({ a: 1, b: undefined } as unknown as JsonObject, { a: 1 })).toEqual([]);
  });

  it('shows a value whole when its type changes', () => {
    expect(buildAdminDiff({ limits: { rate: 5 } }, { limits: null })).toEqual([
      { path: '/limits', before: { rate: 5 }, after: null },
    ]);
  });

  it('lists every field of a created resource as added, and of a deleted one as removed', () => {
    expect(buildAdminDiff(null, { name: 'ops', enabled: true })).toEqual([
      { path: '/enabled', after: true },
      { path: '/name', after: 'ops' },
    ]);
    expect(buildAdminDiff({ name: 'ops' }, null)).toEqual([{ path: '/name', before: 'ops' }]);
    expect(buildAdminDiff(null, null)).toEqual([]);
  });

  it('escapes a member name into its JSON Pointer', () => {
    expect(buildAdminDiff({ 'a/b': 1, 'c~d': 1 }, { 'a/b': 2, 'c~d': 2 })).toEqual([
      { path: '/a~1b', before: 1, after: 2 },
      { path: '/c~0d', before: 1, after: 2 },
    ]);
  });

  it('keeps a member named __proto__ a member', () => {
    const before = JSON.parse('{"x": {"__proto__": {"polluted": 1}}}') as JsonObject;
    const after = JSON.parse('{"x": {"__proto__": {"polluted": 2}}, "y": [{"__proto__": 1}]}');
    const diff = buildAdminDiff(before, after);
    expect(diff.map((change) => change.path)).toEqual(['/x/__proto__/polluted', '/y']);
    expect(Object.hasOwn((diff[1].after as JsonObject[])[0], '__proto__')).toBe(true);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  it('does not change its input', () => {
    const before = { webhook: { secret: 'old', url: 'https://a.example' } };
    const after = { webhook: { secret: 'new', url: 'https://b.example' } };
    const copy = structuredClone({ before, after });
    buildAdminDiff(before, after, { secretFields: ['webhook.url'] });
    expect({ before, after }).toEqual(copy);
  });

  it.each([
    ['a Date', { at: new Date(0) }],
    ['a Buffer', { hash: Buffer.from('ab') }],
    ['NaN', { n: Number.NaN }],
    ['a lone surrogate', { s: '\uD800' }],
    // eslint-disable-next-line no-sparse-arrays -- the hole is what is refused
    ['a hole in an array', { list: [1, , 3] }],
    ['undefined in an array', { list: [1, undefined] }],
    ['a bigint', { n: 1n }],
  ])('refuses %s, which is not plain JSON', (_label, value) => {
    expect(() => buildAdminDiff({}, value as unknown as JsonObject)).toThrow(TypeError);
  });

  it('refuses a side that is not an object', () => {
    expect(() => buildAdminDiff([] as unknown as JsonObject, null)).toThrow(/plain object or null/);
  });

  it('refuses a secret field mark with an empty segment', () => {
    expect(() => buildAdminDiff({}, {}, { secretFields: ['smtp..password'] })).toThrow(
      /empty segment/
    );
  });

  it(`refuses a diff of more than ${ADMIN_DIFF_MAX_CHANGES} changes`, () => {
    const after = Object.fromEntries(
      Array.from({ length: ADMIN_DIFF_MAX_CHANGES + 1 }, (_, i) => [`f${i}`, i])
    );
    expect(() => buildAdminDiff(null, after)).toThrow(/more than one diff lists/);
  });

  it('builds a diff its schema accepts', () => {
    const diff = buildAdminDiff(
      { a: { b: [1, { c: null }] }, d: 'x' },
      { a: { b: [2] }, e: { f: true } }
    );
    expect(adminDiffSchema.safeParse(diff).success).toBe(true);
  });
});

describe('masking', () => {
  // The acceptance criterion of #459: a table of known secret field names
  // shows *** in the stored event, marked or not.
  it.each([
    ['client secret hash', 'clientSecretHash'],
    ['signing key', 'signingKey'],
    ['private key', 'privateKey'],
    ['webhook secret', 'webhookSecret'],
    ['SMTP password', 'smtpPassword'],
    ['plain password', 'password'],
    ['API key', 'apiKey'],
    ['set-up link', 'setupLink'],
    ['reset token', 'resetToken'],
    ['recovery codes', 'recoveryCodes'],
    ['TOTP seed', 'totpSeed'],
    ['snake case secret', 'client_secret'],
  ])('masks a %s (%s) without a mark', (_label, field) => {
    const diff = buildAdminDiff({ [field]: 'old-value', label: 'a' }, { [field]: 'new-value' });
    expect(diff).toHaveLength(2);
    expect(diff).toContainEqual({ path: `/${field}`, before: MASK, after: MASK });
    expect(diff).toContainEqual({ path: '/label', before: 'a' });
    expect(JSON.stringify(diff)).not.toMatch(/old-value|new-value/);
  });

  it('masks a secret nested in an object, at its own path', () => {
    const diff = buildAdminDiff(
      { smtp: { host: 'a.example', password: 'hunter2' } },
      { smtp: { host: 'b.example', password: 'hunter3' } }
    );
    expect(diff).toEqual([
      { path: '/smtp/host', before: 'a.example', after: 'b.example' },
      { path: '/smtp/password', before: MASK, after: MASK },
    ]);
  });

  it('masks a marked field whatever its name', () => {
    const diff = buildAdminDiff(
      { smtp: { relayPass: 'a' }, hooks: [{ sig: 'x', name: 'h' }] },
      { smtp: { relayPass: 'b' }, hooks: [{ sig: 'y', name: 'h' }] },
      { secretFields: ['smtp.relayPass', 'hooks.*.sig'] }
    );
    expect(diff).toEqual([
      { path: '/hooks', before: [{ sig: MASK, name: 'h' }], after: [{ sig: MASK, name: 'h' }] },
      { path: '/smtp/relayPass', before: MASK, after: MASK },
    ]);
  });

  it('masks a secret field whole: null, an object or an array', () => {
    const diff = buildAdminDiff(
      { secrets: { a: 'x' }, signingKeys: ['k1'], webhookSecret: null },
      { secrets: { a: 'y' }, signingKeys: ['k1', 'k2'], webhookSecret: 'whsec_x' }
    );
    expect(diff).toEqual([
      { path: '/secrets', before: MASK, after: MASK },
      { path: '/signingKeys', before: MASK, after: MASK },
      { path: '/webhookSecret', before: MASK, after: MASK },
    ]);
  });

  it('lists a rotated secret as changed, and leaves an unrotated one out', () => {
    expect(buildAdminDiff({ clientSecretHash: 'h1' }, { clientSecretHash: 'h2' })).toEqual([
      { path: '/clientSecretHash', before: MASK, after: MASK },
    ]);
    expect(buildAdminDiff({ clientSecretHash: 'h1' }, { clientSecretHash: 'h1' })).toEqual([]);
  });

  it('shows a secret that was set or cleared as the marker on the side that has it', () => {
    expect(buildAdminDiff({}, { webhookSecret: 'whsec_a' })).toEqual([
      { path: '/webhookSecret', after: MASK },
    ]);
    expect(buildAdminDiff({ webhookSecret: 'whsec_a' }, {})).toEqual([
      { path: '/webhookSecret', before: MASK },
    ]);
  });

  it('masks secrets inside a value shown whole', () => {
    const diff = buildAdminDiff(
      { webhooks: [] },
      { webhooks: [{ id: 'w1', signingSecret: 'whsec_a', events: ['user.signed_in'] }] }
    );
    expect(diff).toEqual([
      {
        path: '/webhooks',
        before: [],
        after: [{ id: 'w1', signingSecret: MASK, events: ['user.signed_in'] }],
      },
    ]);
  });

  it('masks a string shaped like a token or a key wherever it sits', () => {
    const pem = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI\n-----END PRIVATE KEY-----';
    const diff = buildAdminDiff(
      { note: 'plain', list: ['a'] },
      { note: `Bearer ${COMPACT_JWS}`, list: ['a', pem] }
    );
    expect(diff).toEqual([
      { path: '/list', before: ['a'], after: ['a', MASK] },
      { path: '/note', before: 'plain', after: MASK },
    ]);
  });

  // Secrets a resource names in ways an event never does: the SMTP provider's
  // own `auth.pass`, a directory bind password, a connection string.
  it.each([
    [
      'an SMTP provider auth block',
      { smtp: { auth: { user: 'u', pass: 'hunter2' } } },
      '/smtp/auth',
    ],
    ['a pass field', { smtp: { pass: 'hunter2' } }, '/smtp/pass'],
    ['a bind password', { ldap: { bindPw: 'hunter2' } }, '/ldap/bindPw'],
    ['a DSN', { dsn: 'postgres://db/qauth' }, '/dsn'],
    [
      'a connection string',
      { connectionString: 'Server=db;Uid=u;Pwd=hunter2' },
      '/connectionString',
    ],
    ['an authorization value', { headers: { authorization: 'opaque' } }, '/headers/authorization'],
    ['a salt', { salt: 'c2FsdA' }, '/salt'],
    ['a set-up URL', { setupUrl: 'https://auth.example/setup?x=1' }, '/setupUrl'],
    ['a magic link', { magicLinkUrl: 'https://auth.example/m/1' }, '/magicLinkUrl'],
  ])('masks %s', (_label, after, path) => {
    // The same resource with every string replaced: the diff descends to the field.
    const before = JSON.parse(JSON.stringify(after), (_key, value: unknown) =>
      typeof value === 'string' ? 'old-value' : value
    ) as JsonObject;
    const diff = buildAdminDiff(before, after as JsonObject);
    expect(diff).toEqual([{ path, before: MASK, after: MASK }]);
    expect(JSON.stringify(diff)).not.toMatch(/hunter2|old-value|opaque/);
  });

  // Security settings an admin event must show: masking them would hide the
  // change the audit exists for, such as a redirect URI an attacker added.
  it.each([
    [
      'redirectUris',
      ['https://app.example/cb'],
      ['https://app.example/cb', 'https://evil.example/cb'],
    ],
    ['jwksUri', 'https://app.example/jwks', 'https://evil.example/jwks'],
    ['tokenEndpointAuthMethod', 'private_key_jwt', 'none'],
    ['accessTokenTtl', 900, 3600],
    ['authorizationCodeLifespan', 60, 600],
    ['passwordMinScore', 3, 1],
    ['codeChallengeMethod', 'S256', 'plain'],
    ['secretRotatedAt', '2026-01-01T00:00:00Z', '2026-10-24T00:00:00Z'],
    ['url', 'https://hooks.example/a', 'https://hooks.example/b'],
  ])('shows %s', (field, before, after) => {
    expect(buildAdminDiff({ [field]: before }, { [field]: after })).toEqual([
      { path: `/${field}`, before, after },
    ]);
  });

  it('keeps a flag under a secret name: it holds no secret', () => {
    expect(buildAdminDiff({ revokeRefreshToken: false }, { revokeRefreshToken: true })).toEqual([
      { path: '/revokeRefreshToken', before: false, after: true },
    ]);
  });

  it('masks a value shaped like a secret under a harmless name', () => {
    const diff = buildAdminDiff(
      {},
      {
        upstream: 'https://svc:hunter2@upstream.example/',
        header: 'Basic dTpodW50ZXIy',
        jwks: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'pub' }] },
        material: { kty: 'oct', k: 'c2VjcmV0' },
      }
    );
    expect(diff).toEqual([
      { path: '/header', after: MASK },
      { path: '/jwks', after: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'pub' }] } },
      { path: '/material', after: MASK },
      { path: '/upstream', after: MASK },
    ]);
  });

  it('judges a key by its shape: a public JWK is shown, a private one masked, a marked one masked', () => {
    const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: 'cHVi' };
    const privateJwk = { ...publicJwk, d: 'cHJpdg' };
    expect(buildAdminDiff({}, { signingKey: publicJwk })).toEqual([
      { path: '/signingKey', after: publicJwk },
    ]);
    expect(buildAdminDiff({}, { signingKey: privateJwk })).toEqual([
      { path: '/signingKey', after: MASK },
    ]);
    expect(buildAdminDiff({}, { verifier: publicJwk }, { secretFields: ['verifier'] })).toEqual([
      { path: '/verifier', after: MASK },
    ]);
    expect(scanAdminDiff([{ path: '/signingKey', after: privateJwk }])).not.toEqual([]);
    expect(scanAdminDiff([{ path: '/signingKey', after: publicJwk }])).toEqual([]);
  });

  it('masks an ML-DSA private key: an AKP JWK with `priv` or `seed`', () => {
    const publicAkp = { kty: 'AKP', alg: 'ML-DSA-65', pub: 'cHVi' };
    for (const member of ['priv', 'seed']) {
      const privateAkp = { ...publicAkp, [member]: 'c2VlZA' };
      expect(buildAdminDiff({}, { signingKey: privateAkp })).toEqual([
        { path: '/signingKey', after: MASK },
      ]);
      expect(scanAdminDiff([{ path: '/signingKey', after: privateAkp }])).not.toEqual([]);
    }
    expect(buildAdminDiff({}, { signingKey: publicAkp })).toEqual([
      { path: '/signingKey', after: publicAkp },
    ]);
  });

  it('masks the value of a name and value pair whose name holds a secret', () => {
    const headers = [
      { name: 'X-Api-Key', value: 'sk_live_abc123' },
      { name: 'Authorization', value: 'Token ghp_abc' },
      { name: 'X-Tenant', value: 'acme' },
    ];
    expect(buildAdminDiff({ headers: [] }, { headers })).toEqual([
      {
        path: '/headers',
        before: [],
        after: [
          { name: 'X-Api-Key', value: MASK },
          { name: 'Authorization', value: MASK },
          { name: 'X-Tenant', value: 'acme' },
        ],
      },
    ]);
    // A pair diffed member by member, and one named by `key`.
    expect(
      buildAdminDiff(
        { smtp: { key: 'SMTP_PASSWORD', value: 'hunter1' } },
        { smtp: { key: 'SMTP_PASSWORD', value: 'hunter2' } }
      )
    ).toEqual([{ path: '/smtp/value', before: MASK, after: MASK }]);
    expect(
      scanAdminDiff([{ path: '/headers', after: [{ name: 'X-Api-Key', value: 'sk_live_abc123' }] }])
    ).toEqual([expect.objectContaining({ path: '/0/after/0/value', rule: 'secret_field' })]);
  });

  it('masks an Authorization value, and shows prose that starts with a scheme', () => {
    const diff = buildAdminDiff(
      {},
      {
        a: 'Token ghp_abc123',
        b: 'DPoP eyJ0eXAi',
        c: 'Digest username="u", realm="r", response="x"',
        d: 'Basic plan for teams',
        e: 'Bearer of record',
      }
    );
    expect(diff).toEqual([
      { path: '/a', after: MASK },
      { path: '/b', after: MASK },
      { path: '/c', after: MASK },
      { path: '/d', after: 'Basic plan for teams' },
      { path: '/e', after: 'Bearer of record' },
    ]);
  });

  it('keeps a member name that only starts with a scheme, such as "Basic tier"', () => {
    expect(buildAdminDiff({}, { plans: { 'Basic tier': 5 } })).toEqual([
      { path: '/plans', after: { 'Basic tier': 5 } },
    ]);
    expect(scanAdminDiff([{ path: '/plans', after: { 'Basic tier': 5 } }])).toEqual([]);
  });

  it('refuses a member name shaped like a secret, which no mask can hide', () => {
    expect(() => buildAdminDiff({}, { allow: { [`Bearer ${COMPACT_JWS}`]: true } })).toThrow(
      /member name under \/allow is shaped like a secret/
    );
    expect(() => buildAdminDiff({}, { [COMPACT_JWS]: 1 })).toThrow(/shaped like a secret/);
  });

  it('keeps fields that only name an id, a type or a count of a secret', () => {
    const diff = buildAdminDiff(
      { signingKeyId: 'k1', tokenType: 'jwt', apiKeyCount: 1 },
      { signingKeyId: 'k2', tokenType: 'opaque', apiKeyCount: 2 }
    );
    expect(diff).toEqual([
      { path: '/apiKeyCount', before: 1, after: 2 },
      { path: '/signingKeyId', before: 'k1', after: 'k2' },
      { path: '/tokenType', before: 'jwt', after: 'opaque' },
    ]);
  });

  it('builds diffs the masking check accepts', () => {
    const diff = buildAdminDiff(
      { smtp: { password: 'a' }, hooks: [{ secret: 'x' }], note: COMPACT_JWS },
      { smtp: { password: 'b' }, hooks: [{ secret: 'y' }], note: 'clear' }
    );
    expect(scanAdminDiff(diff)).toEqual([]);
  });
});

describe('scanAdminDiff', () => {
  it('passes a masked diff', () => {
    expect(
      scanAdminDiff([
        { path: '/smtp/password', before: MASK, after: MASK },
        { path: '/hooks', after: [{ secret: MASK, url: MASK }] },
        { path: '/displayName', before: 'a', after: 'b' },
      ])
    ).toEqual([]);
  });

  it('reports a change whose path names a secret but holds a value', () => {
    expect(scanAdminDiff([{ path: '/smtp/password', before: MASK, after: 'hunter2' }])).toEqual([
      expect.objectContaining({ path: '/0/after', rule: 'secret_field' }),
    ]);
  });

  it('reports a secret ancestor in the path, too', () => {
    expect(scanAdminDiff([{ path: '/secrets/region', after: 'eu' }], '/diff')).toEqual([
      expect.objectContaining({ path: '/diff/0/after' }),
    ]);
  });

  it('reports a member named like a secret inside a value', () => {
    expect(
      scanAdminDiff([{ path: '/hooks', after: [{ id: 'w1', signingSecret: 'whsec_a' }] }])
    ).toEqual([expect.objectContaining({ path: '/0/after/0/signingSecret' })]);
  });

  it('reports a value or a member name shaped like a secret, and passes a masked flag', () => {
    expect(
      scanAdminDiff([
        { path: '/upstream', after: 'https://u:pw@host.example/' },
        { path: '/allow', after: { 'https://u:pw@host.example/': true } },
        { path: '/key', after: { kty: 'oct', k: 'c2VjcmV0' } },
        { path: '/revokeRefreshToken', before: false, after: true },
      ])
    ).toEqual([
      expect.objectContaining({ path: '/0/after', rule: 'secret_value' }),
      expect.objectContaining({
        path: '/1/after/https:~1~1u:pw@host.example~1',
        rule: 'secret_value',
      }),
      expect.objectContaining({ path: '/2/after', rule: 'secret_field' }),
    ]);
  });

  it('ignores what is not a diff', () => {
    expect(scanAdminDiff({ path: '/password', after: 'x' })).toEqual([]);
    expect(scanAdminDiff([null, { before: 'x' }])).toEqual([]);
  });
});
