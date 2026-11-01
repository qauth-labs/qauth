import { describe, expect, it } from 'vitest';

import {
  DEFAULT_INTERNAL_HOST,
  DEFAULT_INTERNAL_PORT,
  internalListenerEnvSchema,
  parsePeerSan,
  peerSanKey,
} from './internal-listener';

/** The internal listener's settings (issue #496). */

describe('parsePeerSan', () => {
  it('reads a value with a colon as a URI SAN, exactly as written', () => {
    expect(parsePeerSan('spiffe://example.org/qauth/Web')).toEqual({
      san: { type: 'uri', value: 'spiffe://example.org/qauth/Web' },
    });
    expect(parsePeerSan('urn:qauth:peer:web')).toEqual({
      san: { type: 'uri', value: 'urn:qauth:peer:web' },
    });
  });

  it('reads any other value as a DNS name, in lower case', () => {
    expect(parsePeerSan('API.qauth.Internal')).toEqual({
      san: { type: 'dns', value: 'api.qauth.internal' },
    });
    expect(parsePeerSan('signer')).toEqual({ san: { type: 'dns', value: 'signer' } });
  });

  it('refuses a wildcard, an IP address and a value that is neither', () => {
    for (const value of [
      '*.qauth.internal',
      '10.0.0.7',
      '::1',
      '[::1]',
      'fe80::1',
      'api..internal',
      '-api.internal',
      'api_internal',
      '__proto__',
      'spiffe ://example.org/web',
      'spiffe://example.org/we b',
      '://missing-scheme',
      '',
      `${'a'.repeat(2049)}`,
    ]) {
      expect('problem' in parsePeerSan(value), value).toBe(true);
    }
  });

  it('keys a DNS name without regard to case and a URI exactly', () => {
    expect(peerSanKey({ type: 'dns', value: 'Web.Internal' })).toBe('dns:web.internal');
    expect(peerSanKey({ type: 'uri', value: 'spiffe://x/Web' })).toBe('uri:spiffe://x/Web');
  });
});

describe('internalListenerEnvSchema', () => {
  it('binds to loopback on its default port, with no peer, when nothing is set', () => {
    const parsed = internalListenerEnvSchema.parse({});
    expect(parsed.INTERNAL_HOST).toBe(DEFAULT_INTERNAL_HOST);
    expect(DEFAULT_INTERNAL_HOST).toBe('127.0.0.1');
    expect(parsed.INTERNAL_PORT).toBe(DEFAULT_INTERNAL_PORT);
    expect(DEFAULT_INTERNAL_PORT).toBe(3443);
    expect(parsed.INTERNAL_PEER_ROLES.size).toBe(0);
  });

  it('reads blank settings as unset', () => {
    const parsed = internalListenerEnvSchema.parse({
      INTERNAL_HOST: ' ',
      INTERNAL_PORT: '',
      INTERNAL_PEER_ROLES: '  ',
    });
    expect(parsed.INTERNAL_HOST).toBe(DEFAULT_INTERNAL_HOST);
    expect(parsed.INTERNAL_PORT).toBe(DEFAULT_INTERNAL_PORT);
    expect(parsed.INTERNAL_PEER_ROLES.size).toBe(0);
  });

  it('refuses a port out of range', () => {
    for (const value of ['0', '65536', 'https']) {
      const result = internalListenerEnvSchema.safeParse({ INTERNAL_PORT: value });
      expect(result.success, value).toBe(false);
      expect(result.error?.issues[0]?.path).toEqual(['INTERNAL_PORT']);
    }
  });

  it('maps each SAN to its role', () => {
    const { INTERNAL_PEER_ROLES: roles } = internalListenerEnvSchema.parse({
      INTERNAL_PEER_ROLES: JSON.stringify({
        'spiffe://example.org/qauth/web': 'web',
        'API.qauth.internal': 'api',
        'delivery.qauth.internal': 'delivery',
      }),
    });
    expect([...roles]).toEqual([
      ['uri:spiffe://example.org/qauth/web', 'web'],
      ['dns:api.qauth.internal', 'api'],
      ['dns:delivery.qauth.internal', 'delivery'],
    ]);
  });

  it('accepts two spellings of one DNS name that name the same role', () => {
    const { INTERNAL_PEER_ROLES: roles } = internalListenerEnvSchema.parse({
      INTERNAL_PEER_ROLES: JSON.stringify({ 'web.internal': 'web', 'WEB.internal': 'web' }),
    });
    expect([...roles]).toEqual([['dns:web.internal', 'web']]);
  });

  it.each([
    ['not JSON', '{web.internal: web}', 'must be a JSON object'],
    ['an array', '["web.internal"]', 'JSON object keyed by SAN'],
    ['a string', '"web.internal"', 'JSON object keyed by SAN'],
    ['null', 'null', 'JSON object keyed by SAN'],
    ['an unknown role', '{"web.internal":"browser"}', 'must name one role'],
    ['all', '{"web.internal":"all"}', 'must name one role'],
    ['a role list', '{"web.internal":["web","api"]}', 'must name one role'],
    ['a wildcard SAN', '{"*.internal":"web"}', 'no wildcard'],
    ['an IP SAN', '{"10.1.2.3":"web"}', 'an IP address is not a peer name'],
    ['the prototype', '{"__proto__":"web"}', '"__proto__"'],
    [
      'one DNS name in two roles',
      '{"web.internal":"web","Web.Internal":"api"}',
      'to both web and api',
    ],
  ])('refuses %s, naming the variable', (_case, value, message) => {
    const result = internalListenerEnvSchema.safeParse({ INTERNAL_PEER_ROLES: value });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual(['INTERNAL_PEER_ROLES']);
    expect(result.error?.issues[0]?.message).toContain('INTERNAL_PEER_ROLES');
    expect(result.error?.issues[0]?.message).toContain(message);
  });

  it('refuses more SANs than it takes', () => {
    const many = Object.fromEntries(
      Array.from({ length: 257 }, (_, index) => [`peer-${index}.internal`, 'web'])
    );
    const result = internalListenerEnvSchema.safeParse({
      INTERNAL_PEER_ROLES: JSON.stringify(many),
    });
    expect(result.error?.issues[0]?.message).toContain('more than the 256');
  });
});
