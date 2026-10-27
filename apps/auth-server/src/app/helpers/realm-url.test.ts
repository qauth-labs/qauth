import type { FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';

import { buildRealmUrl, realmIssuer, realmTokenIssuer } from './realm-url';

/** A server whose JWT plugin signs every token with `signedIssuer`. */
function serverSigningWith(signedIssuer: string): FastifyInstance {
  return { jwtUtils: { getIssuer: () => signedIssuer } } as unknown as FastifyInstance;
}

describe('realmIssuer', () => {
  it('is the stored issuer, byte for byte', () => {
    expect(realmIssuer({ issuer: 'https://b.example.com' })).toBe('https://b.example.com');
    expect(realmIssuer({ issuer: 'https://auth.example.com:8443/qauth' })).toBe(
      'https://auth.example.com:8443/qauth'
    );
  });

  it('refuses a realm with no issuer, which the resolver never lets through', () => {
    expect(() => realmIssuer({ issuer: null })).toThrow(/no issuer/);
  });
});

describe('buildRealmUrl', () => {
  it('joins the issuer and the path as strings, as discovery does', () => {
    expect(buildRealmUrl({ issuer: 'https://b.example.com' }, '/oauth/token')).toBe(
      'https://b.example.com/oauth/token'
    );
    expect(buildRealmUrl({ issuer: 'https://b.example.com' }, '/auth/verify?token=abc')).toBe(
      'https://b.example.com/auth/verify?token=abc'
    );
  });

  it('keeps a path the issuer carries, which new URL(path, issuer) would drop', () => {
    expect(buildRealmUrl({ issuer: 'https://example.com/auth' }, '/oauth/token')).toBe(
      'https://example.com/auth/oauth/token'
    );
  });

  it.each(['oauth/token', '//evil.example/oauth/token', '', '.evil.example/x'])(
    'refuses the path %j, which would join into another host or label',
    (path) => {
      expect(() => buildRealmUrl({ issuer: 'https://b.example.com' }, path)).toThrow(
        /must start with a single/
      );
    }
  );
});

describe('realmTokenIssuer', () => {
  it('is the realm issuer for the realm the JWT plugin signs for', () => {
    const fastify = serverSigningWith('https://a.example.com');

    expect(realmTokenIssuer(fastify, { issuer: 'https://a.example.com' })).toBe(
      'https://a.example.com'
    );
  });

  it('keeps the trailing slash JWT_ISSUER gives the tokens, which the realm row drops', () => {
    const fastify = serverSigningWith('https://a.example.com/');

    expect(realmTokenIssuer(fastify, { issuer: 'https://a.example.com' })).toBe(
      'https://a.example.com/'
    );
  });

  it("is another realm's own issuer, never the plugin's", () => {
    const fastify = serverSigningWith('https://a.example.com/');

    expect(realmTokenIssuer(fastify, { issuer: 'https://b.example.com' })).toBe(
      'https://b.example.com'
    );
  });
});
