import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { getJsonObject } from '../../helpers/http';
import { call } from '../../helpers/operations';

const { baseUrl } = wireConfig();
const documentUrl = serverPath(baseUrl, '/.well-known/oauth-authorization-server');

/** The endpoint members the metadata names, and the path each is served at. */
const ENDPOINTS: readonly (readonly [member: string, path: string])[] = [
  ['authorization_endpoint', '/oauth/authorize'],
  ['token_endpoint', '/oauth/token'],
  ['introspection_endpoint', '/oauth/introspect'],
  ['revocation_endpoint', '/oauth/revoke'],
  ['registration_endpoint', '/oauth/register'],
  ['jwks_uri', '/.well-known/jwks.json'],
];

describe('RFC 8414 §3 — authorization server metadata, over HTTP', () => {
  it('answers a GET at the well-known URL with 200 and an application/json object (§3.1, §3.2)', async () => {
    const response = await call('GET /.well-known/oauth-authorization-server');
    const text = await response.text();

    expect(response.status, text).toBe(200);
    expect(response.headers.get('content-type') ?? '').toMatch(/^application\/json\b/i);
    const body: unknown = JSON.parse(text);
    expect(body !== null && typeof body === 'object' && !Array.isArray(body)).toBe(true);
    expect(Object.keys(body as object).length).toBeGreaterThan(0);
  });

  it('reports an issuer identical to the issuer identifier the well-known URL was built from (§3.3)', async () => {
    const { body } = await getJsonObject(documentUrl);

    expect(body['issuer']).toBe(baseUrl);
  });
});

describe('RFC 8414 §2 — the metadata members', () => {
  it('publishes the required fields anchored on the issuer, with no query or fragment (§2)', async () => {
    const { body } = await getJsonObject(documentUrl);

    const issuer = new URL(body['issuer'] as string);
    expect(issuer.search).toBe('');
    expect(issuer.hash).toBe('');
    for (const [member, path] of ENDPOINTS) {
      expect(body[member], member).toBe(serverPath(baseUrl, path));
    }
  });

  it('advertises the response types, grants, and PKCE methods the server serves (§2)', async () => {
    const { body } = await getJsonObject(documentUrl);

    // The authorization code flow only: no implicit or hybrid response type.
    expect(body['response_types_supported']).toEqual(['code']);
    const grants = body['grant_types_supported'] as string[];
    for (const grant of ['authorization_code', 'refresh_token', 'client_credentials']) {
      expect(grants, grant).toContain(grant);
    }
    // OAuth 2.1 drops both; neither may be advertised.
    expect(grants).not.toContain('implicit');
    expect(grants).not.toContain('password');
    // RFC 7636 §4.2: S256 only, never `plain`.
    expect(body['code_challenge_methods_supported']).toEqual(['S256']);
  });

  it('advertises both client secret methods at the token, introspection and revocation endpoints (§2)', async () => {
    const { body } = await getJsonObject(documentUrl);

    for (const member of [
      'token_endpoint_auth_methods_supported',
      'introspection_endpoint_auth_methods_supported',
      'revocation_endpoint_auth_methods_supported',
    ]) {
      expect(body[member], member).toEqual(
        expect.arrayContaining(['client_secret_basic', 'client_secret_post'])
      );
    }
  });
});

describe('RFC 9207 §3 — the issuer identification metadata parameter', () => {
  it('advertises authorization_response_iss_parameter_supported as true (§3, §2.3)', async () => {
    const { body } = await getJsonObject(documentUrl);

    expect(body['authorization_response_iss_parameter_supported']).toBe(true);
  });
});
