import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { getJsonObject } from '../../helpers/http';
import { call } from '../../helpers/operations';

const { baseUrl } = wireConfig();
const documentUrl = serverPath(baseUrl, '/.well-known/openid-configuration');

describe('OIDC Discovery 1.0 §4 — the provider configuration document, over HTTP', () => {
  it('answers a GET at the issuer plus the well-known path with 200 and an application/json object (§4.1, §4.2)', async () => {
    const response = await call('GET /.well-known/openid-configuration');
    const text = await response.text();

    expect(response.status, text).toBe(200);
    expect(response.headers.get('content-type') ?? '').toMatch(/^application\/json\b/i);
    const body: unknown = JSON.parse(text);
    expect(body !== null && typeof body === 'object' && !Array.isArray(body)).toBe(true);
    expect(Object.keys(body as object).length).toBeGreaterThan(0);
  });

  it('reports an issuer identical to the base URL the document was fetched from (§4.3)', async () => {
    const { body } = await getJsonObject(documentUrl);

    expect(body['issuer']).toBe(baseUrl);
  });
});

describe('OIDC Discovery 1.0 §3 — the provider metadata', () => {
  it('is a document superset of the AS metadata, with its issuer and public subject identifiers (§3)', async () => {
    const { body: configuration } = await getJsonObject(documentUrl);
    const { body: metadata } = await getJsonObject(
      serverPath(baseUrl, '/.well-known/oauth-authorization-server')
    );

    // Every member of the RFC 8414 document, with the same value.
    for (const [member, value] of Object.entries(metadata)) {
      expect(configuration[member], member).toEqual(value);
    }
    expect(configuration['issuer']).toBe(baseUrl);
    expect(configuration['subject_types_supported']).toContain('public');
    expect(configuration['userinfo_endpoint']).toBe(serverPath(baseUrl, '/oauth/userinfo'));
    const algorithms = configuration['id_token_signing_alg_values_supported'];
    expect(Array.isArray(algorithms) && algorithms.length > 0).toBe(true);
  });

  it('carries the request/request_uri flags into the OIDC config, both false (OIDC Discovery 1.0 §3)', async () => {
    const { body } = await getJsonObject(documentUrl);

    // Omitted, request_uri_parameter_supported would default to true.
    expect(body['request_parameter_supported']).toBe(false);
    expect(body['request_uri_parameter_supported']).toBe(false);
  });

  it('advertises the default scope list, openid included (§3)', async () => {
    const { body } = await getJsonObject(documentUrl);

    expect(body['scopes_supported']).toEqual(
      expect.arrayContaining(['openid', 'profile', 'email', 'offline_access'])
    );
  });

  it('lists the claims the ID token carries in claims_supported (§3)', async () => {
    const { body } = await getJsonObject(documentUrl);

    expect(body['claims_supported']).toEqual(
      expect.arrayContaining(['sub', 'iss', 'aud', 'exp', 'iat'])
    );
  });
});
