import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { getJsonObject } from '../../helpers/http';

const { baseUrl } = wireConfig();

/**
 * How a client first touches each endpoint a discovery document names: the
 * method the endpoint serves, and a request that carries no credential and no
 * valid parameters, so nothing is created. Every one must reach a route —
 * answer with the endpoint's own refusal or document — and none may answer as
 * a path that does not exist, or fail.
 */
const PROBES: Record<string, { readonly method: 'GET' | 'POST'; readonly body?: string }> = {
  authorization_endpoint: { method: 'GET' },
  token_endpoint: { method: 'POST', body: 'grant_type=' },
  introspection_endpoint: { method: 'POST', body: 'token=wire-suite-not-a-token' },
  revocation_endpoint: { method: 'POST', body: 'token=wire-suite-not-a-token' },
  userinfo_endpoint: { method: 'GET' },
  jwks_uri: { method: 'GET' },
};

/** Registration takes JSON (RFC 7591 §3.1); an empty object registers nothing. */
const REGISTRATION_PROBE = { method: 'POST', body: '{}' } as const;

/** The URL members of a discovery document: every `*_endpoint` and `jwks_uri`. */
function endpointMembers(document: Record<string, unknown>): [string, string][] {
  return Object.entries(document)
    .filter(([member]) => member.endsWith('_endpoint') || member === 'jwks_uri')
    .map(([member, value]) => {
      expect(value, member).toBeTypeOf('string');
      return [member, value as string];
    });
}

async function probe(member: string, url: string): Promise<Response> {
  const isRegistration = member === 'registration_endpoint';
  const known = isRegistration ? REGISTRATION_PROBE : PROBES[member];
  expect(known, `no probe for the advertised ${member}`).toBeDefined();
  return fetch(url, {
    method: known.method,
    redirect: 'manual',
    ...(known.body === undefined
      ? {}
      : {
          body: known.body,
          headers: {
            'content-type': isRegistration
              ? 'application/json'
              : 'application/x-www-form-urlencoded',
          },
        }),
  });
}

describe.each([
  ['RFC 8414 §2', '/.well-known/oauth-authorization-server'],
  ['OIDC Discovery 1.0 §3', '/.well-known/openid-configuration'],
])('%s — every endpoint the discovery document advertises', (_spec, path) => {
  it('lives under the issuer and answers as a route, never as a path that does not exist', async () => {
    const { body: document } = await getJsonObject(serverPath(baseUrl, path));
    const unknown = await fetch(serverPath(baseUrl, `/wire-suite/no-such-route/${randomUUID()}`), {
      redirect: 'manual',
    });
    expect(unknown.status).toBe(404);
    await unknown.body?.cancel();

    const members = endpointMembers(document);
    expect(members.map(([member]) => member)).toEqual(
      expect.arrayContaining(['authorization_endpoint', 'token_endpoint', 'jwks_uri'])
    );
    for (const [member, url] of members) {
      expect(url.startsWith(`${baseUrl.replace(/\/$/, '')}/`), `${member} ${url}`).toBe(true);

      const response = await probe(member, url);
      const text = await response.text();
      const context = `${member} ${url} answered ${response.status}: ${text.slice(0, 300)}`;
      expect(response.status, context).not.toBe(404);
      expect(response.status, context).toBeLessThan(500);
      expect(response.headers.get('content-type') ?? '', context).toMatch(/json/i);
    }
  });
});
