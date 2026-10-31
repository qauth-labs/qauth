import { randomUUID } from 'node:crypto';

import { beforeAll, describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import {
  authorizationRequest,
  authorizeAs,
  newBrowser,
  SEEDED_REDIRECT_URI,
  type SignedInBrowser,
} from '../../fixtures/authorization';
import { expectOAuthError } from '../../helpers/error-shape';
import { getJsonObject } from '../../helpers/http';
import { call } from '../../helpers/operations';

/**
 * The authorization endpoint, as a browser and a client see it: what it
 * refuses before any user interaction, how it answers a request it can send
 * back to the client, and the RFC 9207 issuer on every answer it sends there.
 */

const { baseUrl } = wireConfig();

/** The issuer the discovery documents publish, which every `iss` must repeat. */
async function publishedIssuer(): Promise<string> {
  const { body } = await getJsonObject(
    serverPath(baseUrl, '/.well-known/oauth-authorization-server')
  );
  return body['issuer'] as string;
}

/**
 * Assert that a response refused the request on the issuer: a 400 with the
 * RFC 6749 §5.2 body, and no `Location`, so the browser is sent nowhere.
 */
async function expectRefusedWithoutRedirect(response: Response, error = 'invalid_request') {
  expect(response.headers.get('location'), 'the refusal must not redirect').toBeNull();
  return expectOAuthError(response, { status: 400, error });
}

/** The redirect an operator-provisioned client gets, read as an authorization response. */
function redirectResponse(response: Response): URL {
  expect(response.status, 'an authorization response is a 302').toBe(302);
  const location = response.headers.get('location');
  expect(location, 'the 302 names a Location').not.toBeNull();
  const url = new URL(location as string);
  expect(url.origin + url.pathname, 'sent to the registered redirect URI').toBe(
    SEEDED_REDIRECT_URI
  );
  return url;
}

describe('RFC 7636 §4.4.1 — an authorization request without a valid PKCE challenge', () => {
  it('refuses a request with no code_challenge with 400 invalid_request, issuing no code (§4.4.1)', async () => {
    const { params } = authorizationRequest({ code_challenge: null });

    await expectRefusedWithoutRedirect(await call('GET /oauth/authorize', { query: params }));
  });

  it('refuses the plain transform, accepting S256 only (§4.2, §4.4.1)', async () => {
    const request = authorizationRequest();
    request.params.set('code_challenge', request.pkce.verifier);
    request.params.set('code_challenge_method', 'plain');

    await expectRefusedWithoutRedirect(
      await call('GET /oauth/authorize', { query: request.params })
    );
  });

  it('refuses a challenge sent without its method rather than reading it as plain (§4.3)', async () => {
    const { params } = authorizationRequest({ code_challenge_method: null });

    await expectRefusedWithoutRedirect(await call('GET /oauth/authorize', { query: params }));
  });

  it('refuses a form-encoded POST with no code_challenge identically to GET (OIDC Core 1.0 §3.1.2.1)', async () => {
    const { params } = authorizationRequest({ code_challenge: null });

    const viaGet = await expectRefusedWithoutRedirect(
      await call('GET /oauth/authorize', { query: params })
    );
    const viaPost = await expectRefusedWithoutRedirect(
      await call('POST /oauth/authorize', { form: params })
    );

    expect(viaPost).toEqual(viaGet);
  });
});

describe('RFC 6749 §4.1.2.1 — a request whose client or redirect URI does not check out', () => {
  it('refuses a redirect_uri the client did not register and never redirects to it (§4.1.2.1, §3.1.2.2)', async () => {
    const { params } = authorizationRequest({
      redirect_uri: 'https://wire-suite.example/callback',
    });

    await expectRefusedWithoutRedirect(await call('GET /oauth/authorize', { query: params }));
  });

  it('refuses another path on the registered loopback host: only the port may vary (§3.1.2.3; RFC 8252 §7.3)', async () => {
    const { params } = authorizationRequest({
      redirect_uri: 'http://127.0.0.1:9/wire-suite/elsewhere',
    });

    await expectRefusedWithoutRedirect(await call('GET /oauth/authorize', { query: params }));
  });

  it('refuses a client_id that names no client, without redirecting (§4.1.2.1)', async () => {
    const { params } = authorizationRequest({ client_id: `wire-suite-${randomUUID()}` });

    await expectRefusedWithoutRedirect(await call('GET /oauth/authorize', { query: params }));
  });
});

describe('RFC 9207 §2 — iss on every authorization response', () => {
  it('adds the iss equal to the published issuer to a login_required error under prompt=none (§2, §2.3; OIDC Core 1.0 §3.1.2.1)', async () => {
    const request = authorizationRequest({ prompt: 'none' });

    const url = redirectResponse(await call('GET /oauth/authorize', { query: request.params }));

    expect(url.searchParams.get('error')).toBe('login_required');
    expect(url.searchParams.get('state')).toBe(request.state);
    expect(url.searchParams.get('iss')).toBe(await publishedIssuer());
    expect(url.searchParams.get('iss')).toBe(baseUrl);
    expect(url.searchParams.has('code')).toBe(false);
  });

  it('answers a form-encoded POST identically to GET, iss included (OIDC Core 1.0 §3.1.2.1)', async () => {
    const { params } = authorizationRequest({ prompt: 'none' });

    const viaGet = redirectResponse(await call('GET /oauth/authorize', { query: params }));
    const viaPost = redirectResponse(await call('POST /oauth/authorize', { form: params }));

    expect([...viaPost.searchParams].sort()).toEqual([...viaGet.searchParams].sort());
    expect(viaPost.searchParams.get('iss')).toBe(baseUrl);
  });

  describe('with a signed-in user', () => {
    let session: SignedInBrowser;

    beforeAll(async () => {
      session = await newBrowser();
    });

    // `prompt=consent` shows the consent screen whatever the user allowed
    // before, so this test does not depend on the order the tests run in.
    it('adds iss to the access_denied error the user’s denial sends back (§2; RFC 6749 §4.1.2.1)', async () => {
      const request = authorizationRequest({ prompt: 'consent' });

      const response = await authorizeAs(session, request, {
        decision: 'deny',
        rememberConsent: false,
      });

      expect(response.pages).toContain('consent');
      expect(response.params.get('error')).toBe('access_denied');
      expect(response.params.get('state')).toBe(request.state);
      expect(response.params.get('iss')).toBe(baseUrl);
      expect(response.params.has('code')).toBe(false);
    });

    it('adds iss on the success response, beside the code and the unchanged state (§2; RFC 6749 §4.1.2)', async () => {
      const request = authorizationRequest();

      const response = await authorizeAs(session, request);

      expect(response.params.get('code')).toMatch(/\S/);
      expect(response.params.get('state')).toBe(request.state);
      expect(response.params.get('iss')).toBe(baseUrl);
      expect(response.params.has('error')).toBe(false);
    });
  });
});
