import { describe, expect, it, vi } from 'vitest';

import { createAccountClient, OPERATIONS } from '../generated/account-api';
import { expandPath, queryString, UnexpectedStatusError } from './runtime';

const PASSKEY_ID = '019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b';

/** A `fetch` that records each call and answers `status` with `body`. */
function recordingFetch(status: number, body?: unknown, contentType = 'application/json') {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetch = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: body === undefined ? {} : { 'content-type': contentType },
    });
  });
  return { fetch, calls };
}

const headersOf = (init: RequestInit) => init.headers as Record<string, string>;

describe('the account API client', () => {
  it('sends the token under Bearer, with no cookie, and never follows a redirect', async () => {
    const { fetch, calls } = recordingFetch(200, { remaining: 8, issuedAt: null });
    const client = createAccountClient({
      baseUrl: 'https://auth.example.com',
      accessToken: 'at-1',
      fetch,
    });
    const result = await client.recoveryCodesGet();
    expect(result.status).toBe(200);
    expect(result.data).toEqual({ remaining: 8, issuedAt: null });
    expect(calls[0]?.url).toBe('https://auth.example.com/account/v1-rc.0/recovery-codes');
    expect(calls[0]?.init).toMatchObject({
      method: 'GET',
      credentials: 'omit',
      redirect: 'manual',
    });
    expect(headersOf(calls[0]?.init ?? {})['authorization']).toBe('Bearer at-1');
  });

  it('sends a DPoP-bound token under DPoP, with a proof for the URL without its query', async () => {
    const { fetch, calls } = recordingFetch(200, { items: [], nextCursor: null });
    const dpopProof = vi.fn(async () => 'proof-jwt');
    const client = createAccountClient({
      baseUrl: 'https://auth.example.com',
      accessToken: async () => 'at-2',
      dpopProof,
      fetch,
    });
    await client.securityLogList({ query: { limit: 20, kind: 'new_device' } });
    expect(calls[0]?.url).toBe(
      'https://auth.example.com/account/v1-rc.0/security-log?limit=20&kind=new_device'
    );
    expect(dpopProof).toHaveBeenCalledWith({
      method: 'GET',
      url: 'https://auth.example.com/account/v1-rc.0/security-log',
      accessToken: 'at-2',
    });
    expect(headersOf(calls[0]?.init ?? {})).toMatchObject({
      authorization: 'DPoP at-2',
      dpop: 'proof-jwt',
    });
  });

  it('sends an update as a Merge Patch with If-Match', async () => {
    const { fetch, calls } = recordingFetch(
      412,
      {
        type: 'https://docs.qauth.dev/reference/problem-types/#precondition-failed',
        title: 'Precondition failed',
        status: 412,
        code: 'precondition_failed',
        trace_id: 't-1',
      },
      'application/problem+json'
    );
    const client = createAccountClient({
      baseUrl: 'https://auth.example.com',
      accessToken: 'at',
      fetch,
    });
    const result = await client.passkeysUpdate({
      path: { passkeyId: PASSKEY_ID },
      headers: { 'If-Match': '"v1"' },
      body: { nickname: 'Laptop' },
    });
    expect(result.status).toBe(412);
    expect(calls[0]?.url).toBe(`https://auth.example.com/account/v1-rc.0/passkeys/${PASSKEY_ID}`);
    expect(calls[0]?.init.method).toBe('PATCH');
    expect(calls[0]?.init.body).toBe('{"nickname":"Laptop"}');
    expect(headersOf(calls[0]?.init ?? {})).toMatchObject({
      'content-type': 'application/merge-patch+json',
      'if-match': '"v1"',
    });
  });

  it('keeps the caller’s extra headers from replacing its own', async () => {
    const { fetch, calls } = recordingFetch(204);
    const client = createAccountClient({
      baseUrl: 'https://auth.example.com',
      accessToken: 'at',
      fetch,
      headers: { Authorization: 'Bearer other', 'X-Request-Id': 'r-1' },
    });
    const result = await client.sessionsEndAll();
    expect(result.status).toBe(204);
    expect(result.data).toBeUndefined();
    const headers = headersOf(calls[0]?.init ?? {});
    expect(headers['authorization']).toBe('Bearer at');
    expect(headers['Authorization']).toBeUndefined();
    expect(headers['X-Request-Id']).toBe('r-1');
    expect(calls[0]?.init.body).toBeUndefined();
  });

  it('refuses a status the document does not declare, such as a redirect', async () => {
    const { fetch } = recordingFetch(302);
    const client = createAccountClient({
      baseUrl: 'https://auth.example.com',
      accessToken: 'at',
      fetch,
    });
    await expect(client.profileGet()).rejects.toBeInstanceOf(UnexpectedStatusError);
  });

  it('refuses a path parameter that would leave its segment', async () => {
    const { fetch, calls } = recordingFetch(204);
    const client = createAccountClient({
      baseUrl: 'https://auth.example.com',
      accessToken: 'at',
      fetch,
    });
    await expect(client.sessionsDelete({ path: { sessionId: '../deletion' } })).rejects.toThrow(
      /malformed/
    );
    expect(calls).toHaveLength(0);
    expect(() =>
      expandPath(
        '/x/{id}',
        { id: `${PASSKEY_ID}/..` },
        OPERATIONS['account.passkeys.get'].pathPatterns
      )
    ).toThrow(/missing or malformed/);
  });

  it('builds the query from the declared parameters only, skipping absent ones', () => {
    expect(queryString(['limit', 'cursor'], { cursor: 'abc', other: 'x' })).toBe('?cursor=abc');
    expect(queryString(['limit'], undefined)).toBe('');
    expect(() => queryString(['limit'], { limit: { a: 1 } })).toThrow(/not a scalar/);
  });

  it('records what each operation asks of the token', () => {
    expect(OPERATIONS['account.deletion.create']).toMatchObject({
      freshAuthentication: 'strongest-factor',
      actChain: 'refused',
    });
    expect(OPERATIONS['account.consents.delete']).toMatchObject({
      freshAuthentication: 'none',
      actChain: 'accepted',
    });
  });
});
