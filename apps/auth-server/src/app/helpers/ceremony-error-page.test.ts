import type { FastifyReply, FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { testPolicyStore } from '../../testing/realm-policies';
import { testRealm } from '../../testing/request-realm';
import {
  ceremonyErrorPageOf,
  ceremonyErrorPageUrl,
  sendToCeremonyErrorPage,
} from './ceremony-error-page';

/**
 * THE CEREMONY APP'S ERROR PAGE (#1106): the realm's `ceremonyApp.errorPage`
 * policy, and the URL the auth server sends the browser to for an ending
 * that leaves no interaction: on the realm's issuer, with `code`, the
 * request's id as `trace_id`, and a logout's facts.
 */

const REALM = testRealm({ id: '44444444-4444-4444-8444-444444444444' });

function requestWithId(id: string): FastifyRequest {
  return { id, realm: REALM } as unknown as FastifyRequest;
}

describe('ceremonyErrorPageOf (#1106)', () => {
  it("reads the realm's policy, none by default", () => {
    expect(ceremonyErrorPageOf({ policyStore: testPolicyStore() } as never, REALM)).toBeNull();
    const store = testPolicyStore({}, { ceremonyApp: { errorPage: '/ui/error' } });
    expect(ceremonyErrorPageOf({ policyStore: store } as never, REALM)).toBe('/ui/error');
    expect(store.ofRealm).toHaveBeenCalledWith(REALM);
  });
});

describe('ceremonyErrorPageUrl (#1106)', () => {
  it("builds the page's URL on the realm's issuer, with the code and the request's id", () => {
    const url = new URL(
      ceremonyErrorPageUrl(requestWithId('9b2c4f1e-trace'), '/ui/error', 'interaction_expired')
    );
    expect(url.origin + url.pathname).toBe(`${REALM.issuer}/ui/error`);
    expect([...url.searchParams]).toEqual([
      ['code', 'interaction_expired'],
      ['trace_id', '9b2c4f1e-trace'],
    ]);
  });

  it("adds a logout's facts, the host as text", () => {
    const url = new URL(
      ceremonyErrorPageUrl(requestWithId('req-1'), '/ui/a/b', 'logout_finished', {
        signedOut: true,
        host: 'notes.example.com',
      })
    );
    expect(url.pathname).toBe('/ui/a/b');
    expect([...url.searchParams]).toEqual([
      ['code', 'logout_finished'],
      ['trace_id', 'req-1'],
      ['signed_out', 'true'],
      ['host', 'notes.example.com'],
    ]);
    expect(
      new URL(
        ceremonyErrorPageUrl(requestWithId('req-2'), '/ui/error', 'logout_finished', {
          signedOut: false,
        })
      ).searchParams.get('signed_out')
    ).toBe('false');
  });

  it('leaves out a request id a trace_id cannot carry', () => {
    for (const id of ['x'.repeat(129), 'has space', 'quote"d', 'é']) {
      const url = new URL(ceremonyErrorPageUrl(requestWithId(id), '/ui/error', 'logout_refused'));
      expect([...url.searchParams], id).toEqual([['code', 'logout_refused']]);
    }
  });
});

describe('sendToCeremonyErrorPage (#1106)', () => {
  it('answers 303 to the page, with nothing to cache', () => {
    const reply = { header: vi.fn(), redirect: vi.fn() };
    reply.header.mockReturnValue(reply);
    sendToCeremonyErrorPage(
      requestWithId('req-3'),
      reply as unknown as FastifyReply,
      '/ui/error',
      'interaction_expired'
    );
    expect(reply.header).toHaveBeenCalledWith('Cache-Control', 'no-store');
    expect(reply.redirect).toHaveBeenCalledWith(
      `${REALM.issuer}/ui/error?code=interaction_expired&trace_id=req-3`,
      303
    );
  });
});
