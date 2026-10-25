import {
  BadRequestError,
  ForbiddenError,
  InvalidClientError,
  InvalidGrantError,
  InvalidScopeError,
  JWTExpiredError,
  JWTInvalidError,
  NotFoundError,
  TemporarilyUnavailableError,
  TooManyRequestsError,
  UnauthorizedClientError,
} from '@qauth-labs/shared-errors';
import { parseEvent } from '@qauth-labs/shared-events';
import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { emitUserEvent, oauthErrorCode, userEventFor } from './user-events';

const REALM_ID = '0b5c1f3e-8a4d-4c2b-9f6e-1d2a3b4c5d6e';
const REQUEST_REALM_ID = '7d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6';
const USER_ID = '3f6c2a1b-9d8e-4f7a-b6c5-d4e3f2a1b0c9';

function createRequest(
  overrides: { headers?: Record<string, string>; ip?: string; realm?: { id: string } | null } = {}
) {
  const events = {
    emit: vi.fn().mockResolvedValue('event-in-tx'),
    emitInOwnTransaction: vi.fn().mockResolvedValue('event-own-tx'),
  };
  const request = {
    id: 'req-42',
    method: 'GET',
    ip: overrides.ip ?? '203.0.113.7',
    headers: overrides.headers ?? { 'user-agent': 'vitest-agent' },
    // The realm the resolver found through the request's host (#486).
    realm:
      overrides.realm === undefined ? { id: REQUEST_REALM_ID, name: 'tenant' } : overrides.realm,
    routeOptions: { url: '/probe' },
    server: { repositories: { events } },
  } as unknown as FastifyRequest;
  return { request, events };
}

describe('emitUserEvent', () => {
  it('fills the realm, the request, the subject, the client and the actor', async () => {
    const { request, events } = createRequest();

    const id = await emitUserEvent(
      request,
      'urn:qauth:event:user.signed_in:v1-rc.0',
      { method: 'password' },
      { realmId: REALM_ID, userId: USER_ID, clientId: 'portal', actor: 'user' }
    );

    expect(id).toBe('event-own-tx');
    expect(events.emit).not.toHaveBeenCalled();
    expect(events.emitInOwnTransaction).toHaveBeenCalledWith({
      type: 'urn:qauth:event:user.signed_in:v1-rc.0',
      realm: REALM_ID,
      actor: { type: 'user', id: USER_ID },
      subject: { type: 'user', id: USER_ID },
      client: { id: 'portal' },
      request: { traceId: 'req-42', ip: '203.0.113.7', userAgent: 'vitest-agent' },
      data: { method: 'password' },
    });
  });

  it('writes in the handler transaction when it is given one', async () => {
    const { request, events } = createRequest();
    const tx = { marker: 'tx' } as never;

    const id = await emitUserEvent(
      request,
      'urn:qauth:event:user.registered:v1-rc.0',
      { method: 'password' },
      { realmId: REALM_ID, userId: USER_ID, actor: 'user', tx }
    );

    expect(id).toBe('event-in-tx');
    expect(events.emitInOwnTransaction).not.toHaveBeenCalled();
    expect(events.emit).toHaveBeenCalledWith(
      tx,
      expect.objectContaining({ type: 'urn:qauth:event:user.registered:v1-rc.0', realm: REALM_ID })
    );
  });

  it('takes the request’s realm when the handler names none (#487)', async () => {
    const { request, events } = createRequest();

    await emitUserEvent(
      request,
      'urn:qauth:event:userinfo.served:v1-rc.0',
      {},
      { userId: USER_ID }
    );

    expect(events.emitInOwnTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ realm: REQUEST_REALM_ID })
    );
  });

  it('keeps the realm the handler names over the request’s', async () => {
    const { request, events } = createRequest();

    await emitUserEvent(
      request,
      'urn:qauth:event:userinfo.served:v1-rc.0',
      {},
      { realmId: REALM_ID, userId: USER_ID }
    );

    expect(events.emitInOwnTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ realm: REALM_ID })
    );
  });

  it('refuses to guess a realm when the request has none and the handler names none', async () => {
    const { request, events } = createRequest({ realm: null });

    await expect(
      emitUserEvent(request, 'urn:qauth:event:userinfo.served:v1-rc.0', {}, { userId: USER_ID })
    ).rejects.toThrow('has no resolved realm');
    expect(events.emitInOwnTransaction).not.toHaveBeenCalled();
  });

  it('makes the acting client of a delegated request the actor, with the whole chain', async () => {
    const { request, events } = createRequest();

    await emitUserEvent(
      request,
      'urn:qauth:event:token.issued:v1-rc.0',
      { grantType: 'urn:ietf:params:oauth:grant-type:token-exchange', scopeMode: 'exec' },
      {
        realmId: REALM_ID,
        userId: USER_ID,
        clientId: 'agent-b',
        actor: 'client',
        act: { sub: 'agent-b', act: { sub: 'agent-a' } },
      }
    );

    const [event] = events.emitInOwnTransaction.mock.calls[0];
    expect(event.actor).toEqual({
      type: 'client',
      id: 'agent-b',
      delegationChain: ['agent-b', 'agent-a'],
    });
    expect(event.client).toEqual({ id: 'agent-b' });
    expect(event.data).toEqual({
      grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
      scopeMode: 'exec',
    });
  });

  it('names the client as the actor of an undelegated client request', async () => {
    const { request, events } = createRequest();

    await emitUserEvent(
      request,
      'urn:qauth:event:token.issued:v1-rc.0',
      { grantType: 'client_credentials' },
      { realmId: REALM_ID, clientId: 'service', actor: 'client' }
    );

    const [event] = events.emitInOwnTransaction.mock.calls[0];
    expect(event.actor).toEqual({ type: 'client', id: 'service' });
    expect(event).not.toHaveProperty('subject');
  });

  it('leaves the actor out when the options name none, or name one without its id', async () => {
    const { request, events } = createRequest();

    await emitUserEvent(
      request,
      'urn:qauth:event:token.request_failed:v1-rc.0',
      { error: 'invalid_client' },
      { realmId: REALM_ID, actor: 'client', clientId: null }
    );

    const [event] = events.emitInOwnTransaction.mock.calls[0];
    expect(event).not.toHaveProperty('actor');
    expect(event).not.toHaveProperty('client');
  });

  it('gives a subject only to a type whose subject is a user', async () => {
    const { request, events } = createRequest();

    await emitUserEvent(
      request,
      'urn:qauth:event:token.revocation_failed:v1-rc.0',
      { error: 'invalid_client' },
      { realmId: REALM_ID, userId: USER_ID }
    );

    const [event] = events.emitInOwnTransaction.mock.calls[0];
    expect(event).not.toHaveProperty('subject');
  });

  it('takes an explicit subject for a client or API key type', async () => {
    const { request, events } = createRequest();

    await emitUserEvent(
      request,
      'urn:qauth:event:api_key.created:v1-rc.0',
      {},
      { realmId: REALM_ID, subject: { type: 'api_key', id: 'key-1' }, clientId: 'portal' }
    );

    const [event] = events.emitInOwnTransaction.mock.calls[0];
    expect(event.subject).toEqual({ type: 'api_key', id: 'key-1' });
  });

  it('fails the request when the write fails', async () => {
    const { request, events } = createRequest();
    events.emitInOwnTransaction.mockRejectedValueOnce(new Error('connection refused'));

    await expect(
      emitUserEvent(request, 'urn:qauth:event:userinfo.served:v1-rc.0', {}, { realmId: REALM_ID })
    ).rejects.toThrow('connection refused');
  });
});

describe('userEventFor', () => {
  it('sizes what the client controls, so a long header cannot fail the event', () => {
    const { request } = createRequest({
      headers: { 'user-agent': 'x'.repeat(5000) },
      ip: '::ffff:198.51.100.4',
    });

    const event = userEventFor(
      request,
      'urn:qauth:event:userinfo.served:v1-rc.0',
      {},
      { userId: USER_ID },
      REALM_ID
    );

    expect(event.request).toEqual({
      traceId: 'req-42',
      ip: '198.51.100.4',
      userAgent: 'x'.repeat(1024),
    });
  });

  it('builds an event the contract accepts', () => {
    const { request } = createRequest();

    const event = userEventFor(
      request,
      'urn:qauth:event:consent.revoked:v1-rc.0',
      { consentId: '5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d', revokedRefreshCount: 2 },
      { userId: USER_ID, clientId: 'portal', actor: 'user' },
      REALM_ID
    );

    expect(() =>
      parseEvent({
        id: '01920000-0000-7000-8000-000000000001',
        time: new Date(0).toISOString(),
        category: 'user',
        ...event,
      })
    ).not.toThrow();
  });
});

describe('oauthErrorCode', () => {
  it.each([
    [new InvalidGrantError('code expired'), 'invalid_grant'],
    [new InvalidClientError(), 'invalid_client'],
    [new InvalidScopeError(), 'invalid_scope'],
    [new UnauthorizedClientError(), 'unauthorized_client'],
    [new BadRequestError('unsupported_grant_type'), 'unsupported_grant_type'],
    [new BadRequestError('Missing redirect_uri'), 'invalid_request'],
    [new JWTInvalidError('bad signature'), 'invalid_token'],
    [new JWTExpiredError('expired'), 'invalid_token'],
    [new ForbiddenError('no'), 'access_denied'],
    [new NotFoundError('Client', 'x'), 'invalid_request'],
    [new TooManyRequestsError('slow down'), 'temporarily_unavailable'],
    [new TemporarilyUnavailableError(1), 'temporarily_unavailable'],
    [new Error('connection reset'), 'server_error'],
    ['not an error', 'server_error'],
  ])('maps %s to %s', (error, code) => {
    expect(oauthErrorCode(error)).toBe(code);
  });
});
