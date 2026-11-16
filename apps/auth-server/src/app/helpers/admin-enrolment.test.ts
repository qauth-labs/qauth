import { WebAuthnRejection } from '@qauth-labs/fastify-plugin-federation';
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import { stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { testPolicyStore } from '../../testing/realm-policies';
import { testRealm } from '../../testing/request-realm';
import {
  ADMIN_ENROLMENT_STEP,
  adminAccountNameOf,
  adminEnrolmentEndUrl,
  answerAdminEnrolmentStatus,
  decideAdminEnrolment,
  sendAdminEnrolmentRefused,
  startAdminEnrolment,
} from './admin-enrolment';

const { startAdminEnrolmentInteraction } = vi.hoisted(() => ({
  startAdminEnrolmentInteraction: vi.fn(),
}));
// The interaction store is `interaction.test.ts`'s: here only what a start hands it.
vi.mock('./interaction', () => ({ startAdminEnrolmentInteraction }));

/**
 * THE ONE-TIME ADMIN ENROLMENT'S RULES (#621), with its repositories, the
 * WebAuthn provider and the interaction store faked: what a start reads and
 * refuses, what an answer stores and in which transaction, and where an
 * enrolment ends. `admin-enrolment.integration.test.ts` runs it end to end.
 */

const REALM_ID = '44444444-4444-4444-8444-444444444444';
const ENROLMENT_ID = '55555555-5555-4555-8555-555555555555';
const USER_ID = '66666666-6666-4666-8666-666666666666';
const CREDENTIAL_ID = '77777777-7777-4777-8777-777777777777';
const REALM = testRealm({ id: REALM_ID, webauthnRpId: null } as never);
const TOKEN = Buffer.alloc(32, 0xab).toString('base64url');
const HANDLE = Buffer.alloc(32, 0x11).toString('base64url');
const CEREMONY = Buffer.alloc(32, 0x22).toString('base64url');
const TX = Object.freeze({ tx: true });

/** The creation options the fake provider starts a ceremony with. */
function creationOptions(challenge: string) {
  return {
    rp: { id: 'auth.example.com', name: 'master' },
    user: { id: HANDLE, name: adminAccountNameOf(HANDLE), displayName: adminAccountNameOf(HANDLE) },
    challenge,
    pubKeyCredParams: [{ type: 'public-key', alg: -8 }],
    timeout: 300_000,
    excludeCredentials: [],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    },
    attestation: 'none',
    extensions: { credProps: true },
  };
}

function fakeProvider() {
  let n = 0;
  return {
    startRegistration: vi.fn(async () => creationOptions(`challenge-${(n += 1)}`)),
    finishRegistration: vi.fn(async () => ({
      externalSub: 'credential-id',
      rpId: 'auth.example.com',
      purpose: 'sign-in',
      attestationFormat: 'none',
      credentialData: { public_key: 'key', user_handle: HANDLE },
    })),
  };
}

function fakeServer(errorPage: string | null = null) {
  const repositories = {
    realms: {
      findById: vi.fn(async () => REALM),
      lockRpIdForEnrolment: vi.fn(async () => ({
        rpId: 'auth.example.com',
        lockedAt: 1,
        lockedNow: true,
      })),
    },
    users: { findById: vi.fn(async () => ({ id: USER_ID, enabled: true })) },
    adminEnrolments: {
      findRedeemable: vi.fn(async () => ({
        id: ENROLMENT_ID,
        realmId: REALM_ID,
        userId: USER_ID,
        createdAt: 1_000,
        expiresAt: 3_601_000,
      })),
      redeemEnrolment: vi.fn(async () => ({ id: ENROLMENT_ID }) as unknown),
    },
    userCredentials: {
      create: vi.fn(async (input: Record<string, unknown>) => ({ id: CREDENTIAL_ID, ...input })),
    },
    events: { emit: vi.fn(async () => 'event-id') },
    adminGrants: { recordSecurityChange: vi.fn(async () => 1) },
  };
  const fastify = {
    passkeySignIn: true,
    policyStore: testPolicyStore({}, errorPage === null ? {} : { ceremonyApp: { errorPage } }),
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    db: { transaction: vi.fn(async (work: (tx: unknown) => Promise<unknown>) => work(TX)) },
    repositories,
  };
  const request = {
    id: 'req-1',
    ip: '203.0.113.9',
    headers: {},
    realm: REALM,
    server: fastify,
    log: { info: vi.fn(), warn: vi.fn() },
  };
  return {
    fastify: fastify as unknown as FastifyInstance,
    request: request as unknown as FastifyRequest,
    repositories,
  };
}

/** The interaction state an answer to the step is decided in. */
function stateOf() {
  return {
    purpose: 'admin_enrolment' as const,
    request: { enrolmentId: ENROLMENT_ID, userId: USER_ID, ceremony: CEREMONY, userHandle: HANDLE },
    step: { name: ADMIN_ENROLMENT_STEP, params: {}, alternatives: [] },
    personal: {},
    transaction: { amr: [] },
    signInTransaction: null,
    revision: 0,
  };
}

function fakeReply() {
  const reply = {
    header: vi.fn(),
    code: vi.fn(),
    send: vi.fn(),
    redirect: vi.fn(),
  };
  reply.header.mockReturnValue(reply);
  reply.code.mockReturnValue(reply);
  return reply;
}

beforeEach(() => {
  startAdminEnrolmentInteraction.mockReset();
  startAdminEnrolmentInteraction.mockResolvedValue({ id: 'interaction-id', expiresAt: 1 });
});

describe('the admin enrolment step', () => {
  it('is the contract’s admin_enrolment, and names the account by its handle alone', () => {
    expect(ADMIN_ENROLMENT_STEP).toBe(stepUrn('admin_enrolment'));
    expect(adminAccountNameOf(HANDLE)).toBe(`admin-${HANDLE.slice(0, 8)}`);
  });
});

describe('startAdminEnrolment (#621)', () => {
  it('starts an interaction at the step for a redeemable token, reading and spending nothing else', async () => {
    const { fastify, request, repositories } = fakeServer();
    const provider = fakeProvider();
    const started = await startAdminEnrolment(
      fastify,
      request,
      {} as FastifyReply,
      TOKEN,
      provider as never
    );
    expect(started).toEqual({ kind: 'started', id: 'interaction-id' });
    expect(repositories.adminEnrolments.findRedeemable).toHaveBeenCalledWith(
      REALM_ID,
      TOKEN,
      expect.any(Number)
    );
    expect(repositories.adminEnrolments.redeemEnrolment).not.toHaveBeenCalled();

    const [registration] = provider.startRegistration.mock.calls[0] as unknown as [
      Record<string, unknown>,
    ];
    expect(registration).toMatchObject({
      purpose: 'sign-in',
      rp: { id: 'auth.example.com' },
      origins: ['https://auth.example.com'],
    });
    const [, , input] = startAdminEnrolmentInteraction.mock.calls[0] as [
      unknown,
      unknown,
      {
        request: Record<string, string>;
        step: { name: string; params: { options: Record<string, unknown> }; alternatives: [] };
        personal: { user: { id: string } };
        expiresAt: number;
      },
    ];
    // Never the token: the enrolment by its id, and the ceremony's keys.
    expect(Object.keys(input.request).sort()).toEqual([
      'ceremony',
      'enrolmentId',
      'userHandle',
      'userId',
    ]);
    expect(JSON.stringify(input)).not.toContain(TOKEN);
    expect(input.request).toMatchObject({ enrolmentId: ENROLMENT_ID, userId: USER_ID });
    expect(input.request['ceremony']).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(
      (registration as { transactionId: string }).transactionId.endsWith(input.request['ceremony'])
    ).toBe(true);
    expect(input.expiresAt).toBe(3_601_000);
    expect(input.step.name).toBe(ADMIN_ENROLMENT_STEP);
    expect(input.step.alternatives).toEqual([]);
    expect(input.step.params.options).toEqual({
      challenge: 'challenge-1',
      rp: { id: 'auth.example.com', name: 'master' },
      pubKeyCredParams: [{ type: 'public-key', alg: -8 }],
      timeout: 300_000,
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
    });
    expect(input.personal.user.id).toBe(HANDLE);
  });

  it('refuses every start while passkey sign-in is off, without reading the token', async () => {
    const { fastify, request, repositories } = fakeServer();
    (fastify as { passkeySignIn: boolean }).passkeySignIn = false;
    expect(
      await startAdminEnrolment(
        fastify,
        request,
        {} as FastifyReply,
        TOKEN,
        fakeProvider() as never
      )
    ).toEqual({ kind: 'refused' });
    expect(repositories.adminEnrolments.findRedeemable).not.toHaveBeenCalled();
    expect(startAdminEnrolmentInteraction).not.toHaveBeenCalled();
  });

  it('refuses a token that is not text, without reading the store', async () => {
    const { fastify, request, repositories } = fakeServer();
    for (const token of [undefined, null, ['a', 'b'], 7]) {
      expect(
        await startAdminEnrolment(
          fastify,
          request,
          {} as FastifyReply,
          token,
          fakeProvider() as never
        )
      ).toEqual({ kind: 'refused' });
    }
    expect(repositories.adminEnrolments.findRedeemable).not.toHaveBeenCalled();
    expect(startAdminEnrolmentInteraction).not.toHaveBeenCalled();
  });

  it('refuses a token that names no redeemable enrolment, and one for a disabled or missing account', async () => {
    const unredeemable = fakeServer();
    unredeemable.repositories.adminEnrolments.findRedeemable.mockResolvedValueOnce(
      undefined as never
    );
    const disabled = fakeServer();
    disabled.repositories.users.findById.mockResolvedValueOnce({ id: USER_ID, enabled: false });
    const missing = fakeServer();
    missing.repositories.users.findById.mockResolvedValueOnce(undefined as never);
    for (const { fastify, request } of [unredeemable, disabled, missing]) {
      const provider = fakeProvider();
      expect(
        await startAdminEnrolment(fastify, request, {} as FastifyReply, TOKEN, provider as never)
      ).toEqual({ kind: 'refused' });
      expect(provider.startRegistration).not.toHaveBeenCalled();
    }
    expect(startAdminEnrolmentInteraction).not.toHaveBeenCalled();
  });
});

describe('decideAdminEnrolment (#621)', () => {
  it('stores the passkey, spends the enrolment and records both events in one transaction', async () => {
    const { fastify, request, repositories } = fakeServer();
    const provider = fakeProvider();
    const answered = vi.fn();
    const decision = await decideAdminEnrolment(
      fastify,
      request,
      stateOf() as never,
      '{"id":"credential-id"}',
      answered,
      provider as never
    );
    expect(decision).toEqual({ kind: 'finished' });
    expect(answered).toHaveBeenCalledWith('enrolled');
    expect(provider.finishRegistration).toHaveBeenCalledWith({
      transactionId: `${REALM_ID}:admin-enrolment:${CEREMONY}`,
      response: { id: 'credential-id' },
    });
    // Only a webauthn credential: no password, ever.
    expect(repositories.userCredentials.create).toHaveBeenCalledTimes(1);
    expect(repositories.userCredentials.create).toHaveBeenCalledWith(
      expect.objectContaining({ userId: USER_ID, realmId: REALM_ID, providerType: 'webauthn' }),
      TX
    );
    expect(repositories.adminEnrolments.redeemEnrolment).toHaveBeenCalledWith(
      REALM_ID,
      ENROLMENT_ID,
      USER_ID,
      expect.any(Number),
      TX
    );
    const types = repositories.events.emit.mock.calls.map(
      (call) => (call as unknown as [unknown, { type: string }])[1].type
    );
    expect(types).toEqual([
      'urn:qauth:event:user.credential_added:v1-rc.0',
      'urn:qauth:event:admin.enrolment_completed:v1-rc.0',
    ]);
    for (const call of repositories.events.emit.mock.calls) {
      const [tx, event] = call as unknown as [unknown, Record<string, unknown>];
      expect(tx).toBe(TX);
      expect(event).toMatchObject({
        realm: REALM_ID,
        subject: { type: 'user', id: USER_ID },
        actor: { type: 'user', id: USER_ID },
        data: expect.objectContaining({ credentialId: CREDENTIAL_ID }),
      });
    }
    // The two-admin rule's record: the account cannot approve for 7 days.
    expect(repositories.adminGrants.recordSecurityChange).toHaveBeenCalledWith(
      REALM_ID,
      USER_ID,
      TX
    );
  });

  it('shows the step again with invalid_credentials and a new ceremony for a refused registration', async () => {
    const { fastify, request, repositories } = fakeServer();
    const provider = fakeProvider();
    provider.finishRegistration.mockRejectedValueOnce(new WebAuthnRejection('user-not-verified'));
    const answered = vi.fn();
    const decision = await decideAdminEnrolment(
      fastify,
      request,
      stateOf() as never,
      '{}',
      answered,
      provider as never
    );
    expect(decision).toMatchObject({
      kind: 'step',
      step: {
        name: ADMIN_ENROLMENT_STEP,
        error: 'invalid_credentials',
        alternatives: [],
        params: { options: { challenge: 'challenge-1' } },
      },
      personal: { user: { id: HANDLE } },
    });
    expect(provider.startRegistration).toHaveBeenCalledWith(
      expect.objectContaining({
        transactionId: `${REALM_ID}:admin-enrolment:${CEREMONY}`,
        user: expect.objectContaining({ handle: HANDLE }),
      })
    );
    expect(answered).not.toHaveBeenCalled();
    expect(repositories.userCredentials.create).not.toHaveBeenCalled();
    expect(repositories.adminEnrolments.redeemEnrolment).not.toHaveBeenCalled();
  });

  it('shows the step again for a credential id the realm already holds', async () => {
    const { fastify, request, repositories } = fakeServer();
    repositories.userCredentials.create.mockRejectedValueOnce(
      new UniqueConstraintError('user_credentials_realm_provider_sub')
    );
    const decision = await decideAdminEnrolment(
      fastify,
      request,
      stateOf() as never,
      '{}',
      vi.fn(),
      fakeProvider() as never
    );
    expect(decision).toMatchObject({ kind: 'step', step: { error: 'invalid_credentials' } });
    expect(repositories.adminEnrolments.redeemEnrolment).not.toHaveBeenCalled();
  });

  it('ends as refused, recording nothing, when the enrolment was spent or expired meanwhile', async () => {
    const { fastify, request, repositories } = fakeServer();
    repositories.adminEnrolments.redeemEnrolment.mockResolvedValueOnce(undefined);
    const answered = vi.fn();
    const decision = await decideAdminEnrolment(
      fastify,
      request,
      stateOf() as never,
      '{}',
      answered,
      fakeProvider() as never
    );
    expect(decision).toEqual({ kind: 'finished' });
    expect(answered).toHaveBeenCalledWith('refused');
    // The throw rolled the transaction back: no event was written in it.
    expect(repositories.events.emit).not.toHaveBeenCalled();
    expect(repositories.adminGrants.recordSecurityChange).not.toHaveBeenCalled();
  });

  it('fails, so the turn is given back, on an error that is no refusal', async () => {
    const { fastify, request } = fakeServer();
    const provider = fakeProvider();
    provider.finishRegistration.mockRejectedValueOnce(new Error('redis down'));
    await expect(
      decideAdminEnrolment(fastify, request, stateOf() as never, '{}', vi.fn(), provider as never)
    ).rejects.toThrow('redis down');
  });
});

describe('where an admin enrolment ends (#621)', () => {
  it('is the auth server’s status page while the realm names no error page', () => {
    const { fastify, request } = fakeServer();
    for (const result of ['enrolled', 'cancelled', 'refused'] as const) {
      expect(adminEnrolmentEndUrl(fastify, request, result)).toBe(
        `https://auth.example.com/auth/admin-enrolment/status?result=${result}`
      );
    }
  });

  it('is the realm’s error page when it names one', () => {
    const { fastify, request } = fakeServer('/ui/error');
    expect(adminEnrolmentEndUrl(fastify, request, 'enrolled')).toBe(
      'https://auth.example.com/ui/error?code=admin_enrolment_finished&trace_id=req-1&enrolled=true'
    );
    expect(adminEnrolmentEndUrl(fastify, request, 'cancelled')).toBe(
      'https://auth.example.com/ui/error?code=admin_enrolment_finished&trace_id=req-1&enrolled=false'
    );
    expect(adminEnrolmentEndUrl(fastify, request, 'refused')).toBe(
      'https://auth.example.com/ui/error?code=admin_enrolment_refused&trace_id=req-1'
    );
  });

  it('shows one refusal page for every refused start, or sends the browser to the error page', () => {
    const own = fakeServer();
    const reply = fakeReply();
    sendAdminEnrolmentRefused(own.fastify, own.request, reply as unknown as FastifyReply);
    expect(reply.code).toHaveBeenCalledWith(400);
    expect(reply.header).toHaveBeenCalledWith('Cache-Control', 'no-store');
    expect(reply.header).toHaveBeenCalledWith('Referrer-Policy', 'no-referrer');
    expect(String(reply.send.mock.calls[0]?.[0])).toContain(
      'This enrolment link is no longer valid'
    );

    const routed = fakeServer('/ui/error');
    const redirected = fakeReply();
    sendAdminEnrolmentRefused(
      routed.fastify,
      routed.request,
      redirected as unknown as FastifyReply
    );
    expect(redirected.redirect).toHaveBeenCalledWith(
      'https://auth.example.com/ui/error?code=admin_enrolment_refused&trace_id=req-1',
      303
    );
  });

  it('reads a status that is not a result as refused', () => {
    const { fastify, request } = fakeServer();
    const pageOf = (result: unknown): string => {
      const reply = fakeReply();
      answerAdminEnrolmentStatus(fastify, request, reply as unknown as FastifyReply, result);
      expect(reply.code).toHaveBeenCalledWith(200);
      return String(reply.send.mock.calls[0]?.[0]);
    };
    expect(pageOf('enrolled')).toContain('Your passkey is registered');
    expect(pageOf('cancelled')).toContain('The enrolment was cancelled');
    const refused = pageOf('refused');
    expect(refused).toContain('This enrolment link is no longer valid');
    for (const other of [undefined, 'ENROLLED', ['enrolled'], '']) {
      expect(pageOf(other)).toBe(refused);
    }
  });
});
