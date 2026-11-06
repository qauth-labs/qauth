import { stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { testRealm } from '../../testing/request-realm';
import type { AuthorizeQuery } from '../schemas/oauth';
import type { BackgroundTasks } from './background-tasks';
import { createInteractionEngines, decisionOf } from './interaction-engines';
import { passkeyFirstStarter } from './passkey-first';
import { roundEnvironment } from './round-limits';

vi.mock('./interaction-engines', () => ({
  createInteractionEngines: vi.fn(),
  decisionOf: vi.fn(),
}));
vi.mock('./round-limits', () => ({ roundEnvironment: vi.fn(async () => 'production') }));
vi.mock('./account-policies', () => ({
  accountPoliciesOf: vi.fn(() => ({ requireVerifiedAccount: true })),
}));
vi.mock('./user-events', () => ({ emitUserEvent: vi.fn() }));

const REALM = testRealm({ id: 'realm-1' });
const WEBAUTHN_GET = stepUrn('webauthn_get');
const STEP = {
  name: WEBAUTHN_GET,
  params: { challenge: 'c'.repeat(43), rpId: 'auth.example.com' },
  alternatives: [stepUrn('password'), stepUrn('identifier')],
};
const TRANSACTION = { id: 'tx-1' };

const request = { headers: {}, ip: '203.0.113.7' } as unknown as FastifyRequest;
const reply = {} as FastifyReply;
const tasks = {} as BackgroundTasks;

function query(extra: Partial<AuthorizeQuery> = {}): AuthorizeQuery {
  return { client_id: 'client-1', response_type: 'code', ...extra } as AuthorizeQuery;
}

/**
 * Passkey-first on the hosted pages (#651; ADR-017 Decision 4): a sign-in
 * with no `login_hint` starts at the engine's first round, which asks for a
 * discoverable passkey; one with a hint, a registration, or with passkey
 * sign-in off starts at the identifier step, as every sign-in did.
 */
describe('passkeyFirstStarter (#651)', () => {
  const advance = vi.fn();
  const of = vi.fn(() => ({ advance }));
  const forRequest = vi.fn(async (_request: unknown, rounds: () => Promise<unknown>) => rounds());
  const warn = vi.fn();
  const fastify = (passkeySignIn: boolean) =>
    ({ passkeySignIn, log: { warn } }) as unknown as FastifyInstance;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(createInteractionEngines).mockReturnValue({ of, forRequest } as never);
    advance.mockResolvedValue({ kind: 'step' });
    vi.mocked(decisionOf).mockReturnValue({
      kind: 'step',
      step: STEP,
      personal: {},
      signInTransaction: TRANSACTION,
    } as never);
  });

  it('starts a sign-in with no hint at the engine’s first round, which reads no account', async () => {
    const start = passkeyFirstStarter(fastify(true), tasks);

    const first = await start(request, reply, REALM, query());

    expect(first).toEqual({ step: STEP, personal: {}, signInTransaction: TRANSACTION });
    expect(of).toHaveBeenCalledWith(true);
    expect(advance).toHaveBeenCalledTimes(1);
    const [transaction, answer, context] = advance.mock.calls[0];
    expect(transaction).toBeNull();
    expect(answer).toBeNull();
    expect(context).toMatchObject({
      realm: { id: REALM.id },
      client: { id: 'client-1' },
      environment: 'production',
    });
    expect(context).not.toHaveProperty('freshSignIn');
    // The transport can start a provider, so the round offers them.
    expect(typeof context.startUpstream).toBe('function');
    expect(roundEnvironment).toHaveBeenCalledWith(expect.anything(), REALM, 'client-1');
  });

  it('asks the round for a fresh sign-in under prompt=login or max_age', async () => {
    const start = passkeyFirstStarter(fastify(true), tasks);

    await start(request, reply, REALM, query({ prompt: 'login' }));
    await start(request, reply, REALM, query({ max_age: 0 }));

    for (const call of advance.mock.calls) expect(call[2]).toMatchObject({ freshSignIn: true });
  });

  it('builds the engines once, on the first request', async () => {
    const start = passkeyFirstStarter(fastify(true), tasks);

    await start(request, reply, REALM, query());
    await start(request, reply, REALM, query());

    expect(createInteractionEngines).toHaveBeenCalledTimes(1);
    expect(createInteractionEngines).toHaveBeenCalledWith(expect.anything(), { tasks });
  });

  it.each([
    ['a login_hint', true, { login_hint: 'ada@example.com' }],
    ['prompt=create', true, { prompt: 'create' }],
    ['passkey sign-in off', false, {}],
  ] as const)('starts at the identifier step with %s, running no round', async (_, on, extra) => {
    const start = passkeyFirstStarter(fastify(on), tasks);

    expect(await start(request, reply, REALM, query(extra as Partial<AuthorizeQuery>))).toBeNull();
    expect(advance).not.toHaveBeenCalled();
    expect(createInteractionEngines).not.toHaveBeenCalled();
  });

  it('starts at the identifier step when the first round offers no step', async () => {
    advance.mockResolvedValue({ kind: 'refused', reason: 'unavailable' });
    const start = passkeyFirstStarter(fastify(true), tasks);

    expect(await start(request, reply, REALM, query())).toBeNull();
    expect(warn).toHaveBeenCalled();
    expect(decisionOf).not.toHaveBeenCalled();
  });
});
