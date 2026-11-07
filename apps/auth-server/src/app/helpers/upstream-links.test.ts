import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { EngineMailer } from './engine-mail';
import {
  linkUpstreamIdentity,
  unlinkUpstreamIdentity,
  type UpstreamLinkServer,
} from './upstream-links';
import { emitUserEvent } from './user-events';

vi.mock('./user-events', () => ({ emitUserEvent: vi.fn(async () => undefined) }));
vi.mock('./upstream-providers', () => ({
  upstreamProviderCatalog: () => ({
    offered: async () => [],
    find: async (_realmId: string, type: string) =>
      type === 'oidc_corp' ? { entry: { provider: type, name: 'Corp' } } : undefined,
  }),
}));

/**
 * The upstream account links (#670): the account a link joins is the one the
 * person just signed in to, named by the caller, and the identity is found by
 * the provider's type and subject alone. No call reads an email address or
 * an attribute to find either: the only address read is the owner's own,
 * by the owner's id, for the notice once the link is made.
 */

const REALM = { id: 'realm-1', name: 'master', displayName: null } as never as Parameters<
  typeof linkUpstreamIdentity
>[2]['realm'];
const REALM_ID = 'realm-1';
const OWNER = '0190f0e0-0000-7000-8000-000000000001';
const OTHER = '0190f0e0-0000-7000-8000-000000000002';
const EMAIL = 'ada@example.com';
const IDENTITY = { provider: 'oidc_corp', externalSub: 'corp-user-1', iss: 'https://idp.example' };
const TX = { transaction: 'tx' };

/** One repository call: `<repository>.<method>` and its arguments. */
interface Call {
  readonly name: string;
  readonly args: readonly unknown[];
}

/**
 * A server whose repositories record every call and answer only the calls
 * `answers` names: any other read fails the test, so the calls a path makes
 * are exactly the ones listed.
 */
function recordingServer(answers: Record<string, (...args: never[]) => unknown>) {
  const calls: Call[] = [];
  const repositories = new Proxy(
    {},
    {
      get: (_target, repository) =>
        typeof repository !== 'string'
          ? undefined
          : new Proxy(
              {},
              {
                get: (_inner, method) =>
                  typeof method !== 'string'
                    ? undefined
                    : (...args: unknown[]) => {
                        const name = `${repository}.${method}`;
                        calls.push({ name, args });
                        const answer = answers[name] as
                          | ((...args: unknown[]) => unknown)
                          | undefined;
                        if (answer === undefined)
                          throw new Error(`unexpected repository call: ${name}`);
                        return answer(...args);
                      },
              }
            ),
    }
  );
  const server = {
    repositories,
    db: { transaction: async (work: (tx: unknown) => Promise<unknown>) => work(TX) },
    log: { error: vi.fn(), warn: vi.fn(), info: vi.fn() },
  } as unknown as UpstreamLinkServer;
  return { server, calls };
}

function mailer() {
  const sendUncounted = vi.fn();
  return { mailer: { sendUncounted } as unknown as EngineMailer, sendUncounted };
}

const request = { id: 'req-670', log: { error: vi.fn() } } as unknown as FastifyRequest;

/** The account's own password credential, whose `external_sub` is its address. */
const passwordOf = async (userId: string, type: string) => ({
  id: 'cred-password',
  userId,
  realmId: REALM_ID,
  providerType: type,
  externalSub: EMAIL,
});

describe('linkUpstreamIdentity (#670)', () => {
  beforeEach(() => {
    vi.mocked(emitUserEvent).mockClear();
  });

  it('joins the account it is given and finds the identity by provider type and subject alone, reading no address to do so', async () => {
    const { server, calls } = recordingServer({
      'userCredentials.lockUser': async () => true,
      'users.findById': async (_realm: string, id: string) => ({
        id,
        enabled: true,
        notValidBefore: null,
      }),
      'userCredentials.findByRealmProviderSub': async () => undefined,
      'userCredentials.findAllByUserIdAndType': async () => [],
      'userCredentials.create': async (data: Record<string, unknown>) => ({
        id: 'cred-upstream',
        ...data,
      }),
      'userCredentials.findByUserIdAndType': passwordOf,
    });
    const { mailer: notices, sendUncounted } = mailer();

    const result = await linkUpstreamIdentity(server, request, {
      realm: REALM,
      userId: OWNER,
      identity: IDENTITY,
      providerName: 'Corp',
      clientId: 'portal',
      mailer: notices,
    });

    expect(result).toEqual({ kind: 'linked', credentialId: 'cred-upstream', created: true });
    expect(calls).toEqual([
      { name: 'userCredentials.lockUser', args: [REALM_ID, OWNER, TX] },
      { name: 'users.findById', args: [REALM_ID, OWNER, TX] },
      {
        name: 'userCredentials.findByRealmProviderSub',
        args: [REALM_ID, 'oidc_corp', 'corp-user-1', TX],
      },
      { name: 'userCredentials.findAllByUserIdAndType', args: [OWNER, 'oidc_corp', TX] },
      {
        name: 'userCredentials.create',
        args: [
          {
            userId: OWNER,
            realmId: REALM_ID,
            providerType: 'oidc_corp',
            externalSub: 'corp-user-1',
            credentialData: { kind: 'upstream', iss: 'https://idp.example', verified: true },
          },
          TX,
        ],
      },
      // The notice, once the link is made: the owner's own address, by the owner's id.
      { name: 'userCredentials.findByUserIdAndType', args: [OWNER, 'password'] },
    ]);
    expect(calls.some((call) => call.name.startsWith('userAttributes.'))).toBe(false);
    expect(JSON.stringify(calls.slice(0, -1))).not.toContain('@');
    expect(sendUncounted).toHaveBeenCalledWith(REALM, EMAIL, {
      template: 'upstream_linked',
      providerName: 'Corp',
    });
    expect(vi.mocked(emitUserEvent)).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:user.upstream_linked:v1-rc.0',
      { provider: 'oidc_corp', credentialId: 'cred-upstream' },
      expect.objectContaining({ tx: TX, realmId: REALM_ID, userId: OWNER, actor: 'user' })
    );
  });

  /** The answers a refused link differs in, by what it is refused for. */
  type Answers = Record<string, (...args: never[]) => unknown>;
  const refusals: readonly (readonly [string, Answers, string])[] = [
    [
      'an identity another account holds',
      {
        'userCredentials.findByRealmProviderSub': async () => ({ id: 'cred-held', userId: OTHER }),
      },
      'already_linked',
    ],
    [
      'a second identity of the provider for the account',
      {
        'userCredentials.findByRealmProviderSub': async () => undefined,
        'userCredentials.findAllByUserIdAndType': async () => [{ id: 'cred-earlier' }],
      },
      'provider_linked',
    ],
    [
      'an identity another account took between the read and the insert',
      {
        'userCredentials.findByRealmProviderSub': async () => undefined,
        'userCredentials.findAllByUserIdAndType': async () => [],
        'userCredentials.create': async () => {
          throw new UniqueConstraintError('user_credentials_realm_provider_sub_unique');
        },
      },
      'already_linked',
    ],
    [
      'a disabled account',
      {
        'users.findById': async (_realm: string, id: string) => ({
          id,
          enabled: false,
          notValidBefore: Date.now(),
        }),
      },
      'account_unavailable',
    ],
  ];

  it.each(refusals)('refuses %s, records it, and mails nobody', async (_label, answers, reason) => {
    const { server, calls } = recordingServer({
      'userCredentials.lockUser': async () => true,
      'users.findById': async (_realm: string, id: string) => ({
        id,
        enabled: true,
        notValidBefore: null,
      }),
      ...answers,
    });
    const { mailer: notices, sendUncounted } = mailer();

    const result = await linkUpstreamIdentity(server, request, {
      realm: REALM,
      userId: OWNER,
      identity: IDENTITY,
      providerName: 'Corp',
      clientId: 'portal',
      mailer: notices,
    });

    expect(result).toEqual({ kind: 'refused', reason });
    expect(sendUncounted).not.toHaveBeenCalled();
    expect(calls.some((call) => call.name === 'userCredentials.findByUserIdAndType')).toBe(false);
    expect(vi.mocked(emitUserEvent)).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:user.upstream_link_failed:v1-rc.0',
      { provider: 'oidc_corp', reason },
      expect.objectContaining({ realmId: REALM_ID, userId: OWNER })
    );
  });

  it('links an account that was disabled once and enabled again, since its sign-in just proved it', async () => {
    const { server } = recordingServer({
      'userCredentials.lockUser': async () => true,
      'users.findById': async (_realm: string, id: string) => ({
        id,
        enabled: true,
        notValidBefore: Date.now() - 60_000,
      }),
      'userCredentials.findByRealmProviderSub': async () => undefined,
      'userCredentials.findAllByUserIdAndType': async () => [],
      'userCredentials.create': async () => ({ id: 'cred-upstream' }),
      'userCredentials.findByUserIdAndType': passwordOf,
    });

    const result = await linkUpstreamIdentity(server, request, {
      realm: REALM,
      userId: OWNER,
      identity: IDENTITY,
      providerName: 'Corp',
      clientId: null,
      mailer: mailer().mailer,
    });

    expect(result).toEqual({ kind: 'linked', credentialId: 'cred-upstream', created: true });
  });

  it('answers linked, with nothing written or mailed, when the account already holds the identity', async () => {
    const { server, calls } = recordingServer({
      'userCredentials.lockUser': async () => true,
      'users.findById': async (_realm: string, id: string) => ({
        id,
        enabled: true,
        notValidBefore: null,
      }),
      'userCredentials.findByRealmProviderSub': async () => ({ id: 'cred-held', userId: OWNER }),
    });
    const { mailer: notices, sendUncounted } = mailer();

    const result = await linkUpstreamIdentity(server, request, {
      realm: REALM,
      userId: OWNER,
      identity: IDENTITY,
      providerName: 'Corp',
      clientId: 'portal',
      mailer: notices,
    });

    expect(result).toEqual({ kind: 'linked', credentialId: 'cred-held', created: false });
    expect(calls.some((call) => call.name === 'userCredentials.create')).toBe(false);
    expect(sendUncounted).not.toHaveBeenCalled();
    expect(vi.mocked(emitUserEvent)).not.toHaveBeenCalled();
  });
});

describe('unlinkUpstreamIdentity (#670)', () => {
  const upstream = {
    id: 'cred-upstream',
    userId: OWNER,
    realmId: REALM_ID,
    providerType: 'oidc_corp',
    externalSub: 'corp-user-1',
    credentialData: { kind: 'upstream', iss: 'https://idp.example', verified: true },
  };
  const password = {
    id: 'cred-password',
    userId: OWNER,
    realmId: REALM_ID,
    providerType: 'password',
    externalSub: EMAIL,
    credentialData: { hash: '$argon2id$...' },
  };
  const totp = {
    id: 'cred-totp',
    userId: OWNER,
    realmId: REALM_ID,
    providerType: 'totp',
    externalSub: OWNER,
    credentialData: { secret: 'sealed', last_step: 0 },
  };

  beforeEach(() => {
    vi.mocked(emitUserEvent).mockClear();
  });

  function unlink(server: UpstreamLinkServer, credentialId: string, notices: EngineMailer) {
    return unlinkUpstreamIdentity(server, request, {
      realm: REALM,
      userId: OWNER,
      credentialId,
      mailer: notices,
    });
  }

  it('removes the identity under the lock, records it with the delete, and tells the owner', async () => {
    const { server, calls } = recordingServer({
      'userCredentials.lockUser': async () => true,
      'userCredentials.findAllByUserId': async () => [password, upstream],
      'userCredentials.deleteById': async () => upstream,
      'userCredentials.findByUserIdAndType': passwordOf,
    });
    const { mailer: notices, sendUncounted } = mailer();

    expect(await unlink(server, upstream.id, notices)).toEqual({ kind: 'unlinked' });

    expect(calls.map((call) => call.name)).toEqual([
      'userCredentials.lockUser',
      'userCredentials.findAllByUserId',
      'userCredentials.deleteById',
      'userCredentials.findByUserIdAndType',
    ]);
    expect(calls[2]?.args).toEqual([REALM_ID, upstream.id, TX]);
    expect(vi.mocked(emitUserEvent)).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:user.upstream_unlinked:v1-rc.0',
      { provider: 'oidc_corp', credentialId: upstream.id },
      expect.objectContaining({ tx: TX, realmId: REALM_ID, userId: OWNER, actor: 'user' })
    );
    expect(sendUncounted).toHaveBeenCalledWith(REALM, EMAIL, {
      template: 'upstream_unlinked',
      providerName: 'Corp',
    });
  });

  it('refuses the last way to sign in, an authenticator app notwithstanding, and deletes nothing', async () => {
    const { server, calls } = recordingServer({
      'userCredentials.lockUser': async () => true,
      'userCredentials.findAllByUserId': async () => [upstream, totp],
    });
    const { mailer: notices, sendUncounted } = mailer();

    expect(await unlink(server, upstream.id, notices)).toEqual({ kind: 'last_credential' });

    expect(calls.some((call) => call.name === 'userCredentials.deleteById')).toBe(false);
    expect(vi.mocked(emitUserEvent)).not.toHaveBeenCalled();
    expect(sendUncounted).not.toHaveBeenCalled();
  });

  it('counts neither a marked credential nor the identity of a provider switched off as a way in (#844)', async () => {
    const gone = { ...upstream, id: 'cred-gone', providerType: 'oidc_gone', externalSub: 'gone-1' };
    const marked = { ...password, disabledAt: 1_700_000_000_000 };
    const { server, calls } = recordingServer({
      'userCredentials.lockUser': async () => true,
      'userCredentials.findAllByUserId': async () => [upstream, gone, marked, totp],
    });

    expect(await unlink(server, upstream.id, mailer().mailer)).toEqual({
      kind: 'last_credential',
    });
    expect(calls.some((call) => call.name === 'userCredentials.deleteById')).toBe(false);

    // The identity of a provider that is on is one: the other may go.
    const kept = recordingServer({
      'userCredentials.lockUser': async () => true,
      'userCredentials.findAllByUserId': async () => [upstream, gone],
      'userCredentials.deleteById': async () => gone,
      'userCredentials.findByUserIdAndType': async () => undefined,
    });
    expect(await unlink(kept.server, gone.id, mailer().mailer)).toEqual({ kind: 'unlinked' });
  });

  it.each([
    ['a credential that is no upstream identity (the password)', password.id],
    ['an id the account does not hold', 'cred-elsewhere'],
  ])('answers not_found for %s', async (_label, credentialId) => {
    const { server, calls } = recordingServer({
      'userCredentials.lockUser': async () => true,
      'userCredentials.findAllByUserId': async () => [password, upstream],
    });

    expect(await unlink(server, credentialId, mailer().mailer)).toEqual({ kind: 'not_found' });
    expect(calls.some((call) => call.name === 'userCredentials.deleteById')).toBe(false);
  });

  it('answers not_found for an account that is gone', async () => {
    const { server } = recordingServer({ 'userCredentials.lockUser': async () => false });

    expect(await unlink(server, upstream.id, mailer().mailer)).toEqual({ kind: 'not_found' });
  });
});
