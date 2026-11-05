import { describe, expect, it, vi } from 'vitest';

const envMock: Record<string, unknown> = {};
vi.mock('../../config/env', () => ({
  get env() {
    return envMock;
  },
}));

import { createServerBotChallenge, registrationChallengeRequired } from './bot-challenge';
import type { RealmRow } from './request-realm';

/**
 * The deployment's bot challenge (#643): the built-in proof of work at the
 * realm's difficulty by default, a hosted provider through the egress client
 * when the operator configured one, and the registration requirement of the
 * realm or the client.
 */

const REALM_ID = '0199fa20-0000-7000-8000-00000000aaaa';
const REALM = { id: REALM_ID } as RealmRow;

function sources(difficulty: number, egress?: { request: ReturnType<typeof vi.fn> }) {
  const ofRealm = vi.fn(() => ({ policies: { botChallenge: { difficulty } } }));
  return {
    fastify: {
      policyStore: { ofRealm },
      hasDecorator: (name: string) => name === 'egress' && egress !== undefined,
      ...(egress === undefined ? {} : { egress }),
    } as unknown as Parameters<typeof createServerBotChallenge>[0],
    ofRealm,
  };
}

function setEnv(values: Record<string, unknown>) {
  for (const key of Object.keys(envMock)) delete envMock[key];
  Object.assign(envMock, values);
}

describe('createServerBotChallenge (#643)', () => {
  it('offers the built-in proof of work at the difficulty the realm row holds', async () => {
    setEnv({ BOT_CHALLENGE_PROVIDER: 'pow' });
    const { fastify, ofRealm } = sources(7);
    const realmOf = vi.fn(async () => REALM);
    const provider = createServerBotChallenge(fastify, realmOf);
    const params = await provider.params({ realmId: REALM_ID, clientId: 'web' });
    expect(params).toMatchObject({ provider: 'pow', difficulty: 7 });
    expect(realmOf).toHaveBeenCalledWith(REALM_ID);
    expect(ofRealm).toHaveBeenCalledWith(REALM);
  });

  it('fails the challenge, not waves it through, when the realm cannot be read', async () => {
    setEnv({ BOT_CHALLENGE_PROVIDER: 'pow' });
    const { fastify } = sources(7);
    const provider = createServerBotChallenge(fastify, async () => {
      throw new Error('no realm');
    });
    await expect(provider.params({ realmId: REALM_ID, clientId: 'web' })).rejects.toThrow();
  });

  it('checks a hosted provider through the egress client, at the configured URL', async () => {
    setEnv({
      BOT_CHALLENGE_PROVIDER: 'hosted',
      BOT_CHALLENGE_HOSTED_NAME: 'turnstile',
      BOT_CHALLENGE_HOSTED_SITE_KEY: '0x4AAAAAAA',
      BOT_CHALLENGE_HOSTED_SECRET: 'operator-secret',
      BOT_CHALLENGE_HOSTED_VERIFY_URL: 'https://challenges.example.com/siteverify',
    });
    const request = vi.fn(async (_request: { readonly method: string; readonly url: string }) => ({
      status: 200,
      headers: {},
      body: Buffer.from('{"success":true}'),
      url: 'https://challenges.example.com/siteverify',
      redirects: 0,
    }));
    const { fastify } = sources(7, { request });
    const provider = createServerBotChallenge(fastify, async () => REALM);
    const params = await provider.params({ realmId: REALM_ID, clientId: 'web' });
    expect(params).toEqual({ provider: 'hosted', name: 'turnstile', site_key: '0x4AAAAAAA' });
    expect(await provider.verify({ realmId: REALM_ID, params, token: 'a-token' })).toBe(true);
    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0]?.[0]).toMatchObject({
      method: 'POST',
      url: 'https://challenges.example.com/siteverify',
    });
  });

  it('fails the boot when a hosted provider has no egress client to check through', () => {
    setEnv({
      BOT_CHALLENGE_PROVIDER: 'hosted',
      BOT_CHALLENGE_HOSTED_NAME: 'turnstile',
      BOT_CHALLENGE_HOSTED_SITE_KEY: '0x4AAAAAAA',
      BOT_CHALLENGE_HOSTED_SECRET: 'operator-secret',
      BOT_CHALLENGE_HOSTED_VERIFY_URL: 'https://challenges.example.com/siteverify',
    });
    const { fastify } = sources(7);
    expect(() => createServerBotChallenge(fastify, async () => REALM)).toThrow(TypeError);
  });
});

describe('registrationChallengeRequired (#643)', () => {
  it('asks for the challenge when the realm or the client does, and only then', () => {
    expect(registrationChallengeRequired({ requiredAtSignUp: false }, undefined)).toBe(false);
    expect(registrationChallengeRequired({ requiredAtSignUp: false }, null)).toBe(false);
    expect(
      registrationChallengeRequired({ requiredAtSignUp: false }, { registrationChallenge: null })
    ).toBe(false);
    expect(
      registrationChallengeRequired({ requiredAtSignUp: false }, { registrationChallenge: false })
    ).toBe(false);
    expect(
      registrationChallengeRequired({ requiredAtSignUp: false }, { registrationChallenge: true })
    ).toBe(true);
    expect(registrationChallengeRequired({ requiredAtSignUp: true }, undefined)).toBe(true);
    // A client's `false` does not lift the realm's requirement.
    expect(
      registrationChallengeRequired({ requiredAtSignUp: true }, { registrationChallenge: false })
    ).toBe(true);
  });
});
