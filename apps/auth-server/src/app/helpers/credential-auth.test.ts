import {
  buildPasswordCredentialData,
  createPasswordProvider,
} from '@qauth-labs/fastify-plugin-federation';
import { passwordPlugin } from '@qauth-labs/fastify-plugin-password';
import { createPasswordPolicyValidator } from '@qauth-labs/shared-validation';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { verifyPasswordCredential } from './credential-auth';

const REALM_ID = 'realm-1';
const EMAIL = 'ada@example.com';

/** One text, two spellings: composed (U+00E9) and decomposed (e + U+0301). */
const COMPOSED = 'café-terrace-at-night';
const DECOMPOSED = 'café-terrace-at-night';

/**
 * `verifyPasswordCredential` over a real Argon2id hasher (#634, ADR-017
 * Decision 8): a password set under the one password policy is hashed in NFC
 * and its credential records the marker, so either spelling verifies against
 * the one hash; a credential without the marker, as every credential before
 * the policy, is verified on the password as typed.
 */
describe('verifyPasswordCredential and the normalisation marker (#634)', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = Fastify();
    // The lowest costs the hasher accepts: the tests compare, not measure.
    await server.register(passwordPlugin, {
      hashConfig: { memoryCost: 1024, timeCost: 1, parallelism: 1 },
    });
    await server.ready();
  });

  afterAll(async () => {
    await server.close();
  });

  /**
   * A server whose realm holds one password credential of `credentialData`,
   * and the account's `webauthn` credentials `passkeys`.
   */
  function serverWith(
    credentialData: Record<string, unknown>,
    passkeys: readonly { readonly realmId: string }[] = []
  ): FastifyInstance {
    return {
      passwordHasher: server.passwordHasher,
      repositories: {
        userCredentials: {
          findByRealmProviderSub: vi.fn(async () => ({
            id: 'cred-1',
            userId: 'user-1',
            realmId: REALM_ID,
            providerType: 'password',
            externalSub: EMAIL,
            credentialData,
            disabledAt: null,
          })),
          findAllByUserIdAndType: vi.fn(async () => passkeys),
        },
      },
      passwordAttempts: { hardActionArmed: vi.fn(async () => false) },
      providerRegistry: { resolve: () => createPasswordProvider() },
      log: { error: vi.fn(), info: vi.fn() },
    } as unknown as FastifyInstance;
  }

  async function verify(fastify: FastifyInstance, password: string) {
    return (await verifyPasswordCredential(fastify, { realmId: REALM_ID, email: EMAIL, password }))
      .status;
  }

  it('verifies the NFC and NFD spellings against one hash made under the policy (acceptance criterion)', async () => {
    expect(COMPOSED).not.toBe(DECOMPOSED);
    // Registration's path: the policy's check, then a hash of what it returns.
    const checked = createPasswordPolicyValidator().check(DECOMPOSED);
    if (!checked.valid) throw new Error('the test password must meet the policy');
    const hash = await server.passwordHasher.hashPassword(checked.password);
    const fastify = serverWith(buildPasswordCredentialData(hash, true, checked.normalization));

    expect(await verify(fastify, COMPOSED)).toBe('ok');
    expect(await verify(fastify, DECOMPOSED)).toBe('ok');
    expect(await verify(fastify, 'café-terrace-at-noon')).toBe('invalid');
  });

  it('verifies a credential without the marker on the password as typed', async () => {
    const hash = await server.passwordHasher.hashPassword(DECOMPOSED);
    const fastify = serverWith(buildPasswordCredentialData(hash, true, null));

    expect(await verify(fastify, DECOMPOSED)).toBe('ok');
    // Not normalised: the other spelling is another password for it.
    expect(await verify(fastify, COMPOSED)).toBe('invalid');
  });

  it('refuses a credential whose marker this release does not know, as unreadable', async () => {
    const hash = await server.passwordHasher.hashPassword(COMPOSED);
    const fastify = serverWith({
      password_hash: hash,
      email_verified: true,
      password_normalization: 'nfkc',
    });

    expect(await verify(fastify, COMPOSED)).toBe('invalid');
    expect(fastify.log.error).toHaveBeenCalledWith(
      { credentialId: 'cred-1' },
      'malformed credential_data on password credential'
    );
  });
});

/**
 * The password-only login routes and a passkey-bound account (#651; ADR-017
 * Decision 4, the downgrade rule): a right password does not sign it in, and
 * the refusal is a wrong password's, naming no account.
 */
describe('verifyPasswordCredential and a passkey-bound account (#651)', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = Fastify();
    await server.register(passwordPlugin, {
      hashConfig: { memoryCost: 1024, timeCost: 1, parallelism: 1 },
    });
    await server.ready();
  });

  afterAll(async () => {
    await server.close();
  });

  function serverWith(passkeys: readonly { readonly realmId: string }[], hash: string) {
    const findAllByUserIdAndType = vi.fn(async () => passkeys);
    const fastify = {
      passwordHasher: server.passwordHasher,
      repositories: {
        userCredentials: {
          findByRealmProviderSub: vi.fn(async () => ({
            id: 'cred-1',
            userId: 'user-1',
            realmId: REALM_ID,
            providerType: 'password',
            externalSub: EMAIL,
            credentialData: buildPasswordCredentialData(hash, true, null),
            disabledAt: null,
          })),
          findAllByUserIdAndType,
        },
      },
      passwordAttempts: { hardActionArmed: vi.fn(async () => false) },
      providerRegistry: { resolve: () => createPasswordProvider() },
      log: { error: vi.fn(), info: vi.fn() },
    } as unknown as FastifyInstance;
    return { fastify, findAllByUserIdAndType };
  }

  it('refuses a right password of an account that holds a passkey, naming no account', async () => {
    const hash = await server.passwordHasher.hashPassword(COMPOSED);
    const { fastify, findAllByUserIdAndType } = serverWith([{ realmId: REALM_ID }], hash);

    const check = await verifyPasswordCredential(fastify, {
      realmId: REALM_ID,
      email: EMAIL,
      password: COMPOSED,
    });

    // `invalid` with no user: the failure ladder's hard action never
    // disables a password that was right.
    expect(check).toEqual({ status: 'invalid' });
    expect(findAllByUserIdAndType).toHaveBeenCalledWith('user-1', 'webauthn');
  });

  it('refuses a wrong password as before, without reading the passkeys', async () => {
    const hash = await server.passwordHasher.hashPassword(COMPOSED);
    const { fastify, findAllByUserIdAndType } = serverWith([{ realmId: REALM_ID }], hash);

    const check = await verifyPasswordCredential(fastify, {
      realmId: REALM_ID,
      email: EMAIL,
      password: 'café-terrace-at-noon',
    });

    expect(check).toEqual({ status: 'invalid', userId: 'user-1' });
    expect(findAllByUserIdAndType).not.toHaveBeenCalled();
  });

  it('signs in an account whose passkey is in another realm only', async () => {
    const hash = await server.passwordHasher.hashPassword(COMPOSED);
    const { fastify } = serverWith([{ realmId: 'another-realm' }], hash);

    const check = await verifyPasswordCredential(fastify, {
      realmId: REALM_ID,
      email: EMAIL,
      password: COMPOSED,
    });

    expect(check.status).toBe('ok');
  });
});
