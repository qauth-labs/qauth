import {
  ProviderAlreadyRegisteredError,
  ProviderNotRegisteredError,
} from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { createSampleAuthMethod } from '../../testing/sample-auth-method.fixture';
import { AUTH_METHOD_CONTRACT } from '../auth-method/contract';
import { AuthMethodContractError } from '../auth-method/errors';
import { isAuthMethod } from '../auth-method/validate';
import type {
  CredentialProvider,
  UserAttribute,
  VerifiedIdentity,
} from './credential-provider.interface';
import { createPasswordProvider, PASSWORD_PROVIDER_TYPE } from './password.provider';
import { createProviderRegistry } from './provider-registry';
import { createWalletProvider, WALLET_PROVIDER_TYPE } from './wallet.provider';

/**
 * Minimal in-test {@link CredentialProvider} used to exercise the registry
 * without any real crypto or I/O. Proves the registry is provider-agnostic —
 * no concrete provider (PasswordProvider #228, WalletProvider #232) ships here.
 */
function createStubProvider(type: string): CredentialProvider {
  return {
    type,
    verify(): Promise<VerifiedIdentity> {
      return Promise.resolve({
        externalSub: `sub-${type}`,
        assuranceLevel: 'low',
        rawClaims: {},
      });
    },
    extractAttributes(): UserAttribute[] {
      return [];
    },
  };
}

/** Capture the error thrown by `fn`, failing the test if it does not throw. */
function captureThrown(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error('Expected the function to throw, but it did not');
}

describe('createProviderRegistry', () => {
  describe('registration and resolution', () => {
    it('resolves a provider registered via register()', () => {
      const registry = createProviderRegistry();
      const provider = createStubProvider('password');

      registry.register(provider);

      expect(registry.has('password')).toBe(true);
      expect(registry.resolve('password')).toBe(provider);
    });

    it('seeds providers passed at construction (config/DI bootstrap path)', () => {
      const password = createStubProvider('password');
      const wallet = createStubProvider('wallet');

      const registry = createProviderRegistry([password, wallet]);

      expect(registry.resolve('password')).toBe(password);
      expect(registry.resolve('wallet')).toBe(wallet);
    });

    it('resolves the correct provider when several are registered', () => {
      const password = createStubProvider('password');
      const wallet = createStubProvider('wallet');
      const registry = createProviderRegistry();

      registry.register(password);
      registry.register(wallet);

      expect(registry.resolve('wallet')).toBe(wallet);
      expect(registry.resolve('password')).toBe(password);
    });

    it('reports has() === false for an unregistered type', () => {
      const registry = createProviderRegistry([createStubProvider('password')]);

      expect(registry.has('wallet')).toBe(false);
    });
  });

  describe('unknown provider type', () => {
    it('throws ProviderNotRegisteredError when resolving an unregistered type', () => {
      const registry = createProviderRegistry();

      expect(() => registry.resolve('wallet')).toThrow(ProviderNotRegisteredError);
    });

    it('carries the offending type and a leak-safe 500 contract', () => {
      const registry = createProviderRegistry([createStubProvider('password')]);

      const error = captureThrown(() => registry.resolve('wallet'));

      expect(error).toBeInstanceOf(ProviderNotRegisteredError);
      const providerError = error as ProviderNotRegisteredError;
      expect(providerError.code).toBe('PROVIDER_NOT_REGISTERED');
      expect(providerError.statusCode).toBe(500);
      expect(providerError.providerType).toBe('wallet');
      // The wire-facing message must not leak the specific requested type.
      expect(providerError.message).not.toContain('wallet');
    });
  });

  describe('duplicate registration', () => {
    it('throws ProviderAlreadyRegisteredError when a type is registered twice', () => {
      const registry = createProviderRegistry();
      registry.register(createStubProvider('password'));

      const error = captureThrown(() => registry.register(createStubProvider('password')));

      expect(error).toBeInstanceOf(ProviderAlreadyRegisteredError);
      const providerError = error as ProviderAlreadyRegisteredError;
      expect(providerError.code).toBe('PROVIDER_ALREADY_REGISTERED');
      expect(providerError.statusCode).toBe(500);
      expect(providerError.providerType).toBe('password');
    });

    it('rejects duplicate types in the seeded provider list', () => {
      expect(() =>
        createProviderRegistry([createStubProvider('password'), createStubProvider('password')])
      ).toThrow(ProviderAlreadyRegisteredError);
    });

    it('does not overwrite the original provider when a duplicate is rejected', () => {
      const original = createStubProvider('password');
      const registry = createProviderRegistry([original]);

      expect(() => registry.register(createStubProvider('password'))).toThrow(
        ProviderAlreadyRegisteredError
      );
      expect(registry.resolve('password')).toBe(original);
    });
  });
});

/**
 * AuthMethod entries beside plain providers (#599). The registry holds both in
 * one `type` space: the engine resolves an AuthMethod by `type` like any
 * other provider, and a duplicate `type` fails at boot whichever kind it is.
 */
describe('AuthMethod entries (#599)', () => {
  it('registers a method beside PasswordProvider, and the engine resolves each by type', async () => {
    const password = createPasswordProvider();
    const method = createSampleAuthMethod({ type: 'oidc_sample' });
    const registry = createProviderRegistry([password, method]);

    expect(registry.resolve(PASSWORD_PROVIDER_TYPE)).toBe(password);
    expect(registry.resolve('oidc_sample')).toBe(method);
    expect(registry.resolveAuthMethod('oidc_sample')).toBe(method);
    expect(registry.authMethods()).toEqual([method]);
    expect(registry.has('oidc_sample')).toBe(true);
    // The password path is unchanged: still a plain provider, never an AuthMethod.
    expect(() => registry.resolveAuthMethod(PASSWORD_PROVIDER_TYPE)).toThrow(
      ProviderNotRegisteredError
    );
    await expect(
      registry.resolve(PASSWORD_PROVIDER_TYPE).verify({
        email: 'person@example.com',
        passwordHash: '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA',
        emailVerified: true,
      })
    ).resolves.toMatchObject({ externalSub: 'person@example.com' });
  });

  it('fails at boot when two methods share a type', () => {
    const error = captureThrown(() =>
      createProviderRegistry([
        createPasswordProvider(),
        createSampleAuthMethod({ type: 'oidc_corp' }),
        createSampleAuthMethod({ type: 'oidc_corp' }),
      ])
    );
    expect(error).toBeInstanceOf(ProviderAlreadyRegisteredError);
    expect((error as ProviderAlreadyRegisteredError).providerType).toBe('oidc_corp');
  });

  it('fails at boot when a method takes the type of a plain provider registered first', () => {
    const plain = createStubProvider('oidc_corp');
    expect(() =>
      createProviderRegistry([plain, createSampleAuthMethod({ type: 'oidc_corp' })])
    ).toThrow(ProviderAlreadyRegisteredError);
  });

  it('fails at boot when a method does not meet the contract, naming every problem', () => {
    const broken = {
      ...createSampleAuthMethod(),
      contract: 'qauth-auth-method/0',
      routes: [
        { kind: 'callback', method: 'GET', path: '/../oauth/token', handle: async () => ({}) },
      ],
    };
    const error = captureThrown(() =>
      createProviderRegistry([createPasswordProvider(), broken as unknown as CredentialProvider])
    );
    expect(error).toBeInstanceOf(AuthMethodContractError);
    expect((error as AuthMethodContractError).problems).toEqual([
      'it is written against the contract qauth-auth-method/0, and this server implements qauth-auth-method/1-rc.0',
      "routes[0].path must be one to four lower-case segments, such as /callback: a route cannot leave the method's prefix",
    ]);
  });

  it('holds a provider that carries a contract member to the whole contract', () => {
    const halfway = { ...createStubProvider('oidc_corp'), contract: AUTH_METHOD_CONTRACT };
    expect(() => createProviderRegistry([halfway])).toThrow(AuthMethodContractError);
  });

  it('refuses a method under a type QAuth writes itself', () => {
    for (const type of ['password', 'wallet', 'webauthn', 'self_reported']) {
      const error = captureThrown(() =>
        createProviderRegistry([{ ...createSampleAuthMethod(), type }])
      );
      expect(error).toBeInstanceOf(AuthMethodContractError);
      expect((error as AuthMethodContractError).problems).toEqual([
        `type ${type} is reserved for QAuth's own credentials`,
      ]);
    }
  });

  it('keeps WalletProvider a plain provider whose verify() still rejects', async () => {
    const wallet = createWalletProvider();
    const registry = createProviderRegistry([createPasswordProvider(), wallet]);

    expect(isAuthMethod(wallet)).toBe(false);
    expect('contract' in wallet).toBe(false);
    expect(registry.resolve(WALLET_PROVIDER_TYPE)).toBe(wallet);
    expect(() => registry.resolveAuthMethod(WALLET_PROVIDER_TYPE)).toThrow(
      ProviderNotRegisteredError
    );
    expect(registry.authMethods()).toEqual([]);
    await expect(wallet.verify({})).rejects.toThrow();
    await expect(
      wallet.verify({ externalSub: 'x', assuranceLevel: 'high', rawClaims: {} })
    ).rejects.toThrow();
  });
});
