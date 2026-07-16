import {
  ProviderAlreadyRegisteredError,
  ProviderNotRegisteredError,
} from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import type {
  CredentialProvider,
  UserAttribute,
  VerifiedIdentity,
} from './credential-provider.interface';
import { createProviderRegistry } from './provider-registry';

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
