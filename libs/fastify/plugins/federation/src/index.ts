export * from './lib/configured-providers';
export * from './lib/federation-plugin';
export type * from './types';

// Re-exported provider surface: app code (scope:app) may only depend on
// fastify plugins (scope:fastify), never on server libs directly — routes and
// bootstrap reach the ADR-003 provider API through here.
export type {
  AssuranceLevel,
  CredentialProvider,
  PasswordCredentialData,
  TrustRankedAttribute,
  UserAttribute,
  VerifiedIdentity,
} from '@qauth-labs/server-federation';
// Note the asymmetry with the password surface: `createWalletProvider` is
// deliberately NOT re-exported. `createConfiguredProviders` is the only
// sanctioned way for app code to put a wallet provider in the registry, so no
// bootstrap can register one while bypassing WALLET_FEDERATION_ENABLED (#232).
// The type/source constants ARE re-exported — #237/#238 route and claim code
// needs them.
export {
  buildPasswordCredentialData,
  createPasswordProvider,
  EMAIL_ATTR_KEY,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  rankAttributeSource,
  selectTrustedAttribute,
  SELF_REPORTED_SOURCE,
  WALLET_PROVIDER_TYPE,
  WALLET_SOURCE,
} from '@qauth-labs/server-federation';
