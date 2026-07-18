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
export {
  buildPasswordCredentialData,
  createPasswordProvider,
  EMAIL_ATTR_KEY,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  rankAttributeSource,
  selectTrustedAttribute,
  SELF_REPORTED_SOURCE,
} from '@qauth-labs/server-federation';
