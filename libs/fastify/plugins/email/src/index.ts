export * from './lib/fastify-plugin-email';
export type * from './types';
// What the auth server works with, from the email library it may not import.
export {
  type RealmEmailService,
  type RealmMailRead,
  type RealmMailSecretPath,
  type RealmMailSettings,
  type RealmMailSource,
  RealmMailUnavailableError,
} from '@qauth-labs/server-email';
