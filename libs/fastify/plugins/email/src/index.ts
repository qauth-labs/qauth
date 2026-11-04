export * from './lib/fastify-plugin-email';
export type * from './types';
// What the auth server works with, from the email library it may not import.
export {
  DEFAULT_MAIL_BRAND,
  type EngineMail,
  engineMailCarriesCode,
  type EngineMailContext,
  EngineMailError,
  isMailPass,
  MAIL_PASS_PARAMETER,
  MAIL_PASS_PATH,
  type MailBrand,
  type MailBrandSettings,
  type RealmEmailService,
  type RealmMailRead,
  type RealmMailSecretPath,
  type RealmMailSettings,
  type RealmMailSource,
  RealmMailUnavailableError,
  resolveMailBrand,
} from '@qauth-labs/server-email';
