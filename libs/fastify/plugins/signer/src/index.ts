export * from './lib/fastify-plugin-signer';
export * from './lib/key-custody-check';
export * from './lib/realm-keys';
export * from './lib/repository-key-stores';
export * from './lib/upstream-client-keys';
export type * from './types';
// The context prefix the auth server builds an AuthMethod plugin secret's
// context from (#600), so the app, which may not import server-keys, and the
// signer's policy name the same one.
export { AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX } from '@qauth-labs/server-keys';
// The same for a value sealed for an admin operation's secret member (#984).
export { ADMIN_SEALED_VALUE_CONTEXT_PREFIX } from '@qauth-labs/server-keys';
// The same for an OID4VP request state's ephemeral response key (#546), and
// the request-object typ the signer stamps, which the auth server pins equal to
// the federation library's.
export {
  OID4VP_RESPONSE_KEY_CONTEXT_PREFIX,
  OID4VP_REQUEST_OBJECT_TYP as SIGNER_REQUEST_OBJECT_TYP,
  TOTP_SECRET_CONTEXT_PREFIX,
} from '@qauth-labs/server-keys';
// The refusals of a provider's client-assertion key import and switch
// (#1073), which the admin API answers as 400 or 409: the app may not import
// server-keys.
export {
  KeyChangeRefusedError,
  KeyCreationRefusedError,
  KeyIdConflictError,
  NextKeyConflictError,
} from '@qauth-labs/server-keys';
