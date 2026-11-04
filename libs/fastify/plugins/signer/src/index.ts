export * from './lib/fastify-plugin-signer';
export * from './lib/key-custody-check';
export * from './lib/realm-keys';
export * from './lib/repository-key-stores';
export type * from './types';
// The context prefix the auth server builds an AuthMethod plugin secret's
// context from (#600), so the app, which may not import server-keys, and the
// signer's policy name the same one.
export { AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX } from '@qauth-labs/server-keys';
// The same for an OID4VP request state's ephemeral response key (#546), and
// the request-object typ the signer stamps, which the auth server pins equal to
// the federation library's.
export {
  OID4VP_RESPONSE_KEY_CONTEXT_PREFIX,
  OID4VP_REQUEST_OBJECT_TYP as SIGNER_REQUEST_OBJECT_TYP,
} from '@qauth-labs/server-keys';
// The algorithm of each event token kind (#624), so the SSF transmitter's JWKS
// lists the keys that sign SETs and no logout-token key.
export { EVENT_TOKEN_ALGORITHM } from '@qauth-labs/server-keys';
