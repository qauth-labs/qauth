// The Vault Transit KEK adapter (ADR-019 Decision 9, #578).
//
// An optional package: the auth server does not depend on it.
// `KEK_PROVIDER=vault` makes the key library's `loadKekProvider` import
// `@qauth-labs/keys-vault` and call `createKekProvider`; any other value never
// loads it. The KEK stays in a Vault Transit key, which wraps and unwraps data
// keys; signing stays in the signer.
export { VAULT_KEK_PROVIDER } from './lib/settings';
export { createKekProvider } from './lib/vault-kek-provider';
