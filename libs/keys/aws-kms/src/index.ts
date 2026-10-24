// The AWS KMS KEK adapter (ADR-019 Decision 9, #577).
//
// An optional package: the auth server does not depend on it.
// `KEK_PROVIDER=aws-kms` makes the key library's `loadKekProvider` import
// `@qauth-labs/keys-aws-kms` and call `createKekProvider`; any other value
// never loads it. The KEK stays in KMS, which wraps and unwraps data keys;
// signing stays in the signer.
export { createKekProvider } from './lib/aws-kms-kek-provider';
export { ENCRYPTION_CONTEXT_KEYS } from './lib/encryption-context';
export { AWS_KMS_KEK_PROVIDER } from './lib/settings';
