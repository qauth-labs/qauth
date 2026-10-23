// Key custody: the KEK provider, envelope encryption, key generation, the key
// factory and the in-process signer (ADR-019 Decision 9).
//
// ADR-019 provisions the KEK to the signer role alone, so only the signer's
// wiring may import this entry point; everything else reaches keys through the
// `Signer` interface of `@qauth-labs/server-keys`. A `no-restricted-imports`
// rule in eslint.config.mjs enforces it (issue #464).
export {
  encodeKeyAad,
  KEY_AAD_VERSION,
  type KeyAad,
  keyAad,
  type KeyIdentity,
  SUPPORTED_KEY_AAD_VERSIONS,
} from './lib/aad';
export { DATA_AT_REST_VERSION, MAX_DATA_CONTEXT_LENGTH } from './lib/data-at-rest';
export { createLocalKekProvider, LOCAL_KEK_PROVIDER } from './lib/default-kek-provider';
export {
  DATA_KEY_BYTES,
  IV_BYTES,
  openKeyMaterial,
  type SealedKeyMaterial,
  sealKeyMaterial,
  TAG_BYTES,
} from './lib/envelope';
export {
  createInProcessSigner,
  DEFAULT_SIGNER_KEY_CACHE_SIZE,
  DEFAULT_SIGNER_REFRESH_INTERVAL_MS,
  type InProcessSignerOptions,
} from './lib/in-process-signer';
export type {
  KekEnv,
  KekProvider,
  KekProviderContext,
  KekProviderHealth,
  KekProviderModule,
  KekWarning,
  WrappedDataKey,
} from './lib/kek-provider';
export {
  type KekProviderContractOptions,
  runKekProviderContract,
} from './lib/kek-provider-contract';
export { computeKekRef, DEV_KEK_DEFAULT, KEK_BYTES } from './lib/kek-sources';
export {
  type ActivatedKey,
  type ActivateNextKeyInput,
  type CreatedKey,
  createKeyFactory,
  type CreateKeyInput,
  type KeyFactory,
  type KeyFactoryOptions,
  MAX_SCOPE_ID_LENGTH,
  type ProvisionRealmKeysOptions,
  type ScopedKeyInput,
} from './lib/key-factory';
export {
  assertAllowedBySigningMode,
  type GeneratedKeyMaterial,
  generateKeyMaterial,
  type GenerateKeyMaterialOptions,
  isAllowedBySigningMode,
  jwkThumbprintKid,
  RANDOM_KID_BYTES,
  SYMMETRIC_KEY_BYTES,
} from './lib/key-generation';
export type {
  NewKeyStatus,
  NewStoredKey,
  NewStoredKeyRow,
  RealmKeyStore,
  StoredKeyFilter,
  StoredKeyStatus,
  StoredKeyStatusChange,
  StoredKeySummary,
} from './lib/key-store';
export {
  DEFAULT_KEK_PROVIDER,
  type ImportKekProviderModule,
  KEK_PROVIDER_NAME,
  kekProviderPackage,
  loadKekProvider,
} from './lib/load-kek-provider';
export type {
  PublicKeyRecord,
  SignerKeyRecord,
  SignerKeyStore,
  WrappedSignerKey,
} from './lib/signer-key-store';
