// Envelope encryption of stored keys, the KEK provider, and the key purposes (ADR-019 Decision 9)
export {
  encodeKeyAad,
  KEY_AAD_VERSION,
  type KeyAad,
  keyAad,
  type KeyIdentity,
  SUPPORTED_KEY_AAD_VERSIONS,
} from './lib/aad';
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
  isKeyCustodyError,
  KekAccessDeniedError,
  KekUnavailableError,
  KEY_DECRYPTION_ERROR_MESSAGE,
  KeyCustodyError,
  type KeyCustodyErrorCode,
  KeyDecryptionError,
  UnknownKekRefError,
} from './lib/errors';
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
  ActiveKeyConflictError,
  type KeyCreationRefusalReason,
  KeyCreationRefusedError,
  KeyIdConflictError,
} from './lib/key-creation-errors';
export {
  type CreatedKey,
  createKeyFactory,
  type CreateKeyInput,
  type KeyFactory,
  type KeyFactoryOptions,
  MAX_SCOPE_ID_LENGTH,
  type ProvisionRealmKeysOptions,
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
export {
  DEFAULT_KEY_ROTATION_PERIOD_DAYS,
  getKeyPurpose,
  isKeyPurpose,
  KEY_ALGORITHM_KINDS,
  KEY_ALGORITHMS,
  KEY_PURPOSES,
  type KeyAlgorithm,
  type KeyKind,
  type KeyPurpose,
  type KeyPurposeDefinition,
  type KeyRotationDefault,
  STANDARD_REALM_KEY_PURPOSES,
} from './lib/key-purposes';
export type {
  NewKeyStatus,
  NewStoredKey,
  NewStoredKeyRow,
  RealmKeyStore,
  StoredKeyFilter,
  StoredKeyStatus,
  StoredKeySummary,
} from './lib/key-store';
export {
  DEFAULT_KEK_PROVIDER,
  type ImportKekProviderModule,
  KEK_PROVIDER_NAME,
  kekProviderPackage,
  loadKekProvider,
} from './lib/load-kek-provider';
