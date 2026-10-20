// Envelope encryption of stored keys and the KEK provider (ADR-019 Decision 9)
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
export { computeKekRef, DEV_KEK_DEFAULT, KEK_BYTES } from './lib/kek-sources';
export {
  DEFAULT_KEK_PROVIDER,
  type ImportKekProviderModule,
  KEK_PROVIDER_NAME,
  kekProviderPackage,
  loadKekProvider,
} from './lib/load-kek-provider';
