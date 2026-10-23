// The signer interface and the public facts about keys (ADR-019 Decision 9).
//
// This entry point holds nothing that touches a KEK or key material. The KEK
// provider, the envelope, key generation, the key factory and the in-process
// signer are in `@qauth-labs/server-keys/custody`, which only the signer's
// wiring may import (eslint.config.mjs, issue #464).
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
export {
  ActiveKeyConflictError,
  type KeyChangeRefusalReason,
  KeyChangeRefusedError,
  type KeyCreationRefusalReason,
  KeyCreationRefusedError,
  KeyIdConflictError,
  NextKeyConflictError,
} from './lib/key-creation-errors';
export {
  DEFAULT_KEY_PREPUBLISH_DAYS,
  DEFAULT_KEY_RETIRED_RETENTION_DAYS,
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
export {
  type CookieSecret,
  type CookieSecrets,
  type DecryptRequest,
  type EncryptRequest,
  type JwsKeyAlgorithm,
  type RealmJwks,
  type Signer,
  SIGNER_OPERATIONS,
  type SignerOperation,
  type SignHybridRequest,
  type SignJwsRequest,
  type VerificationKey,
} from './lib/signer';
export {
  DATA_DECRYPTION_ERROR_MESSAGE,
  DataDecryptionError,
  isSignerError,
  RealmIssuerNotFoundError,
  SignerAccessDeniedError,
  SignerError,
  type SignerErrorCode,
  SignerKeyNotFoundError,
  type SignerRefusalReason,
  SignerRequestRefusedError,
} from './lib/signer-errors';
export {
  isSignerCallAllowed,
  isSignerCaller,
  SIGNER_CALLERS,
  SIGNER_POLICY,
  type SignerCaller,
  type SignerGrant,
} from './lib/signer-policy';
export {
  isJwsSigningPurpose,
  isTypAllowed,
  JWS_SIGNING_PURPOSES,
  JWS_TYP_BY_PURPOSE,
  type JwsSigningPurpose,
  type JwsTyp,
  REALM_JWKS_PURPOSES,
} from './lib/signer-typ';
export {
  MAX_WEBHOOK_ID_LENGTH,
  WEBHOOK_SECRET_PREFIX,
  WEBHOOK_SIGNATURE_VERSION,
} from './lib/webhook-signature';
