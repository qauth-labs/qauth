export {
  JOSE_P256_CURVE,
  JWE_CONTENT_ENCRYPTION_ALGORITHMS,
  JWE_KEY_AGREEMENT_ALGORITHMS,
  type JweContentEncryptionAlgorithm,
  type JweKeyAgreementAlgorithm,
  type JwsAlgorithm,
  type SignatureAlgorithm,
} from './lib/algorithms';
export {
  getSignatureBackend,
  registerSignatureBackend,
  resetSignatureBackends,
} from './lib/backend-registry';
export { deriveMlDsaPublicKey, deriveMlDsaPublicKeyAndZeroize } from './lib/backends/ml-dsa-65';
export {
  type EncryptionKey,
  EPHEMERAL_ENCRYPTION_KEY_MAX_AGE_SECONDS,
  type EphemeralEncryptionKeyPair,
  exportEncryptionPrivateJwk,
  exportEncryptionPublicJwk,
  generateEphemeralEncryptionKeyPair,
  type GenerateEphemeralEncryptionKeyPairOptions,
  importEncryptionPrivateJwk,
  importEncryptionPublicJwk,
  isEphemeralEncryptionKeyPairExpired,
} from './lib/encryption-keys';
export {
  CRYPTO_DECRYPTION_ERROR_MESSAGE,
  CryptoDecryptionError,
  CryptoVerificationError,
  type CryptoVerificationErrorReason,
} from './lib/errors';
export {
  PQC_AKP_PUBLIC_JWK_MEMBERS,
  PQC_ALG_ML_DSA_65,
  PQC_HEADER_ALG_MEMBER,
  PQC_HEADER_KID_MEMBER,
  PQC_JOSE_ALG_POLICY_SPEC,
  PQC_JOSE_MLDSA_SPEC,
} from './lib/hybrid-constants';
export {
  extractJwsSigningInput,
  type HybridSignedToken,
  type HybridSigningKey,
  type HybridVerifyKey,
  type MlDsaKeyResolver,
  type PqcBackendSelection,
  signHybrid,
  verifyHybrid,
} from './lib/hybrid-signing';
export {
  type DecryptedJwe,
  decryptJwe,
  type DecryptJweOptions,
  encryptJwe,
  type EncryptJweOptions,
  RESERVED_JWE_PROTECTED_HEADER_MEMBERS,
} from './lib/jwe';
export {
  exportPublicSigningJwk,
  type ExportPublicSigningJwkOptions,
  generateSigningKeyPair,
  type GenerateSigningKeyPairOptions,
  importPrivateSigningKey,
  importPublicSigningJwk,
  importPublicSigningKey,
} from './lib/key-management';
export {
  assertMlDsaSigningKey,
  isMlDsaKey,
  ML_DSA_65_LENGTHS,
  type MlDsaBackendId,
  MlDsaKey,
  type RawSigningKeyPair,
  type SigningKey,
  type SigningKeyPair,
} from './lib/keys';
export type {
  GenerateRawKeyPairOptions,
  ImportRawKeyOptions,
  SignatureBackend,
} from './lib/primitives';
export {
  RESERVED_PROTECTED_HEADER_MEMBERS,
  sign,
  type SignOptions,
  type VerifiedToken,
  verify,
  type VerifyOptions,
  verifyWithHeader,
} from './lib/signing';
