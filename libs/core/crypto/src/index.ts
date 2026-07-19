export type { JwsAlgorithm, SignatureAlgorithm } from './lib/algorithms';
export {
  getSignatureBackend,
  registerSignatureBackend,
  resetSignatureBackends,
} from './lib/backend-registry';
export { deriveMlDsaPublicKey, deriveMlDsaPublicKeyAndZeroize } from './lib/backends/ml-dsa-65';
export { CryptoVerificationError, type CryptoVerificationErrorReason } from './lib/errors';
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
  generateSigningKeyPair,
  type GenerateSigningKeyPairOptions,
  importPrivateSigningKey,
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
