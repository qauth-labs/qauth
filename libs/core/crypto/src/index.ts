export type { JwsAlgorithm, SignatureAlgorithm } from './lib/algorithms';
export { getSignatureBackend } from './lib/backend-registry';
export { deriveMlDsaPublicKey } from './lib/backends/ml-dsa-65';
export { CryptoVerificationError, type CryptoVerificationErrorReason } from './lib/errors';
export {
  PQC_ALG_ML_DSA_65,
  PQC_HEADER_ALG_MEMBER,
  PQC_HEADER_KID_MEMBER,
  PQC_JOSE_COMPOSITE_DRAFT,
} from './lib/hybrid-constants';
export {
  extractJwsSigningInput,
  type HybridSignedToken,
  type HybridSigningKey,
  type HybridVerifyKey,
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
  isMlDsaKey,
  ML_DSA_65_LENGTHS,
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
export { sign, type SignOptions, verify, type VerifyOptions } from './lib/signing';
