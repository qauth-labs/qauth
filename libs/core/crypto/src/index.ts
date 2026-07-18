export type { JwsAlgorithm, SignatureAlgorithm } from './lib/algorithms';
export { getSignatureBackend } from './lib/backend-registry';
export { CryptoVerificationError, type CryptoVerificationErrorReason } from './lib/errors';
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
