import type { HybridSignedToken } from '@qauth-labs/core-crypto';
import type { JWK } from 'jose';

import type { SignerCaller } from './signer-policy';
import type { JwsSigningPurpose } from './signer-typ';

/**
 * The signer: the one component that uses a realm's private keys (ADR-019
 * Decision 9, issue #464).
 *
 * Every other component signs, encrypts and reads verification keys through
 * this interface. In a single deployment the signer runs in-process
 * (`createInProcessSigner`); in a distributed one the other roles reach it over
 * mutual TLS through a client with this same interface (#497).
 *
 * What the interface promises:
 *
 * - **No key leaves it.** No operation returns private key material or a key
 *   object. The one secret it hands out is the cookie HMAC secret, to the
 *   browser-facing role, as ADR-019 Decision 9 provides.
 * - **The signer names the issuer and the key.** It sets `iss` from the realm
 *   row and `kid` from the realm's active key. A caller cannot set either, so a
 *   compromised caller cannot mint a token for another issuer or under another
 *   key.
 * - **Each purpose signs only its own token types** (`JWS_TYP_BY_PURPOSE`).
 * - **Each call names its caller's role**, and the role's grants in
 *   `SIGNER_POLICY` decide whether the call runs. A compromised caller still
 *   gets signatures for the purposes its role may use, never a key.
 * - **Keys are never created here.** A realm without a key for the purpose gets
 *   a `SignerKeyNotFoundError`; creating keys is the key factory's job.
 *
 * Claim shaping stays with the caller: it passes the finished claims set,
 * `exp`, `aud`, `iat` and `sub` included, and the signer adds `iss`.
 */
export interface Signer {
  /**
   * Sign `claims` as a compact JWS with the realm's active key of `purpose`.
   *
   * The protected header is `alg`, `kid` and `typ`. The payload is `iss`, from
   * the realm row, followed by `claims`.
   *
   * @throws SignerAccessDeniedError when `caller` may not sign with `purpose`
   * @throws SignerRequestRefusedError when the purpose cannot sign `typ`, the
   *   algorithm does not fit the purpose, `claims` sets `iss`, the request
   *   carries a field the operation does not take (such as `kid`), or the
   *   claims are not a JSON object
   * @throws RealmIssuerNotFoundError when the realm does not exist or has no issuer
   * @throws SignerKeyNotFoundError when the realm has no active key of the
   *   purpose and algorithm
   * @throws KeyCustodyError (`KEY_DECRYPTION_FAILED`, `KEK_UNKNOWN_REF`,
   *   `KEK_UNAVAILABLE`, `KEK_ACCESS_DENIED`) when the key cannot be unwrapped.
   *   The signer never tries another key instead.
   */
  signJws(caller: SignerCaller, request: SignJwsRequest): Promise<string>;

  /**
   * Sign `claims` with the realm's hybrid `token_signing` pair: the
   * detached-parallel carrier of ADR-005. `token` is an ordinary EdDSA compact
   * JWS whose protected header also names the ML-DSA-65 key (`pqc_alg`,
   * `pqc_kid`); `pqcSignature` is the ML-DSA-65 signature over the same JWS
   * signing input. `verifyHybrid` in `@qauth-labs/core-crypto` checks both.
   *
   * @throws SignerRequestRefusedError (`HYBRID_SIGNING_DISABLED`) when
   *   `HYBRID_SIGNING_ENABLED` is off: the ML-DSA-65 key is then never unwrapped
   * @throws SignerKeyNotFoundError when the realm has no active EdDSA and
   *   ML-DSA-65 `token_signing` keys that form one pair
   * @throws the errors of {@link signJws} otherwise
   */
  signHybrid(caller: SignerCaller, request: SignHybridRequest): Promise<HybridSignedToken>;

  /**
   * The realm's cookie HMAC secrets: the active one, which signs, and the most
   * recently retired one, which only verifies until its retention ends (#542).
   * Each call returns fresh buffers that belong to the caller.
   *
   * @throws SignerKeyNotFoundError when the realm has no active `cookie_hmac` key
   */
  getCookieSecrets(caller: SignerCaller, realmId: string): Promise<CookieSecrets>;

  /**
   * Encrypt `plaintext` with the realm's active `data_at_rest` key
   * (AES-256-GCM). The result names the key's `kid`, so it still decrypts after
   * a rotation, while the old key is retained. The format is `v1.<kid>.<iv>.<ciphertext>`;
   * the server-keys README describes it.
   *
   * @throws SignerKeyNotFoundError when the realm has no active `data_at_rest` key
   */
  encrypt(caller: SignerCaller, request: EncryptRequest): Promise<string>;

  /**
   * Decrypt what {@link encrypt} returned, with the key its `kid` names. An
   * `active` or `retired` key decrypts; a `next` key has encrypted nothing and
   * a `compromised` one is refused.
   *
   * @throws DataDecryptionError when the ciphertext is malformed, was made for
   *   another realm or `context`, or was changed
   * @throws SignerKeyNotFoundError when the realm holds no usable
   *   `data_at_rest` key with the ciphertext's `kid`
   */
  decrypt(caller: SignerCaller, request: DecryptRequest): Promise<Buffer>;

  /**
   * The public keys that may verify tokens of `purpose`: its `active` keys and
   * its `retired` keys still inside their publication window. A `next` key has
   * signed nothing and a `compromised` one verifies nothing, so neither is
   * listed. ML-DSA-65 keys of a hybrid pair are listed with the rest.
   */
  getVerificationKeys(
    caller: SignerCaller,
    realmId: string,
    purpose: JwsSigningPurpose
  ): Promise<readonly VerificationKey[]>;

  /**
   * The realm's JWKS (RFC 7517 §5): every published key of
   * `REALM_JWKS_PURPOSES` inside its publication window, `next` keys included,
   * so relying parties learn a key before it signs. Never a `compromised` key.
   * The order is fixed, so every node returns the same document.
   */
  getJwks(caller: SignerCaller, realmId: string): Promise<RealmJwks>;
}

/** The JWS algorithms `signJws` signs with. ML-DSA-65 signs only through `signHybrid`. */
export type JwsKeyAlgorithm = 'EdDSA' | 'RS256' | 'ES256';

/** Input of {@link Signer.signJws}. */
export interface SignJwsRequest {
  readonly realmId: string;
  readonly purpose: JwsSigningPurpose;
  /**
   * The owner of a scoped key. Every purpose `signJws` serves today is
   * unscoped, so a scope id is refused; the scoped signing purposes get their
   * own operations (#547).
   */
  readonly scopeId?: string | null;
  /** The token type. It must be one that `purpose` signs (`JWS_TYP_BY_PURPOSE`). */
  readonly typ: string;
  /**
   * The algorithm of the key to sign with. Defaults to the purpose's default
   * algorithm (`EdDSA`). An ID token for a client that registered
   * `id_token_signed_response_alg=RS256` passes `RS256`.
   */
  readonly algorithm?: JwsKeyAlgorithm;
  /** The claims set, without `iss`. */
  readonly claims: Readonly<Record<string, unknown>>;
}

/** Input of {@link Signer.signHybrid}. The purpose is always `token_signing`. */
export interface SignHybridRequest {
  readonly realmId: string;
  /** The token type. It must be one that `token_signing` signs. */
  readonly typ: string;
  /** The claims set, without `iss`. */
  readonly claims: Readonly<Record<string, unknown>>;
}

/** One cookie HMAC secret and the `kid` of the key that holds it. */
export interface CookieSecret {
  readonly kid: string;
  /** The secret. A fresh buffer that belongs to the caller. */
  readonly secret: Buffer;
}

/** What {@link Signer.getCookieSecrets} returns. */
export interface CookieSecrets {
  /** Signs new cookies and verifies them. */
  readonly current: CookieSecret;
  /** Only verifies cookies signed before the last rotation. `null` when there is none. */
  readonly previous: CookieSecret | null;
}

/** Input of {@link Signer.encrypt}. */
export interface EncryptRequest {
  readonly realmId: string;
  readonly plaintext: Uint8Array;
  /**
   * What the ciphertext belongs to, such as a table, column and row id. It is
   * authenticated, not stored: decrypting needs the same value, so a
   * ciphertext copied to another row fails to decrypt. Defaults to the empty
   * string.
   */
  readonly context?: string;
}

/** Input of {@link Signer.decrypt}. */
export interface DecryptRequest {
  readonly realmId: string;
  /** What {@link Signer.encrypt} returned. */
  readonly ciphertext: string;
  /** The `context` the ciphertext was made with. */
  readonly context?: string;
}

/** A key that may verify, as {@link Signer.getVerificationKeys} returns it. */
export interface VerificationKey {
  readonly kid: string;
  /** `EdDSA`, `RS256`, `ES256` or `ML-DSA-65`. */
  readonly algorithm: string;
  readonly status: 'active' | 'retired';
  /** The public JWK with `kid`, `alg` and `use`. Never a private member. */
  readonly publicJwk: JWK;
}

/** A JWK Set (RFC 7517 §5). */
export interface RealmJwks {
  readonly keys: readonly JWK[];
}

/**
 * Every operation of {@link Signer}. The policy table, the remote signer's
 * routes (#497) and the test that no operation returns key material all
 * enumerate this list, and a type check keeps it equal to the interface.
 */
export const SIGNER_OPERATIONS = Object.freeze([
  'signJws',
  'signHybrid',
  'getCookieSecrets',
  'encrypt',
  'decrypt',
  'getVerificationKeys',
  'getJwks',
] as const satisfies readonly (keyof Signer)[]);

/** An operation of {@link Signer}. */
export type SignerOperation = (typeof SIGNER_OPERATIONS)[number];

// Fails to compile when the interface gains an operation the list lacks.
type MissingOperation = Exclude<keyof Signer, SignerOperation>;
const everyOperationListed: [MissingOperation] extends [never] ? true : MissingOperation = true;
void everyOperationListed;
