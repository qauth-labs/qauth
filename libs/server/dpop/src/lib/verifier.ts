import { createHash, timingSafeEqual } from 'node:crypto';

import {
  calculateJwkThumbprint,
  compactVerify,
  decodeProtectedHeader,
  errors as joseErrors,
  importJWK,
  type JWK,
} from 'jose';

import {
  DEFAULT_DPOP_ALGORITHMS,
  type DpopAlgorithm,
  isDpopAlgorithm,
  keyFitsAlgorithm,
} from './algorithms';
import { DpopProofError, type DpopRejectionReason } from './dpop-error';
import { normalizeHtu } from './htu';
import type { DpopNonceSource } from './nonce';
import type { DpopReplayStore } from './replay-store';

/** The `typ` of a DPoP proof (RFC 9449 §4.2). */
export const DPOP_PROOF_TYP = 'dpop+jwt';

/** The default `iat` window, in seconds on either side of the server's clock. */
export const DEFAULT_DPOP_IAT_WINDOW_SECONDS = 60;

/** The default time the replay store has to answer, in milliseconds. */
export const DEFAULT_DPOP_REPLAY_STORE_TIMEOUT_MS = 250;

/**
 * The longest `DPoP` header value the verifier reads. A proof with a 4096-bit
 * RSA key in its header is under 3 KiB.
 */
export const MAX_DPOP_PROOF_LENGTH = 8192;

/** The longest `jti` the verifier accepts (RFC 9449 §11.1: refuse large ones). */
export const MAX_DPOP_JTI_LENGTH = 256;

/** A compact JWS: three base64url parts, none empty. */
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/** JWK members that only a private or a symmetric key has (RFC 7518 §6, RFC 8037 §2). */
const PRIVATE_KEY_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'] as const;

/**
 * Claims of the other JWTs a DPoP key signs — spawn assertions (`sub`,
 * `cnf`) and security event tokens (`events`) — which a proof never carries,
 * so the JWT types of the key family stay disjoint by claim set (ADR-014 §4).
 */
const CLAIMS_NOT_ALLOWED = ['sub', 'cnf', 'events'] as const;

/** Options for {@link createDpopVerifier}. */
export interface DpopVerifierOptions {
  /** Where used proofs are recorded. Required: without it, replays pass. */
  readonly replayStore: DpopReplayStore;
  /**
   * The algorithms a proof may use, a non-empty subset of
   * `DPOP_SIGNATURE_ALGORITHMS`. Default {@link DEFAULT_DPOP_ALGORITHMS}.
   */
  readonly algorithms?: readonly DpopAlgorithm[];
  /**
   * How far `iat` may be from the server's clock, in seconds, in either
   * direction. Default 60.
   */
  readonly iatWindowSeconds?: number;
  /** Where this server's nonces come from. Needed only by calls that require one. */
  readonly nonces?: DpopNonceSource;
  /** How long the replay store may take before the proof is refused. Default 250 ms. */
  readonly replayStoreTimeoutMs?: number;
  /** The clock, in epoch milliseconds. Default `Date.now`. */
  readonly now?: () => number;
}

/** One request's proof and what it must match. */
export interface DpopProofCheck {
  /**
   * The request's `DPoP` header: a string, or the list of values when the
   * framework gives one per header line. `undefined` or empty means none.
   */
  readonly proof: string | readonly string[] | undefined;
  /** The request's method, as received, such as `POST`. Compared with `htm` exactly. */
  readonly method: string;
  /**
   * The URL the request was sent to, built from the server's own configuration
   * (its issuer or the realm's host) and the request path, never from the
   * proof or an unchecked `Host`. Query and fragment are ignored.
   */
  readonly url: string;
  /**
   * The access token presented with the proof, at a protected resource. When
   * set, `ath` must be its hash (RFC 9449 §4.3 step 12).
   */
  readonly accessToken?: string;
  /**
   * The thumbprint the token, code or session is bound to (`cnf.jkt`,
   * `dpop_jkt`). When set, the proof's key must have it.
   */
  readonly expectedThumbprint?: string;
  /**
   * Require a server-provided nonce (RFC 9449 §8, §9). A proof without one, or
   * with one the nonce source does not accept, is refused with
   * `use_dpop_nonce` and a fresh nonce. Needs {@link DpopVerifierOptions.nonces}.
   */
  readonly requireNonce?: boolean;
}

/** A proof that passed every check. */
export interface VerifiedDpopProof {
  /**
   * The RFC 7638 SHA-256 thumbprint of the proof's key, base64url: the value
   * of `cnf.jkt` for a token bound to it (RFC 9449 §6.1).
   */
  readonly thumbprint: string;
  readonly algorithm: DpopAlgorithm;
  /** The proof's public key, as its `jwk` header gave it. */
  readonly jwk: Readonly<JWK>;
  readonly jti: string;
  /** The proof's `iat`, in seconds. */
  readonly issuedAt: number;
  /**
   * A nonce for the response's `DPoP-Nonce` header (RFC 9449 §8.2), when the
   * verifier has a nonce source; the client uses it for its next proof.
   */
  readonly nextNonce?: string;
}

/** The shared DPoP proof verifier (RFC 9449 §4.3). */
export interface DpopVerifier {
  /** The algorithms it accepts, for `dpop_signing_alg_values_supported` and the `algs` challenge parameter. */
  readonly algorithms: readonly DpopAlgorithm[];
  /**
   * Check one request's proof. Resolves with the key's thumbprint when every
   * check passes, and records the proof so it cannot be used again; rejects
   * with a {@link DpopProofError} otherwise.
   */
  verify(check: DpopProofCheck): Promise<VerifiedDpopProof>;
  /** A fresh nonce for a `DPoP-Nonce` header, or `undefined` without a nonce source. */
  nonce(): Promise<string | undefined>;
}

/** The base64url SHA-256 of an access token: a proof's `ath` for it (RFC 9449 §4.2). */
export function dpopAccessTokenHash(accessToken: string): string {
  return createHash('sha256').update(accessToken, 'utf8').digest('base64url');
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sameText(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

function refuse(reason: DpopRejectionReason, cause?: unknown): never {
  throw new DpopProofError(reason, undefined, cause === undefined ? undefined : { cause });
}

/** The one proof of a request, or a refusal when there is none or more than one. */
function singleProof(proof: DpopProofCheck['proof']): string {
  const values = typeof proof === 'string' ? [proof] : (proof ?? []);
  const present = values.filter((value) => value.trim() !== '');
  if (present.length === 0) refuse('missing-proof');
  if (present.length > 1) refuse('multiple-proofs');
  const value = present[0].trim();
  // Node joins repeated unknown headers with ", "; a compact JWS has no comma.
  if (value.includes(',')) refuse('multiple-proofs');
  if (value.length > MAX_DPOP_PROOF_LENGTH || !COMPACT_JWS.test(value)) refuse('malformed');
  return value;
}

/**
 * Create the DPoP proof verifier. It takes the `DPoP` header value, the
 * request's method and URL and, at a protected resource, the access token,
 * and returns the key's RFC 7638 thumbprint.
 *
 * Checks, in this order (RFC 9449 §4.3): exactly one header holding one
 * compact JWS; `typ` exactly `dpop+jwt`; `alg` on the allowlist; a public
 * `jwk` header of the type `alg` needs, with no private members; the
 * signature under that key; no `sub`, `cnf` or `events` claim; `jti`; `htm`
 * and `htu` against the method and URL the CALLER passes; `iat` within the
 * window; `ath` when an access token is presented; the thumbprint when one is
 * expected; the nonce when one is required; and last, the replay store. A
 * proof that fails an earlier check never reaches the store.
 *
 * Options are checked here, so a misconfigured verifier fails at boot: an
 * allowlist that is empty or names `none`, a MAC or an unknown algorithm
 * throws.
 */
export function createDpopVerifier(options: DpopVerifierOptions): DpopVerifier {
  if (options.replayStore === undefined || typeof options.replayStore.record !== 'function') {
    throw new TypeError('A DPoP verifier needs a replay store');
  }
  const algorithms = Object.freeze([...(options.algorithms ?? DEFAULT_DPOP_ALGORITHMS)]);
  if (algorithms.length === 0) {
    throw new TypeError('A DPoP verifier needs at least one algorithm');
  }
  for (const alg of algorithms) {
    if (!isDpopAlgorithm(alg)) {
      throw new TypeError(
        `${String(alg)} is not an asymmetric signature algorithm a DPoP proof may use`
      );
    }
  }
  const iatWindowSeconds = options.iatWindowSeconds ?? DEFAULT_DPOP_IAT_WINDOW_SECONDS;
  if (!Number.isInteger(iatWindowSeconds) || iatWindowSeconds <= 0) {
    throw new TypeError('iatWindowSeconds must be a positive whole number of seconds');
  }
  const replayStoreTimeoutMs = options.replayStoreTimeoutMs ?? DEFAULT_DPOP_REPLAY_STORE_TIMEOUT_MS;
  if (!Number.isFinite(replayStoreTimeoutMs) || replayStoreTimeoutMs <= 0) {
    throw new TypeError('replayStoreTimeoutMs must be a positive number of milliseconds');
  }
  const { replayStore, nonces } = options;
  const now = options.now ?? Date.now;

  /**
   * Record the proof, given up after {@link replayStoreTimeoutMs}. The call
   * itself is left to finish or fail on its own; its late failure is ignored.
   */
  async function recordOnce(key: string): Promise<boolean> {
    // A proof passes while the clock is within the window of its iat, edges
    // included, and its iat is at most one window ahead of the clock now. So
    // it passes at most two windows from now; one second more keeps the
    // record past the last moment it does.
    const call = replayStore.record(key, (2 * iatWindowSeconds + 1) * 1000);
    call.catch(() => undefined);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error('The DPoP replay store did not answer in time')),
        replayStoreTimeoutMs
      );
    });
    try {
      return await Promise.race([call, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  async function freshNonce(): Promise<string | undefined> {
    return nonces === undefined ? undefined : await nonces.current();
  }

  async function verify(check: DpopProofCheck): Promise<VerifiedDpopProof> {
    const expectedUrl = normalizeHtu(check.url);
    if (expectedUrl === undefined) {
      throw new TypeError('The URL to check a DPoP proof against must be an absolute http(s) URL');
    }
    if (check.requireNonce && nonces === undefined) {
      throw new TypeError('A DPoP verifier without a nonce source cannot require a nonce');
    }

    const proof = singleProof(check.proof);

    let header: Record<string, unknown>;
    try {
      header = decodeProtectedHeader(proof) as Record<string, unknown>;
    } catch (error) {
      refuse('malformed', error);
    }
    // No extension is understood here, so any crit is refused (RFC 7515 §4.1.11),
    // as jose would; and no unencoded payload (RFC 7797).
    if (!isObject(header) || 'crit' in header || 'b64' in header) refuse('malformed');
    if (header['typ'] !== DPOP_PROOF_TYP) refuse('typ');

    const alg = header['alg'];
    if (!isDpopAlgorithm(alg) || !algorithms.includes(alg)) refuse('alg');

    const jwk = header['jwk'];
    if (!isObject(jwk)) refuse('jwk');
    if (jwk['kty'] === 'oct' || PRIVATE_KEY_MEMBERS.some((member) => member in jwk)) {
      refuse('private-key');
    }
    // jose's import refuses such a key too; checked here so the rule does not
    // depend on the crypto library.
    if (!keyFitsAlgorithm(alg, jwk)) refuse('jwk');

    let key: Awaited<ReturnType<typeof importJWK>>;
    try {
      key = await importJWK(jwk as JWK, alg);
    } catch (error) {
      refuse('jwk', error);
    }
    if (key instanceof Uint8Array || key.type !== 'public') refuse('private-key');

    let payloadBytes: Uint8Array;
    try {
      ({ payload: payloadBytes } = await compactVerify(proof, key, { algorithms: [alg] }));
    } catch (error) {
      if (error instanceof joseErrors.JWSSignatureVerificationFailed) refuse('signature', error);
      // jose refuses an RSA key under 2048 bits with a TypeError.
      if (error instanceof TypeError) refuse('jwk', error);
      refuse('malformed', error);
    }

    let claims: unknown;
    try {
      claims = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes));
    } catch (error) {
      refuse('malformed', error);
    }
    if (!isObject(claims)) refuse('malformed');
    if (CLAIMS_NOT_ALLOWED.some((claim) => claim in claims)) refuse('claims-not-allowed');

    const jti = claims['jti'];
    if (typeof jti !== 'string' || jti.length === 0 || jti.length > MAX_DPOP_JTI_LENGTH) {
      refuse('jti');
    }

    if (typeof claims['htm'] !== 'string' || claims['htm'] !== check.method) refuse('htm');

    const htu = claims['htu'];
    if (typeof htu !== 'string' || normalizeHtu(htu) !== expectedUrl) refuse('htu');

    const iat = claims['iat'];
    const nowSeconds = now() / 1000;
    if (
      typeof iat !== 'number' ||
      !Number.isFinite(iat) ||
      Math.abs(nowSeconds - iat) > iatWindowSeconds
    ) {
      refuse('iat');
    }

    if (check.accessToken !== undefined) {
      const ath = claims['ath'];
      if (typeof ath !== 'string' || !sameText(ath, dpopAccessTokenHash(check.accessToken))) {
        refuse('ath');
      }
    }

    const thumbprint = await calculateJwkThumbprint(jwk as JWK, 'sha256');
    if (check.expectedThumbprint !== undefined && !sameText(thumbprint, check.expectedThumbprint)) {
      refuse('key-mismatch');
    }

    if (check.requireNonce && nonces !== undefined) {
      const nonce = claims['nonce'];
      if (nonce === undefined) {
        throw new DpopProofError('nonce-required', await nonces.current());
      }
      if (typeof nonce !== 'string' || !(await nonces.accepts(nonce))) {
        throw new DpopProofError('nonce-invalid', await nonces.current());
      }
    }

    // The key and the jti, hashed: a proof is replayed only by its own key,
    // so one client's jti values cannot block another's, and the client
    // chooses neither the stored key nor its length.
    const replayKey = createHash('sha256')
      .update(`${thumbprint}.${jti}`, 'utf8')
      .digest('base64url');
    let firstUse: boolean;
    try {
      firstUse = await recordOnce(replayKey);
    } catch (error) {
      refuse('replay-store-unavailable', error);
    }
    if (!firstUse) refuse('replayed');

    const publicJwk: JWK = { ...(jwk as JWK) };
    return {
      thumbprint,
      algorithm: alg,
      jwk: Object.freeze(publicJwk),
      jti,
      issuedAt: iat,
      nextNonce: await freshNonce(),
    };
  }

  return { algorithms, verify, nonce: freshNonce };
}
