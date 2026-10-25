import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Where server-provided DPoP nonces come from (RFC 9449 §8 and §9).
 *
 * An endpoint that asks for a nonce answers a proof without one, or with an
 * old one, with `use_dpop_nonce` and a fresh value in the `DPoP-Nonce`
 * header; the client retries with it. Nonces are opaque to the client and
 * MUST be unpredictable (§8). A source belongs to one server: an
 * authorization server and a resource server each have their own, so a nonce
 * is accepted only by the server that issued it (§9).
 */
export interface DpopNonceSource {
  /** A nonce to hand out now, for a `DPoP-Nonce` header. */
  current(): string | Promise<string>;
  /** Whether `nonce`, read from a proof, is one this source handed out recently. */
  accepts(nonce: string): boolean | Promise<boolean>;
}

/** A nonce source that answers at once: what {@link createHmacDpopNonceSource} returns. */
export interface SyncDpopNonceSource extends DpopNonceSource {
  current(): string;
  accepts(nonce: string): boolean;
}

/** Options for {@link createHmacDpopNonceSource}. */
export interface HmacDpopNonceSourceOptions {
  /**
   * The key the nonces are derived from, at least 32 bytes of random data.
   * Every node of one server shares it; without it, a node refuses the nonces
   * another node handed out.
   */
  readonly secret: Uint8Array;
  /** How often the nonce changes, in seconds. Default 60. */
  readonly rotateSeconds?: number;
  /** The clock, in epoch milliseconds. Default `Date.now`. */
  readonly now?: () => number;
}

/** The shortest secret {@link createHmacDpopNonceSource} accepts, in bytes. */
export const MIN_NONCE_SECRET_BYTES = 32;

/** The default {@link HmacDpopNonceSourceOptions.rotateSeconds}. */
export const DEFAULT_NONCE_ROTATE_SECONDS = 60;

/**
 * A nonce source that keeps no state: the nonce of each period of
 * `rotateSeconds` is an HMAC-SHA256 of the period's number under `secret`,
 * base64url, so it is unpredictable without the secret and every node with
 * the same secret computes the same one.
 *
 * A nonce is accepted during its own period and the next one, so a nonce
 * handed out just before a change still works for at least `rotateSeconds`
 * and never for more than twice that. Its 43 characters are all in the NQCHAR
 * set of RFC 9449 §8.1.
 */
export function createHmacDpopNonceSource(
  options: HmacDpopNonceSourceOptions
): SyncDpopNonceSource {
  if (!(options.secret instanceof Uint8Array) || options.secret.length < MIN_NONCE_SECRET_BYTES) {
    throw new TypeError(
      `The DPoP nonce secret must be at least ${MIN_NONCE_SECRET_BYTES} bytes of random data`
    );
  }
  const rotateSeconds = options.rotateSeconds ?? DEFAULT_NONCE_ROTATE_SECONDS;
  if (!Number.isInteger(rotateSeconds) || rotateSeconds <= 0) {
    throw new TypeError('rotateSeconds must be a positive whole number of seconds');
  }
  const secret = Buffer.from(options.secret);
  const now = options.now ?? Date.now;

  const period = (): number => {
    const time = now();
    if (!Number.isFinite(time)) throw new TypeError('The DPoP nonce clock gave no time');
    return Math.floor(time / 1000 / rotateSeconds);
  };
  const nonceOf = (index: number): Buffer =>
    createHmac('sha256', secret).update(`dpop-nonce:${index}`).digest();

  return {
    current: () => nonceOf(period()).toString('base64url'),
    accepts(nonce) {
      const presented = Buffer.from(nonce, 'utf8');
      const index = period();
      let accepted = false;
      for (const candidate of [nonceOf(index), nonceOf(index - 1)]) {
        const expected = Buffer.from(candidate.toString('base64url'), 'utf8');
        if (presented.length === expected.length && timingSafeEqual(presented, expected)) {
          accepted = true;
        }
      }
      return accepted;
    },
  };
}
