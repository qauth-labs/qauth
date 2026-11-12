/**
 * The solver of the built-in bot challenge (#643; ADR-017 Decision 7): the
 * `captcha` step whose params are `provider` `pow`, a `challenge` and a
 * `difficulty`. It runs in the page, from the realm origin, so the strict
 * content security policy needs no exception for it, and it asks nothing of
 * any other host.
 *
 * The rule is the contract's (#1082): the `pow` params of the `captcha` step
 * state it, and a replacement ceremony app writes its solver from it. A nonce
 * solves the puzzle when the SHA-256 of the UTF-8 bytes of
 * `<challenge>:<nonce>` starts with at least `difficulty` zero bits; this
 * solver returns the smallest. The server checks it in one hash; finding it
 * takes about 2^difficulty. The nonce goes back as the step's `captcha_token`.
 * The tests run the shared vectors, `test-vectors/interaction/proof-of-work.json`,
 * which the server's check runs too.
 *
 * Internal to the reference ceremony app: this package is not published
 * (the Interaction API reference, "Replacement apps").
 */

/** The `captcha` step's params of the built-in proof of work. */
export interface ProofOfWorkParams {
  readonly provider: 'pow';
  readonly challenge: string;
  readonly difficulty: number;
}

/** Options of {@link solveProofOfWork}. */
export interface ProofOfWorkOptions {
  /** Stops the search: the promise rejects with the signal's reason. */
  readonly signal?: AbortSignal;
  /**
   * The most nonces tried before giving up. 2^40 by default: at the highest
   * difficulty a realm may set, 32 bits, a solution is all but certain well
   * before it, and a nonce stays within the 16 digits the server takes.
   */
  readonly maxAttempts?: number;
  /** The Web Crypto to hash with. The global `crypto.subtle` by default. */
  readonly subtle?: Pick<SubtleCrypto, 'digest'>;
}

/** How many hashes run at once: Web Crypto answers each one asynchronously. */
const BATCH = 256;

/** The leading zero bits of `digest`. */
function leadingZeroBits(digest: Uint8Array): number {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

/**
 * Find the nonce that solves `params`: its decimal form, to send as
 * `captcha_token`.
 *
 * @throws RangeError when the params are not a proof of work this solver
 *   takes, or no nonce below `maxAttempts` solves them
 */
export async function solveProofOfWork(
  params: ProofOfWorkParams,
  options: ProofOfWorkOptions = {}
): Promise<string> {
  const { challenge, difficulty } = params;
  if (
    params.provider !== 'pow' ||
    typeof challenge !== 'string' ||
    !/^[A-Za-z0-9_-]{22,128}$/.test(challenge) ||
    !Number.isInteger(difficulty) ||
    difficulty < 1 ||
    difficulty > 32
  ) {
    throw new RangeError('not a proof of work');
  }
  const subtle = options.subtle ?? globalThis.crypto.subtle;
  const maxAttempts = options.maxAttempts ?? 2 ** 40;
  const encoder = new TextEncoder();
  for (let start = 0; start < maxAttempts; start += BATCH) {
    options.signal?.throwIfAborted();
    const nonces = Array.from({ length: Math.min(BATCH, maxAttempts - start) }, (_, i) =>
      String(start + i)
    );
    const digests = await Promise.all(
      nonces.map((nonce) => subtle.digest('SHA-256', encoder.encode(`${challenge}:${nonce}`)))
    );
    const found = digests.findIndex(
      (digest) => leadingZeroBits(new Uint8Array(digest)) >= difficulty
    );
    if (found !== -1) return nonces[found] as string;
  }
  throw new RangeError('no solution within the attempts allowed');
}
