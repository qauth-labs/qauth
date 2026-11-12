import { createHash, randomBytes } from 'node:crypto';

import { grammarStep, type StepParams } from '@qauth-labs/server-step-grammar';

import type { SignInFlow } from './round';

/**
 * THE BOT CHALLENGE'S PROVIDERS (PRO-19, #643; ADR-017 Decision 7, ADR-019
 * Decision 5): a provider-neutral verifier behind the `captcha` step.
 *
 * - The built-in proof of work is the default. The engine issues the puzzle in
 *   the `captcha` step's params (`provider` `pow`, `challenge`, `difficulty`)
 *   and checks the answer itself, so it makes no outbound call. The reference
 *   ceremony app solves it with its own script, served from the realm origin
 *   (`solveProofOfWork` of `@qauth-labs/shared-interaction-client`), so the
 *   strict CSP needs no exception for it.
 * - An operator may add a hosted provider instead: the step names it
 *   (`provider` `hosted`, `name`, `site_key`), the page runs the provider's
 *   script, and the provider's token is checked by a server-side call to one
 *   host the operator configured (`createSiteVerifyChallengeProvider` of
 *   `@qauth-labs/fastify-plugin-sign-in-engine`, through the egress client).
 *
 * Either way the answer is `captcha_token`. A provider that cannot answer
 * (a hosted provider that is down) throws, and the engine refuses the round
 * (fail closed): a challenge is never waved through.
 */

/** A provider of the bot challenge. */
export interface BotChallengeProvider {
  /**
   * The `captcha` step's params for a new challenge: a fresh puzzle, or the
   * hosted provider's name and site key. The engine keeps them in the
   * transaction until they are answered, and reads the answer against them.
   */
  params(round: {
    readonly realmId: string;
    readonly clientId: string;
    /**
     * The transaction's flow, when it is not a sign-in: `register` or
     * `reset`. A deployment whose hosted provider may run on the sign-in and
     * sign-up pages alone (ADR-019 Decision 5) answers a reset with the
     * built-in proof of work.
     */
    readonly flow?: SignInFlow;
  }): Promise<StepParams<'captcha'>>;
  /**
   * Check `token` against the params it was offered with: `true` when the
   * challenge is solved, `false` when it is not. A throw is an outage (the
   * provider cannot be reached, or answered out of shape), which refuses the
   * round. The token is never logged, audited or kept.
   */
  verify(input: {
    readonly realmId: string;
    readonly params: StepParams<'captcha'>;
    readonly token: string;
  }): Promise<boolean>;
}

/** The provider name the built-in proof of work goes by on the wire: QAuth reserves it. */
export const PROOF_OF_WORK_PROVIDER = 'pow';

/** The fewest leading zero bits a proof of work may ask for: the step's schema. */
export const PROOF_OF_WORK_MIN_DIFFICULTY = 1;

/** The most leading zero bits a proof of work may ask for: the step's schema. */
export const PROOF_OF_WORK_MAX_DIFFICULTY = 32;

/**
 * The difficulty a realm's policy starts from: 18 leading zero bits, about
 * 262,000 SHA-256 hashes on average, a second or two of a browser's time.
 */
export const PROOF_OF_WORK_DEFAULT_DIFFICULTY = 18;

/** The puzzle's random bytes: 256 bits, 43 base64url characters. */
const CHALLENGE_BYTES = 32;

/**
 * A solution: a decimal nonce with no leading zero, below 10^16 (past
 * `Number.MAX_SAFE_INTEGER`, which no solver reaches).
 */
const NONCE_PATTERN = /^(?:0|[1-9][0-9]{0,15})$/;

/** The leading zero bits of `digest`. */
export function leadingZeroBits(digest: Uint8Array): number {
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
 * The bytes a proof of work hashes: the challenge, a colon and the nonce, in
 * UTF-8 (all of it ASCII). The solver hashes the same.
 */
export function proofOfWorkInput(challenge: string, nonce: string): string {
  return `${challenge}:${nonce}`;
}

/**
 * Whether `token` solves the proof of work `params`: a decimal nonce whose
 * SHA-256 over {@link proofOfWorkInput} starts with at least `difficulty`
 * zero bits. Anything else (another provider's params, a token that is no
 * nonce) does not.
 *
 * The Interaction API contract states this rule in the `captcha` step's `pow`
 * params, so a replacement ceremony app writes its solver from the contract
 * alone (#1082). Changing it changes the contract: the tests run the shared
 * vectors, `test-vectors/interaction/proof-of-work.json`, which the reference
 * solver runs too.
 */
export function solvesProofOfWork(params: StepParams<'captcha'>, token: string): boolean {
  if (params.provider !== PROOF_OF_WORK_PROVIDER) return false;
  if (!NONCE_PATTERN.test(token)) return false;
  const digest = createHash('sha256').update(proofOfWorkInput(params.challenge, token)).digest();
  return leadingZeroBits(digest) >= params.difficulty;
}

/** Whether `difficulty` is one the step's schema takes. */
export function isProofOfWorkDifficulty(difficulty: unknown): difficulty is number {
  return (
    Number.isSafeInteger(difficulty) &&
    (difficulty as number) >= PROOF_OF_WORK_MIN_DIFFICULTY &&
    (difficulty as number) <= PROOF_OF_WORK_MAX_DIFFICULTY
  );
}

/** What {@link createProofOfWorkProvider} needs. */
export interface ProofOfWorkProviderOptions {
  /**
   * The realm's difficulty: its policy (`botChallenge.difficulty`), read for
   * every new puzzle. A value outside 1 to 32 is a store fault.
   */
  readonly difficulty: (input: { readonly realmId: string }) => number | Promise<number>;
  /** The puzzle's randomness: `crypto.randomBytes` by default. For tests. */
  readonly random?: (size: number) => Buffer;
}

/**
 * The built-in proof of work (ADR-017 Decision 7, decided 2026-10-11): a
 * puzzle of 256 random bits, at the realm's difficulty, checked in process.
 * The puzzle is single use: the engine keeps it in the transaction until it
 * is answered and drops it then, right or wrong, so a solution never counts
 * twice.
 */
export function createProofOfWorkProvider(
  options: ProofOfWorkProviderOptions
): BotChallengeProvider {
  const random = options.random ?? randomBytes;
  return Object.freeze({
    async params({ realmId }: { readonly realmId: string }) {
      const difficulty = await options.difficulty({ realmId });
      if (!isProofOfWorkDifficulty(difficulty)) {
        throw new Error('a proof-of-work difficulty outside 1 to 32');
      }
      const params = {
        provider: PROOF_OF_WORK_PROVIDER,
        challenge: random(CHALLENGE_BYTES).toString('base64url'),
        difficulty,
      } as const;
      return checkedChallengeParams(params);
    },
    async verify({
      params,
      token,
    }: {
      readonly params: StepParams<'captcha'>;
      readonly token: string;
    }) {
      return solvesProofOfWork(params, token);
    },
  });
}

/**
 * `params`, checked by the `captcha` step's schema: a provider that offers
 * anything else is a fault, which refuses the round.
 */
export function checkedChallengeParams(params: unknown): StepParams<'captcha'> {
  const parsed = grammarStep('captcha').params.safeParse(params);
  if (!parsed.success) throw new Error('bot challenge params outside the captcha step’s schema');
  return parsed.data as StepParams<'captcha'>;
}
