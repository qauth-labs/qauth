import { randomBytes } from 'node:crypto';

import type { PasswordVerifier } from '@qauth-labs/server-sign-in-engine';

/** The Argon2id hasher of `@qauth-labs/server-password`, by shape. */
export interface Argon2Hasher {
  hashPassword(password: string): Promise<string>;
  verifyPassword(hashedPassword: string, plainPassword: string): Promise<boolean>;
}

/** Where a failed dummy verification is reported. */
export interface PasswordVerifierLog {
  error(details: Record<string, unknown>, message: string): void;
}

/**
 * The sign-in engine's password verifier over the auth server's Argon2id
 * hasher.
 *
 * The dummy verification (ADR-017 Decision 7) runs against the hash of a
 * random secret nobody holds, made once by the hasher itself, so its cost
 * parameters are the ones real hashes are stored with. Argon2id runs on the
 * libuv thread pool, one queue for the whole process, so a miss must queue
 * for and cost what a hit does. A dummy verification never throws: a failure
 * there must not turn the ordinary refusal of an unknown identifier into an
 * answer only unknown identifiers would get. It is logged, and the next miss
 * makes a new dummy hash.
 */
export function createArgon2PasswordVerifier(
  hasher: Argon2Hasher,
  log: PasswordVerifierLog
): PasswordVerifier {
  let dummyHash: Promise<string> | undefined;
  return Object.freeze({
    verify: (hash: string, presented: string) => hasher.verifyPassword(hash, presented),
    async verifyDecoy(presented: string): Promise<void> {
      try {
        dummyHash ??= hasher.hashPassword(randomBytes(32).toString('hex'));
        await hasher.verifyPassword(await dummyHash, presented);
      } catch (err) {
        dummyHash = undefined;
        log.error({ err }, 'dummy password verification failed');
      }
    },
  });
}
