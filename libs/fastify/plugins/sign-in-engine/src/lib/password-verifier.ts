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
 * for and cost what a hit does. The dummy hash is made when the verifier is
 * built, so the first miss after a start costs no more than a hit.
 *
 * The two paths fail alike, so a failure tells no account from another: the
 * verification itself throws the same way on both (an outage the engine
 * refuses as `unavailable` for every identifier), while a failure to make the
 * dummy hash, which only misses meet, is logged and swallowed, and the next
 * miss makes a new one. The hasher answers `false` for a hash it cannot
 * read, as the engine's port asks.
 */
export function createArgon2PasswordVerifier(
  hasher: Argon2Hasher,
  log: PasswordVerifierLog
): PasswordVerifier {
  const makeDummyHash = (): Promise<string> => {
    const made = hasher.hashPassword(randomBytes(32).toString('hex'));
    // Awaited, and its failure handled, by the first miss.
    made.catch(() => undefined);
    return made;
  };
  // Made now, so the first miss after the server starts costs one
  // verification, as every other miss does, and not a hash on top.
  let dummyHash: Promise<string> | undefined = makeDummyHash();
  return Object.freeze({
    verify: (hash: string, presented: string) => hasher.verifyPassword(hash, presented),
    async verifyDecoy(presented: string): Promise<void> {
      let hash: string;
      try {
        dummyHash ??= makeDummyHash();
        hash = await dummyHash;
      } catch (err) {
        dummyHash = undefined;
        log.error({ err }, 'could not make the dummy password hash');
        return;
      }
      await hasher.verifyPassword(hash, presented);
    },
  });
}
