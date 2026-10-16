import { randomBytes } from 'node:crypto';

import type { FastifyInstance } from 'fastify';

type PasswordHasher = FastifyInstance['passwordHasher'];

/**
 * Argon2id hash of a random secret nobody holds, one per hasher. Made lazily
 * by the configured hasher itself, so its cost parameters are the ones real
 * hashes are stored with.
 */
const decoyHashes = new WeakMap<PasswordHasher, Promise<string>>();

/**
 * Spend one Argon2id verification on a login whose lookup found no password
 * to verify (unknown email, unreadable credential data).
 *
 * `ensureMinimumResponseTime` only hides work that finishes under the floor.
 * Argon2id runs on the libuv thread pool, one FIFO queue for the whole
 * process that any unauthenticated caller can fill (wrong client secrets,
 * client registrations, concurrent logins). Behind such a backlog a real
 * verification outlasts the floor while a path that skips it still answers on
 * time, and that difference tells the caller whether the account exists. So a
 * miss must queue for, and cost, what a hit does.
 *
 * Used on the login path only: the client-authentication paths are not
 * covered, as a decoy there would add Argon2id work to every unauthenticated
 * request naming an unknown client.
 *
 * Never throws: a failing decoy must not turn the caller's generic rejection
 * into a 500 that only misses would produce.
 */
export async function verifyAgainstDecoyHash(
  fastify: FastifyInstance,
  presented: string
): Promise<void> {
  const hasher = fastify.passwordHasher;
  try {
    let decoyHash = decoyHashes.get(hasher);
    if (!decoyHash) {
      decoyHash = hasher.hashPassword(randomBytes(32).toString('hex'));
      decoyHashes.set(hasher, decoyHash);
    }
    await hasher.verifyPassword(await decoyHash, presented);
  } catch (err) {
    // Do not cache the failure: the next miss hashes a new decoy.
    decoyHashes.delete(hasher);
    fastify.log.error({ err }, 'decoy password verification failed');
  }
}
