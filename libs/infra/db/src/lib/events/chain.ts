import { createHash } from 'node:crypto';
import { userInfo } from 'node:os';

import type { EventEnvelope } from '@qauth-labs/shared-events';

import { canonicalizeJson } from '../admin-audit/canonical-json';

/**
 * The hash chain of a realm's admin events (ADR-019 Decision 7, issue #459).
 *
 * Each admin row of `events` stores the `hash` of the realm's admin row
 * before it as `prev_hash`, and {@link EVENT_CHAIN_GENESIS_HASH} for the
 * first. Its own `hash` is {@link eventChainHash}: SHA-256 over the 32 bytes
 * of `prev_hash` followed by the UTF-8 bytes of the RFC 8785 canonical JSON of
 * the envelope the row holds, exactly as a reader gets it back. A changed row
 * no longer hashes to its `hash`; a removed row leaves the next row's
 * `prev_hash` pointing at nothing.
 *
 * The hash is unkeyed: whoever can rewrite a row and every row after it, or
 * cut the newest rows, leaves a chain that verifies. Only a copy of the head
 * kept outside the database shows that; `verifyChain` returns the head, and
 * takes one back as the point to verify from.
 */

/** `prev_hash` of a realm's first admin event: 32 zero bytes. */
export const EVENT_CHAIN_GENESIS_HASH: Buffer = Buffer.alloc(32);

/**
 * An admin row's `hash`: SHA-256 over `prevHash` and the canonical JSON of the
 * envelope. Changing what it covers changes every hash, so this is version 1
 * of the chain format.
 *
 * @throws TypeError when the envelope holds a value outside the I-JSON model
 */
export function eventChainHash(prevHash: Buffer, envelope: EventEnvelope): Buffer {
  if (prevHash.length !== 32) {
    throw new TypeError('eventChainHash: prev_hash is not a SHA-256 digest');
  }
  return createHash('sha256').update(prevHash).update(canonicalizeJson(envelope), 'utf8').digest();
}

/**
 * The prefix of a realm's chain lock key. The lock is
 * `pg_advisory_xact_lock(hashtextextended(prefix || realm_id, 0))`, a key no
 * other lock of QAuth uses.
 */
export const EVENT_CHAIN_LOCK_PREFIX = 'qauth:events:admin-chain:';

/**
 * The actor of a change made through a command-line tool on the server host,
 * such as the break-glass CLI (ADR-019 Decision 7): `operator_cli`, with the
 * operating-system user who ran it. Without a user name (a container user
 * with no passwd entry), the numeric uid stands in.
 */
export function operatorCliActor(): { type: 'operator_cli'; id: string } {
  let name = '';
  try {
    name = userInfo().username;
  } catch {
    // No passwd entry for the uid.
  }
  const id = name !== '' ? name : `uid:${process.getuid?.() ?? 'unknown'}`;
  return { type: 'operator_cli', id: id.slice(0, 255) };
}
