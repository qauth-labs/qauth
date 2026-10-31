import { createHash, randomBytes } from 'node:crypto';

import { takeValue } from '@qauth-labs/fastify-plugin-cache';
import { stepByUrn, stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';
import { z } from 'zod';

import {
  INTERACTION_MAX_RECORD_BYTES,
  INTERACTION_MAX_REQUEST_BYTES,
  INTERACTION_SWEEP_GRACE_MS,
  REDIS_KEYS,
} from '../constants';
import { authorizeQuerySchema } from '../schemas/oauth';

/**
 * THE INTERACTION RECORD (#592, ADR-019 Decision 6): the server-side state of
 * one browser ceremony of the Interaction API, kept in Redis.
 *
 * - **Id.** 32 CSPRNG bytes, base64url (43 characters), handed to the browser
 *   once. Redis keys the record by the id's SHA-256 ({@link interactionIdHash}),
 *   so the id itself is stored nowhere.
 * - **State.** A bounded snapshot of the validated authorization request, the
 *   engine transaction (who has been proved, how and when), the current step
 *   and its personal data, the flow-cookie binding (a hash, `flow-cookie.ts`),
 *   the creation time and an absolute expiry. A revision counts the written
 *   states, so an answer is bound to the step view it answers.
 * - **Expiry.** Absolute, `INTERACTION_TTL` after creation; an answer never
 *   extends it. The server refuses an expired record on every read. Redis
 *   keeps it {@link INTERACTION_SWEEP_GRACE_MS} longer so the expiry sweep can
 *   audit it, and an expiry index ({@link REDIS_KEYS.INTERACTION_EXPIRY_INDEX})
 *   lists every live record for that sweep.
 * - **Turn.** Beside the record, Redis holds the record's turn: the revision
 *   that may be answered next. An answer takes the turn with `GETDEL` and
 *   writes the next state with the next turn (`interaction.ts`): of two
 *   concurrent answers, only the one that took the turn is processed. The
 *   record itself stays readable meanwhile, so a step read or a second answer
 *   that arrives while the engine works sees the interaction, not an expired
 *   one.
 *
 * This module holds the shape and the Redis commands; `interaction.ts` holds
 * the rules (binding, expiry, audit) on top of them.
 */

/** The Redis client the auth server's cache plugin decorates. */
type Redis = FastifyInstance['redis'];

/** CSPRNG bytes per interaction id; 32 bytes are 43 base64url characters. */
const INTERACTION_ID_BYTES = 32;

/** Exactly what `randomBytes(32).toString('base64url')` produces. */
const INTERACTION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The record format. A record of another version reads as absent. */
export const INTERACTION_RECORD_VERSION = 1;

/** The identifier step: where an interaction starts again after a user switch. */
export const IDENTIFIER_STEP = stepUrn('identifier');

/** A new interaction id. */
export function mintInteractionId(): string {
  return randomBytes(INTERACTION_ID_BYTES).toString('base64url');
}

/** Cheap shape guard, so a junk path segment never reaches Redis. */
export function isInteractionId(value: unknown): value is string {
  return typeof value === 'string' && INTERACTION_ID_PATTERN.test(value);
}

/** What the record is keyed by: the SHA-256 of the id, hex. */
export function interactionIdHash(id: string): string {
  return createHash('sha256').update(id).digest('hex');
}

/** A step name of the Interaction API that the contract defines. */
const stepNameSchema = z
  .string()
  .max(96)
  .refine((name) => stepByUrn(name) !== undefined, 'not a step of the Interaction API');

/**
 * A JSON object a step carries: its params or its personal data. Their shape
 * is the step grammar's (#591); the record bounds only their size, through
 * {@link INTERACTION_MAX_RECORD_BYTES}.
 */
const stepDataSchema = z.record(z.string().max(64), z.unknown());

/**
 * The current step as the engine asks for it: its name, its params (what any
 * reader of the interaction id may see, never personal data), the steps
 * offered beside it, and the error of a refused answer, from the step's
 * closed error set.
 */
export const interactionStepSchema = z
  .strictObject({
    name: stepNameSchema,
    params: stepDataSchema,
    alternatives: z.array(stepNameSchema).max(15),
    error: z
      .string()
      .regex(/^[a-z][a-z0-9_]{0,63}$/)
      .optional(),
  })
  .superRefine((step, context) => {
    if (step.alternatives.includes(step.name)) {
      context.addIssue({ code: 'custom', message: 'the current step is not its own alternative' });
    }
    if (new Set(step.alternatives).size !== step.alternatives.length) {
      context.addIssue({ code: 'custom', message: 'an alternative is listed twice' });
    }
    const errors = stepByUrn(step.name)?.errors ?? [];
    if (step.error !== undefined && !errors.includes(step.error)) {
      context.addIssue({ code: 'custom', message: 'the error is not one of the step’s errors' });
    }
  });

export type InteractionStep = z.infer<typeof interactionStepSchema>;

/** The personal data of the current step: only the flow cookie's holder reads it. */
export type InteractionPersonalData = z.infer<typeof stepDataSchema>;

/**
 * The engine transaction: what has been proved in this interaction, and for
 * whom. One subject per transaction (ADR-017): once `userId` is set it never
 * changes, and a user switch starts a new interaction with an empty one.
 */
export const interactionTransactionSchema = z.strictObject({
  /** The user an answer proved, once one did. */
  userId: z.uuid().optional(),
  /** The browser session that authentication created (`sid`). */
  sid: z.uuid().optional(),
  /** When the user authenticated, in epoch milliseconds. */
  authTime: z.int().positive().optional(),
  /** The RFC 8176 `amr` values the answers proved, in order. */
  amr: z
    .array(z.string().regex(/^[a-z][a-z0-9_]{0,31}$/))
    .max(16)
    .readonly(),
});

export type InteractionTransaction = z.infer<typeof interactionTransactionSchema>;

/** The validated authorization request an interaction is for (ADR-019 Decision 6, #628). */
export type InteractionRequest = z.infer<typeof authorizeQuerySchema>;

export const interactionRecordSchema = z.strictObject({
  v: z.literal(INTERACTION_RECORD_VERSION),
  /**
   * The interaction's audit reference: a random UUID that names it in events
   * and in the expiry index. Not derived from the id, and opens nothing.
   */
  ref: z.uuid(),
  realmId: z.uuid(),
  purpose: z.literal('authorization'),
  request: authorizeQuerySchema,
  step: interactionStepSchema,
  personal: stepDataSchema,
  transaction: interactionTransactionSchema,
  /** The SHA-256 (base64url) of the flow secret the record is bound to. */
  flowBinding: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  revision: z.int().min(0).max(1_000_000),
  createdAt: z.int().positive(),
  expiresAt: z.int().positive(),
});

export type InteractionRecord = z.infer<typeof interactionRecordSchema>;

/**
 * The longest `client_id` an event names (the event envelope's `client.id`,
 * the `events.client_id` column). A registered client's id always fits; a
 * longer one, which only a client the authorization endpoint did not resolve
 * could carry, is left out of the event rather than failing it.
 */
export const EVENT_CLIENT_ID_MAX_LENGTH = 255;

/** The record's `client_id` for an event, or `null` when it does not fit one. */
export function eventClientIdOf(record: Pick<InteractionRecord, 'request'>): string | null {
  const clientId = record.request.client_id;
  return clientId.length <= EVENT_CLIENT_ID_MAX_LENGTH ? clientId : null;
}

/**
 * The authorization request is too large to hold through a ceremony
 * ({@link INTERACTION_MAX_REQUEST_BYTES}): the caller's doing, refused when the
 * interaction is created.
 */
export class InteractionRequestTooLargeError extends Error {
  constructor() {
    super(`authorization request is larger than ${INTERACTION_MAX_REQUEST_BYTES} bytes`);
    this.name = 'InteractionRequestTooLargeError';
  }
}

/** The record too large to store: the engine's step data does not fit. */
export class InteractionRecordTooLargeError extends Error {
  constructor() {
    super(`interaction state is larger than ${INTERACTION_MAX_RECORD_BYTES} bytes`);
    this.name = 'InteractionRecordTooLargeError';
  }
}

/**
 * The record as stored, refused when its request is larger than
 * {@link INTERACTION_MAX_REQUEST_BYTES} or the whole is larger than
 * {@link INTERACTION_MAX_RECORD_BYTES}.
 */
function serialize(record: InteractionRecord): string {
  const parsed = interactionRecordSchema.parse(record);
  if (Buffer.byteLength(JSON.stringify(parsed.request), 'utf8') > INTERACTION_MAX_REQUEST_BYTES) {
    throw new InteractionRequestTooLargeError();
  }
  const serialized = JSON.stringify(parsed);
  if (Buffer.byteLength(serialized, 'utf8') > INTERACTION_MAX_RECORD_BYTES) {
    throw new InteractionRecordTooLargeError();
  }
  return serialized;
}

function recordKey(realmId: string, idHash: string): string {
  return REDIS_KEYS.INTERACTION(realmId, idHash);
}

function turnKey(realmId: string, idHash: string): string {
  return REDIS_KEYS.INTERACTION_TURN(realmId, idHash);
}

/** The record's member in the expiry index. */
function indexMember(record: Pick<InteractionRecord, 'realmId' | 'ref'>, idHash: string): string {
  return `${record.realmId}:${record.ref}:${idHash}`;
}

/** When Redis drops the record: a grace after its expiry, for the sweep. */
function redisDeadline(record: Pick<InteractionRecord, 'expiresAt'>): number {
  return record.expiresAt + INTERACTION_SWEEP_GRACE_MS;
}

/** Throw the first failed command of a `MULTI`, which reports failures in its results. */
function assertExecuted(results: [Error | null, unknown][] | null): unknown[] {
  if (results === null) throw new Error('the Redis transaction was discarded');
  const failed = results.find(([error]) => error !== null);
  if (failed) throw failed[0];
  return results.map(([, value]) => value);
}

/**
 * Store a new interaction, its first turn (revision 0) and its member of the
 * expiry index, in one `MULTI`. `SET NX`: an id is never reused, so a record
 * that exists is a failure.
 */
export async function insertInteraction(
  redis: Redis,
  idHash: string,
  record: InteractionRecord
): Promise<void> {
  const serialized = serialize(record);
  const deadline = redisDeadline(record);
  const [stored] = assertExecuted(
    await redis
      .multi()
      .set(recordKey(record.realmId, idHash), serialized, 'PXAT', deadline, 'NX')
      .set(turnKey(record.realmId, idHash), String(record.revision), 'PXAT', deadline)
      .zadd(REDIS_KEYS.INTERACTION_EXPIRY_INDEX(), record.expiresAt, indexMember(record, idHash))
      .exec()
  );
  if (stored !== 'OK') throw new Error('an interaction with this id already exists');
}

/**
 * Write the next state of an interaction whose turn the caller took, and give
 * the new revision its turn, in one `MULTI`. The record is written only over
 * the one that is there (`XX`): a record the expiry sweep or a cancel removed
 * meanwhile is not brought back. `false` when it was gone.
 */
export async function writeInteractionState(
  redis: Redis,
  idHash: string,
  record: InteractionRecord
): Promise<boolean> {
  const serialized = serialize(record);
  const deadline = redisDeadline(record);
  const [stored] = assertExecuted(
    await redis
      .multi()
      .set(recordKey(record.realmId, idHash), serialized, 'PXAT', deadline, 'XX')
      .set(turnKey(record.realmId, idHash), String(record.revision), 'PXAT', deadline, 'NX')
      .exec()
  );
  if (stored === 'OK') return true;
  // No record to write over: the turn just set opens nothing, so drop it.
  await redis.del(turnKey(record.realmId, idHash));
  return false;
}

/** Parse a stored record; anything else reads as absent. */
function parseRecord(raw: string | null, log: FastifyBaseLogger): InteractionRecord | null {
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    log.warn('interaction record is not JSON; treated as absent');
    return null;
  }
  const result = interactionRecordSchema.safeParse(parsed);
  if (!result.success) {
    log.warn('interaction record does not match its schema; treated as absent');
    return null;
  }
  return result.data;
}

/** Read a record without changing it, or `null`. */
export async function readInteractionRecord(
  redis: Redis,
  log: FastifyBaseLogger,
  realmId: string,
  idHash: string
): Promise<InteractionRecord | null> {
  return parseRecord(await redis.get(recordKey(realmId, idHash)), log);
}

const turnSchema = z.int().min(0);

/**
 * Take the interaction's turn: read the revision that may be answered and
 * delete it in one `GETDEL`, so no one else can take it. `null` when there is
 * none: another request took it, or the interaction ended.
 */
export async function takeInteractionTurn(
  redis: Redis,
  log: FastifyBaseLogger,
  realmId: string,
  idHash: string
): Promise<number | null> {
  // A turn that does not parse is logged with its key, which holds the realm
  // and the id's hash, never the id.
  return takeValue(redis, turnKey(realmId, idHash), log, turnSchema);
}

/**
 * Give a turn back that the caller took but may not use, unless another turn
 * is there. Only for a turn taken moments ago: the record's deadline bounds it.
 */
export async function returnInteractionTurn(
  redis: Redis,
  record: Pick<InteractionRecord, 'realmId' | 'expiresAt'>,
  idHash: string,
  revision: number
): Promise<void> {
  await redis.set(
    turnKey(record.realmId, idHash),
    String(revision),
    'PXAT',
    redisDeadline(record),
    'NX'
  );
}

/**
 * Remove an interaction for good: its record, its turn and its member of the
 * expiry index, once it finished, was cancelled or was replaced by a user
 * switch.
 *
 * @returns whether this call took the member out of the index. `false` means
 *   the expiry sweep claimed the interaction first and reports it expired: the
 *   caller must treat it as expired, not as finished or cancelled.
 */
export async function deleteInteraction(
  redis: Redis,
  record: Pick<InteractionRecord, 'realmId' | 'ref'>,
  idHash: string
): Promise<boolean> {
  const [, unlisted] = assertExecuted(
    await redis
      .multi()
      .del(recordKey(record.realmId, idHash), turnKey(record.realmId, idHash))
      .zrem(REDIS_KEYS.INTERACTION_EXPIRY_INDEX(), indexMember(record, idHash))
      .exec()
  );
  return unlisted === 1;
}

/** An index member the expiry sweep may claim: its member string and its expiry. */
export interface ExpiryIndexEntry {
  readonly member: string;
  /** The interaction's absolute expiry, the member's score. */
  readonly expiresAt: number;
}

/** One expired interaction the sweep claimed. */
export interface ExpiredInteraction extends ExpiryIndexEntry {
  readonly realmId: string;
  readonly ref: string;
  readonly idHash: string;
  /** The record, when Redis still held it. */
  readonly record: InteractionRecord | null;
}

/** An index member's parts, or `null` for one this module did not write. */
function parseIndexMember(member: string): { realmId: string; ref: string; idHash: string } | null {
  const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
  const match = new RegExp(`^(${uuid}):(${uuid}):([0-9a-f]{64})$`).exec(member);
  return match ? { realmId: match[1], ref: match[2], idHash: match[3] } : null;
}

/** Up to `limit` index entries whose expiry is at or before `now`, soonest first. */
export async function expiredInteractionEntries(
  redis: Redis,
  now: number,
  limit: number
): Promise<ExpiryIndexEntry[]> {
  const flat = await redis.zrangebyscore(
    REDIS_KEYS.INTERACTION_EXPIRY_INDEX(),
    '-inf',
    now,
    'WITHSCORES',
    'LIMIT',
    0,
    limit
  );
  const entries: ExpiryIndexEntry[] = [];
  for (let index = 0; index + 1 < flat.length; index += 2) {
    entries.push({ member: flat[index], expiresAt: Number(flat[index + 1]) });
  }
  return entries;
}

/**
 * Claim one expired interaction for the sweep: take its member out of the
 * expiry index (`ZREM`), its turn (`DEL`) and its record (`GETDEL`) in one
 * `MULTI`, so the three go together or not at all. A connection that fails
 * mid-claim can never leave the member gone from the index with the record
 * still there and no event written: the claim either happened whole, and the
 * caller writes the event, or did not happen, and the next run claims it.
 *
 * Only the caller whose `ZREM` removed the member claims it, so of two sweeps
 * (or a sweep and an interaction that finishes, which removes the member
 * itself in its own `MULTI`) only one reports it. Whoever removed the member
 * removed the turn and the record with it, so a `MULTI` that lost the race
 * finds neither and takes nothing that is not its own. Once the turn is gone
 * no answer can start on the record any more; the record is present when the
 * interaction was still waiting, and absent when Redis already dropped it or
 * the engine failed on it.
 *
 * @returns `null` when someone else claimed the member, or it is not one this
 *   module writes (then it is dropped)
 */
export async function claimExpiredInteraction(
  redis: Redis,
  log: FastifyBaseLogger,
  entry: ExpiryIndexEntry
): Promise<ExpiredInteraction | null> {
  const index = REDIS_KEYS.INTERACTION_EXPIRY_INDEX();
  const parts = parseIndexMember(entry.member);
  if (parts === null) {
    if ((await redis.zrem(index, entry.member)) === 1) {
      log.warn('interaction expiry index held a member it cannot read; removed');
    }
    return null;
  }
  const [unlisted, , raw] = assertExecuted(
    await redis
      .multi()
      .zrem(index, entry.member)
      .del(turnKey(parts.realmId, parts.idHash))
      .getdel(recordKey(parts.realmId, parts.idHash))
      .exec()
  );
  if (unlisted !== 1) return null;
  // A record that does not parse reads as absent: the expiry is still
  // reported, without its step.
  return { ...entry, ...parts, record: parseRecord(raw as string | null, log) };
}

/**
 * Undo {@link claimExpiredInteraction} when its audit could not be written:
 * the member goes back into the index and the record back into Redis (with no
 * turn: it can never be answered), in one `MULTI`, so the next run claims it
 * again with its step. The record is past its expiry, so no request can use it
 * meanwhile.
 *
 * The record goes back as it was read rather than through the size checks of
 * a write: it was within them when it was written, and a relist that refused
 * it would leave the member out of the index too.
 */
export async function relistExpiredInteraction(
  redis: Redis,
  expired: ExpiredInteraction
): Promise<void> {
  const transaction = redis
    .multi()
    .zadd(REDIS_KEYS.INTERACTION_EXPIRY_INDEX(), expired.expiresAt, expired.member);
  if (expired.record !== null) {
    transaction.set(
      recordKey(expired.realmId, expired.idHash),
      JSON.stringify(expired.record),
      'PXAT',
      redisDeadline(expired.record),
      'NX'
    );
  }
  assertExecuted(await transaction.exec());
}
