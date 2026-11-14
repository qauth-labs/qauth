import {
  dataAtRestLifetimeMs,
  type KeyPurpose,
  type KeyRotationStep,
  type KeysRotatedStep,
  type NextKeyCreatedStep,
  type RotatedKey,
  type ScheduledKeyRotation,
} from '@qauth-labs/fastify-plugin-signer';
import { MAX_ACCESS_TOKEN_LIFESPAN_SECONDS } from '@qauth-labs/server-config';
import { ROTATING_KEY_ALGORITHMS, ROTATING_KEY_PURPOSES } from '@qauth-labs/shared-events';
import type { FastifyInstance } from 'fastify';

import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const KEY_ROTATION_JOB_NAME = 'key-rotation';

/**
 * How often the job looks for a due step: every hour. The windows it keeps
 * are days long, and a step that is due waits at most this long; a missed
 * run never shortens a window (`planKeyRotation`).
 */
export const KEY_ROTATION_INTERVAL_MS = 60 * 60_000;

/**
 * The role whose nodes run the job: `signer`, the only one that holds the
 * KEK, which every new key is sealed under (ADR-019 Decision 9).
 */
export const KEY_ROTATION_ROLE = 'signer';

/**
 * The repositories the job uses beside the signer's key store: the audit
 * events of its steps, and the realms whose browser session lifespan keeps a
 * retired cookie key.
 */
export const KEY_ROTATION_REPOSITORIES = ['events', 'realms'] as const;

/**
 * The longest a token signed with a realm's `token_signing` or
 * `event_signing` key may live, in ms: an access or ID token's lifetime is
 * capped at a day for the realm, a client and the development defaults alike
 * (`MAX_ACCESS_TOKEN_LIFESPAN_SECONDS`; a client's own lifetime can only be
 * shorter than its realm's), and every other token is shorter. A retired
 * signing key stays published at least this long after the switch, however
 * the lifetimes were set when it signed.
 */
export const LONGEST_TOKEN_LIFETIME_MS = MAX_ACCESS_TOKEN_LIFESPAN_SECONDS * 1000;

/** The transaction an event is emitted in, as the events repository takes it. */
type EventTransaction = Parameters<FastifyInstance['repositories']['events']['emit']>[0];

/** What the job uses. */
export interface KeyRotationJobDependencies {
  /** `fastify.keyRotation`: the signer's scheduled rotation. */
  readonly rotation: Pick<ScheduledKeyRotation, 'run'> | null | undefined;
  readonly events: Pick<FastifyInstance['repositories']['events'], 'emit'>;
  readonly realms: Pick<FastifyInstance['repositories']['realms'], 'findById'>;
  /** `SESSION_COOKIE_TTL`, in seconds: a browser session's lifespan where its realm sets none. */
  readonly sessionCookieTtlSeconds: number;
}

/** A purpose the key events name; the event store refuses any other. */
type RotatingKeyPurpose = (typeof ROTATING_KEY_PURPOSES)[number];

/** An algorithm the key events name; the event store refuses any other. */
type RotatingKeyAlgorithm = (typeof ROTATING_KEY_ALGORITHMS)[number];

/** An RFC 3339 time in UTC. */
function isoTime(epochMs: number): string {
  return new Date(epochMs).toISOString();
}

/** The keys of a step, as the key events name them. */
function eventKeys(list: readonly RotatedKey[]) {
  // The rotating algorithms are the events' (a test holds the lists equal);
  // the event store checks each value again.
  return list.map((key) => ({ keyId: key.kid, algorithm: key.algorithm as RotatingKeyAlgorithm }));
}

/** The `key.next_created` event of a step. */
function nextCreatedEvent(step: NextKeyCreatedStep) {
  return {
    type: 'urn:qauth:event:key.next_created:v1-rc.0' as const,
    realm: step.realmId,
    actor: { type: 'system' as const },
    data: {
      purpose: step.purpose as RotatingKeyPurpose,
      created: eventKeys(step.keys),
      activatesAt: isoTime(step.activatesAt),
    },
  };
}

/** The `key.rotated` event of a step. */
function rotatedEvent(step: KeysRotatedStep) {
  return {
    type: 'urn:qauth:event:key.rotated:v1-rc.0' as const,
    realm: step.realmId,
    actor: { type: 'system' as const },
    data: {
      purpose: step.purpose as RotatingKeyPurpose,
      activated: eventKeys(step.activated),
      retired: eventKeys(step.retired),
      activatesAt: isoTime(step.switchAt),
      ...(step.retainedUntil === null ? {} : { retainedUntil: isoTime(step.retainedUntil) }),
    },
  };
}

/** Write the audit event of one step in the step's transaction. */
async function recordStep(
  events: KeyRotationJobDependencies['events'],
  step: KeyRotationStep,
  tx: EventTransaction
): Promise<void> {
  if (step.kind === 'next_created') {
    await events.emit(tx, nextCreatedEvent(step));
  } else {
    await events.emit(tx, rotatedEvent(step));
  }
}

/**
 * The longest a token, cookie or ciphertext made with a key of `purpose` in
 * the realm may live, in ms, or `null` when one may live for ever.
 *
 * - `token_signing`, `event_signing`, `oid4vp_response_encryption`: a day
 *   ({@link LONGEST_TOKEN_LIFETIME_MS}). A security event token carries no
 *   expiry, but is signed at each delivery attempt and verified on receipt;
 *   an OID4VP response lives as long as its request, 15 minutes at most.
 * - `cookie_hmac`: the longest browser session, the realm's
 *   `sso_max_lifespan` or `SESSION_COOKIE_TTL`, whichever is longer, since a
 *   session cookie lives to its session's end and is not signed again.
 * - `data_at_rest`: the longest lifetime its consumers state
 *   (`DATA_AT_REST_CONSUMERS`); a stored secret has none, so the key is kept.
 * - `agent_wrap`, and any purpose without a rule here: kept.
 */
export async function keyLifetimeOf(
  deps: Pick<KeyRotationJobDependencies, 'realms' | 'sessionCookieTtlSeconds'>,
  realmId: string,
  purpose: KeyPurpose
): Promise<number | null> {
  switch (purpose) {
    case 'token_signing':
    case 'event_signing':
    case 'oid4vp_response_encryption':
      return LONGEST_TOKEN_LIFETIME_MS;
    case 'cookie_hmac': {
      const realm = await deps.realms.findById(realmId);
      const realmLifespan = realm?.ssoMaxLifespan ?? null;
      return Math.max(realmLifespan ?? 0, deps.sessionCookieTtlSeconds) * 1000;
    }
    case 'data_at_rest':
      return dataAtRestLifetimeMs();
    default:
      return null;
  }
}

/**
 * Rotate the realms' keys on schedule (ADR-019 Decision 9, #542): for every
 * realm that holds keys, and every purpose that rotates automatically, create
 * the `next` key when one is due, and switch to it when its window has run.
 * Each step writes its audit event (`key.next_created`, `key.rotated`) in
 * the transaction that changes the keys, so a step and its record commit
 * together or not at all.
 *
 * Safe on many nodes and to repeat: the runner holds the job's advisory lock,
 * and each purpose is planned again under the realm's key lock from what is
 * stored. A purpose that fails is logged and left as it was; the others go
 * on, and the run then fails so the runner records it.
 *
 * @throws Error when this process does not hold the scheduled rotation
 *   (`fastify.keyRotation`), that is, when it loads no signer
 */
export function createKeyRotationJob(deps: KeyRotationJobDependencies): JobDefinition {
  const { rotation } = deps;
  if (rotation === undefined || rotation === null) {
    throw new Error(
      'The key rotation job needs `fastify.keyRotation`: it runs only where the signer plugin is registered'
    );
  }
  return defineJob({
    name: KEY_ROTATION_JOB_NAME,
    role: KEY_ROTATION_ROLE,
    intervalMs: KEY_ROTATION_INTERVAL_MS,
    async run({ signal, now, log }) {
      const report = await rotation.run({
        now,
        signal,
        lifetimeOf: (realmId, purpose) => keyLifetimeOf(deps, realmId, purpose),
        // The key store runs every step inside a transaction of its own.
        onStep: (step, tx) => recordStep(deps.events, step, tx as EventTransaction),
      });
      for (const step of report.steps) {
        log.info(
          {
            realmId: step.realmId,
            purpose: step.purpose,
            step: step.kind,
            kids:
              step.kind === 'next_created'
                ? step.keys.map((key) => key.kid)
                : step.activated.map((key) => key.kid),
          },
          step.kind === 'next_created' ? 'next key created' : 'keys rotated'
        );
      }
      for (const failure of report.failures) {
        log.error(
          { realmId: failure.realmId, purpose: failure.purpose, err: failure.error },
          'key rotation step failed; the keys were left as they were'
        );
      }
      log.info(
        { realms: report.realms, steps: report.steps.length, failures: report.failures.length },
        'key rotation run finished'
      );
      if (report.failures.length > 0) {
        throw new Error(
          `Key rotation failed for ${report.failures.length} purpose(s); the next run retries them`
        );
      }
    },
  });
}
