import type { EventEnvelope } from '@qauth-labs/shared-events';

import type {
  ClaimedDelivery,
  DeliveryAttemptRecord,
  DeliveryDestination,
  DeliveryStore,
} from '../lib/types';

/**
 * TEST SUPPORT — a {@link DeliveryStore} in memory, with the queue's rules:
 * one row per destination and event, a position per realm and route kind
 * that starts at the end of the stream, leases that make a row due again,
 * and outcomes written only by the claim that holds the row. Every event is
 * final at once: the horizon is the container suites' to test.
 */
export interface MemoryRow {
  readonly id: string;
  readonly kind: string;
  readonly destinationId: string;
  readonly event: EventEnvelope | null;
  readonly eventId: string;
  readonly realmId: string;
  status: 'pending' | 'delivered' | 'failed';
  attempt: number;
  nextAttemptAt: number;
  lockedUntil: number | null;
  lastStatusCode: number | null;
  lastErrorClass: string | null;
}

export interface MemoryStore extends DeliveryStore {
  /** Append an event to its realm's stream. */
  append(event: EventEnvelope): void;
  /** Every row, in the order the fan-out wrote them. */
  readonly rows: MemoryRow[];
  /** Every call, by method, for the tests that check what the role asked. */
  readonly calls: { fanOut: number; claim: number; release: number };
}

function matches(destination: DeliveryDestination, event: EventEnvelope): boolean {
  return (
    (destination.types === undefined || destination.types.includes(event.type)) &&
    (destination.categories === undefined || destination.categories.includes(event.category)) &&
    (destination.subjects === undefined ||
      destination.subjects.some(
        (subject) => subject.type === event.subject?.type && subject.id === event.subject.id
      ))
  );
}

export function createMemoryStore(): MemoryStore {
  const streams = new Map<string, EventEnvelope[]>();
  const positions = new Map<string, number>();
  const rows: MemoryRow[] = [];
  const calls = { fanOut: 0, claim: 0, release: 0 };
  let nextId = 1;

  const holds = (row: MemoryRow, claim: { id: string; attempt: number }): boolean =>
    row.id === claim.id &&
    row.attempt === claim.attempt &&
    row.status === 'pending' &&
    row.lockedUntil !== null;

  return {
    rows,
    calls,

    append(event) {
      const stream = streams.get(event.realm) ?? [];
      stream.push(event);
      streams.set(event.realm, stream);
    },

    async fanOut({ kinds, destinations }) {
      calls.fanOut += 1;
      const pairs = new Map<string, { realm: string; kind: string }>();
      for (const destination of destinations) {
        if (!kinds.includes(destination.kind)) throw new TypeError('a destination of another kind');
        pairs.set(`${destination.realmId}/${destination.kind}`, {
          realm: destination.realmId,
          kind: destination.kind,
        });
      }
      for (const key of [...positions.keys()]) {
        const kind = key.slice(key.indexOf('/') + 1);
        if (kinds.includes(kind) && !pairs.has(key)) positions.delete(key);
      }
      let deliveries = 0;
      for (const [key, { realm, kind }] of pairs) {
        const stream = streams.get(realm) ?? [];
        const position = positions.get(key);
        positions.set(key, stream.length);
        if (position === undefined) continue;
        for (const event of stream.slice(position)) {
          for (const destination of destinations) {
            if (destination.realmId !== realm || destination.kind !== kind) continue;
            if (!matches(destination, event)) continue;
            const exists = rows.some(
              (row) =>
                row.eventId === event.id &&
                row.kind === destination.kind &&
                row.destinationId === destination.id
            );
            if (exists) continue;
            rows.push({
              id: `delivery-${nextId++}`,
              kind: destination.kind,
              destinationId: destination.id,
              event,
              eventId: event.id,
              realmId: realm,
              status: 'pending',
              attempt: 0,
              nextAttemptAt: 0,
              lockedUntil: null,
              lastStatusCode: null,
              lastErrorClass: null,
            });
            deliveries += 1;
          }
        }
      }
      return { deliveries, more: false };
    },

    async dueDestinations(kinds, now) {
      const due = new Map<string, { kind: string; id: string }>();
      for (const row of rows) {
        if (row.status !== 'pending' || row.nextAttemptAt > now || !kinds.includes(row.kind)) {
          continue;
        }
        due.set(`${row.kind}/${row.destinationId}`, { kind: row.kind, id: row.destinationId });
      }
      return [...due.values()].sort((a, b) => a.id.localeCompare(b.id));
    },

    async claim({ picks, now, leaseMs, maxAttempts }) {
      calls.claim += 1;
      const claimed: ClaimedDelivery[] = [];
      for (const pick of picks) {
        const due = rows
          .filter(
            (row) =>
              row.kind === pick.kind &&
              row.destinationId === pick.id &&
              row.status === 'pending' &&
              row.nextAttemptAt <= now
          )
          .sort((a, b) => a.nextAttemptAt - b.nextAttemptAt)
          .slice(0, pick.limit);
        for (const row of due) {
          if (row.attempt >= maxAttempts) {
            row.status = 'failed';
            row.lockedUntil = null;
            row.lastErrorClass = 'attempt_interrupted';
            continue;
          }
          row.attempt += 1;
          row.lockedUntil = now + leaseMs;
          row.nextAttemptAt = now + leaseMs;
          claimed.push({
            id: row.id,
            destinationKind: row.kind,
            destinationId: row.destinationId,
            realmId: row.realmId,
            eventId: row.eventId,
            attempt: row.attempt,
            lockedUntil: row.lockedUntil,
            event: row.event,
          });
        }
      }
      return claimed;
    },

    async record(claim, outcome: DeliveryAttemptRecord) {
      const row = rows.find((candidate) => holds(candidate, claim));
      if (!row) return false;
      if (outcome.result === 'hold') {
        // No attempt: give back the one the claim counted.
        row.attempt -= 1;
        row.lockedUntil = null;
        row.nextAttemptAt = outcome.nextAttemptAt;
        return true;
      }
      row.status = outcome.result === 'retry' ? 'pending' : outcome.result;
      row.lockedUntil = null;
      if (outcome.result === 'retry') row.nextAttemptAt = outcome.nextAttemptAt;
      row.lastStatusCode = outcome.statusCode ?? null;
      row.lastErrorClass = outcome.result === 'delivered' ? null : outcome.errorClass;
      return true;
    },

    async release(claims, now) {
      calls.release += 1;
      let released = 0;
      for (const claim of claims) {
        const row = rows.find((candidate) => holds(candidate, claim));
        if (!row) continue;
        row.lockedUntil = null;
        row.nextAttemptAt = now;
        row.lastErrorClass = 'attempt_interrupted';
        released += 1;
      }
      return released;
    },
  };
}
