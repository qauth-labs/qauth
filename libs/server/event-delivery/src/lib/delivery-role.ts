import type { EventEnvelope } from '@qauth-labs/shared-events';

import {
  checkRetrySchedule,
  DEFAULT_RETRY_SCHEDULE,
  retryDelayMs,
  type RetrySchedule,
} from './retry';
import type {
  ClaimedDelivery,
  Delivery,
  DeliveryAttemptRecord,
  DeliveryAttemptResult,
  DeliveryClock,
  DeliveryDestination,
  DeliveryLogger,
  DeliveryMetrics,
  DeliveryOutcome,
  DeliveryRoute,
  DeliverySigner,
  DeliveryStore,
  EventSubjectRef,
} from './types';

/**
 * THE DELIVERY ROLE (ADR-019 Decision 8, issue #460).
 *
 * A worker that hands every event to every destination whose filter matches
 * it, at least once and with the event's own id. It runs in-process in a
 * single deployment, beside the other roles; a distributed deployment runs it
 * on nodes of its own (the topology area's entry point), as many as it
 * likes, over the same database.
 *
 * ## One cycle
 *
 * Every `pollIntervalMs` the role:
 *
 * 1. asks each route for its destinations, and has the store fan the new
 *    events out to them: one delivery row per destination and event. A
 *    route whose listing fails stops the fan-out for that cycle, so no
 *    destination misses an event because its route could not be asked;
 * 2. claims due deliveries, as many as it has free slots (`concurrency`),
 *    taking them destination by destination in turn and at most
 *    `maxInFlightPerDestination` of one destination at a time, so a slow
 *    destination holds a few slots and never all of them;
 * 3. hands each claimed event to its route, with a time limit
 *    (`attemptTimeoutMs`), and records the outcome: delivered, retried
 *    later on the backoff schedule, or failed for good after `maxAttempts`.
 *    A delivery the route holds, such as one to a paused SSF stream, is no
 *    attempt: it is not counted and comes due again after
 *    {@link DELIVERY_HOLD_INTERVAL_MS}, however long the hold lasts.
 *
 * A finished attempt claims the next delivery at once; the cycle only paces
 * the fan-out and picks up retries that came due.
 *
 * ## At least once
 *
 * A claim leases its delivery for `leaseMs`, longer than an attempt may run.
 * A worker that dies holding a lease leaves the delivery to come due again
 * when the lease runs out, and another worker, or this one after a restart,
 * delivers it again. A receiver drops the duplicate by the event id. Order
 * is not kept across retries; receivers order by `time` or by the stream
 * position.
 *
 * ## Stopping
 *
 * {@link DeliveryRole.stop} stops the cycle and claims nothing more, waits
 * for the attempts in flight up to `shutdownTimeoutMs`, then gives up on the
 * ones whose route still runs: it aborts their signals and releases their
 * leases, so another node takes them at once. A released attempt counts,
 * since it may have reached the destination. An attempt whose outcome is
 * being recorded keeps its lease. Every wait of the shutdown has the same
 * limit, so a database that stopped answering cannot hold it; a lease that
 * was not given back runs out by itself.
 *
 * ## Route kinds
 *
 * The fan-out keeps one position per realm and route kind, and a node moves
 * and forgets only the positions of the kinds it has routes for. Nodes with
 * different routes, such as two releases during a rollout, or a node with no
 * route at all, so leave each other's positions alone.
 *
 * ## No keys
 *
 * The role holds no private key and loads none. A route that signs, such as
 * the webhook route, signs through the {@link DeliverySigner} the signer role
 * handed the role, which it passes on in each attempt's context.
 */

/** How the role runs. Every member has a default ({@link DEFAULT_DELIVERY_SETTINGS}). */
export interface DeliverySettings {
  /** The attempts a delivery gets before it ends `failed`. 1 to 100. */
  readonly maxAttempts: number;
  /** The waits between attempts. */
  readonly retry: RetrySchedule;
  /** How long a claim holds a delivery, in milliseconds. Longer than `attemptTimeoutMs`. */
  readonly leaseMs: number;
  /** How long one attempt may run, in milliseconds. */
  readonly attemptTimeoutMs: number;
  /** How often the role fans out and looks for due retries, in milliseconds. */
  readonly pollIntervalMs: number;
  /** The attempts this node runs at once. */
  readonly concurrency: number;
  /** The attempts this node runs at once for one destination. At most `concurrency`. */
  readonly maxInFlightPerDestination: number;
  /** The events the fan-out reads per page of one realm. 1 to 1000. */
  readonly fanOutPageSize: number;
  /** How long {@link DeliveryRole.stop} waits for attempts in flight, in milliseconds. */
  readonly shutdownTimeoutMs: number;
}

/**
 * How long a delivery the route holds waits before the role asks again, in
 * milliseconds: a destination that stops holding, such as an SSF stream that
 * is enabled again, gets its events within this time.
 */
export const DELIVERY_HOLD_INTERVAL_MS = 30_000;

/**
 * How often the role warns again about a delivery it still holds because the
 * signer is unavailable (#495), in milliseconds. It warns at the first hold,
 * then at this interval while the hold lasts. A delivery this node has not
 * held for this long, because another node claimed it or it ended, is
 * forgotten.
 */
export const SIGNER_HOLD_WARN_INTERVAL_MS = 15 * 60_000;

/** The deliveries a node holds because the signer is unavailable, for `/metrics`. */
export interface SignerHeldDeliveries {
  /** How many this node holds. */
  readonly count: number;
  /** Seconds since this node first held the oldest of them; 0 when it holds none. */
  readonly oldestSeconds: number;
}

/** The settings a role runs with when it is given none. */
export const DEFAULT_DELIVERY_SETTINGS: DeliverySettings = Object.freeze({
  maxAttempts: 12,
  retry: DEFAULT_RETRY_SCHEDULE,
  leaseMs: 60_000,
  attemptTimeoutMs: 30_000,
  pollIntervalMs: 1_000,
  concurrency: 10,
  maxInFlightPerDestination: 2,
  fanOutPageSize: 500,
  shutdownTimeoutMs: 10_000,
});

/** Settings to change; the rest keep their defaults. */
export type DeliverySettingsInput = Partial<Omit<DeliverySettings, 'retry'>> & {
  readonly retry?: Partial<RetrySchedule>;
};

/** What {@link startDeliveryRole} takes. */
export interface DeliveryRoleOptions {
  /** The delivery queue, connected as the delivery role's own database user. */
  readonly store: DeliveryStore;
  /** The routes this node delivers through. Kinds must be unique. */
  readonly routes: readonly DeliveryRoute[];
  /** The handle the signer role gives the delivery role. */
  readonly signer: DeliverySigner;
  readonly log: DeliveryLogger;
  /** Counts attempts by route kind and result. */
  readonly metrics?: DeliveryMetrics;
  readonly settings?: DeliverySettingsInput;
  /** Defaults to the system clock, with unref'd timers. */
  readonly clock?: DeliveryClock;
  /** A number in [0, 1), for the jitter of the retry schedule. Defaults to `Math.random`. */
  readonly random?: () => number;
}

/** A running delivery role. */
export interface DeliveryRole {
  /** The route kinds it delivers. */
  readonly kinds: readonly string[];
  /** The settings it runs with. */
  readonly settings: DeliverySettings;
  /**
   * The deliveries this node holds because the signer is unavailable: a
   * hold without an end spends no attempt, so this is where it shows.
   */
  signerHeld(): SignerHeldDeliveries;
  /**
   * Stop claiming, let the attempts in flight finish up to the shutdown
   * limit, then abort and release the rest. Resolves once the role has
   * stopped; safe to call more than once.
   */
  stop(): Promise<void>;
}

/** The abort reason of an attempt that reached its time limit. */
export class DeliveryAttemptTimeoutError extends Error {
  override readonly name = 'DeliveryAttemptTimeoutError';

  constructor() {
    super('The event delivery attempt reached its time limit');
  }
}

/**
 * Whether a route threw a `503` `TemporarilyUnavailableError` of
 * `@qauth-labs/shared-errors`: what a signer that cannot be reached throws.
 * Read by its fields, since the error may come from another copy of the
 * module.
 */
function isTemporarilyUnavailable(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const { statusCode, code } = error as { statusCode?: unknown; code?: unknown };
  return statusCode === 503 && code === 'TEMPORARILY_UNAVAILABLE';
}

/** The abort reason of an attempt the role gave up on when it stopped. */
export class DeliveryRoleStoppedError extends Error {
  override readonly name = 'DeliveryRoleStoppedError';

  constructor() {
    super('The delivery role stopped before the attempt ended');
  }
}

/**
 * The error classes the role itself records.
 *
 * - `timeout` — the attempt reached `attemptTimeoutMs`.
 * - `route_error` — the route threw, or returned something that is not an
 *   outcome.
 * - `unreadable_event` — the store could not read the event (a row layout
 *   this release does not know). Not retried.
 */
export const DELIVERY_ERROR_CLASSES = Object.freeze({
  timeout: 'timeout',
  routeError: 'route_error',
  unreadableEvent: 'unreadable_event',
} as const);

/** A route kind: lower case, 1 to 32 characters. */
const KIND_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;
/** An error class: what the store accepts. */
const ERROR_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const DESTINATION_ID_MAX_LENGTH = 255;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The real clock. Its timers are unref'd: a waiting role never keeps the process alive. */
const systemClock: DeliveryClock = Object.freeze({
  now: () => Date.now(),
  setTimeout(callback: () => void, delayMs: number): unknown {
    return setTimeout(callback, delayMs).unref();
  },
  clearTimeout(timer: unknown): void {
    clearTimeout(timer as ReturnType<typeof setTimeout>);
  },
});

function checkInteger(name: string, value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`delivery role: ${name} must be a whole number from ${min} to ${max}`);
  }
  return value;
}

/**
 * Fill in and check the role's settings.
 *
 * @throws {TypeError} when a setting is out of range, or an attempt may run
 *   as long as its lease
 */
export function resolveDeliverySettings(input: DeliverySettingsInput = {}): DeliverySettings {
  const merged = { ...DEFAULT_DELIVERY_SETTINGS, ...input };
  const retry = checkRetrySchedule({ ...DEFAULT_RETRY_SCHEDULE, ...input.retry });
  const settings: DeliverySettings = {
    maxAttempts: checkInteger('maxAttempts', merged.maxAttempts, 1, 100),
    retry,
    leaseMs: checkInteger('leaseMs', merged.leaseMs, 2, 24 * 60 * 60_000),
    attemptTimeoutMs: checkInteger(
      'attemptTimeoutMs',
      merged.attemptTimeoutMs,
      1,
      24 * 60 * 60_000
    ),
    pollIntervalMs: checkInteger('pollIntervalMs', merged.pollIntervalMs, 1, 60 * 60_000),
    concurrency: checkInteger('concurrency', merged.concurrency, 1, 1000),
    maxInFlightPerDestination: checkInteger(
      'maxInFlightPerDestination',
      merged.maxInFlightPerDestination,
      1,
      1000
    ),
    fanOutPageSize: checkInteger('fanOutPageSize', merged.fanOutPageSize, 1, 1000),
    shutdownTimeoutMs: checkInteger('shutdownTimeoutMs', merged.shutdownTimeoutMs, 0, 60 * 60_000),
  };
  // An attempt that outlives its lease could be claimed again while it runs.
  if (settings.attemptTimeoutMs >= settings.leaseMs) {
    throw new TypeError('delivery role: attemptTimeoutMs must be shorter than leaseMs');
  }
  if (settings.maxInFlightPerDestination > settings.concurrency) {
    throw new TypeError('delivery role: maxInFlightPerDestination must be at most concurrency');
  }
  return Object.freeze(settings);
}

/** One attempt in flight on this node. */
interface InFlight {
  readonly claim: ClaimedDelivery;
  readonly controller: AbortController;
  /**
   * `attempting` while the route runs, `recording` once the outcome is being
   * written: shutdown gives up on and releases only an attempt whose route
   * still runs, never one whose outcome is on its way to the store.
   */
  stage: 'attempting' | 'recording';
  done: Promise<void>;
}

/** What {@link Runner.attempt} found: an outcome, or that the role gave up on it. */
type AttemptEnd = DeliveryOutcome | 'abandoned';

function destinationKey(kind: string, id: string): string {
  return `${kind}\u0000${id}`;
}

/** A promise that rejects with the signal's reason once it is aborted. */
function aborted(signal: AbortSignal): Promise<never> {
  return new Promise((_, reject) => {
    if (signal.aborted) {
      reject(signal.reason);
      return;
    }
    signal.addEventListener('abort', () => reject(signal.reason), { once: true });
  });
}

function statusCodeOf(value: unknown): { statusCode?: number } {
  return typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599
    ? { statusCode: value }
    : {};
}

class Runner implements DeliveryRole {
  readonly kinds: readonly string[];
  readonly settings: DeliverySettings;

  private readonly store: DeliveryStore;
  private readonly routes: ReadonlyMap<string, DeliveryRoute>;
  private readonly signer: DeliverySigner;
  private readonly log: DeliveryLogger;
  private readonly metrics: DeliveryMetrics | undefined;
  private readonly clock: DeliveryClock;
  private readonly random: () => number;

  private state: 'running' | 'stopping' | 'stopped' = 'running';
  private stopping: Promise<void> | undefined;
  private timer: unknown;
  private cycle: Promise<void> | undefined;
  private filling: Promise<void> | undefined;
  private fillAgain = false;
  /** The attempts in flight, by delivery and attempt: a row claimed again is a new entry. */
  private readonly inFlight = new Map<string, InFlight>();
  private readonly perDestination = new Map<string, number>();
  /** Where the next claim round starts among the due destinations. */
  private rotation = 0;
  /** Destinations already reported as invalid, so each is logged once. */
  private readonly reported = new Set<string>();
  /**
   * The deliveries held because the signer is unavailable, by id: when this
   * node first held each, last warned about it and last held it.
   */
  private readonly signerHolds = new Map<
    string,
    { readonly since: number; warnedAt: number; seenAt: number }
  >();

  constructor(options: DeliveryRoleOptions) {
    const routes = new Map<string, DeliveryRoute>();
    for (const route of options.routes) {
      if (typeof route.kind !== 'string' || !KIND_PATTERN.test(route.kind)) {
        throw new TypeError(
          `delivery role: route kind "${String(route.kind)}" must be lower case, 1 to 32 characters`
        );
      }
      if (routes.has(route.kind)) {
        throw new TypeError(`delivery role: two routes have the kind "${route.kind}"`);
      }
      routes.set(route.kind, route);
    }
    this.routes = routes;
    this.kinds = Object.freeze([...routes.keys()]);
    this.settings = resolveDeliverySettings(options.settings);
    this.store = options.store;
    this.signer = options.signer;
    this.log = options.log;
    this.metrics = options.metrics;
    this.clock = options.clock ?? systemClock;
    this.random = options.random ?? Math.random;
  }

  start(): void {
    this.log.info({ kinds: this.kinds }, 'delivery role started');
    this.schedule(0);
  }

  stop(): Promise<void> {
    this.stopping ??= this.stopGracefully();
    return this.stopping;
  }

  private schedule(delayMs: number): void {
    this.timer = this.clock.setTimeout(() => {
      this.timer = undefined;
      if (this.state !== 'running') return;
      this.cycle = this.runCycle().finally(() => {
        this.cycle = undefined;
      });
    }, delayMs);
  }

  private async runCycle(): Promise<void> {
    let more = false;
    try {
      more = await this.fanOut();
    } catch (error) {
      this.log.error({ err: error }, 'event fan-out failed; it runs again at the next cycle');
    }
    await this.fill();
    if (this.state === 'running') this.schedule(more ? 0 : this.settings.pollIntervalMs);
  }

  /** Fan the new events out to every route's destinations. Returns whether a realm has more. */
  private async fanOut(): Promise<boolean> {
    // A node with no route fans nothing out and touches no position: the
    // positions belong to the nodes that serve their kinds.
    if (this.routes.size === 0) return false;
    const destinations: DeliveryDestination[] = [];
    for (const route of this.routes.values()) {
      let listed: readonly unknown[];
      try {
        listed = await route.destinations();
      } catch (error) {
        this.log.warn(
          { err: error, kind: route.kind },
          'a delivery route could not list its destinations; nothing is fanned out this cycle'
        );
        return false;
      }
      for (const destination of listed) {
        const checked = this.checkDestination(route.kind, destination);
        if (checked) destinations.push(checked);
      }
    }
    const result = await this.store.fanOut({
      kinds: this.kinds,
      destinations,
      now: this.clock.now(),
      pageSize: this.settings.fanOutPageSize,
    });
    if (result.deliveries > 0) void this.fill();
    return result.more;
  }

  /** A route's destination with its kind, or `undefined` (logged once) when it is malformed. */
  private checkDestination(kind: string, value: unknown): DeliveryDestination | undefined {
    const candidate = (value ?? {}) as Partial<DeliveryDestination>;
    const { id, realmId, types, categories, subjects } = candidate;
    const listOf = (list: unknown): boolean =>
      Array.isArray(list) && list.every((item) => typeof item === 'string');
    const subjectsOf = (list: unknown): boolean =>
      Array.isArray(list) &&
      list.every(
        (item: unknown) =>
          typeof item === 'object' &&
          item !== null &&
          typeof (item as EventSubjectRef).type === 'string' &&
          typeof (item as EventSubjectRef).id === 'string'
      );
    if (
      typeof id !== 'string' ||
      id.length === 0 ||
      id.length > DESTINATION_ID_MAX_LENGTH ||
      typeof realmId !== 'string' ||
      !UUID_PATTERN.test(realmId) ||
      (types !== undefined && !listOf(types)) ||
      (categories !== undefined && !listOf(categories)) ||
      (subjects !== undefined && !subjectsOf(subjects))
    ) {
      const key = destinationKey(kind, String(id));
      if (!this.reported.has(key)) {
        this.reported.add(key);
        this.log.warn(
          { kind, destinationId: typeof id === 'string' ? id.slice(0, 64) : null },
          'a delivery route listed a malformed destination; it receives nothing'
        );
      }
      return undefined;
    }
    return {
      kind,
      id,
      realmId,
      ...(types === undefined ? {} : { types: [...types] }),
      ...(categories === undefined ? {} : { categories: [...categories] }),
      ...(subjects === undefined
        ? {}
        : { subjects: subjects.map((subject) => ({ type: subject.type, id: subject.id })) }),
    };
  }

  /** Claim due deliveries into the free slots. One claim loop at a time; a call meanwhile runs it again. */
  private fill(): Promise<void> {
    if (this.filling) {
      this.fillAgain = true;
      return this.filling;
    }
    this.filling = (async () => {
      try {
        do {
          this.fillAgain = false;
          await this.claimRound();
        } while (this.fillAgain && this.state === 'running');
      } catch (error) {
        this.log.error(
          { err: error },
          'event deliveries could not be claimed; the next cycle tries again'
        );
      }
    })().finally(() => {
      this.filling = undefined;
    });
    return this.filling;
  }

  private inFlightAt(kind: string, id: string): number {
    return this.perDestination.get(destinationKey(kind, id)) ?? 0;
  }

  private async claimRound(): Promise<void> {
    const { concurrency, maxInFlightPerDestination, leaseMs, maxAttempts } = this.settings;
    if (this.kinds.length === 0) return;
    for (;;) {
      if (this.state !== 'running') return;
      const free = concurrency - this.inFlight.size;
      if (free <= 0) return;
      const due = await this.store.dueDestinations(this.kinds, this.clock.now());
      const open = due.filter(
        (destination) =>
          this.inFlightAt(destination.kind, destination.id) < maxInFlightPerDestination
      );
      if (open.length === 0) return;

      // Hand the free slots out one per destination in turn, starting at a
      // different destination each round, so no destination waits behind
      // another's backlog.
      const start = this.rotation % open.length;
      this.rotation = (this.rotation + 1) % Number.MAX_SAFE_INTEGER;
      const order = [...open.slice(start), ...open.slice(0, start)];
      const picks = new Map<string, { kind: string; id: string; limit: number }>();
      let remaining = free;
      for (let progressed = true; remaining > 0 && progressed;) {
        progressed = false;
        for (const destination of order) {
          if (remaining === 0) break;
          const key = destinationKey(destination.kind, destination.id);
          const pick = picks.get(key) ?? { kind: destination.kind, id: destination.id, limit: 0 };
          if (
            this.inFlightAt(destination.kind, destination.id) + pick.limit >=
            maxInFlightPerDestination
          ) {
            continue;
          }
          pick.limit += 1;
          picks.set(key, pick);
          remaining -= 1;
          progressed = true;
        }
      }
      const asked = [...picks.values()];
      const claims = await this.store.claim({
        picks: asked,
        now: this.clock.now(),
        leaseMs,
        maxAttempts,
      });
      if (this.state !== 'running') {
        // Stopped while claiming: nothing was attempted, so give them back.
        await this.release(claims);
        return;
      }
      for (const claim of claims) this.begin(claim);
      // Fewer than asked: what was due is taken, by this node or another.
      if (claims.length < asked.reduce((sum, pick) => sum + pick.limit, 0)) return;
    }
  }

  private begin(claim: ClaimedDelivery): void {
    const key = destinationKey(claim.destinationKind, claim.destinationId);
    this.perDestination.set(key, (this.perDestination.get(key) ?? 0) + 1);
    const entry: InFlight = {
      claim,
      controller: new AbortController(),
      stage: 'attempting',
      done: Promise.resolve(),
    };
    const id = `${claim.id}:${claim.attempt}`;
    this.inFlight.set(id, entry);
    entry.done = this.run(entry).finally(() => {
      this.inFlight.delete(id);
      const left = (this.perDestination.get(key) ?? 1) - 1;
      if (left > 0) this.perDestination.set(key, left);
      else this.perDestination.delete(key);
      if (this.state === 'running') void this.fill();
    });
  }

  private async run(entry: InFlight): Promise<void> {
    const end = await this.attempt(entry);
    if (end === 'abandoned') return;
    entry.stage = 'recording';
    await this.record(entry.claim, end);
  }

  private async attempt({ claim, controller }: InFlight): Promise<AttemptEnd> {
    if (claim.event === null) {
      return { ok: false, errorClass: DELIVERY_ERROR_CLASSES.unreadableEvent, retry: false };
    }
    const route = this.routes.get(claim.destinationKind);
    if (!route) return { ok: false, errorClass: DELIVERY_ERROR_CLASSES.routeError };
    const event: EventEnvelope = claim.event;
    const delivery: Delivery = Object.freeze({
      id: claim.id,
      destinationKind: claim.destinationKind,
      destinationId: claim.destinationId,
      realmId: claim.realmId,
      eventId: claim.eventId,
      attempt: claim.attempt,
    });

    let timedOut = false;
    let signerHeld = false;
    const timer = this.clock.setTimeout(() => {
      timedOut = true;
      controller.abort(new DeliveryAttemptTimeoutError());
    }, this.settings.attemptTimeoutMs);
    try {
      // The race stops waiting at the time limit or the shutdown, whatever
      // the route does with its signal.
      const result = await Promise.race([
        Promise.resolve().then(() =>
          route.deliver(delivery, event, { signal: controller.signal, signer: this.signer })
        ),
        aborted(controller.signal),
      ]);
      return this.outcomeOf(route.kind, result);
    } catch (error) {
      if (timedOut) return { ok: false, errorClass: DELIVERY_ERROR_CLASSES.timeout };
      if (controller.signal.aborted) return 'abandoned';
      if (isTemporarilyUnavailable(error)) {
        // The signer cannot be reached from this process (#495, #497): the
        // receiver was never called, so the delivery waits like a held one
        // and spends no attempt, instead of failing for good while it lasts.
        // A hold without an end must not stay quiet: warned at the first
        // hold and again at an interval while it lasts.
        signerHeld = true;
        this.noteSignerHold(route.kind, claim);
        return { ok: false, hold: true };
      }
      this.log.warn(
        { err: error, kind: route.kind, deliveryId: claim.id, attempt: claim.attempt },
        'a delivery route threw; the attempt counts as failed'
      );
      return { ok: false, errorClass: DELIVERY_ERROR_CLASSES.routeError };
    } finally {
      this.clock.clearTimeout(timer);
      if (!signerHeld) this.signerHolds.delete(claim.id);
    }
  }

  /** Record a hold for an unavailable signer, warning at the first and at an interval. */
  private noteSignerHold(kind: string, claim: ClaimedDelivery): void {
    const now = this.clock.now();
    this.forgetStaleSignerHolds(now);
    const fields = { kind, deliveryId: claim.id, attempt: claim.attempt };
    const known = this.signerHolds.get(claim.id);
    if (known === undefined) {
      this.signerHolds.set(claim.id, { since: now, warnedAt: now, seenAt: now });
      this.log.warn(
        fields,
        'the signer is unavailable; the delivery is held and spends no attempt'
      );
      return;
    }
    known.seenAt = now;
    if (now - known.warnedAt >= SIGNER_HOLD_WARN_INTERVAL_MS) {
      known.warnedAt = now;
      this.log.warn(
        { ...fields, heldForSeconds: Math.floor((now - known.since) / 1000) },
        'the signer is still unavailable; the delivery is still held'
      );
    }
  }

  /** Forget the holds this node has not seen for a warning interval. */
  private forgetStaleSignerHolds(now: number): void {
    for (const [id, hold] of this.signerHolds) {
      if (now - hold.seenAt >= SIGNER_HOLD_WARN_INTERVAL_MS) this.signerHolds.delete(id);
    }
  }

  signerHeld(): SignerHeldDeliveries {
    const now = this.clock.now();
    this.forgetStaleSignerHolds(now);
    let oldest = now;
    for (const hold of this.signerHolds.values()) oldest = Math.min(oldest, hold.since);
    return { count: this.signerHolds.size, oldestSeconds: Math.max(0, (now - oldest) / 1000) };
  }

  /** What a route returned, as an outcome the store accepts. */
  private outcomeOf(kind: string, result: unknown): DeliveryOutcome {
    const value = result as Partial<{
      ok: unknown;
      errorClass: unknown;
      statusCode: unknown;
      retry: unknown;
      hold: unknown;
    }> | null;
    if (value?.ok === true) return { ok: true, ...statusCodeOf(value.statusCode) };
    if (value?.ok === false && value.hold === true) return { ok: false, hold: true };
    if (value?.ok === false) {
      const known =
        typeof value.errorClass === 'string' && ERROR_CLASS_PATTERN.test(value.errorClass);
      if (!known) {
        this.log.warn({ kind }, 'a delivery route gave an error class that is not a short word');
      }
      return {
        ok: false,
        errorClass: known ? (value.errorClass as string) : DELIVERY_ERROR_CLASSES.routeError,
        ...statusCodeOf(value.statusCode),
        retry: value.retry !== false,
      };
    }
    this.log.warn({ kind }, 'a delivery route returned no outcome; the attempt counts as failed');
    return { ok: false, errorClass: DELIVERY_ERROR_CLASSES.routeError };
  }

  private async record(claim: ClaimedDelivery, outcome: DeliveryOutcome): Promise<void> {
    const now = this.clock.now();
    let record: DeliveryAttemptRecord;
    // A held delivery made no attempt, so none is counted.
    let result: DeliveryAttemptResult | undefined;
    if (outcome.ok) {
      record = { result: 'delivered', ...statusCodeOf(outcome.statusCode) };
      result = 'delivered';
    } else if ('hold' in outcome) {
      record = { result: 'hold', nextAttemptAt: now + DELIVERY_HOLD_INTERVAL_MS };
    } else if (outcome.retry !== false && claim.attempt < this.settings.maxAttempts) {
      record = {
        result: 'retry',
        nextAttemptAt: now + retryDelayMs(claim.attempt, this.settings.retry, this.random),
        errorClass: outcome.errorClass,
        ...statusCodeOf(outcome.statusCode),
      };
      result = 'retry';
    } else {
      record = {
        result: 'failed',
        errorClass: outcome.errorClass,
        ...statusCodeOf(outcome.statusCode),
      };
      result = 'failed';
      this.log.warn(
        {
          kind: claim.destinationKind,
          destinationId: claim.destinationId,
          eventId: claim.eventId,
          attempt: claim.attempt,
          errorClass: outcome.errorClass,
        },
        'event delivery failed for good'
      );
    }
    if (result !== undefined) this.metrics?.attempt(claim.destinationKind, result);
    try {
      const held = await this.store.record(claim, record, now);
      if (!held) {
        this.log.warn(
          { deliveryId: claim.id, attempt: claim.attempt },
          'event delivery outcome not recorded: the claim had lost its lease'
        );
      }
    } catch (error) {
      this.log.error(
        { err: error, deliveryId: claim.id, attempt: claim.attempt },
        'event delivery outcome could not be recorded; the delivery comes due again when its lease runs out'
      );
    }
  }

  private async release(claims: readonly ClaimedDelivery[]): Promise<void> {
    if (claims.length === 0) return;
    try {
      await this.store.release(claims, this.clock.now());
    } catch (error) {
      this.log.error(
        { err: error, deliveries: claims.length },
        'event deliveries could not be released; they come due again when their leases run out'
      );
    }
  }

  /** Whether `promises` all settle within `limitMs` of the role's clock. */
  private settledWithin(
    promises: ReadonlyArray<Promise<unknown> | undefined>,
    limitMs: number
  ): Promise<boolean> {
    const pending = promises.filter(
      (promise): promise is Promise<unknown> => promise !== undefined
    );
    if (pending.length === 0) return Promise.resolve(true);
    return new Promise((resolve) => {
      const timer = this.clock.setTimeout(() => resolve(false), limitMs);
      void Promise.allSettled(pending).then(() => {
        this.clock.clearTimeout(timer);
        resolve(true);
      });
    });
  }

  private async stopGracefully(): Promise<void> {
    if (this.state !== 'running') return;
    this.state = 'stopping';
    if (this.timer !== undefined) this.clock.clearTimeout(this.timer);
    this.timer = undefined;

    const work = () => [
      this.cycle,
      this.filling,
      ...[...this.inFlight.values()].map((entry) => entry.done),
    ];
    const limit = this.settings.shutdownTimeoutMs;
    const settled = await this.settledWithin(work(), limit);
    // Give up on the attempts whose route still runs; one whose outcome is
    // being recorded keeps its lease, since releasing it could undo that
    // outcome.
    const left = [...this.inFlight.values()].filter((entry) => entry.stage === 'attempting');
    if (!settled && left.length > 0) {
      for (const entry of left) entry.controller.abort(new DeliveryRoleStoppedError());
      // Each wait has the same limit, so a store that no longer answers
      // cannot hold the shutdown: an unreleased lease runs out by itself.
      await this.settledWithin([this.release(left.map((entry) => entry.claim))], limit);
      this.log.warn(
        { deliveries: left.length, shutdownTimeoutMs: limit },
        'event deliveries still running at the shutdown limit were released'
      );
    }
    // Recording outcomes and a store call still running (a fan-out, a claim)
    // get the same limit.
    await this.settledWithin(work(), limit);
    this.state = 'stopped';
    this.log.info({ kinds: this.kinds }, 'delivery role stopped');
  }
}

/**
 * Start the delivery role: in-process, in a single deployment, beside the
 * other roles; or alone, on nodes of its own. Its first cycle runs at once.
 *
 * @throws {TypeError} on a route with a malformed or repeated kind, or a
 *   setting out of range
 */
export function startDeliveryRole(options: DeliveryRoleOptions): DeliveryRole {
  const runner = new Runner(options);
  runner.start();
  return runner;
}
