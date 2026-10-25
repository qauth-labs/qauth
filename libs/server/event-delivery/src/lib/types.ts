import type { EventCategory, EventEnvelope } from '@qauth-labs/shared-events';

/**
 * The delivery role's vocabulary (ADR-019 Decisions 8 and 9, issue #460).
 *
 * The role reads the event store through a {@link DeliveryStore}, hands each
 * event to a {@link DeliveryRoute}, and signs only through the
 * {@link DeliverySigner} handle the signer role gives it. Nothing here loads,
 * reads or holds a key, and this library depends on no library that does: an
 * Nx constraint and a test (`key-isolation.test.ts`) hold that.
 */

/** A place a route delivers events to, as the route lists it. */
export interface RouteDestination {
  /** Its id within the route, such as a webhook subscription's id; 1 to 255 characters. */
  readonly id: string;
  /** The realm whose events it receives. */
  readonly realmId: string;
  /** Only events of these types. Absent: every type. An empty list matches none. */
  readonly types?: readonly string[];
  /** Only events of these categories. Absent: both. An empty list matches none. */
  readonly categories?: readonly EventCategory[];
  /**
   * Only events about one of these subjects: the envelope's `subject`, by
   * type and id. Absent: any subject, or none. An empty list matches none,
   * and an event without a subject never matches a list.
   */
  readonly subjects?: readonly EventSubjectRef[];
}

/** An event's subject, as a destination's filter names it. */
export interface EventSubjectRef {
  readonly type: string;
  readonly id: string;
}

/** A destination with the kind of the route that delivers to it. */
export interface DeliveryDestination extends RouteDestination {
  readonly kind: string;
}

/** One attempt to deliver one event to one destination. */
export interface Delivery {
  /** The delivery's own id: one per destination and event, the same on every attempt. */
  readonly id: string;
  readonly destinationKind: string;
  readonly destinationId: string;
  readonly realmId: string;
  /** The event's id, the same on every attempt and route: a receiver drops a duplicate by it. */
  readonly eventId: string;
  /** This attempt, 1 for the first. */
  readonly attempt: number;
}

/**
 * Signing for the delivery role (ADR-019 Decision 9): it sends what is to be
 * signed and gets the signature back, and never sees a key. The signer role
 * makes the handle (`deliverySignerHandle` in
 * `@qauth-labs/fastify-plugin-event-delivery`), which calls the signer as the
 * `delivery` caller, so the signer's policy allows these three and nothing
 * else.
 */
export interface DeliverySigner {
  /**
   * The `webhook-signature` header for one message (Standard Webhooks): the
   * subscription's secrets sign `id`, `timestamp` and the exact bytes of
   * `body`, inside the signer.
   */
  signWebhook(request: {
    readonly realmId: string;
    /** The subscription whose secrets sign. */
    readonly subscriptionId: string;
    /** The `webhook-id`: the event's id, the same on every retry. */
    readonly id: string;
    /** The `webhook-timestamp` of this attempt, in whole seconds. */
    readonly timestamp: number;
    /** The body as it is sent. */
    readonly body: Uint8Array | string;
  }): Promise<string>;

  /**
   * A Security Event Token or a logout token: a compact JWS signed by the
   * realm's `event_signing` key.
   */
  signEventToken(request: {
    readonly realmId: string;
    /** The token type, such as `secevent+jwt` or `logout+jwt`. */
    readonly typ: string;
    /** The claims set, without `iss`; the signer adds the realm's issuer. */
    readonly claims: Readonly<Record<string, unknown>>;
  }): Promise<string>;

  /**
   * Decrypt a destination's secret that the realm's `data_at_rest` key
   * encrypted, such as the `Authorization` header an SSF receiver asked QAuth
   * to send (#410). The plaintext lives only for the attempt.
   */
  decrypt(request: {
    readonly realmId: string;
    /** The ciphertext as stored. */
    readonly ciphertext: string;
    /** The context it was encrypted under: it names the destination. */
    readonly context: string;
  }): Promise<Uint8Array>;
}

/** What a route gets beside the delivery and the event. */
export interface DeliveryContext {
  /**
   * Aborted when the attempt reaches its time limit, or when the role stops
   * and gives up waiting for it. The role stops waiting at once either way;
   * a route passes the signal on to its outbound call.
   */
  readonly signal: AbortSignal;
  /** The only way a route signs. */
  readonly signer: DeliverySigner;
}

/**
 * How one attempt ended.
 *
 * `errorClass` is a short lower-case word such as `timeout`, `http_status`
 * or `destination_blocked`, never a message: it is stored and shown in the
 * delivery history. A route never puts a secret, a token or a response body
 * in it.
 */
export type DeliveryOutcome =
  | {
      readonly ok: true;
      /** The status the destination answered, when it answered over HTTP. */
      readonly statusCode?: number;
    }
  | {
      readonly ok: false;
      readonly errorClass: string;
      readonly statusCode?: number;
      /**
       * `false` for a refusal no retry can change, such as a destination that
       * no longer exists: the delivery ends `failed` at once. Retried by default.
       */
      readonly retry?: boolean;
    };

/**
 * A delivery route: webhooks (#538), SSF streams (#410), or any later one.
 * The role finds the route of a delivery by `kind`.
 */
export interface DeliveryRoute {
  /** The route's name, such as `webhook` or `ssf`: lower case, 1 to 32 characters. */
  readonly kind: string;

  /**
   * Every enabled destination of this route. The role calls it before each
   * fan-out. When it throws, the role fans out nothing until it answers
   * again, so no destination misses an event because its listing failed.
   */
  destinations(): Promise<readonly RouteDestination[]>;

  /**
   * Deliver one event to one destination. A throw counts as a failed attempt
   * (`route_error`) that is retried.
   */
  deliver(
    delivery: Delivery,
    event: EventEnvelope,
    context: DeliveryContext
  ): Promise<DeliveryOutcome>;
}

/** A claimed delivery, as the store hands it over. */
export interface ClaimedDelivery extends Delivery {
  /** When the claim's lease runs out, in epoch milliseconds. */
  readonly lockedUntil: number;
  /** The event, or `null` when the store cannot read it. */
  readonly event: EventEnvelope | null;
}

/** How an attempt ended, as the store records it. */
export type DeliveryAttemptRecord =
  | { readonly result: 'delivered'; readonly statusCode?: number }
  | {
      readonly result: 'retry';
      readonly nextAttemptAt: number;
      readonly statusCode?: number;
      readonly errorClass: string;
    }
  | { readonly result: 'failed'; readonly statusCode?: number; readonly errorClass: string };

/**
 * Where the role keeps its work: the delivery queue. In QAuth it is
 * `createEventDeliveriesRepository` of `@qauth-labs/infra-db`, connected as
 * the delivery role's own database user. All times are the role's clock.
 */
export interface DeliveryStore {
  fanOut(request: {
    /** The route kinds this node serves: only their positions are moved or forgotten. */
    readonly kinds: readonly string[];
    readonly destinations: readonly DeliveryDestination[];
    readonly now: number;
    readonly pageSize?: number;
  }): Promise<{ readonly deliveries: number; readonly more: boolean }>;
  dueDestinations(
    kinds: readonly string[],
    now: number
  ): Promise<ReadonlyArray<{ readonly kind: string; readonly id: string }>>;
  claim(request: {
    readonly picks: ReadonlyArray<{
      readonly kind: string;
      readonly id: string;
      readonly limit: number;
    }>;
    readonly now: number;
    readonly leaseMs: number;
    readonly maxAttempts: number;
  }): Promise<readonly ClaimedDelivery[]>;
  record(
    claim: { readonly id: string; readonly attempt: number },
    outcome: DeliveryAttemptRecord,
    now: number
  ): Promise<boolean>;
  release(
    claims: ReadonlyArray<{ readonly id: string; readonly attempt: number }>,
    now: number
  ): Promise<number>;
}

/**
 * How an attempt is counted: `delivered`; `retry`, failed and tried again
 * later; `failed`, failed for good.
 */
export type DeliveryAttemptResult = 'delivered' | 'retry' | 'failed';

/** Where the role counts attempts (`qauth_events_delivery_attempts_total`). */
export interface DeliveryMetrics {
  attempt(kind: string, result: DeliveryAttemptResult): void;
}

/** The part of a pino logger the role writes to; `fastify.log` fits. */
export interface DeliveryLogger {
  debug(object: object, message: string): void;
  info(object: object, message: string): void;
  warn(object: object, message: string): void;
  error(object: object, message: string): void;
}

/**
 * Time and timers, injectable so a test can move time by hand. The same
 * shape as the job runner's clock.
 */
export interface DeliveryClock {
  /** Epoch milliseconds. */
  now(): number;
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(timer: unknown): void;
}
