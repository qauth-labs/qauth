import { z } from 'zod';

/**
 * The delivery role's retry schedule (ADR-019 Decision 8, issue #460): how
 * many attempts an event delivery gets, and how long it waits between them.
 *
 * After attempt `n` fails, attempt `n + 1` waits
 * `EVENT_DELIVERY_RETRY_INITIAL_DELAY × 2^(n - 1)` seconds, at most
 * `EVENT_DELIVERY_RETRY_MAX_DELAY`, less up to 20% at random. The defaults
 * spread 12 attempts over about 12 to 14.5 hours. The role refuses to start
 * when the cap is below the first wait.
 *
 * None of these turns delivery or any event off: events are stored whatever
 * they say, and a delivery that runs out of attempts stays in the queue as
 * `failed`.
 *
 * A plain `z.object`, so the auth server can spread its `.shape`.
 */
export const eventDeliveryEnvSchema = z.object({
  /** The attempts an event delivery gets before it ends `failed`. */
  EVENT_DELIVERY_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(100).default(12),

  /** Seconds a delivery waits after its first failed attempt. */
  EVENT_DELIVERY_RETRY_INITIAL_DELAY: z.coerce.number().int().min(1).max(604_800).default(30),

  /** The longest wait between two attempts of a delivery, in seconds. */
  EVENT_DELIVERY_RETRY_MAX_DELAY: z.coerce.number().int().min(1).max(604_800).default(21_600),
});

/** The delivery role's retry settings. */
export type EventDeliveryEnv = z.infer<typeof eventDeliveryEnvSchema>;
