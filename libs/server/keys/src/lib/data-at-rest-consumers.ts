import {
  ADMIN_SEALED_VALUE_CONTEXT_PREFIX,
  AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX,
  DELIVERY_SECRET_CONTEXT_PREFIX,
  OID4VP_RESPONSE_KEY_CONTEXT_PREFIX,
  REALM_MAIL_SECRET_CONTEXT_PREFIX,
  TOTP_SECRET_CONTEXT_PREFIX,
  UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX,
} from './signer-policy';

/**
 * Who seals data with a realm's `data_at_rest` key, and how long a ciphertext
 * of each lives (#542). The rotation job keeps a retired `data_at_rest` key
 * until every ciphertext it made has expired: for the longest lifetime here.
 * A consumer whose ciphertexts have no end keeps every retired key for good,
 * since nothing re-seals them under the new key yet.
 *
 * A new consumer adds its context prefix here, with its longest lifetime; a
 * test holds every prefix the signer policy names to an entry.
 */

/** One kind of ciphertext sealed with the `data_at_rest` key. */
export interface DataAtRestConsumer {
  /** The `context` prefix its ciphertexts are sealed under (`signer-policy.ts`). */
  readonly contextPrefix: string;
  /** What it seals, in one line. */
  readonly description: string;
  /**
   * The longest a ciphertext of it lives, in ms; `null` when one may live for
   * ever, as a stored secret does until someone replaces it.
   */
  readonly longestLifetimeMs: number | null;
}

/** The longest an OID4VP request state lives (`MAX_OID4VP_REQUEST_TTL_MS` in `server-federation`). */
const OID4VP_REQUEST_STATE_LIFETIME_MS = 15 * 60 * 1000;

/** Every consumer of the `data_at_rest` key. */
export const DATA_AT_REST_CONSUMERS: readonly DataAtRestConsumer[] = Object.freeze(
  [
    {
      contextPrefix: REALM_MAIL_SECRET_CONTEXT_PREFIX,
      description: "A realm's mail transport secret, such as its SMTP password.",
      longestLifetimeMs: null,
    },
    {
      contextPrefix: UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX,
      description: "An upstream OpenID Provider's client secret.",
      longestLifetimeMs: null,
    },
    {
      contextPrefix: AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX,
      description: "A secret member of an AuthMethod plugin's configuration.",
      longestLifetimeMs: null,
    },
    {
      contextPrefix: TOTP_SECRET_CONTEXT_PREFIX,
      description: "The shared secret of an account's authenticator app.",
      longestLifetimeMs: null,
    },
    {
      contextPrefix: DELIVERY_SECRET_CONTEXT_PREFIX,
      description:
        "A delivery destination's secret, such as an SSF receiver's Authorization header.",
      longestLifetimeMs: null,
    },
    {
      contextPrefix: ADMIN_SEALED_VALUE_CONTEXT_PREFIX,
      description:
        'A secret member of an admin operation, sealed before the request is filed; a filed request has no fixed end.',
      longestLifetimeMs: null,
    },
    {
      contextPrefix: OID4VP_RESPONSE_KEY_CONTEXT_PREFIX,
      description:
        "An OID4VP request state's ephemeral response key, which lives as long as the request.",
      longestLifetimeMs: OID4VP_REQUEST_STATE_LIFETIME_MS,
    },
  ].map((consumer) => Object.freeze(consumer))
);

/**
 * How long a retired `data_at_rest` key must be kept, in ms: the longest
 * lifetime of any consumer's ciphertext, or `null` when one may live for ever.
 */
export function dataAtRestLifetimeMs(
  consumers: readonly DataAtRestConsumer[] = DATA_AT_REST_CONSUMERS
): number | null {
  let longest = 0;
  for (const consumer of consumers) {
    if (consumer.longestLifetimeMs === null) return null;
    longest = Math.max(longest, consumer.longestLifetimeMs);
  }
  return longest;
}
