import {
  isRetryableStatus,
  vaultErrorsOf,
  VaultHttpError,
  type VaultOperation,
  VaultTransportError,
} from './errors';
import type { VaultHttpResponse, VaultTransport } from './https-transport';

/**
 * The Vault API client (ADR-019 Decision 9, #578): headers, bounded retries,
 * and Vault's statuses as errors.
 */

/**
 * The clock the client, the token session and the key check use: time, and
 * timers. Only the difference between two readings is used, for ages and
 * expiries counted from a TTL Vault reports in seconds, so it may be
 * monotonic: a wall clock stepped by NTP or by hand moves no expiry.
 */
export interface VaultClock {
  /** Milliseconds from an arbitrary origin; never goes back. */
  now(): number;
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(timer: unknown): void;
}

/** The process clock: monotonic time (`performance.now()`), and Node's timers. */
export const SYSTEM_CLOCK: VaultClock = Object.freeze({
  now: () => performance.now(),
  setTimeout: (callback: () => void, delayMs: number): unknown => setTimeout(callback, delayMs),
  clearTimeout: (timer: unknown) => clearTimeout(timer as NodeJS.Timeout),
});

/** Every Vault call is tried at most this many times, the first attempt included. */
export const VAULT_MAX_ATTEMPTS = 3;

/** The backoff before the second attempt, in ms; it doubles for each attempt after. */
export const VAULT_BACKOFF_MS = 200;

/** Node error codes that mean the request never reached Vault: no connection was made. */
const UNSENT_CODES: ReadonlySet<string> = new Set([
  'ECONNREFUSED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
]);

/**
 * Node error codes after which the same request may succeed. A TLS
 * verification failure is not one.
 */
const RETRYABLE_CODES: ReadonlySet<string> = new Set([
  ...UNSENT_CODES,
  'ECONNRESET',
  'EPIPE',
  'ETIMEDOUT',
]);

/**
 * Calls that are not repeated once Vault may have served them. Each AppRole
 * login uses one use of the secret ID and creates a token, so a login whose
 * answer was lost is not sent again: only a connection that never opened, and
 * a 429 or 503 (Vault served nothing), are retried.
 */
const NOT_IDEMPOTENT: ReadonlySet<VaultOperation> = new Set(['approle-login']);

/** A call the client makes. */
export interface VaultCall {
  readonly method: 'GET' | 'POST';
  /** The API path below `/v1/`, such as `transit/encrypt/qauth-kek`. */
  readonly path: string;
  /** The Vault token, for every call but a login. */
  readonly token?: string;
  readonly body?: Readonly<Record<string, unknown>>;
  /** Replaces the transport's answer size cap, for a call whose answer can be larger. */
  readonly maxResponseBytes?: number;
}

/** Sends Vault calls. */
export interface VaultClient {
  /**
   * Send one call, retrying a connection failure, a timeout, throttling and a
   * server fault up to {@link VAULT_MAX_ATTEMPTS} attempts in all. An AppRole
   * login is retried only when Vault cannot have served it.
   *
   * @returns Vault's answer to a call it served (200 or 204)
   * @throws VaultHttpError for any other status
   * @throws VaultTransportError when no attempt got an answer
   */
  send(operation: VaultOperation, call: VaultCall): Promise<VaultHttpResponse>;
}

/** What {@link createVaultClient} needs. */
export interface VaultClientOptions {
  readonly transport: VaultTransport;
  /** The namespace every call is made in, sent as `X-Vault-Namespace`. */
  readonly namespace?: string;
  readonly clock?: VaultClock;
  /** A number in [0, 1), for the backoff's jitter. Defaults to `Math.random`. */
  readonly random?: () => number;
}

function retryableTransportError(error: unknown, idempotent: boolean): boolean {
  const code = error instanceof Error ? (error as NodeJS.ErrnoException).code : undefined;
  return code !== undefined && (idempotent ? RETRYABLE_CODES : UNSENT_CODES).has(code);
}

function retryableAnswer(status: number, idempotent: boolean): boolean {
  return idempotent ? isRetryableStatus(status) : status === 429 || status === 503;
}

/** The Vault client over `transport`. */
export function createVaultClient(options: VaultClientOptions): VaultClient {
  const clock = options.clock ?? SYSTEM_CLOCK;
  const random = options.random ?? Math.random;

  /** Wait before attempt `attempt + 1`: exponential, with jitter over its upper half. */
  function backoff(attempt: number): Promise<void> {
    const ceiling = VAULT_BACKOFF_MS * 2 ** (attempt - 1);
    const delay = Math.round(ceiling / 2 + (ceiling / 2) * random());
    return new Promise((resolve) => {
      clock.setTimeout(resolve, delay);
    });
  }

  return Object.freeze({
    async send(operation: VaultOperation, call: VaultCall): Promise<VaultHttpResponse> {
      const headers: Record<string, string> = { 'X-Vault-Request': 'true' };
      if (call.token !== undefined) headers['X-Vault-Token'] = call.token;
      if (options.namespace !== undefined) headers['X-Vault-Namespace'] = options.namespace;
      const request = {
        method: call.method,
        path: `/v1/${call.path}`,
        headers,
        ...(call.body !== undefined ? { body: JSON.stringify(call.body) } : {}),
        ...(call.maxResponseBytes !== undefined ? { maxResponseBytes: call.maxResponseBytes } : {}),
      };

      const idempotent = !NOT_IDEMPOTENT.has(operation);
      for (let attempt = 1; ; attempt++) {
        let response: VaultHttpResponse;
        try {
          response = await options.transport(request);
        } catch (error) {
          if (attempt < VAULT_MAX_ATTEMPTS && retryableTransportError(error, idempotent)) {
            await backoff(attempt);
            continue;
          }
          throw new VaultTransportError(operation, error);
        }
        if (response.status === 200 || response.status === 204) return response;
        if (attempt < VAULT_MAX_ATTEMPTS && retryableAnswer(response.status, idempotent)) {
          await backoff(attempt);
          continue;
        }
        throw new VaultHttpError(operation, response.status, vaultErrorsOf(response.body));
      }
    },
  });
}
