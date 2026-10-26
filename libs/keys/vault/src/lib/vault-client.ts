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

/** The clock the client and the token session use: time, and timers. */
export interface VaultClock {
  /** Epoch milliseconds. */
  now(): number;
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(timer: unknown): void;
}

/** The process clock. */
export const SYSTEM_CLOCK: VaultClock = Object.freeze({
  now: () => Date.now(),
  setTimeout: (callback: () => void, delayMs: number): unknown => setTimeout(callback, delayMs),
  clearTimeout: (timer: unknown) => clearTimeout(timer as NodeJS.Timeout),
});

/** Every Vault call is tried at most this many times, the first attempt included. */
export const VAULT_MAX_ATTEMPTS = 3;

/** The backoff before the second attempt, in ms; it doubles for each attempt after. */
export const VAULT_BACKOFF_MS = 200;

/** Node error codes after which the same request may succeed. A TLS verification failure is not one. */
const RETRYABLE_CODES: ReadonlySet<string> = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'EPIPE',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
]);

/** A call the client makes. */
export interface VaultCall {
  readonly method: 'GET' | 'POST';
  /** The API path below `/v1/`, such as `transit/encrypt/qauth-kek`. */
  readonly path: string;
  /** The Vault token, for every call but a login. */
  readonly token?: string;
  readonly body?: Readonly<Record<string, unknown>>;
}

/** Sends Vault calls. */
export interface VaultClient {
  /**
   * Send one call, retrying a connection failure, a timeout, throttling and a
   * server fault up to {@link VAULT_MAX_ATTEMPTS} attempts in all.
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

function retryableTransportError(error: unknown): boolean {
  const code = error instanceof Error ? (error as NodeJS.ErrnoException).code : undefined;
  return code !== undefined && RETRYABLE_CODES.has(code);
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
      };

      for (let attempt = 1; ; attempt++) {
        let response: VaultHttpResponse;
        try {
          response = await options.transport(request);
        } catch (error) {
          if (attempt < VAULT_MAX_ATTEMPTS && retryableTransportError(error)) {
            await backoff(attempt);
            continue;
          }
          throw new VaultTransportError(operation, error);
        }
        if (response.status === 200 || response.status === 204) return response;
        if (attempt < VAULT_MAX_ATTEMPTS && isRetryableStatus(response.status)) {
          await backoff(attempt);
          continue;
        }
        throw new VaultHttpError(operation, response.status, vaultErrorsOf(response.body));
      }
    },
  });
}
