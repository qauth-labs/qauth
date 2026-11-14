import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';

import { BoundedCache } from './bounded-cache';
import { isKeyPurpose } from './key-purposes';
import type { PublishedKeyReader } from './published-keys';
import type {
  DecryptRequest,
  EncryptRequest,
  RealmJwks,
  Signer,
  SignerOperation,
  SignHybridRequest,
  SignJwsRequest,
} from './signer';
import { isSignerError, SignerAccessDeniedError, SignerRequestRefusedError } from './signer-errors';
import {
  hasSignerGrant,
  isSignerCallAllowed,
  isSignerCaller,
  type SignerCaller,
} from './signer-policy';
import { JWS_TYPS } from './signer-typ';
import {
  decodeSignerError,
  decodeSignerResult,
  encodeSignerRequest,
  SIGNER_REQUEST_BODY_LIMITS,
  SIGNER_SERVICE_PATH,
  SIGNER_SERVICE_ROUTES,
  type SignerOperationArgs,
  type SignerOperationResult,
} from './signer-wire';

/**
 * THE REMOTE SIGNER (ADR-019 Decision 9, issue #497): the {@link Signer} of
 * a process that does not hold the signer role. It holds no KEK and no key;
 * every operation that needs one is a call to the signer service over mutual
 * TLS, through a {@link SignerTransport} the auth server builds on its
 * internal client.
 *
 * - **Public reads stay local.** `getVerificationKeys` and `getJwks` answer
 *   from the realm's published keys (`realm_public_keys`) through
 *   `publishedKeys`, which caches each realm's list for 60 seconds: a signer
 *   outage stops neither token verification nor the JWKS.
 * - **The certificate decides.** The signer takes the caller's role from
 *   this process's client certificate. The `caller` each call names is
 *   checked here first, against the same policy table, so a call the
 *   in-process signer would refuse for its caller is refused here too, with
 *   no request sent; the signer then holds the call to its own role. A call
 *   the signer still refuses for its role took this process for another
 *   role than the call's (INTERNAL_PEER_ROLES on the signer, or a process
 *   that holds two roles with one certificate): it ends in a 503
 *   (`role_refused`), never in a refusal its caller would take for its own.
 * - **Bounded requests.** A request larger than the signer service takes
 *   (`SIGNER_REQUEST_BODY_LIMITS`) is refused here, before it is sent, as
 *   `REQUEST_TOO_LARGE`, and so is one the service answers `413` to: neither
 *   counts as an outage.
 * - **Fail closed.** No answer, an answer of another shape, or the signer's
 *   own trouble ends the call with a `TemporarilyUnavailableError` (503):
 *   nothing is signed with anything else, and nothing is retried past the
 *   limits below.
 * - **Short deadlines, one retry.** Each attempt has `attemptTimeoutMs`.
 *   The calls whose repeat changes nothing and answers the same
 *   ({@link IDEMPOTENT_SIGNER_OPERATIONS}) are tried once more after an
 *   outage; a call the signer's listener refused before it reached the
 *   service (a `403` with no signer error, which closes the connection, such
 *   as after the signer reloaded its TLS files) is tried once more whatever
 *   it is, as it never ran.
 * - **A circuit breaker.** After `failureThreshold` calls in a row end in an
 *   outage, calls fail at once for `openMs`; then one call at a time probes
 *   the signer, and the first that gets an answer closes the circuit. So a
 *   restarted signer is used again with no restart of this process.
 * - **The upstream JWKS is cached** for `upstreamJwksCacheMs` per realm and
 *   provider. The cookie secrets are not: their caller, the auth server's
 *   cookie key ring, keeps them for 60 seconds as key objects, and a second
 *   cache here would keep the raw secrets on the heap and delay a rotation
 *   twice.
 *
 * Errors name the operation and a reason. They never carry a claim value,
 * a plaintext, a ciphertext or key material: the request's body is not read
 * back, and the signer's error is rebuilt from its public fields
 * (`decodeSignerError`).
 */

/** One call to the signer service: a `POST` of a JSON body. */
export interface SignerTransportRequest {
  /** The route's path, {@link SIGNER_SERVICE_PATH} followed by the operation's route. */
  readonly path: string;
  /** The JSON body. */
  readonly body: string;
  /** Aborts the call at the attempt's deadline. */
  readonly signal: AbortSignal;
}

/** The signer service's answer, whatever its status. */
export interface SignerTransportResponse {
  readonly status: number;
  readonly body: Uint8Array;
}

/**
 * How the remote signer reaches the signer service: the auth server's
 * internal client over mutual TLS. It rejects when no answer came (no
 * connection, a refused handshake, the deadline): the remote signer treats
 * every rejection alike and reads nothing of it but its `code`.
 */
export interface SignerTransport {
  send(request: SignerTransportRequest): Promise<SignerTransportResponse>;
}

/** What the remote signer reports, for the auth server's log. Never a value of a request. */
export type RemoteSignerEvent =
  | {
      readonly type: 'call_failed';
      readonly operation: SignerOperation;
      readonly reason: RemoteSignerFailure;
      /** The answer's status, when there was one. */
      readonly status?: number;
      /** The transport's error code, such as `unreachable` or `timeout`. */
      readonly code?: string;
    }
  | { readonly type: 'circuit_opened'; readonly failures: number; readonly openMs: number }
  | { readonly type: 'circuit_closed' };

/**
 * Why a remote call has no answer:
 *
 * - `unreachable`: the transport failed (no connection, the handshake, the deadline);
 * - `signer_failed`: the signer answered that it cannot do its work now, or failed;
 * - `malformed_answer`: the answer is not one the signer service gives;
 * - `peer_refused`: the signer's listener refused this process, twice: its
 *   certificate maps to no role the signer service admits;
 * - `role_refused`: the signer refused the call for the role this process's
 *   certificate maps to, which is not the call's own;
 * - `rate_limited`: the signer refused the call for this peer's rate;
 * - `circuit_open`: calls fail at once after repeated outages.
 */
export type RemoteSignerFailure =
  | 'unreachable'
  | 'signer_failed'
  | 'malformed_answer'
  | 'peer_refused'
  | 'role_refused'
  | 'rate_limited'
  | 'circuit_open';

/** Options of {@link createRemoteSigner}. */
export interface RemoteSignerOptions {
  /** How the signer service is reached. */
  readonly transport: SignerTransport;
  /** The realms' published keys, which answer `getVerificationKeys` and `getJwks`. */
  readonly publishedKeys: PublishedKeyReader;
  /** One attempt's deadline, in ms. {@link DEFAULT_REMOTE_SIGNER_ATTEMPT_TIMEOUT_MS}. */
  readonly attemptTimeoutMs?: number;
  /** The pause before an idempotent call's second attempt, in ms. {@link DEFAULT_REMOTE_SIGNER_RETRY_DELAY_MS}. */
  readonly retryDelayMs?: number;
  /** The outages in a row that open the circuit. {@link DEFAULT_REMOTE_SIGNER_FAILURE_THRESHOLD}. */
  readonly failureThreshold?: number;
  /** How long an open circuit fails calls at once, in ms. {@link DEFAULT_REMOTE_SIGNER_OPEN_MS}. */
  readonly openMs?: number;
  /** How long an upstream provider's JWKS is kept, in ms. {@link DEFAULT_REMOTE_SIGNER_CACHE_MS}. */
  readonly upstreamJwksCacheMs?: number;
  /** The most upstream JWKS kept at once. */
  readonly upstreamJwksCacheSize?: number;
  /** Receives what the auth server logs. */
  readonly onEvent?: (event: RemoteSignerEvent) => void;
  /** The clock, in epoch ms. */
  readonly now?: () => number;
}

/** One attempt's deadline: the signer answers in milliseconds, so a longer wait is an outage. */
export const DEFAULT_REMOTE_SIGNER_ATTEMPT_TIMEOUT_MS = 2_000;

/** The pause before an idempotent call is tried again. */
export const DEFAULT_REMOTE_SIGNER_RETRY_DELAY_MS = 50;

/** The outages in a row after which calls fail at once. */
export const DEFAULT_REMOTE_SIGNER_FAILURE_THRESHOLD = 5;

/** How long calls fail at once once the circuit opened, before one probes the signer. */
export const DEFAULT_REMOTE_SIGNER_OPEN_MS = 5_000;

/** How long a public answer is kept: the published keys' own interval. */
export const DEFAULT_REMOTE_SIGNER_CACHE_MS = 60_000;

const DEFAULT_UPSTREAM_JWKS_CACHE_SIZE = 256;

/**
 * The operations a remote signer tries a second time after an outage: each
 * changes nothing on the signer and answers the same when repeated. A
 * signature or an encryption is not tried again after a deadline, so a
 * token request waits one attempt at most before it answers 503.
 */
export const IDEMPOTENT_SIGNER_OPERATIONS: readonly SignerOperation[] = Object.freeze([
  'getCookieSecrets',
  'getUpstreamJwks',
  'getVerificationKeys',
  'getJwks',
  'decrypt',
]);

function positive(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`createRemoteSigner: ${name} must be a positive integer`);
  }
  return value;
}

function nonNegative(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`createRemoteSigner: ${name} must be a whole number of ms`);
  }
  return value;
}

/** How one attempt ended. */
type Attempt<T> =
  | { readonly kind: 'answered'; readonly value: T }
  /** The signer answered with a refusal or an error of the request: thrown to the caller. */
  | { readonly kind: 'refused'; readonly error: Error }
  | {
      readonly kind: 'outage';
      readonly reason: RemoteSignerFailure;
      readonly status?: number;
      readonly code?: string;
    }
  /** The signer's listener refused the call before the service read it. */
  | { readonly kind: 'not_run'; readonly status: number }
  /** The signer refused the call for this process's certificate's role. */
  | { readonly kind: 'role_refused' }
  | { readonly kind: 'rate_limited' };

const TEXT = new TextDecoder('utf-8', { fatal: true });

function parseJson(body: Uint8Array): unknown {
  try {
    return JSON.parse(TEXT.decode(body)) as unknown;
  } catch {
    return undefined;
  }
}

/** A request larger than the signer service takes for `operation`. */
function tooLarge(operation: SignerOperation): SignerRequestRefusedError {
  return new SignerRequestRefusedError(
    'REQUEST_TOO_LARGE',
    `The '${operation}' request is larger than the signer service takes`
  );
}

/** The member `name` of `value` when it is a plain object that has it. */
function member(value: unknown, name: string): unknown {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)[name]
    : undefined;
}

/**
 * Make the remote signer over `options.transport`. The returned object is
 * the {@link Signer} of a process without the signer role.
 */
export function createRemoteSigner(options: RemoteSignerOptions): Signer {
  const { transport, publishedKeys } = options;
  const now = options.now ?? (() => Date.now());
  const attemptTimeoutMs = positive(
    options.attemptTimeoutMs,
    DEFAULT_REMOTE_SIGNER_ATTEMPT_TIMEOUT_MS,
    'attemptTimeoutMs'
  );
  const retryDelayMs = nonNegative(
    options.retryDelayMs,
    DEFAULT_REMOTE_SIGNER_RETRY_DELAY_MS,
    'retryDelayMs'
  );
  const failureThreshold = positive(
    options.failureThreshold,
    DEFAULT_REMOTE_SIGNER_FAILURE_THRESHOLD,
    'failureThreshold'
  );
  const openMs = positive(options.openMs, DEFAULT_REMOTE_SIGNER_OPEN_MS, 'openMs');
  const upstreamJwksCacheMs = positive(
    options.upstreamJwksCacheMs,
    DEFAULT_REMOTE_SIGNER_CACHE_MS,
    'upstreamJwksCacheMs'
  );
  const report = (event: RemoteSignerEvent): void => {
    try {
      options.onEvent?.(event);
    } catch {
      // A log sink that throws must not change a call's outcome.
    }
  };

  // The circuit breaker.
  let failures = 0;
  let openUntil = 0;
  let open = false;
  let probing = false;

  /** Whether a call may go out now, and whether it is the probe of an open circuit. */
  function admit(operation: SignerOperation): { probe: boolean } {
    if (!open) return { probe: false };
    const remaining = openUntil - now();
    if (remaining <= 0 && !probing) {
      probing = true;
      return { probe: true };
    }
    report({ type: 'call_failed', operation, reason: 'circuit_open' });
    throw unavailable(operation, 'circuit_open', Math.max(remaining, 1));
  }

  function succeeded(probe: boolean): void {
    if (probe) probing = false;
    failures = 0;
    if (open) {
      open = false;
      report({ type: 'circuit_closed' });
    }
  }

  function failed(probe: boolean): void {
    if (probe) probing = false;
    failures += 1;
    if (probe || (!open && failures >= failureThreshold)) {
      open = true;
      openUntil = now() + openMs;
      report({ type: 'circuit_opened', failures, openMs });
    }
  }

  /** A call that did not get its answer, as its caller sees it. */
  function unavailable(
    operation: SignerOperation,
    reason: RemoteSignerFailure,
    retryAfterMs: number
  ): TemporarilyUnavailableError {
    return new TemporarilyUnavailableError(Math.max(1, Math.ceil(retryAfterMs / 1000)), {
      reason: `signer_${reason}`,
      operation,
    });
  }

  async function attempt<O extends SignerOperation>(
    operation: O,
    body: string,
    realmId: unknown
  ): Promise<Attempt<SignerOperationResult<O>>> {
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), attemptTimeoutMs);
    deadline.unref?.();
    let response: SignerTransportResponse;
    try {
      response = await transport.send({
        path: `${SIGNER_SERVICE_PATH}${SIGNER_SERVICE_ROUTES[operation]}`,
        body,
        signal: controller.signal,
      });
    } catch (error) {
      const code = member(error, 'code');
      return {
        kind: 'outage',
        reason: 'unreachable',
        ...(typeof code === 'string' && /^[a-z_]{1,32}$/.test(code) ? { code } : {}),
      };
    } finally {
      clearTimeout(deadline);
    }
    const json = parseJson(response.body);
    if (response.status === 200) {
      try {
        return { kind: 'answered', value: decodeSignerResult(operation, member(json, 'result')) };
      } catch {
        return { kind: 'outage', reason: 'malformed_answer', status: 200 };
      }
    }
    const wire = member(json, 'error');
    if (wire !== undefined) {
      const error = decodeSignerError(wire, { operation, realmId });
      if (error === undefined) {
        return { kind: 'outage', reason: 'signer_failed', status: response.status };
      }
      // The call's own role passed the same table here (`authorize`): the
      // signer refused the role this process's certificate maps to.
      if (isSignerError(error, 'SIGNER_ACCESS_DENIED')) return { kind: 'role_refused' };
      return { kind: 'refused', error };
    }
    // The service's own cap on the request's size: the signer is up, and the
    // request cannot succeed as it is.
    if (response.status === 413) return { kind: 'refused', error: tooLarge(operation) };
    // The listener's own refusal: no peer role, a role the service does not
    // admit, a certificate that expired or files reloaded since the
    // connection was made. The service never read the call.
    if (response.status === 403) return { kind: 'not_run', status: 403 };
    if (response.status === 429) return { kind: 'rate_limited' };
    return {
      kind: 'outage',
      reason: response.status >= 500 ? 'signer_failed' : 'malformed_answer',
      status: response.status,
    };
  }

  async function call<O extends SignerOperation>(
    operation: O,
    args: SignerOperationArgs<O>,
    realmId: unknown
  ): Promise<SignerOperationResult<O>> {
    const body = encodeSignerRequest(operation, args);
    if (Buffer.byteLength(body, 'utf8') > SIGNER_REQUEST_BODY_LIMITS[operation]) {
      throw tooLarge(operation);
    }
    const { probe } = admit(operation);
    const idempotent = IDEMPOTENT_SIGNER_OPERATIONS.includes(operation);
    let outcome = await attempt(operation, body, realmId);
    if (outcome.kind === 'not_run' || (outcome.kind === 'outage' && idempotent)) {
      if (outcome.kind === 'outage' && retryDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
      outcome = await attempt(operation, body, realmId);
    }
    switch (outcome.kind) {
      case 'answered':
        succeeded(probe);
        return outcome.value;
      case 'refused':
        // The signer answered: it is up, whatever it answered.
        succeeded(probe);
        throw outcome.error;
      case 'role_refused':
        succeeded(probe);
        report({ type: 'call_failed', operation, reason: 'role_refused', status: 403 });
        throw unavailable(operation, 'role_refused', openMs);
      case 'rate_limited':
        // The signer is up and asks this peer to slow down: neither an
        // outage nor a success for the circuit.
        if (probe) probing = false;
        report({ type: 'call_failed', operation, reason: 'rate_limited', status: 429 });
        throw unavailable(operation, 'rate_limited', 1000);
      case 'not_run':
        failed(probe);
        report({ type: 'call_failed', operation, reason: 'peer_refused', status: outcome.status });
        throw unavailable(operation, 'peer_refused', openMs);
      case 'outage':
        failed(probe);
        report({
          type: 'call_failed',
          operation,
          reason: outcome.reason,
          ...(outcome.status === undefined ? {} : { status: outcome.status }),
          ...(outcome.code === undefined ? {} : { code: outcome.code }),
        });
        throw unavailable(operation, outcome.reason, openMs);
    }
  }

  /**
   * Refuse a call the in-process signer would refuse for `caller`, before
   * anything is sent: the role's grant names no such call, or not the token
   * type or the context it asks for. A malformed request goes on, and the
   * signer refuses it with its reason.
   */
  function authorize(caller: unknown, operation: SignerOperation, request?: unknown): void {
    const deny = (purpose?: string): never => {
      throw new SignerAccessDeniedError(
        isSignerCaller(caller) ? caller : undefined,
        operation,
        purpose
      );
    };
    if (!hasSignerGrant(caller, operation)) deny();
    if (operation === 'signJws' || operation === 'signHybrid') {
      const typ = member(request, 'typ');
      const purposeField =
        operation === 'signHybrid' ? 'token_signing' : member(request, 'purpose');
      const purpose =
        typeof purposeField === 'string' && isKeyPurpose(purposeField) ? purposeField : undefined;
      if (
        typeof typ === 'string' &&
        (JWS_TYPS as readonly string[]).includes(typ) &&
        !isSignerCallAllowed(caller, 'signJws', typ)
      ) {
        deny(purpose);
      }
    }
    if (operation === 'encrypt' || operation === 'decrypt') {
      const context = member(request, 'context');
      if (
        (context === undefined || typeof context === 'string') &&
        !isSignerCallAllowed(caller, operation, context ?? '')
      ) {
        deny();
      }
    }
  }

  const upstreamJwks = new BoundedCache<string, { value: RealmJwks; readAt: number }>(
    options.upstreamJwksCacheSize ?? DEFAULT_UPSTREAM_JWKS_CACHE_SIZE
  );
  const upstreamReads = new Map<string, Promise<RealmJwks>>();

  return Object.freeze({
    async signJws(caller: SignerCaller, request: SignJwsRequest) {
      authorize(caller, 'signJws', request);
      return call('signJws', [request], member(request, 'realmId'));
    },
    async signHybrid(caller: SignerCaller, request: SignHybridRequest) {
      authorize(caller, 'signHybrid', request);
      return call('signHybrid', [request], member(request, 'realmId'));
    },
    async signWebhook(caller, request) {
      authorize(caller, 'signWebhook');
      return call('signWebhook', [request], member(request, 'realmId'));
    },
    async signClientAssertion(caller, request) {
      authorize(caller, 'signClientAssertion');
      return call('signClientAssertion', [request], member(request, 'realmId'));
    },
    async signRequestObject(caller, request) {
      authorize(caller, 'signRequestObject');
      return call('signRequestObject', [request], member(request, 'realmId'));
    },
    async getCookieSecrets(caller, realmId, cookieOptions) {
      authorize(caller, 'getCookieSecrets');
      return call('getCookieSecrets', [realmId, cookieOptions], realmId);
    },
    async encrypt(caller: SignerCaller, request: EncryptRequest) {
      authorize(caller, 'encrypt', request);
      return call('encrypt', [request], member(request, 'realmId'));
    },
    async decrypt(caller: SignerCaller, request: DecryptRequest) {
      authorize(caller, 'decrypt', request);
      return call('decrypt', [request], member(request, 'realmId'));
    },
    getVerificationKeys(caller, realmId, purpose) {
      return publishedKeys.getVerificationKeys(caller, realmId, purpose);
    },
    getJwks(caller, realmId, purpose) {
      return publishedKeys.getJwks(caller, realmId, purpose);
    },
    async getUpstreamJwks(caller, realmId, providerId) {
      authorize(caller, 'getUpstreamJwks');
      const key = `${String(realmId).toLowerCase()}\u0000${String(providerId)}`;
      const cached = upstreamJwks.get(key);
      if (cached !== undefined && now() - cached.readAt < upstreamJwksCacheMs) {
        return cached.value;
      }
      let read = upstreamReads.get(key);
      if (read === undefined) {
        const readAt = now();
        read = call('getUpstreamJwks', [realmId, providerId], realmId)
          .then((value) => {
            upstreamJwks.set(key, { value, readAt });
            return value;
          })
          .finally(() => upstreamReads.delete(key));
        upstreamReads.set(key, read);
      }
      return read;
    },
  } satisfies Signer);
}
