import { validateHeaderName, validateHeaderValue } from 'node:http';

import { type CheckedUrl, checkUrl, hostForLog, resolveCheckedAddresses } from './destination';
import { EgressError, type EgressErrorReason, EgressFailure, type EgressOutcome } from './errors';
import { DEFAULT_EGRESS_LIMITS, type EgressLimits, mergeLimits } from './limits';
import { type EgressTransport, exchange, NODE_TRANSPORT } from './transport';

/** The HTTP methods the client sends. */
export const EGRESS_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] as const;
export type EgressMethod = (typeof EGRESS_METHODS)[number];

/** One outbound call. */
export interface EgressRequest {
  method: EgressMethod;
  /** An absolute `https` URL without credentials. */
  url: string | URL;
  /**
   * Request headers. The client sets `host`, `connection` and
   * `content-length` itself, and refuses them and the other hop-by-hop headers
   * here.
   */
  headers?: Record<string, string>;
  /** Request body; a string is sent as UTF-8. Not allowed with `GET` or `HEAD`. */
  body?: string | Uint8Array;
  /**
   * What the call is for — `webhook`, `cimd`, `backchannel-logout` — a fixed
   * label, not data: it names the call in counts and logs. Lower-case letters,
   * digits and `_ . : -`, starting with a letter, at most 64 characters.
   */
  purpose: string;
  /** Caps for this call, over the client's. */
  limits?: Partial<EgressLimits>;
}

/** The final response of a call, after the redirects it followed. */
export interface EgressResponse {
  status: number;
  /** Lower-case names; a repeated header's values joined with `, `. */
  headers: Record<string, string>;
  body: Buffer;
  /** The URL that answered. */
  url: string;
  /** Redirects followed to reach it. */
  redirects: number;
}

/** A destination that passed every check, without anything sent to it. */
export interface ValidatedDestination {
  url: string;
  host: string;
  port: number;
  /** The addresses the host resolved to, each of them public. */
  addresses: string[];
}

/** Counters of the calls that were blocked or failed, by purpose. */
export type EgressCounts = Record<
  string,
  Record<EgressOutcome, number> & { reasons: Partial<Record<EgressErrorReason, number>> }
>;

/** Labels of one blocked or failed call. */
export interface EgressCounterLabels {
  purpose: string;
  outcome: EgressOutcome;
  reason: EgressErrorReason;
}

/**
 * Where the client also counts blocked and failed calls. A prom-client
 * `Counter<'purpose' | 'outcome' | 'reason'>` fits.
 */
export interface EgressCounter {
  inc(labels: EgressCounterLabels): void;
}

/** The part of a pino-style logger the client uses. */
export interface EgressLogger {
  warn(fields: Record<string, unknown>, message: string): void;
}

export interface EgressClientOptions {
  /** Caps of every call, over {@link DEFAULT_EGRESS_LIMITS}. */
  limits?: Partial<EgressLimits>;
  /** Gets one line per blocked or failed call: purpose, host and reason. */
  logger?: EgressLogger;
  /** Also counts blocked and failed calls, besides {@link EgressClient.counts}. */
  counter?: EgressCounter;
}

/** The SSRF-safe client for every outbound call (ADR-019 Decision 8). */
export interface EgressClient {
  /**
   * Send one request. Resolves with the final response, whatever its status;
   * rejects with an {@link EgressError} when a check refuses the call or the
   * call fails.
   */
  request(request: EgressRequest): Promise<EgressResponse>;
  /**
   * Run the checks of {@link request} — the URL, then every address of its
   * host — without sending anything. A caller runs it when a destination is
   * registered; {@link request} checks again at every delivery.
   */
  validateDestination(
    url: string | URL,
    options: { purpose: string; limits?: Partial<EgressLimits> }
  ): Promise<ValidatedDestination>;
  /** Blocked and failed calls since the client was created, by purpose. */
  counts(): EgressCounts;
}

const PURPOSE_PATTERN = /^[a-z][a-z0-9_.:-]{0,63}$/;

/** Set by the client or meaningful only to one hop; never taken from a caller. */
const FORBIDDEN_HEADERS: ReadonlySet<string> = new Set([
  'host',
  'connection',
  'content-length',
  'transfer-encoding',
  'keep-alive',
  'upgrade',
  'te',
  'trailer',
  'expect',
  'proxy-connection',
  'proxy-authorization',
]);

/** Dropped when a redirect leaves the origin the caller named. */
const CREDENTIAL_HEADERS: readonly string[] = ['authorization', 'cookie'];

/** Dropped when a redirect turns the request into a `GET`. */
const BODY_HEADERS: readonly string[] = [
  'content-type',
  'content-encoding',
  'content-language',
  'content-location',
];

const DEFAULT_USER_AGENT = 'qauth-egress';

function checkPurpose(purpose: unknown): string {
  if (typeof purpose !== 'string' || !PURPOSE_PATTERN.test(purpose)) {
    throw new TypeError('egress purpose must be a short lower-case label such as "webhook"');
  }
  return purpose;
}

function requestHeaders(headers: Record<string, string> | undefined): Record<string, string> {
  const result: Record<string, string> = { 'user-agent': DEFAULT_USER_AGENT };
  for (const [rawName, value] of Object.entries(headers ?? {})) {
    validateHeaderName(rawName);
    validateHeaderValue(rawName, value);
    const name = rawName.toLowerCase();
    if (FORBIDDEN_HEADERS.has(name)) {
      throw new TypeError(`egress request header ${name} is set by the client`);
    }
    result[name] = value;
  }
  return result;
}

function requestBody(
  method: EgressMethod,
  body: string | Uint8Array | undefined
): Buffer | undefined {
  if (body === undefined) return undefined;
  if (method === 'GET' || method === 'HEAD') {
    throw new TypeError(`an egress ${method} request has no body`);
  }
  // A copy: the caller may reuse its array while the call is in flight.
  return typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
}

function sameOrigin(a: CheckedUrl, b: CheckedUrl): boolean {
  return a.hostname === b.hostname && a.port === b.port;
}

/**
 * Run `work` against the call's deadline: when `signal` aborts first, the
 * promise rejects at once, whatever `work` is still doing.
 */
function withinDeadline<T>(work: Promise<T>, signal: AbortSignal, host: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void =>
      reject(
        new EgressFailure('timeout', 'failed', `egress to ${host} failed: the call timed out`)
      );
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    work.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (err: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(err);
      }
    );
  });
}

/**
 * The client over `transport`. Only {@link createEgressClient} calls it, with
 * the real network: no export lets a caller hand in a network of its own. The
 * tests replace the transport module instead.
 */
function buildEgressClient(options: EgressClientOptions, transport: EgressTransport): EgressClient {
  const baseLimits = mergeLimits(DEFAULT_EGRESS_LIMITS, options.limits);
  // A Map, not an object: a purpose such as `constructor` must not reach a
  // prototype.
  const counts = new Map<string, EgressCounts[string]>();

  /** Count, log and convert a refusal or failure into the error the caller gets. */
  const report = (err: unknown, purpose: string, host: string | undefined): EgressError => {
    const failure =
      err instanceof EgressFailure
        ? err
        : new EgressFailure(
            'network',
            'failed',
            `egress to ${host ?? 'a URL'} failed: ${err instanceof Error ? err.message : 'unknown error'}`
          );
    const { reason, outcome } = failure;
    let entry = counts.get(purpose);
    if (entry === undefined) {
      entry = { blocked: 0, failed: 0, reasons: {} };
      counts.set(purpose, entry);
    }
    entry[outcome] += 1;
    entry.reasons[reason] = (entry.reasons[reason] ?? 0) + 1;
    options.counter?.inc({ purpose, outcome, reason });
    options.logger?.warn(
      { purpose, host, reason, outcome },
      outcome === 'blocked' ? 'egress call blocked' : 'egress call failed'
    );
    return new EgressError({ reason, outcome, purpose, host, message: failure.message });
  };

  /** Run `work` under a total deadline of `limits.totalTimeoutMs`. */
  const withDeadline = async <T>(
    limits: EgressLimits,
    work: (signal: AbortSignal) => Promise<T>
  ): Promise<T> => {
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), limits.totalTimeoutMs);
    try {
      return await work(controller.signal);
    } finally {
      clearTimeout(deadline);
      // Whatever is still running for this call — a DNS query — stops here.
      controller.abort();
    }
  };

  const request = async (call: EgressRequest): Promise<EgressResponse> => {
    const purpose = checkPurpose(call.purpose);
    if (!(EGRESS_METHODS as readonly string[]).includes(call.method)) {
      throw new TypeError(`egress method must be one of ${EGRESS_METHODS.join(', ')}`);
    }
    const limits = mergeLimits(baseLimits, call.limits);
    let headers = requestHeaders(call.headers);
    let body = requestBody(call.method, call.body);
    let method: EgressMethod = call.method;
    let host = hostForLog(call.url);

    try {
      if (body !== undefined && body.length > limits.maxRequestBytes) {
        throw new EgressFailure(
          'size',
          'blocked',
          `egress to ${host ?? 'a URL'} refused: the request body is larger than ${limits.maxRequestBytes} bytes`
        );
      }
      return await withDeadline(limits, async (signal) => {
        const startedAt = Date.now();
        let target = checkUrl(call.url);
        let redirects = 0;
        for (;;) {
          host = target.hostname;
          const addresses = await withinDeadline(
            resolveCheckedAddresses(target, transport.resolveHost, {
              timeoutMs: Math.max(1, limits.totalTimeoutMs - (Date.now() - startedAt)),
              signal,
            }),
            signal,
            target.hostname
          );
          const result = await exchange(
            {
              target,
              addresses,
              method,
              headers,
              body,
              connectTimeoutMs: limits.connectTimeoutMs,
              maxResponseBytes: limits.maxResponseBytes,
              signal,
            },
            transport.dial
          );
          if (result.location === undefined) {
            return {
              status: result.status,
              headers: result.headers,
              body: result.body,
              url: target.url.href,
              redirects,
            };
          }

          if (redirects >= limits.maxRedirects) {
            throw new EgressFailure(
              'redirect',
              'blocked',
              `egress to ${target.hostname} refused: redirect limit of ${limits.maxRedirects} reached`
            );
          }
          let next: URL;
          try {
            next = new URL(result.location, target.url);
          } catch {
            throw new EgressFailure(
              'redirect',
              'blocked',
              `egress to ${target.hostname} refused: the redirect has no valid Location`
            );
          }
          host = hostForLog(next) ?? host;
          // The same checks as the first URL, before anything is sent to it.
          const nextTarget = checkUrl(next);
          if (!sameOrigin(target, nextTarget)) {
            headers = Object.fromEntries(
              Object.entries(headers).filter(([name]) => !CREDENTIAL_HEADERS.includes(name))
            );
          }
          // As fetch does: 303 turns every method but HEAD into GET, and 301
          // and 302 turn POST into GET. The body goes with it.
          if (
            (result.status === 303 && method !== 'GET' && method !== 'HEAD') ||
            ((result.status === 301 || result.status === 302) && method === 'POST')
          ) {
            method = 'GET';
            body = undefined;
            headers = Object.fromEntries(
              Object.entries(headers).filter(([name]) => !BODY_HEADERS.includes(name))
            );
          }
          target = nextTarget;
          redirects += 1;
        }
      });
    } catch (err) {
      throw report(err, purpose, host);
    }
  };

  const validateDestination = async (
    url: string | URL,
    validateOptions: { purpose: string; limits?: Partial<EgressLimits> }
  ): Promise<ValidatedDestination> => {
    const purpose = checkPurpose(validateOptions.purpose);
    const limits = mergeLimits(baseLimits, validateOptions.limits);
    try {
      return await withDeadline(limits, async (signal) => {
        const target = checkUrl(url);
        const addresses = await withinDeadline(
          resolveCheckedAddresses(target, transport.resolveHost, {
            timeoutMs: limits.totalTimeoutMs,
            signal,
          }),
          signal,
          target.hostname
        );
        return {
          url: target.url.href,
          host: target.hostname,
          port: target.port,
          addresses: addresses.map(({ address }) => address),
        };
      });
    } catch (err) {
      throw report(err, purpose, hostForLog(url));
    }
  };

  const snapshot = (): EgressCounts =>
    Object.fromEntries(
      [...counts].map(([purpose, entry]) => [purpose, { ...entry, reasons: { ...entry.reasons } }])
    );

  return { request, validateDestination, counts: snapshot };
}

/**
 * Create the SSRF-safe egress client (ADR-019 Decision 8). Every outbound call
 * that configuration or user input causes goes through it — webhooks,
 * back-channel logout, SSF push, upstream discovery, CIMD and `jwks_uri`
 * fetches, and every call a plugin makes (ADR-019 Decision 12).
 *
 * The client sends `https` only, to URLs without credentials. It resolves the
 * host once per request, refuses the whole name when any address is not
 * public, and connects only to an address it checked, with the host name in
 * SNI and in the certificate check. It checks each redirect target the same way
 * before following it, at most `maxRedirects` times. It caps the connect time,
 * the total time and both bodies, and it never goes through a proxy. There is
 * no switch that lets it reach a private address.
 */
export function createEgressClient(options: EgressClientOptions = {}): EgressClient {
  return buildEgressClient(options, NODE_TRANSPORT);
}
