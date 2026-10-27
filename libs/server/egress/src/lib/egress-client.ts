import { validateHeaderName, validateHeaderValue } from 'node:http';

import { addressKind } from './address';
import {
  type AddressPermit,
  allowlistPermit,
  type EgressAllowlist,
  EMPTY_EGRESS_ALLOWLIST,
  isEgressAllowlist,
} from './allowlist';
import { type CheckedUrl, checkUrl, hostForLog, resolveCheckedAddresses } from './destination';
import { EgressError, type EgressErrorReason, EgressFailure, type EgressOutcome } from './errors';
import { DEFAULT_EGRESS_LIMITS, type EgressLimits, mergeLimits } from './limits';
import { allowlistApplies, checkRealm, checkSource, type EgressSource } from './source';
import { type EgressTransport, LOCAL_TEST_TRANSPORT, NODE_TRANSPORT } from './transport';

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
  /**
   * Who set the destination: `operator`, `admin`, `client`, `end_user` or
   * `remote_document`. Only an `operator` or `admin` destination may use the
   * deployment allowlist, and only for a {@link realm} its entry names.
   */
  source: EgressSource;
  /**
   * The name of the realm the destination belongs to. The allowlist entries
   * that name it apply to an `operator` or `admin` destination; without a
   * realm none does.
   */
  realm?: string;
  /** Caps for this call, over the client's. */
  limits?: Partial<EgressLimits>;
}

/** Where a destination checked by {@link EgressClient.validateDestination} comes from. */
export interface EgressDestinationOptions {
  /** As {@link EgressRequest.purpose}. */
  purpose: string;
  /** As {@link EgressRequest.source}. */
  source: EgressSource;
  /** As {@link EgressRequest.realm}. */
  realm?: string;
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
  /** Gets one line per blocked or failed call: purpose, source, realm, host and reason. */
  logger?: EgressLogger;
  /** Also counts blocked and failed calls, besides {@link EgressClient.counts}. */
  counter?: EgressCounter;
  /**
   * The deployment allowlist (`EGRESS_ALLOWLIST_PATH`), from
   * `parseEgressAllowlist` or `loadEgressAllowlist`. None unless set: every
   * non-public address is refused.
   */
  allowlist?: EgressAllowlist;
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
    options: EgressDestinationOptions
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

/** The body's size in bytes, measured without copying it. */
function requestBodyBytes(
  method: EgressMethod,
  body: string | Uint8Array | undefined
): number | undefined {
  if (body === undefined) return undefined;
  if (method === 'GET' || method === 'HEAD') {
    throw new TypeError(`an egress ${method} request has no body`);
  }
  return typeof body === 'string' ? Buffer.byteLength(body, 'utf8') : body.byteLength;
}

function copyBody(body: string | Uint8Array | undefined): Buffer | undefined {
  if (body === undefined) return undefined;
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

/** Either permit, or `undefined` when neither exists. */
function eitherPermit(
  a: AddressPermit | undefined,
  b: AddressPermit | undefined
): AddressPermit | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return (hostname, address) => a(hostname, address) || b(hostname, address);
}

/**
 * The client over `transport`. Only {@link createEgressClient} calls it with
 * the real network, and {@link createTestEgressClient} with the local test
 * network and `basePermit`: no export lets a caller hand in a network or a
 * permit of its own. The tests of this library replace the transport module
 * instead.
 *
 * @param basePermit - non-public addresses every call may reach, whatever its
 *   source; only the test client sets it, to loopback
 */
function buildEgressClient(
  options: EgressClientOptions,
  transport: EgressTransport,
  basePermit?: AddressPermit
): EgressClient {
  const baseLimits = mergeLimits(DEFAULT_EGRESS_LIMITS, options.limits);
  if (options.allowlist !== undefined && !isEgressAllowlist(options.allowlist)) {
    throw new TypeError(
      'egress allowlist must come from parseEgressAllowlist or loadEgressAllowlist'
    );
  }
  const allowlist = options.allowlist ?? EMPTY_EGRESS_ALLOWLIST;

  /**
   * The non-public addresses a call to a destination of `source` for `realm`
   * may reach: the allowlist entries that name the realm, for an `operator`
   * or `admin` destination only.
   */
  const callPermit = (source: EgressSource, realm: string | undefined) =>
    eitherPermit(
      basePermit,
      realm !== undefined && allowlistApplies(source)
        ? allowlistPermit(allowlist, realm)
        : undefined
    );
  // A Map, not an object: a purpose such as `constructor` must not reach a
  // prototype.
  const counts = new Map<string, EgressCounts[string]>();

  /** Count, log and convert a refusal or failure into the error the caller gets. */
  const report = (
    err: unknown,
    purpose: string,
    source: EgressSource,
    realm: string | undefined,
    host: string | undefined
  ): EgressError => {
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
      { purpose, source, ...(realm === undefined ? {} : { realm }), host, reason, outcome },
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
    const source = checkSource(call.source);
    const realm = checkRealm(call.realm);
    const permit = callPermit(source, realm);
    if (!(EGRESS_METHODS as readonly string[]).includes(call.method)) {
      throw new TypeError(`egress method must be one of ${EGRESS_METHODS.join(', ')}`);
    }
    const limits = mergeLimits(baseLimits, call.limits);
    let headers = requestHeaders(call.headers);
    const bodyBytes = requestBodyBytes(call.method, call.body);
    let body: Buffer | undefined;
    let method: EgressMethod = call.method;
    let host = hostForLog(call.url);

    try {
      // Before the copy: an oversized body is refused without a second allocation.
      if (bodyBytes !== undefined && bodyBytes > limits.maxRequestBytes) {
        throw new EgressFailure(
          'size',
          'blocked',
          `egress to ${host ?? 'a URL'} refused: the request body is larger than ${limits.maxRequestBytes} bytes`
        );
      }
      body = copyBody(call.body);
      return await withDeadline(limits, async (signal) => {
        const startedAt = Date.now();
        let target = checkUrl(call.url, permit);
        // The allowlist is for the destination the operator or an admin set.
        // A redirect to another host is the remote side's choice, so its
        // target gets no more than the test client's base permit.
        const origin = target.hostname;
        let targetPermit = permit;
        let redirects = 0;
        for (;;) {
          host = target.hostname;
          const addresses = await withinDeadline(
            resolveCheckedAddresses(
              target,
              transport.resolveHost,
              {
                timeoutMs: Math.max(1, limits.totalTimeoutMs - (Date.now() - startedAt)),
                signal,
              },
              targetPermit
            ),
            signal,
            target.hostname
          );
          const result = await transport.exchange(
            {
              hostname: target.hostname,
              port: target.port,
              literalFamily: target.literalFamily,
              path: `${target.url.pathname}${target.url.search}`,
              addresses,
              method,
              headers,
              body,
              connectTimeoutMs: limits.connectTimeoutMs,
              maxResponseBytes: limits.maxResponseBytes,
            },
            signal
          );
          if (result.kind === 'failed') {
            throw new EgressFailure(result.reason, 'failed', result.message);
          }
          if (result.location === undefined) {
            const { body: bytes } = result;
            return {
              status: result.status,
              headers: result.headers,
              // Bytes from a fetch process arrive as a plain Uint8Array.
              body: Buffer.isBuffer(bytes)
                ? bytes
                : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength),
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
          targetPermit = hostForLog(next) === origin ? permit : basePermit;
          const nextTarget = checkUrl(next, targetPermit);
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
      throw report(err, purpose, source, realm, host);
    }
  };

  const validateDestination = async (
    url: string | URL,
    validateOptions: EgressDestinationOptions
  ): Promise<ValidatedDestination> => {
    const purpose = checkPurpose(validateOptions.purpose);
    const source = checkSource(validateOptions.source);
    const realm = checkRealm(validateOptions.realm);
    const permit = callPermit(source, realm);
    const limits = mergeLimits(baseLimits, validateOptions.limits);
    try {
      return await withDeadline(limits, async (signal) => {
        const target = checkUrl(url, permit);
        const addresses = await withinDeadline(
          resolveCheckedAddresses(
            target,
            transport.resolveHost,
            { timeoutMs: limits.totalTimeoutMs, signal },
            permit
          ),
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
      throw report(err, purpose, source, realm, hostForLog(url));
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
 * the total time and both bodies, and it never goes through a proxy.
 *
 * A non-public address is reachable only through the deployment allowlist
 * (`allowlist`), for a destination whose `source` is `operator` or `admin`
 * and whose `realm` an entry names. A destination that a client, an end user
 * or a remote document supplies never is, and no allowlist entry opens an
 * unspecified, multicast or cloud metadata address.
 */
export function createEgressClient(options: EgressClientOptions = {}): EgressClient {
  return buildEgressClient(options, NODE_TRANSPORT);
}

/** Loopback addresses: the test client's fixture servers listen there. */
const LOOPBACK_PERMIT: AddressPermit = (_hostname, address) => addressKind(address) === 'loopback';

/** Refuse unless the process is a test run. */
function assertTestEnvironment(): void {
  if (process.env['NODE_ENV'] !== 'test') {
    throw new Error(
      `createTestEgressClient is for tests only: NODE_ENV is ${JSON.stringify(process.env['NODE_ENV'] ?? '')}, not "test"`
    );
  }
}

/**
 * TEST SUPPORT — an egress client that also reaches local fixture servers on
 * loopback (`localhost`, `127.0.0.1`, `::1`), for any source. It exists only
 * while `NODE_ENV` is `test`: creating one, and every call through one,
 * throws otherwise.
 *
 * Everything else is the production client: `https` only, the address checks
 * (a private, link-local or metadata address is still refused), redirects,
 * caps and the allowlist. Two things differ. Names resolve with the operating
 * system's resolver, so `localhost` resolves, and each exchange runs in the
 * test's process rather than in a fetch process. TLS trusts the process's
 * default CA certificates; a test adds its fixture's CA with
 * `tls.setDefaultCACertificates`.
 *
 * It replaces the removed `CIMD_ALLOW_PRIVATE_ADDRESSES` and
 * `ID_JAG_ALLOW_PRIVATE_ADDRESSES` switches: a deployment has no setting that
 * lets the egress client reach loopback.
 *
 * @throws Error when `NODE_ENV` is not `test`
 */
export function createTestEgressClient(options: EgressClientOptions = {}): EgressClient {
  assertTestEnvironment();
  const client = buildEgressClient(options, LOCAL_TEST_TRANSPORT, LOOPBACK_PERMIT);
  return {
    async request(call) {
      assertTestEnvironment();
      return client.request(call);
    },
    async validateDestination(url, validateOptions) {
      assertTestEnvironment();
      return client.validateDestination(url, validateOptions);
    },
    counts: () => client.counts(),
  };
}
