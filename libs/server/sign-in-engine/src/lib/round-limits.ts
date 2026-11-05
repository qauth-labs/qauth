import { randomBytes } from 'node:crypto';
import { isIPv4, isIPv6 } from 'node:net';

import type {
  CredentialLimitVerdict,
  CredentialRound,
  CredentialRoundReservation,
  HookRound,
  LimitsHook,
  LimitVerdict,
} from './hooks';
import type { IdentifierDigest } from './ports';
import type { SendWindow } from './send-caps';

/**
 * THE ROUND LIMITS' RULES (PRO-13, #636; ADR-017 Decision 7): the limiter
 * layers around the per-account ladder, keyed on the end-user IP, on the
 * IP's network bucket and on the authenticated client, and the caps on
 * registration starts. The store that counts (the auth server's is a Redis
 * script in `@qauth-labs/fastify-plugin-sign-in-engine`) applies them; this
 * module says what they are, so every store and every test reads one source,
 * and turns a store into the engine's `limits` hook.
 *
 * | Row                 | Key                    | Soft (a delay)                                   | Hard                     |
 * | ------------------- | ---------------------- | ------------------------------------------------ | ------------------------ |
 * | End-user IP         | IP HMAC (IPv6 by /64)  | 10 failed credential rounds in 15 min            | 30: 429 for 15 min, alert |
 * | IP bucket           | /24 or /48 HMAC        | failed rounds for more than 20 identifiers in 15 min, alert | —             |
 * | Client (FiPA)       | client                 | failures above 50 % of at least 200 credential rounds in 5 min, or above 300; alert | above 600 rounds a minute: 429, alert |
 * | Registration starts | IP HMAC; client (FiPA) | —                                                | 3 an hour per IP; 1,000 an hour per client |
 *
 * A credential round carries a password, an `otp` of any step, a recovery
 * code or a WebAuthn response ({@link isCredentialAnswer}). Every one is
 * reserved before its credential is verified: one atomic store operation
 * refuses it inside a delay or past a hard limit, and otherwise counts it as
 * a failed round until it settles. A success then takes the failure back; on
 * the client row it counts as a credential round of its account, at most
 * once per account in each window, so a campaign cannot dilute the ratio
 * with sign-ins to a few accounts it owns. An attempt the account's ladder
 * refuses inside its wait is withdrawn, as if it never came.
 *
 * The soft action is a delay: while a soft threshold holds, its key admits
 * one credential round per `delayMs`, and an earlier one is refused with 429
 * and `Retry-After`, neither verified nor counted. While it holds, every
 * round of the key also owes the bot challenge (PRO-19, #643): `admitRound`
 * says so, and a client that lists `captcha` gets the step before the pending
 * one; a client that does not keeps only the delay (ADR-017 Decision 4,
 * rule 5). Each delay is the
 * row's window over its hard limit or failure budget, so a key held to it
 * meets that limit no sooner than the window it is counted in.
 *
 * `development` relaxes every count tenfold (ADR-008 §5,
 * {@link relaxedRoundLimitPolicy}); `staging` and `production` keep these.
 */

/** The environments of ADR-008: the client's effective one decides which limits a round meets. */
export const ROUND_ENVIRONMENTS = ['development', 'staging', 'production'] as const;
export type RoundEnvironment = (typeof ROUND_ENVIRONMENTS)[number];

/** Read an environment, `production` for anything else: a misconfiguration never relaxes a limit. */
export function roundEnvironmentOf(value: unknown): RoundEnvironment {
  return (ROUND_ENVIRONMENTS as readonly unknown[]).includes(value)
    ? (value as RoundEnvironment)
    : 'production';
}

/** The end-user IP row. Times are in milliseconds. */
export interface EndUserIpLimits {
  /** The window failed credential rounds are counted in. ADR-017 Decision 7: 15 minutes. */
  readonly windowMs: number;
  /** From this many failed rounds in the window, the delay. ADR-017 Decision 7: 10. */
  readonly softFailures: number;
  /** At this many, every round of the IP is refused for `blockMs`. ADR-017 Decision 7: 30. */
  readonly hardFailures: number;
  /** How long the hard action refuses the IP. ADR-017 Decision 7: 15 minutes. */
  readonly blockMs: number;
  /** The delay: one credential round per this long while the soft threshold holds. */
  readonly delayMs: number;
}

/** The IP bucket row: an IPv4 address's /24, an IPv6 address's /48. */
export interface IpBucketLimits {
  /** The window the identifiers are counted in. ADR-017 Decision 7: 15 minutes. */
  readonly windowMs: number;
  /** Failed rounds for more than this many distinct identifiers: the delay and an alert. ADR-017 Decision 7: 20. */
  readonly maxIdentifiers: number;
  /** The delay of the whole bucket while it holds more. */
  readonly delayMs: number;
}

/** The client row: the authenticated client of the FiPA endpoint, never the Interaction API's. */
export interface ClientLimits {
  /** The window of the ratio and of the failure budget. ADR-017 Decision 7: 5 minutes. */
  readonly windowMs: number;
  /** The fewest credential rounds the ratio is read over. ADR-017 Decision 7: 200. */
  readonly ratioMinRounds: number;
  /** A failure ratio above this percentage is the soft threshold. ADR-017 Decision 7: 50. */
  readonly ratioPercent: number;
  /**
   * More failed rounds in the window than this, whatever the ratio: the soft
   * threshold. ADR-017 Decision 7: a tenth of what `maxRounds` admits in the
   * window, 300 at the default.
   */
  readonly failureBudget: number;
  /** The delay of the client while a soft threshold holds. */
  readonly delayMs: number;
  /** Rounds above this many per `maxRoundsWindowMs` are refused. ADR-017 Decision 7: `FIRST_PARTY_CLIENT_MAX_ROUNDS`, 600. */
  readonly maxRounds: number;
  /** The window of `maxRounds`. ADR-017 Decision 7: a minute. */
  readonly maxRoundsWindowMs: number;
}

/** The caps on registration starts (ADR-017 Decision 7, "Registration starts"). */
export interface RegistrationStartLimits {
  /** Per end-user IP. ADR-017 Decision 7: 3 an hour, the `REGISTRATION_RATE_LIMIT` default. */
  readonly endUserIp: SendWindow;
  /** Per authenticated client. The record names no number: QAuth's is 1,000 an hour. */
  readonly client: SendWindow;
}

/** The round limits' rules. */
export interface RoundLimitPolicy {
  readonly endUserIp: EndUserIpLimits;
  readonly ipBucket: IpBucketLimits;
  readonly client: ClientLimits;
  readonly registrationStarts: RegistrationStartLimits;
}

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;

/** `FIRST_PARTY_CLIENT_MAX_ROUNDS`'s default (ADR-017 Decision 7): rounds a minute per client. */
export const FIRST_PARTY_CLIENT_MAX_ROUNDS_DEFAULT = 600;

/** What {@link roundLimitPolicy} builds the rules from. */
export interface RoundLimitPolicyOptions {
  /**
   * `FIRST_PARTY_CLIENT_MAX_ROUNDS`: the client's rounds a minute. The
   * failure budget is derived from it, so an operator who raises the cap for
   * real traffic raises the budget and its alert with it.
   */
  readonly clientMaxRounds?: number;
  /** The per-IP cap on registration starts: `REGISTRATION_RATE_LIMIT` per `REGISTRATION_RATE_WINDOW`. */
  readonly registrationPerIp?: SendWindow;
}

/** The round limits of ADR-017 Decision 7, with the deployment's `FIRST_PARTY_CLIENT_MAX_ROUNDS` and registration cap. */
export function roundLimitPolicy(options: RoundLimitPolicyOptions = {}): RoundLimitPolicy {
  const ipWindowMs = 15 * MINUTE_MS;
  const hardFailures = 30;
  const clientWindowMs = 5 * MINUTE_MS;
  const maxRounds = options.clientMaxRounds ?? FIRST_PARTY_CLIENT_MAX_ROUNDS_DEFAULT;
  const maxRoundsWindowMs = MINUTE_MS;
  // "A tenth of what FIRST_PARTY_CLIENT_MAX_ROUNDS admits in that time".
  const failureBudget = Math.max(
    1,
    Math.floor((maxRounds * (clientWindowMs / maxRoundsWindowMs)) / 10)
  );
  return Object.freeze({
    endUserIp: Object.freeze({
      windowMs: ipWindowMs,
      softFailures: 10,
      hardFailures,
      blockMs: 15 * MINUTE_MS,
      delayMs: Math.floor(ipWindowMs / hardFailures),
    }),
    ipBucket: Object.freeze({
      windowMs: ipWindowMs,
      maxIdentifiers: 20,
      delayMs: Math.floor(ipWindowMs / hardFailures),
    }),
    client: Object.freeze({
      windowMs: clientWindowMs,
      ratioMinRounds: 200,
      ratioPercent: 50,
      failureBudget,
      delayMs: Math.max(1, Math.floor(clientWindowMs / failureBudget)),
      maxRounds,
      maxRoundsWindowMs,
    }),
    registrationStarts: Object.freeze({
      endUserIp: Object.freeze({
        ...(options.registrationPerIp ?? { limit: 3, windowMs: HOUR_MS }),
      }),
      client: Object.freeze({ limit: 1_000, windowMs: HOUR_MS }),
    }),
  });
}

/** The round limits at their defaults. */
export const ROUND_LIMIT_POLICY: RoundLimitPolicy = roundLimitPolicy();

/** How much `development` relaxes every count (ADR-008 §5, "Rate limits: lenient"). */
export const DEVELOPMENT_ROUND_LIMIT_FACTOR = 10;

/**
 * The limits `development` meets (ADR-008 §5): every count tenfold, and each
 * delay a tenth as long, so a developer who mistypes a password from one
 * machine meets none of them. The windows, the ratio and the hard block's
 * length stay. `staging` keeps production values.
 */
export function relaxedRoundLimitPolicy(policy: RoundLimitPolicy): RoundLimitPolicy {
  const f = DEVELOPMENT_ROUND_LIMIT_FACTOR;
  const shorter = (ms: number) => Math.max(1, Math.floor(ms / f));
  const window = (w: SendWindow): SendWindow => Object.freeze({ ...w, limit: w.limit * f });
  return Object.freeze({
    endUserIp: Object.freeze({
      ...policy.endUserIp,
      softFailures: policy.endUserIp.softFailures * f,
      hardFailures: policy.endUserIp.hardFailures * f,
      delayMs: shorter(policy.endUserIp.delayMs),
    }),
    ipBucket: Object.freeze({
      ...policy.ipBucket,
      maxIdentifiers: policy.ipBucket.maxIdentifiers * f,
      delayMs: shorter(policy.ipBucket.delayMs),
    }),
    client: Object.freeze({
      ...policy.client,
      ratioMinRounds: policy.client.ratioMinRounds * f,
      failureBudget: policy.client.failureBudget * f,
      delayMs: shorter(policy.client.delayMs),
      maxRounds: policy.client.maxRounds * f,
    }),
    registrationStarts: Object.freeze({
      endUserIp: window(policy.registrationStarts.endUserIp),
      client: window(policy.registrationStarts.client),
    }),
  });
}

/** The two policies a store applies: the one it was given, and `development`'s. */
export interface RoundLimitPolicies {
  readonly strict: RoundLimitPolicy;
  readonly relaxed: RoundLimitPolicy;
}

/** Check `policy` and derive `development`'s from it. */
export function roundLimitPolicies(policy: RoundLimitPolicy): RoundLimitPolicies {
  const strict = checkRoundLimitPolicy(policy);
  return Object.freeze({ strict, relaxed: checkRoundLimitPolicy(relaxedRoundLimitPolicy(strict)) });
}

/** The policy a round of `environment` meets: `development`'s relaxed one, else the strict one. */
export function roundLimitPolicyFor(
  environment: RoundEnvironment,
  policies: RoundLimitPolicies
): RoundLimitPolicy {
  return environment === 'development' ? policies.relaxed : policies.strict;
}

function whole(value: number, min: number): boolean {
  return Number.isSafeInteger(value) && value >= min;
}

function checkTime(value: number, name: string): void {
  if (!whole(value, 1_000)) throw new Error(`round limit policy: ${name} below a second`);
}

function checkCount(value: number, name: string): void {
  if (!whole(value, 1)) throw new Error(`round limit policy: ${name} below 1`);
}

/** Check a policy's numbers, so a store never runs limits that cannot hold. */
export function checkRoundLimitPolicy(policy: RoundLimitPolicy): RoundLimitPolicy {
  const { endUserIp, ipBucket, client, registrationStarts } = policy;
  checkTime(endUserIp.windowMs, 'endUserIp.windowMs');
  checkCount(endUserIp.softFailures, 'endUserIp.softFailures');
  checkCount(endUserIp.hardFailures, 'endUserIp.hardFailures');
  checkTime(endUserIp.blockMs, 'endUserIp.blockMs');
  if (endUserIp.softFailures > endUserIp.hardFailures) {
    throw new Error('round limit policy: endUserIp.softFailures above hardFailures');
  }
  checkTime(ipBucket.windowMs, 'ipBucket.windowMs');
  checkCount(ipBucket.maxIdentifiers, 'ipBucket.maxIdentifiers');
  checkTime(client.windowMs, 'client.windowMs');
  checkCount(client.ratioMinRounds, 'client.ratioMinRounds');
  checkCount(client.failureBudget, 'client.failureBudget');
  checkCount(client.maxRounds, 'client.maxRounds');
  checkTime(client.maxRoundsWindowMs, 'client.maxRoundsWindowMs');
  if (!whole(client.ratioPercent, 1) || client.ratioPercent > 99) {
    throw new Error('round limit policy: client.ratioPercent outside 1 to 99');
  }
  // A delay is a pace within the window: never none, never longer than it.
  for (const [delay, window, name] of [
    [endUserIp.delayMs, endUserIp.windowMs, 'endUserIp'],
    [ipBucket.delayMs, ipBucket.windowMs, 'ipBucket'],
    [client.delayMs, client.windowMs, 'client'],
  ] as const) {
    if (!whole(delay, 1) || delay > window) {
      throw new Error(`round limit policy: ${name}.delayMs outside 1 ms to its window`);
    }
  }
  for (const [window, name] of [
    [registrationStarts.endUserIp, 'registrationStarts.endUserIp'],
    [registrationStarts.client, 'registrationStarts.client'],
  ] as const) {
    checkCount(window.limit, `${name}.limit`);
    checkTime(window.windowMs, `${name}.windowMs`);
  }
  return policy;
}

/**
 * The answer members that make a round a credential round (ADR-017
 * Decision 7): a password, an `otp` of any step, a recovery code and a
 * WebAuthn response.
 */
export const CREDENTIAL_ANSWER_MEMBERS = Object.freeze([
  'password',
  'otp',
  'recovery_code',
  'webauthn_response',
] as const);

/** Whether an answer, as the step grammar read it, carries a credential: a round the limiters count. */
export function isCredentialAnswer(answer: unknown): boolean {
  if (typeof answer !== 'object' || answer === null) return false;
  const record = answer as Record<string, unknown>;
  return CREDENTIAL_ANSWER_MEMBERS.some(
    (name) => Object.hasOwn(record, name) && record[name] !== undefined
  );
}

/** The eight 16-bit groups of an IPv6 address, an embedded IPv4 tail included; `null` for anything else. */
function ipv6Groups(address: string): number[] | null {
  if (!isIPv6(address)) return null;
  let text = address.toLowerCase();
  const lastColon = text.lastIndexOf(':');
  const last = text.slice(lastColon + 1);
  if (last.includes('.')) {
    if (!isIPv4(last)) return null;
    const [a = 0, b = 0, c = 0, d = 0] = last.split('.').map(Number);
    text = `${text.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split('::');
  const left = halves[0] === '' || halves[0] === undefined ? [] : halves[0].split(':');
  const right =
    halves.length < 2 || halves[1] === '' || halves[1] === undefined ? [] : halves[1].split(':');
  const groups =
    halves.length === 2
      ? [...left, ...Array.from({ length: 8 - left.length - right.length }, () => '0'), ...right]
      : left;
  if (groups.length !== 8) return null;
  return groups.map((group) => Number.parseInt(group, 16));
}

/** An IPv4 address's /24, as a CIDR. */
function ipv4Bucket(octets: readonly number[]): string {
  return `${octets.slice(0, 3).join('.')}.0/24`;
}

/**
 * The network bucket of an end-user IP, for the distinct-identifier count
 * (ADR-017 Decision 7): an IPv4 address's /24, an IPv6 address's /48, as a
 * CIDR. An address in the RFC 6052 well-known prefix 64:ff9b::/96, or an
 * IPv4-mapped one (`::ffff:192.0.2.1`), stands for one IPv4 client, and is
 * bucketed by that client's /24. A value that is not an address is its own
 * bucket.
 */
export function endUserIpBucket(endUserIp: string): string {
  if (isIPv4(endUserIp)) return ipv4Bucket(endUserIp.split('.').map(Number));
  const groups = ipv6Groups(endUserIp.split('%')[0] ?? endUserIp);
  if (groups === null) return endUserIp;
  const [g0, g1, g2, g3, g4, g5, g6 = 0, g7 = 0] = groups;
  const translated = g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0;
  const mapped = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff;
  if (translated || mapped) return ipv4Bucket([g6 >> 8, g6 & 0xff, g7 >> 8]);
  return `${[g0, g1, g2].map((group) => (group ?? 0).toString(16)).join(':')}::/48`;
}

/** Which limit refused a round. */
export const ROUND_LIMITS = [
  /** The end-user IP's hard action: blocked, or its failures full. */
  'end_user_ip',
  /** The end-user IP's delay. */
  'end_user_ip_delay',
  /** The IP bucket's delay. */
  'ip_bucket_delay',
  /** The client's delay. */
  'client_delay',
  /** The client's rounds a minute. */
  'client_rounds',
  /** The registration starts of the end-user IP. */
  'registration_end_user_ip',
  /** The registration starts of the client. */
  'registration_client',
] as const;
export type RoundLimitName = (typeof ROUND_LIMITS)[number];

/**
 * A threshold whose crossing alerts the operator, once per key in each of
 * its windows (the hard block: once per block).
 */
export const ROUND_LIMIT_ALERTS = [
  /** The end-user IP met its hard action. */
  'end_user_ip_blocked',
  /** The IP bucket failed on more distinct identifiers than its bound. */
  'ip_bucket_identifiers',
  /** The client's failure ratio crossed its threshold. */
  'client_failure_ratio',
  /** The client's failures passed its budget. */
  'client_failure_budget',
  /** The client went over its rounds a minute. */
  'client_rounds',
] as const;
export type RoundLimitAlert = (typeof ROUND_LIMIT_ALERTS)[number];

/** What a store decided about a round, a reservation or a registration start. */
export type RoundLimitDecision =
  | {
      readonly kind: 'admitted';
      readonly alerts: readonly RoundLimitAlert[];
      /**
       * `admitRound` only: a soft threshold of the round's IP, bucket or
       * client row holds, so the round owes the bot challenge (PRO-19,
       * #643; ADR-017 Decision 4, rule 5).
       */
      readonly softThreshold?: boolean;
    }
  | {
      readonly kind: 'refused';
      readonly limit: RoundLimitName;
      /** When the round may come again, in ms: at least 1. */
      readonly retryAfterMs: number;
      readonly alerts: readonly RoundLimitAlert[];
    };

/** The keys of one round, as a store counts them: never an address, never a raw identifier. */
export interface RoundLimitKeys {
  readonly realmId: string;
  /** Whose limits the round meets: `development` relaxes them. */
  readonly environment: RoundEnvironment;
  /** The end-user IP's keyed HMAC; absent when the round carries no address. */
  readonly endUserIpHmac?: string;
  /** The keyed HMAC of the IP's bucket ({@link endUserIpBucket}); set with `endUserIpHmac`. */
  readonly ipBucketHmac?: string;
  /** The authenticated client, where the client row applies (FiPA only). The store keys it by a hash. */
  readonly clientKey?: string;
}

/** One credential round a store reserves or settles. */
export interface CredentialRoundKeys extends RoundLimitKeys {
  /** The reservation's id: unique, 16 to 64 characters of base64url. */
  readonly reservation: string;
  /** The identifier's keyed HMAC, for the bucket's distinct-identifier count; absent before any identifier. */
  readonly identifierHmac?: string;
}

/** How a reserved credential round ended. */
export type CredentialRoundOutcome =
  /** The credential was right: the failure is taken back; on the client row, one success of the account. */
  | 'success'
  /** It was wrong: the failure stays, and a threshold it crosses acts. */
  | 'failure'
  /** It was never verified (the account's ladder refused it inside a wait): taken back from every count. */
  | 'withdrawn';

/**
 * Where the round limits count. Every operation is atomic; any error rejects,
 * and the engine fails closed: the round is refused before any credential is
 * checked.
 */
export interface RoundLimitStore {
  /**
   * Rule 3, every round: refuse one from an end-user IP inside its hard
   * block, or one above the client's rounds a minute; otherwise count it on
   * the client's, and say whether a soft threshold of its IP, its bucket or
   * its client holds (`softThreshold`), which asks for the bot challenge.
   */
  admitRound(keys: RoundLimitKeys): Promise<RoundLimitDecision>;
  /**
   * Reserve a credential round before its credential is verified: refuse it
   * inside a delay or past a hard limit, neither verified nor counted;
   * otherwise count it as a failed round of every row until it settles.
   */
  reserveCredential(round: CredentialRoundKeys): Promise<RoundLimitDecision>;
  /** Settle a reservation, once. Returns the alerts a failure's crossing raised. */
  settleCredential(
    round: CredentialRoundKeys & {
      readonly outcome: CredentialRoundOutcome;
      /** The account a success proved: its success counts once per client window. */
      readonly accountKey?: string;
    }
  ): Promise<readonly RoundLimitAlert[]>;
  /** Decide a registration start and, unless refused, count it. */
  reserveRegistrationStart(keys: RoundLimitKeys): Promise<RoundLimitDecision>;
}

/** An alert of the round limits, for the operator: the threshold and the key it concerns. */
export interface RoundLimitAlertEvent {
  readonly realmId: string;
  readonly alert: RoundLimitAlert;
  /** The end-user IP's HMAC, for `end_user_ip_blocked`. */
  readonly endUserIpHmac?: string;
  /** The bucket's HMAC, for `ip_bucket_identifiers`. */
  readonly ipBucketHmac?: string;
  /** The client id, for the client's alerts. */
  readonly clientId?: string;
}

/** What {@link createRoundLimiter} needs. */
export interface RoundLimiterOptions {
  /**
   * The keyed HMAC an end-user IP and its bucket are counted under: the
   * identifier HMAC's derivation under the end-user IP's label, so the
   * store holds no address.
   */
  readonly ipDigest: IdentifierDigest;
  /**
   * Whether the client row and the per-client registration cap apply: the
   * FiPA endpoint's authenticated client, never the Interaction API's.
   */
  readonly perClient: boolean;
  /** Told of every alert: the operator's. A reporter that throws changes no answer. */
  readonly onAlert?: (alert: RoundLimitAlertEvent) => void;
}

/** A registration start the limiter is asked about (for the registration steps, #640). */
export interface RegistrationStartRound {
  readonly realmId: string;
  readonly clientId: string;
  /** The end-user IP as the limiters key it; absent: no per-IP cap applies. */
  readonly endUserIp?: string;
  readonly environment?: RoundEnvironment;
}

/** The engine's `limits` hook over a store, and the registration starts' cap. */
export interface RoundLimiter extends LimitsHook {
  /** Count a registration start, or refuse it with 429 (ADR-017 Decision 7). */
  reserveRegistrationStart(round: RegistrationStartRound): Promise<LimitVerdict>;
}

/** The `Retry-After` of a refusal, in whole seconds, at least 1 (RFC 9110 §10.2.3). */
function retrySeconds(ms: number): number {
  return Math.max(1, Math.ceil(ms / 1_000));
}

/** A store's decision, checked: anything else is a store fault, which fails closed. */
function checkedDecision(decision: RoundLimitDecision): RoundLimitDecision {
  if (
    decision?.kind === 'admitted' &&
    (decision.softThreshold === undefined || typeof decision.softThreshold === 'boolean')
  ) {
    return decision;
  }
  if (
    decision?.kind === 'refused' &&
    (ROUND_LIMITS as readonly string[]).includes(decision.limit) &&
    Number.isFinite(decision.retryAfterMs)
  ) {
    return decision;
  }
  throw new Error('round limits: the store answered out of shape');
}

/**
 * The engine's `limits` hook over `store`: it keys a round by the keyed HMACs
 * of its end-user IP and of the IP's bucket, and by its client where the
 * client row applies, and reports each alert the store raises.
 */
export function createRoundLimiter(
  store: RoundLimitStore,
  options: RoundLimiterOptions
): RoundLimiter {
  const report = (event: RoundLimitAlertEvent) => {
    try {
      options.onAlert?.(Object.freeze(event));
    } catch {
      // An alert that cannot be told changes no answer.
    }
  };

  async function keysOf(round: {
    readonly realmId: string;
    readonly clientId: string;
    readonly endUserIp?: string;
    readonly environment?: RoundEnvironment;
  }): Promise<RoundLimitKeys> {
    const { realmId, endUserIp } = round;
    const ip =
      endUserIp === undefined || endUserIp === ''
        ? {}
        : {
            endUserIpHmac: await options.ipDigest({ realmId, identifier: endUserIp }),
            ipBucketHmac: await options.ipDigest({
              realmId,
              identifier: endUserIpBucket(endUserIp),
            }),
          };
    return {
      realmId,
      environment: roundEnvironmentOf(round.environment),
      ...ip,
      ...(options.perClient ? { clientKey: round.clientId } : {}),
    };
  }

  const alerted = (keys: RoundLimitKeys, clientId: string, alerts: unknown) => {
    if (!Array.isArray(alerts)) return;
    for (const alert of alerts as unknown[]) {
      if (typeof alert !== 'string') continue;
      if (!(ROUND_LIMIT_ALERTS as readonly string[]).includes(alert)) continue;
      report({
        realmId: keys.realmId,
        alert: alert as RoundLimitAlert,
        ...(alert === 'end_user_ip_blocked' && keys.endUserIpHmac !== undefined
          ? { endUserIpHmac: keys.endUserIpHmac }
          : {}),
        ...(alert === 'ip_bucket_identifiers' && keys.ipBucketHmac !== undefined
          ? { ipBucketHmac: keys.ipBucketHmac }
          : {}),
        ...(alert.startsWith('client_') ? { clientId } : {}),
      });
    }
  };

  const verdictOf = (decision: RoundLimitDecision): LimitVerdict =>
    decision.kind === 'admitted'
      ? Object.freeze(
          decision.softThreshold === true
            ? { kind: 'continue', softThreshold: true }
            : { kind: 'continue' }
        )
      : Object.freeze({
          kind: 'throttled',
          retryAfterSeconds: retrySeconds(decision.retryAfterMs),
        });

  async function round(hookRound: HookRound): Promise<LimitVerdict> {
    const keys = await keysOf(hookRound);
    const decision = checkedDecision(await store.admitRound(keys));
    alerted(keys, hookRound.clientId, decision.alerts);
    return verdictOf(decision);
  }

  async function reserve(credential: CredentialRound): Promise<CredentialLimitVerdict> {
    const keys: CredentialRoundKeys = {
      ...(await keysOf(credential)),
      reservation: randomBytes(16).toString('base64url'),
      ...(credential.identifierHmac === undefined
        ? {}
        : { identifierHmac: credential.identifierHmac }),
    };
    const decision = checkedDecision(await store.reserveCredential(keys));
    alerted(keys, credential.clientId, decision.alerts);
    if (decision.kind === 'refused') {
      return Object.freeze({
        kind: 'throttled',
        retryAfterSeconds: retrySeconds(decision.retryAfterMs),
      });
    }
    let settled = false;
    const reservation: CredentialRoundReservation = {
      kind: 'reserved',
      async settle(outcome, settleOptions) {
        if (settled) throw new Error('round limits: a reservation settled twice');
        settled = true;
        const alerts = await store.settleCredential({
          ...keys,
          outcome,
          ...(outcome === 'success' && settleOptions?.userId !== undefined
            ? { accountKey: settleOptions.userId }
            : {}),
        });
        alerted(keys, credential.clientId, alerts);
      },
    };
    return Object.freeze(reservation);
  }

  async function reserveRegistrationStart(start: RegistrationStartRound): Promise<LimitVerdict> {
    const keys = await keysOf(start);
    const decision = checkedDecision(await store.reserveRegistrationStart(keys));
    alerted(keys, start.clientId, decision.alerts);
    return verdictOf(decision);
  }

  return Object.freeze({ round, reserve, reserveRegistrationStart });
}
