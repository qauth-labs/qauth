/**
 * THE SEND CAPS' RULES (PRO-14, #637; ADR-017 Decision 5): how many mailed
 * codes an address, an end-user IP and a client may ask for, which tiers
 * answer quietly and which answer 429, and what lets the owner through. The
 * store that counts (the auth server's is a Redis script in
 * `@qauth-labs/fastify-plugin-sign-in-engine`) applies them; this module only
 * says what they are, so every store and every test reads one source.
 *
 * Every tier counts every request that would send if the account existed,
 * unknown addresses included, so no answer says whether an account exists.
 * Mail that carries no code is never counted and never suppressed.
 *
 * | Tier                      | Key                         | Default        | At the cap                      |
 * | ------------------------- | --------------------------- | -------------- | ------------------------------- |
 * | Address and end-user IP   | address HMAC, IP HMAC       | 3/15 min, 10/24 h | the same step; the mail dropped |
 * | Address and FiPA client   | address HMAC, client        | 10/24 h        | 429 with `Retry-After`          |
 * | Address (the ceiling)     | address HMAC                | 30/24 h        | 429; the operator alerted; one notice with a pass |
 * | Address, after a first factor | address HMAC            | 30/24 h        | 429                             |
 * | End-user IP               | IP HMAC                     | 10/h           | 429                             |
 * | FiPA client               | client                      | 1,000/h        | 429                             |
 *
 * Only the tier keyed on an address and an IP is quiet: a third party cannot
 * spend it for the owner, who asks from another IP. A quiet ceiling would let
 * a third party drop the owner's own reset mail, so the ceiling answers 429
 * to every address alike and mails the owner a pass instead.
 *
 * Three things skip tiers:
 *
 * - an end-user IP known to a verified account (a successful sign-in from it
 *   in the last 30 days, ADR-017 Decision 7) skips every per-address tier;
 * - a pass, mailed with the send-ceiling or password-disabled notice and
 *   bound to its address, takes one reset or registration start past every
 *   per-address tier, and is spent by that start only;
 * - a code mailed after a correct first factor in the same transaction skips
 *   the ceiling and counts toward its own per-address cap instead.
 *
 * The per-IP and per-client caps apply to all three.
 */

/** At most `limit` sends per `windowMs`, over a sliding window. */
export interface SendWindow {
  readonly limit: number;
  readonly windowMs: number;
}

/** The send caps' rules. Times are in milliseconds. */
export interface SendCapPolicy {
  /** Per address and end-user IP, the short window. ADR-017 Decision 5: 3 per 15 minutes. Quiet. */
  readonly addressIpShort: SendWindow;
  /** Per address and end-user IP, the long window. ADR-017 Decision 5: 10 per 24 hours. Quiet. */
  readonly addressIpLong: SendWindow;
  /** Per address and FiPA client. ADR-017 Decision 5: 10 per 24 hours. 429. */
  readonly addressClient: SendWindow;
  /** Per address: the send ceiling. ADR-017 Decision 5: 30 per 24 hours. 429, never quiet. */
  readonly ceiling: SendWindow;
  /**
   * Per address, the codes mailed after a correct first factor, which skip
   * the ceiling. ADR-017 Decision 5: 30 per 24 hours. 429.
   */
  readonly afterFirstFactor: SendWindow;
  /** Per end-user IP, whatever the address. ADR-017 Decision 5: 10 per hour. 429. */
  readonly endUserIp: SendWindow;
  /** Per FiPA client, whatever the address. ADR-017 Decision 5 names no number. 429. */
  readonly client: SendWindow;
  /**
   * How often, at most, an address gets each notice (the send-ceiling one,
   * the password-disabled one) and the operator one alert about its ceiling.
   * ADR-017 Decision 5: once per 24 hours.
   */
  readonly noticeIntervalMs: number;
  /** How long a mailed pass stays valid. ADR-017 Decision 5: 24 hours. */
  readonly passTtlMs: number;
}

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/**
 * The send caps of ADR-017 Decision 5. The per-client cap is QAuth's own
 * number, which the record leaves open: a thousand an hour, well above what
 * one app's sign-ups and resets need, and far below what would bury a mail
 * transport's reputation. `development` may relax these (ADR-008 §5);
 * `staging` and `production` keep them.
 */
export const SEND_CAP_POLICY: SendCapPolicy = Object.freeze({
  addressIpShort: Object.freeze({ limit: 3, windowMs: 15 * MINUTE_MS }),
  addressIpLong: Object.freeze({ limit: 10, windowMs: DAY_MS }),
  addressClient: Object.freeze({ limit: 10, windowMs: DAY_MS }),
  ceiling: Object.freeze({ limit: 30, windowMs: DAY_MS }),
  afterFirstFactor: Object.freeze({ limit: 30, windowMs: DAY_MS }),
  endUserIp: Object.freeze({ limit: 10, windowMs: HOUR_MS }),
  client: Object.freeze({ limit: 1_000, windowMs: HOUR_MS }),
  noticeIntervalMs: DAY_MS,
  passTtlMs: DAY_MS,
});

/** The tiers that answer 429. */
export const SEND_CAP_REFUSING_TIERS = [
  'end_user_ip',
  'client',
  'ceiling',
  'after_first_factor',
  'address_client',
] as const;

/** A tier that answers 429 with `Retry-After`. */
export type SendCapRefusingTier = (typeof SEND_CAP_REFUSING_TIERS)[number];

/** What a mailed pass starts: a reset of the account, or the registration of its address. */
export type MailPassFlow = 'reset' | 'register';

/**
 * The notices an address gets at most once per `noticeIntervalMs`: the
 * send-ceiling and password-disabled notices, and, keyed on the account's
 * own HMAC, the recovery codes' 100-failures notice (#649) and the notice of
 * a wrong second factor after a correct password (#653).
 */
export type OnceANoticeKind =
  | 'send_ceiling'
  | 'password_disabled'
  | 'recovery_codes_failed'
  | 'second_factor_failed';

/** One send the caps are asked about: a code about to be mailed, or a start that would mail one. */
export interface SendCapRequest {
  readonly realmId: string;
  /** The address's keyed HMAC (the identifier's, ADR-017 Decision 7), whether or not an account holds it. */
  readonly addressHmac: string;
  /** The end-user IP's keyed HMAC; absent when the request carries no client address. */
  readonly endUserIpHmac?: string;
  /** A key of the authenticated FiPA client; absent on the hosted pages, which have no per-client tier. */
  readonly clientKey?: string;
  /** The end-user IP is a known IP of a verified account: every per-address tier is skipped. */
  readonly knownIp: boolean;
  /** The code follows a correct first factor in the same transaction: the ceiling is skipped. */
  readonly afterFirstFactor: boolean;
  /**
   * The hash of the pass the start carries. Bound to the address, it skips
   * every per-address tier and is spent, but only when the send goes
   * through: a start a per-IP or per-client cap refuses leaves it unspent.
   */
  readonly passHash?: string;
}

/** What the caps decided about one send. */
export type SendCapDecision =
  /** Send. `passSpent`: the request's pass took it past the per-address tiers and is now spent. */
  | { readonly kind: 'send'; readonly passSpent: boolean }
  /** The address-and-IP tier is full: answer the same step, drop the mail. */
  | { readonly kind: 'quiet' }
  /**
   * A tier that answers 429 is full: every address gets the same answer.
   * `alert`: this is the address's first ceiling refusal in the notice
   * interval, so the operator is alerted once per address HMAC.
   */
  | {
      readonly kind: 'refused';
      readonly tier: SendCapRefusingTier;
      readonly retryAfterMs: number;
      readonly alert: boolean;
    };

/** A pass's binding, as the store keeps it: never the pass itself. */
export interface MailPassBinding {
  /** The pass's SHA-256, base64url: what an interaction holds in its place. */
  readonly passHash: string;
  readonly addressHmac: string;
  readonly flow: MailPassFlow;
}

/**
 * Where the send caps count, and where the passes and the once-a-day notice
 * marks live. Every operation is atomic; any error rejects, and the caller
 * fails closed: the round is refused before anything is mailed.
 */
export interface SendCapStore {
  /** Decide one send and, unless it is refused or quiet, count it on every tier that applies. */
  reserve(request: SendCapRequest): Promise<SendCapDecision>;
  /**
   * Mint a pass for the address: 32 CSPRNG bytes, base64url, valid
   * `passTtlMs`. The store keeps only its hash; the pass goes into the mail.
   */
  mintPass(input: {
    readonly realmId: string;
    readonly addressHmac: string;
    readonly flow: MailPassFlow;
  }): Promise<string>;
  /**
   * The binding of a live pass, without spending it: opening a pass link
   * never spends the pass. `undefined` for a pass that is unknown, spent or
   * expired.
   */
  peekPass(realmId: string, pass: string): Promise<MailPassBinding | undefined>;
  /**
   * Claim the address's notice of `kind` for the next `noticeIntervalMs`:
   * `true` for the first claim in the interval, `false` after it.
   */
  claimNotice(input: {
    readonly realmId: string;
    readonly addressHmac: string;
    readonly kind: OnceANoticeKind;
  }): Promise<boolean>;
  /**
   * Give back a claim whose notice was not sent (the pass not minted, the
   * transport refused the mail), so the next refusal or disable can send it
   * rather than the owner waiting out the interval.
   */
  releaseNotice(input: {
    readonly realmId: string;
    readonly addressHmac: string;
    readonly kind: OnceANoticeKind;
  }): Promise<void>;
}

function checkWindow(window: SendWindow, name: string): void {
  if (!Number.isSafeInteger(window.limit) || window.limit < 1) {
    throw new Error(`send cap policy: ${name}.limit below 1`);
  }
  if (!Number.isSafeInteger(window.windowMs) || window.windowMs < 1_000) {
    throw new Error(`send cap policy: ${name}.windowMs below a second`);
  }
}

/** Check a policy's numbers, so a store never runs caps that cannot hold. */
export function checkSendCapPolicy(policy: SendCapPolicy): SendCapPolicy {
  checkWindow(policy.addressIpShort, 'addressIpShort');
  checkWindow(policy.addressIpLong, 'addressIpLong');
  checkWindow(policy.addressClient, 'addressClient');
  checkWindow(policy.ceiling, 'ceiling');
  checkWindow(policy.afterFirstFactor, 'afterFirstFactor');
  checkWindow(policy.endUserIp, 'endUserIp');
  checkWindow(policy.client, 'client');
  // One log serves both windows of the address-and-IP tier: it keeps the
  // long window, and the short one counts within it.
  if (policy.addressIpShort.windowMs > policy.addressIpLong.windowMs) {
    throw new Error('send cap policy: addressIpShort outlasts addressIpLong');
  }
  if (policy.addressIpShort.limit > policy.addressIpLong.limit) {
    throw new Error('send cap policy: addressIpShort admits more than addressIpLong');
  }
  // The quiet tier must fill before the loud one, or an owner who asks from
  // one IP would meet the ceiling, never the quiet cap.
  if (policy.addressIpLong.limit > policy.ceiling.limit) {
    throw new Error('send cap policy: addressIpLong admits more than the ceiling');
  }
  if (!Number.isSafeInteger(policy.noticeIntervalMs) || policy.noticeIntervalMs < 60_000) {
    throw new Error('send cap policy: noticeIntervalMs below a minute');
  }
  if (!Number.isSafeInteger(policy.passTtlMs) || policy.passTtlMs < 60_000) {
    throw new Error('send cap policy: passTtlMs below a minute');
  }
  if (policy.passTtlMs > DAY_MS) {
    // ADR-017 Decision 5: valid 24 hours; NIST SP 800-63B-4 §4.2.1.2.
    throw new Error('send cap policy: passTtlMs above 24 hours');
  }
  return policy;
}

/** The `Retry-After` value of a refusal, in whole seconds, at least 1 (RFC 9110 §10.2.3). */
export function retryAfterSeconds(retryAfterMs: number): number {
  return Math.max(1, Math.ceil(retryAfterMs / 1_000));
}
