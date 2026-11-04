import {
  type EgressClient,
  type EgressLimits,
  type EgressResponse,
  isEgressError,
} from '@qauth-labs/server-egress';
import { breachRangeUrlProblem } from '@qauth-labs/shared-validation';

import { checkedSha1Hex } from './digest';
import { BreachLookupError } from './errors';

/** The egress purpose of a range lookup: the label of its counts and log lines. */
export const BREACH_RANGE_PURPOSE = 'breached-password-range';

/** How many hex characters of the digest a lookup sends: five, and never more (#635). */
export const BREACH_RANGE_PREFIX_LENGTH = 5;

/**
 * The caps of one range lookup, over the egress client's.
 *
 * - No redirect: the operator named the host, and a redirect would send the
 *   prefix to a host nobody named.
 * - Three seconds in all, two to connect: the lookup runs on the sign-in path
 *   (a presented or new password), and a lookup that fails never blocks the
 *   sign-in, so giving up early costs one unchecked password while waiting
 *   the client's default ten seconds would hold every sign-in behind a slow
 *   host.
 * - 256 KiB of answer: a padded Have I Been Pwned range is 30 to 40 KB, so
 *   this leaves room for a mirror's larger ranges and stops a host that
 *   answers without end.
 */
export const BREACH_RANGE_LIMITS: Readonly<Partial<EgressLimits>> = Object.freeze({
  maxRedirects: 0,
  connectTimeoutMs: 2_000,
  totalTimeoutMs: 3_000,
  maxResponseBytes: 256 * 1024,
});

/** One line of a range answer: the 35 remaining hex characters, a colon, a decimal count. */
const RANGE_LINE = /^([0-9A-Fa-f]{35}):([0-9]+)$/;

/** A count of zero: the padding lines `add-padding` asks for. */
const ZERO_COUNT = /^0+$/;

export interface BreachRangeLookupOptions {
  /** The egress client: the one way the lookup reaches the network (ADR-019 Decision 8). */
  readonly egress: Pick<EgressClient, 'request'>;
  /**
   * `BREACHED_PASSWORD_RANGE_URL`: an absolute `https` URL with no user name,
   * password, query or fragment, whose path ends with `/`. The five-character prefix is appended to
   * its path, as the URL parser writes it (`https://host` is `https://host/`),
   * such as `https://api.pwnedpasswords.com/range/`.
   */
  readonly url: string;
}

/** The k-anonymity range lookup of a deployment (#635). */
export interface BreachRangeLookup {
  /**
   * Whether `sha1Hex` is in the breach corpus behind the configured host. One
   * `GET` of the URL followed by the digest's first five hex characters, upper
   * case, through the egress client; nothing else of the digest leaves the
   * server, and the rest is compared here with the range the host answers.
   *
   * @param options.realm - the realm's name, passed to the egress client so
   *   the deployment allowlist entries naming it apply to an internal mirror
   * @throws BreachLookupError when the lookup could not answer
   * @throws TypeError when `sha1Hex` is not a SHA-1 digest
   */
  lookup(sha1Hex: string, options?: { readonly realm?: string }): Promise<'listed' | 'not_listed'>;
}

/**
 * Whether the remaining 35 characters `suffix` (upper case) are in the range
 * `body`, a Have I Been Pwned range answer: `SUFFIX:COUNT` lines, CRLF or LF,
 * where a count of 0 is padding and does not list the suffix.
 *
 * @throws BreachLookupError (`bad_response`) when `body` is not such a range
 */
export function rangeLists(body: Buffer, suffix: string): boolean {
  // Latin-1 maps each byte to one character, so a byte outside ASCII fails
  // the pattern below instead of being decoded.
  const lines = body.toString('latin1').split('\n');
  if (lines.at(-1) === '') lines.pop();
  if (lines.length === 0) {
    // Every range of a real corpus holds entries, and a padded one more.
    throw new BreachLookupError('bad_response', 'the breach range lookup answered an empty range');
  }
  let listed = false;
  for (const raw of lines) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const match = RANGE_LINE.exec(line);
    if (match === null) {
      throw new BreachLookupError(
        'bad_response',
        'the breach range lookup answered a body that is not a range of SUFFIX:COUNT lines'
      );
    }
    // Every line is checked, so a malformed answer is refused whatever it holds.
    if (!listed && match[1]?.toUpperCase() === suffix && !ZERO_COUNT.test(match[2] ?? '0')) {
      listed = true;
    }
  }
  return listed;
}

/**
 * The k-anonymity range lookup at `url`, through `egress` (#635, ADR-017
 * Decision 8), as Have I Been Pwned's "search by range" defines it: the host
 * is asked for every suffix under the digest's five-character prefix, padded
 * (`add-padding: true`) so the answer's size says nothing about the prefix,
 * and the match is made here.
 *
 * The destination is the operator's (`source: 'operator'`), so an internal
 * mirror on a private address needs an `EGRESS_ALLOWLIST_PATH` entry naming
 * the realms that use it.
 *
 * @throws TypeError when `url` is not an absolute `https` URL without a user
 *   name, password, query or fragment whose path ends with `/`, so a bad
 *   value fails the boot
 */
export function createBreachRangeLookup(options: BreachRangeLookupOptions): BreachRangeLookup {
  const problem =
    typeof options.url === 'string' ? breachRangeUrlProblem(options.url) : 'is not a string';
  if (problem !== undefined) {
    throw new TypeError(`the breach range lookup URL ${problem}`);
  }
  // The parsed form: its path is never empty, so the prefix never joins the host.
  const base = new URL(options.url).href;
  const { egress } = options;

  return Object.freeze({
    async lookup(
      sha1Hex: string,
      lookupOptions: { readonly realm?: string } = {}
    ): Promise<'listed' | 'not_listed'> {
      const digest = checkedSha1Hex(sha1Hex);
      const prefix = digest.slice(0, BREACH_RANGE_PREFIX_LENGTH);
      const suffix = digest.slice(BREACH_RANGE_PREFIX_LENGTH);
      let response: EgressResponse;
      try {
        response = await egress.request({
          method: 'GET',
          url: `${base}${prefix}`,
          headers: { 'add-padding': 'true' },
          purpose: BREACH_RANGE_PURPOSE,
          source: 'operator',
          ...(lookupOptions.realm === undefined ? {} : { realm: lookupOptions.realm }),
          limits: BREACH_RANGE_LIMITS,
        });
      } catch (error) {
        // An EgressError's message names the host only; nothing here names the prefix.
        if (isEgressError(error)) {
          throw new BreachLookupError(
            error.outcome === 'blocked' ? 'lookup_blocked' : 'lookup_failed',
            `the breach range lookup was ${error.outcome === 'blocked' ? 'refused' : 'not completed'} by the egress client (${error.reason})`,
            { cause: error }
          );
        }
        throw new BreachLookupError('lookup_failed', 'the breach range lookup could not be sent', {
          cause: error,
        });
      }
      if (response.status !== 200) {
        throw new BreachLookupError(
          'lookup_failed',
          `the breach range lookup answered status ${response.status}`
        );
      }
      return rangeLists(response.body, suffix) ? 'listed' : 'not_listed';
    },
  });
}
