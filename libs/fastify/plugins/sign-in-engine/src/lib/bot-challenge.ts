import { type EgressClient, type EgressLimits, isEgressError } from '@qauth-labs/server-egress';
import {
  type BotChallengeProvider,
  checkedChallengeParams,
  PROOF_OF_WORK_PROVIDER,
} from '@qauth-labs/server-sign-in-engine';
import type { StepParams } from '@qauth-labs/server-step-grammar';
import {
  botChallengeProviderNameProblem,
  botChallengeVerifyUrlProblem,
} from '@qauth-labs/shared-validation';

/**
 * A HOSTED BOT CHALLENGE (PRO-19, #643; ADR-017 Decision 7): a provider that
 * checks its token server side, such as Cloudflare Turnstile, hCaptcha or
 * reCAPTCHA. Each of them takes the same request — a form `POST` of the
 * operator's `secret` and the visitor's token as `response` — and answers a
 * JSON object whose `success` is `true` or `false`. That is all this adapter
 * reads, so any provider that answers so fits it.
 *
 * The token is checked at one host, the one the operator configured, through
 * the egress client (ADR-019 Decision 8): `https` only, DNS pinned, no
 * redirect followed, and capped in time and size. A provider that cannot be
 * reached, or answers anything else, is an outage: the engine refuses the
 * round, and the challenge is never waved through. Neither the token nor the
 * secret is logged or put in an error.
 */

/** The egress purpose of a token check: the label of its counts and log lines. */
export const BOT_CHALLENGE_PURPOSE = 'bot-challenge';

/**
 * The caps of one token check, over the egress client's: no redirect (the
 * operator named the host, and a redirect would send the secret to a host
 * nobody named); two seconds to connect and five in all, since a visitor
 * waits on it; 16 KiB of answer, many times what a provider sends.
 */
export const BOT_CHALLENGE_LIMITS: Readonly<Partial<EgressLimits>> = Object.freeze({
  maxRedirects: 0,
  connectTimeoutMs: 2_000,
  totalTimeoutMs: 5_000,
  maxResponseBytes: 16 * 1024,
});

/** What {@link createSiteVerifyChallengeProvider} needs. */
export interface SiteVerifyChallengeOptions {
  /** The egress client: the one way the check reaches the network. */
  readonly egress: Pick<EgressClient, 'request'>;
  /**
   * The name the operator gave the provider, sent in the step's params (`a`
   * to `z` first, then `a`–`z`, `0`–`9`, `_` or `-`, at most 32). Never
   * `pow`, which QAuth reserves.
   */
  readonly name: string;
  /** The provider's public site key, sent in the step's params. */
  readonly siteKey: string;
  /** The operator's secret for the provider: sent to the verify URL alone, never logged. */
  readonly secret: string;
  /** Where tokens are checked: an absolute `https` URL with no user name, password, query or fragment. */
  readonly verifyUrl: string;
}

/**
 * The hosted provider at `verifyUrl`. Its params are `provider` `hosted`, the
 * operator's `name` and `site_key`, the same for every challenge; the page
 * runs the provider's script, and the token it returns is checked here.
 *
 * @throws TypeError when an option is out of shape, so a bad value fails the boot
 */
export function createSiteVerifyChallengeProvider(
  options: SiteVerifyChallengeOptions
): BotChallengeProvider {
  const nameProblem =
    typeof options.name === 'string'
      ? botChallengeProviderNameProblem(options.name)
      : 'is not a string';
  if (nameProblem !== undefined || options.name === PROOF_OF_WORK_PROVIDER) {
    throw new TypeError(`the hosted bot challenge provider's name ${nameProblem ?? 'is reserved'}`);
  }
  let params: StepParams<'captcha'>;
  try {
    params = checkedChallengeParams({
      provider: 'hosted',
      name: options.name,
      site_key: options.siteKey,
    });
  } catch {
    throw new TypeError('the hosted bot challenge provider’s name or site key is out of shape');
  }
  if (typeof options.secret !== 'string' || options.secret === '') {
    throw new TypeError('the hosted bot challenge provider needs its secret');
  }
  const problem =
    typeof options.verifyUrl === 'string'
      ? botChallengeVerifyUrlProblem(options.verifyUrl)
      : 'is not a string';
  if (problem !== undefined) {
    throw new TypeError(`the hosted bot challenge verify URL ${problem}`);
  }
  const url = new URL(options.verifyUrl).href;
  const { egress, secret } = options;
  const offered = Object.freeze(params);

  return Object.freeze({
    async params() {
      return offered;
    },
    async verify({
      params: answered,
      token,
    }: {
      readonly params: StepParams<'captcha'>;
      readonly token: string;
    }) {
      // A token answers the params it was offered with: these, or nothing.
      if (
        answered.provider !== 'hosted' ||
        offered.provider !== 'hosted' ||
        answered.name !== offered.name ||
        answered.site_key !== offered.site_key
      ) {
        return false;
      }
      let status: number;
      let body: Buffer;
      try {
        const response = await egress.request({
          method: 'POST',
          url,
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            accept: 'application/json',
          },
          body: new URLSearchParams({ secret, response: token }).toString(),
          purpose: BOT_CHALLENGE_PURPOSE,
          source: 'operator',
          limits: BOT_CHALLENGE_LIMITS,
        });
        status = response.status;
        body = response.body;
      } catch (error) {
        // An EgressError's message names the host only; nothing here names
        // the token. Any other error is dropped: it may quote the request.
        if (isEgressError(error)) {
          throw new Error(
            `the bot challenge provider was ${error.outcome === 'blocked' ? 'refused' : 'not reached'} by the egress client (${error.reason})`,
            { cause: error }
          );
        }
        status = 0;
        body = Buffer.alloc(0);
      }
      if (status === 0) throw new Error('the bot challenge provider could not be asked');
      if (status !== 200) {
        throw new Error(`the bot challenge provider answered status ${status}`);
      }
      let answer: unknown;
      try {
        answer = JSON.parse(body.toString('utf8'));
      } catch {
        throw new Error('the bot challenge provider answered no JSON');
      }
      const success =
        typeof answer === 'object' && answer !== null && !Array.isArray(answer)
          ? (answer as Record<string, unknown>)['success']
          : undefined;
      if (typeof success !== 'boolean') {
        throw new Error('the bot challenge provider answered no success');
      }
      return success;
    },
  });
}
