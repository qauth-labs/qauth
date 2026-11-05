import {
  type BotChallengeProvider,
  createProofOfWorkProvider,
  createSiteVerifyChallengeProvider,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import type { RealmRow } from './request-realm';

/**
 * The bot challenge of the browser transports (PRO-19, #643; ADR-017
 * Decision 7): the provider behind the engine's `captcha` step.
 *
 * `BOT_CHALLENGE_PROVIDER` picks it for the deployment. The default, `pow`,
 * is the built-in proof of work: the page solves it from the realm origin,
 * so the strict content security policy needs no exception, and its
 * difficulty is the realm's `botChallenge.difficulty` policy, read from the
 * realm row on every challenge. `hosted` checks a hosted provider's token at
 * the one verify URL the operator configured, through the egress client.
 */

/**
 * The deployment's bot challenge provider. `realmOf` reads the realm row the
 * proof of work's difficulty comes from.
 *
 * @throws TypeError when a hosted provider's settings are out of shape, or
 *   the egress client it checks tokens through is not registered, so the
 *   boot fails rather than wave the challenge through
 */
export function createServerBotChallenge(
  fastify: Pick<FastifyInstance, 'policyStore' | 'hasDecorator'> &
    Partial<Pick<FastifyInstance, 'egress'>>,
  realmOf: (realmId: string) => Promise<RealmRow>
): BotChallengeProvider {
  if (env.BOT_CHALLENGE_PROVIDER === 'hosted') {
    if (!fastify.hasDecorator('egress') || fastify.egress === undefined) {
      throw new TypeError(
        'the hosted bot challenge needs the egress client, which is not registered'
      );
    }
    return createSiteVerifyChallengeProvider({
      egress: fastify.egress,
      name: env.BOT_CHALLENGE_HOSTED_NAME ?? '',
      siteKey: env.BOT_CHALLENGE_HOSTED_SITE_KEY ?? '',
      secret: env.BOT_CHALLENGE_HOSTED_SECRET ?? '',
      verifyUrl: env.BOT_CHALLENGE_HOSTED_VERIFY_URL ?? '',
    });
  }
  return createProofOfWorkProvider({
    difficulty: async ({ realmId }) =>
      fastify.policyStore.ofRealm(await realmOf(realmId)).policies.botChallenge.difficulty,
  });
}

/** What the registration challenge reads of a client: its operator-set flag. */
export interface ChallengedClient {
  readonly registrationChallenge?: boolean | null;
}

/**
 * Whether a registration through `client` passes the bot challenge first
 * (#643): when the realm's `botChallenge.requiredAtSignUp` says so, or the
 * operator set the client's `registration_challenge`. Either one is enough;
 * neither can lift the other.
 */
export function registrationChallengeRequired(
  policy: { readonly requiredAtSignUp: boolean },
  client: ChallengedClient | null | undefined
): boolean {
  return policy.requiredAtSignUp || client?.registrationChallenge === true;
}
