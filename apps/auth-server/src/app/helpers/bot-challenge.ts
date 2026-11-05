import {
  type BotChallengeProvider,
  createProofOfWorkProvider,
  createSiteVerifyChallengeProvider,
  PROOF_OF_WORK_PROVIDER,
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
 * the one verify URL the operator configured, through the egress client, for
 * a sign-in and a registration; a password reset still gets the proof of
 * work, since a hosted provider's script may run on the sign-in and sign-up
 * pages only (ADR-019 Decision 5).
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
  const proofOfWork = createProofOfWorkProvider({
    difficulty: async ({ realmId }) =>
      fastify.policyStore.ofRealm(await realmOf(realmId)).policies.botChallenge.difficulty,
  });
  if (env.BOT_CHALLENGE_PROVIDER !== 'hosted') return proofOfWork;
  if (!fastify.hasDecorator('egress') || fastify.egress === undefined) {
    throw new TypeError(
      'the hosted bot challenge needs the egress client, which is not registered'
    );
  }
  const hosted = createSiteVerifyChallengeProvider({
    egress: fastify.egress,
    name: env.BOT_CHALLENGE_HOSTED_NAME ?? '',
    siteKey: env.BOT_CHALLENGE_HOSTED_SITE_KEY ?? '',
    secret: env.BOT_CHALLENGE_HOSTED_SECRET ?? '',
    verifyUrl: env.BOT_CHALLENGE_HOSTED_VERIFY_URL ?? '',
    // Named to the egress client, whose allowlist entries name realms.
    realmName: async ({ realmId }) => (await realmOf(realmId)).name,
  });
  return Object.freeze({
    params: (round: Parameters<BotChallengeProvider['params']>[0]) =>
      round.flow === 'reset' ? proofOfWork.params(round) : hosted.params(round),
    // The params come from the transaction, which the server holds: they say
    // which provider issued the challenge.
    verify: (input: Parameters<BotChallengeProvider['verify']>[0]) =>
      input.params.provider === PROOF_OF_WORK_PROVIDER
        ? proofOfWork.verify(input)
        : hosted.verify(input),
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
