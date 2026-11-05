import { type BotChallengeProvider, checkedChallengeParams } from '../bot-challenge';
import { fromStore, SignInStoreUnavailableError } from '../store';
import type { StepHandler } from './handler';

/**
 * The `captcha` step (PRO-19, #643; ADR-017 Decisions 3, 4 and 7): the bot
 * challenge, rule 5 of the engine's order. It proves nothing about the
 * account, so it is a `challenge`, offered alone; the pending step resumes
 * after it. Its params come from `provider` once per challenge and are kept
 * in the transaction until answered (the engine's job), and its answer,
 * `captcha_token`, is checked against them by the same provider.
 *
 * A wrong token is refused with `captcha_failed`. A provider that cannot
 * answer refuses the round (`unavailable`): the challenge is never passed for
 * it.
 */
export function createCaptchaStep(provider: BotChallengeProvider): StepHandler<'captcha'> {
  const handler: StepHandler<'captcha'> = {
    step: 'captcha',
    role: 'challenge',
    params: async ({ realmId, clientId, transaction }) =>
      checkedChallengeParams(
        await fromStore('botChallenge', () =>
          provider.params({
            realmId,
            clientId,
            ...(transaction.flow === undefined ? {} : { flow: transaction.flow }),
          })
        )
      ),
    personal: () => ({}),
    async verify({ realmId }, read) {
      const solved: unknown = await fromStore('botChallenge', () =>
        provider.verify({ realmId, params: read.params, token: read.answer.captcha_token })
      );
      if (typeof solved !== 'boolean') {
        throw new SignInStoreUnavailableError('botChallenge', new Error('not a verdict'));
      }
      return solved === true
        ? { kind: 'passed' }
        : { kind: 'refused', error: 'captcha_failed', audit: { reason: 'captcha_failed' } };
    },
  };
  return Object.freeze(handler);
}
