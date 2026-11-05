import {
  BOT_CHALLENGE_SITE_KEY_PATTERN,
  botChallengeProviderNameProblem,
  botChallengeVerifyUrlProblem,
} from '@qauth-labs/shared-validation';
import { z } from 'zod';

/** Blank is read as unset, since Docker Compose passes an absent variable as `''`. */
function blankAsUnset(value: unknown): unknown {
  return typeof value === 'string' && value.trim() === '' ? undefined : value;
}

/** The providers of the bot challenge an operator may choose (#643). */
export const BOT_CHALLENGE_PROVIDERS = ['pow', 'hosted'] as const;
export type BotChallengeProviderKind = (typeof BOT_CHALLENGE_PROVIDERS)[number];

/**
 * The bot challenge (PRO-19, #643; ADR-017 Decision 7, ADR-019 Decision 5).
 *
 * A plain `z.object`, since the auth server spreads its `.shape`: the check
 * that a hosted provider has every setting it needs is the auth server's
 * (`apps/auth-server/src/config/env-schema.ts`).
 */
export const botChallengeEnvSchema = z.object({
  /**
   * Who answers the challenge: `pow`, the built-in proof of work (the
   * default), or `hosted`, the provider the `BOT_CHALLENGE_HOSTED_*` keys
   * name.
   */
  BOT_CHALLENGE_PROVIDER: z.preprocess(
    blankAsUnset,
    z.enum(BOT_CHALLENGE_PROVIDERS).default('pow')
  ),

  /** The name the hosted provider goes by in the `captcha` step, such as `turnstile`. */
  BOT_CHALLENGE_HOSTED_NAME: z.preprocess(
    blankAsUnset,
    z
      .string()
      .superRefine((value, ctx) => {
        const problem = botChallengeProviderNameProblem(value);
        if (problem !== undefined) {
          ctx.addIssue({ code: 'custom', message: `BOT_CHALLENGE_HOSTED_NAME ${problem}` });
        }
      })
      .optional()
  ),

  /** The hosted provider's public site key, sent to the page in the `captcha` step. */
  BOT_CHALLENGE_HOSTED_SITE_KEY: z.preprocess(
    blankAsUnset,
    z
      .string()
      .regex(BOT_CHALLENGE_SITE_KEY_PATTERN, {
        message:
          'BOT_CHALLENGE_HOSTED_SITE_KEY must be 1 to 256 letters, digits, dots, dashes or underscores',
      })
      .optional()
  ),

  /** The operator's secret for the hosted provider: sent to its verify URL alone. */
  BOT_CHALLENGE_HOSTED_SECRET: z.preprocess(blankAsUnset, z.string().max(4096).optional()),

  /** Where the hosted provider checks a token, such as `https://challenges.cloudflare.com/turnstile/v0/siteverify`. */
  BOT_CHALLENGE_HOSTED_VERIFY_URL: z.preprocess(
    blankAsUnset,
    z
      .string()
      .superRefine((value, ctx) => {
        const problem = botChallengeVerifyUrlProblem(value);
        if (problem !== undefined) {
          ctx.addIssue({ code: 'custom', message: `BOT_CHALLENGE_HOSTED_VERIFY_URL ${problem}` });
        }
      })
      .transform((value) => new URL(value).href)
      .optional()
  ),

  /**
   * Seeds `botChallenge.requiredAtSignUp` of a new realm: whether every
   * sign-up in the realm passes the challenge first.
   */
  BOT_CHALLENGE_REQUIRED_AT_SIGN_UP: z.preprocess(
    blankAsUnset,
    z
      .enum(['true', 'false', '1', '0'])
      .default('false')
      .transform((value) => value === 'true' || value === '1')
  ),

  /**
   * Seeds `botChallenge.difficulty` of a new realm: the leading zero bits the
   * built-in proof of work asks for, 1 to 32.
   */
  BOT_CHALLENGE_DIFFICULTY: z.preprocess(
    blankAsUnset,
    z.coerce.number().int().min(1).max(32).default(18)
  ),
});

export type BotChallengeEnv = z.infer<typeof botChallengeEnvSchema>;
