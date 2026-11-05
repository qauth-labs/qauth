import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

const link = groupDocsLink('botChallenge');

/**
 * The bot challenge (`botChallenge`, PRO-19, #643; ADR-017 Decision 7): when
 * a sign-up must pass it, and how hard the built-in proof of work is. The
 * engine asks for it past a soft threshold of the limits whatever these say.
 *
 * Each loosening is "loosening the brute-force policy" (ADR-019 Decision 7,
 * `credential-path`): no longer requiring the challenge at sign-up, or an
 * easier puzzle.
 */
export const BOT_CHALLENGE_POLICY_GROUP = {
  requiredAtSignUp: policyField(z.boolean(), {
    seedEnv: 'BOT_CHALLENGE_REQUIRED_AT_SIGN_UP',
    default: false,
    direction: 'false-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'Whether every sign-up passes the bot challenge before its address is asked for, whatever the client; the hosted pages then need JavaScript to sign up, and a client that cannot serve the challenge cannot register.',
      link,
    },
  }),
  difficulty: policyField(z.number().int().min(1).max(32), {
    seedEnv: 'BOT_CHALLENGE_DIFFICULTY',
    default: 18,
    direction: 'higher-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'How many leading zero bits the built-in proof of work asks for; each one doubles the work of the page that solves it, and 18 takes a browser a second or two.',
      link,
    },
  }),
} as const;
