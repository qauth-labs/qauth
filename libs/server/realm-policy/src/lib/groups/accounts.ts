import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

/**
 * The verified-account requirement (`accounts`, #514; read from the realm row
 * by #528).
 *
 * The default is `true`, the default of `REQUIRE_VERIFIED_ACCOUNT` since the
 * maintainer's decision of 2026-10-19: a realm seeded without the key must
 * not come out looser than the server is today. Switching it off lets an
 * unverified account sign in, which loosens what can authenticate an account
 * (ADR-019 Decision 7, `credential-path`).
 *
 * `allowSignUp` is off by default (ADR-017: only sign-up is off by default),
 * so `false` is the stricter value: turning it on lets anyone create an
 * account, a loosening of the same `credential-path` effect, the closed
 * list's nearest to "who can create an account" (it changes which
 * credentials or addresses can authenticate an account).
 *
 * `newFactorWindowDays` (#1064; ADR-017 Decision 8, amended 2026-11-12) is
 * how long a passkey or an authenticator app stays *new* after a sign-in
 * that proved only the account's password bound it: 7 days by default, 1 to
 * 30. While it is new, the password alone, after a fresh sign-in, may remove
 * it, and it is not the account's strongest factor for a reset or for the
 * fresh authentication a change needs; it signs in as usual. A shorter
 * window is the stricter value: the factor counts in full sooner. A longer
 * one keeps the account at its password's strength for longer, a loosening
 * of the same `credential-path` effect (it changes which credentials can
 * authenticate a change of the account's factors).
 */
export const ACCOUNTS_POLICY_GROUP = {
  requireVerifiedAccount: policyField(z.boolean(), {
    seedEnv: 'REQUIRE_VERIFIED_ACCOUNT',
    default: true,
    direction: 'true-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        "Whether the legacy login routes (`POST /auth/login`, `POST /ui/login`) refuse an unverified account's right password with the answer a wrong password gets; the Interaction API verifies such an account inline with an emailed code, whatever this says.",
      link: groupDocsLink('accounts'),
    },
  }),
  allowSignUp: policyField(z.boolean(), {
    seedEnv: 'ALLOW_SIGN_UP',
    default: false,
    direction: 'false-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'Whether a person may create a new account through the hosted sign-in, from an unknown upstream identity (#639) or with `prompt=create` (#640, for a client whose `hosted_flows` name `register`), or through the legacy `POST /auth/register` (since 0.2.1; it answers 403 while this is off).',
      link: groupDocsLink('accounts'),
    },
  }),
  newFactorWindowDays: policyField(z.number().int().min(1).max(30), {
    seedEnv: 'NEW_FACTOR_WINDOW_DAYS',
    default: 7,
    // Neither way is stricter (#1064): a longer window leaves a new factor
    // removable with the password for longer, the owner's own included, and
    // a shorter one leaves the owner less time to undo an intruder's.
    direction: 'opaque',
    securityWhen: 'any-change',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        "How many days, 1 to 30, a passkey or authenticator app bound after a sign-in that proved only the password stays new: the password alone may remove it, and it does not count as the account's strongest factor for a reset or a change.",
      link: groupDocsLink('accounts'),
    },
  }),
} as const;
