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
        'Whether an account must be verified before a password sign-in succeeds; an unverified account is refused with the answer a wrong password gets.',
      link: groupDocsLink('accounts'),
    },
  }),
} as const;
