import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

/**
 * Passkeys at sign-in (`passkeys`, #1083; ADR-017 Decisions 4 and 8, ADR-020
 * §3): whether the hosted sign-in offers a passkey of its own accord.
 *
 * `offerAfterSignIn` is on by default, the behaviour of #651: after a
 * password sign-in of a verified account whose only factor is that password,
 * the engine offers `webauthn_create`, optional, once per transaction. Off,
 * it never makes that offer. A passkey the person asks for (the account
 * page, #844) is not an offer, and neither is one a realm requires: both run
 * whatever this says.
 *
 * `true` is the stricter value: the offer moves an account toward a
 * phishing-resistant factor. But turning it off changes neither which
 * credentials can authenticate an account nor what a token says (ADR-019
 * Decision 7's closed list of effects): the person can still add a passkey
 * from the account page. So no change of it is a security operation.
 */
export const PASSKEYS_POLICY_GROUP = {
  offerAfterSignIn: policyField(z.boolean(), {
    seedEnv: 'PASSKEY_OFFER_AFTER_SIGN_IN',
    default: true,
    direction: 'true-is-stricter',
    securityWhen: 'never',
    effects: [],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'Whether the hosted sign-in offers to add a passkey after a password sign-in, to a verified account whose only factor is that password, while passkeys are on (`WEBAUTHN_ENABLED`); a passkey added from the account page is not affected.',
      link: groupDocsLink('passkeys'),
    },
  }),
} as const;
