import { z } from 'zod';

import { defineStep } from '../grammar';
import {
  absoluteUriWithoutFragment,
  array,
  closedEnum,
  dateTime,
  declared,
  displayText,
  EMPTY_OBJECT,
  integer,
  integerEnum,
  matching,
  object,
} from '../zod-kit';
import { accountIdentifier, identifierPersonal } from './shared';

/**
 * The steps that decide what a signed-in person allows: consent, the device
 * authorization grant and logout. Only the Interaction API serves them.
 */

/**
 * RFC 6749 §3.3 `scope-token` (`%x21 / %x23-5B / %x5D-7E`) without `<` and
 * `>`, so no scope value reads as markup on the screen.
 */
const SCOPE_TOKEN_PATTERN = '^[!#-;=?-\\[\\]-~]+$';

/** RFC 8628 §6.1: eight characters of the base-20 consonant alphabet, shown as `XXXX-XXXX`. */
const USER_CODE_PATTERN = '^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$';

export const consent = defineStep({
  name: 'consent',
  transports: ['interaction'],
  params: object({
    scopes: array(
      object({
        scope: matching(z.string().min(1).max(128), SCOPE_TOKEN_PATTERN).meta({
          description:
            'The scope value (RFC 6749 §3.3), from its alphabet without `<` and `>`. A requested scope outside it never reaches this step: the request is refused first.',
        }),
        text: displayText(
          'realm',
          280,
          'The consent text the realm’s scope catalog holds for this scope, in the interaction’s locale. Until realms hold a catalog, QAuth’s own text for a scope it defines (`openid`, `profile`, `email`, `offline_access`). Absent when there is none: the screen shows the scope value.'
        ).optional(),
        sensitive: z
          .boolean()
          .meta({ description: 'Whether the realm flagged the scope as sensitive.' }),
        dangerous: z.boolean().meta({
          description:
            'Whether the scope is dangerous (`write:*`, `agent:admin`, `agent:exec`): it always needs consent and a fresh sign-in.',
        }),
      }),
      0,
      64,
      'The scopes asked for, in the order the screen lists them. Empty when the request asks for none, as a client of a CIMD document often does: the screen then names the client and where the code goes, and says that no scope was asked for.'
    ),
    resources: array(
      declared(
        absoluteUriWithoutFragment(
          2048,
          'One resource indicator, as the request named it. The request chose it, so the screen marks it as asked for by the app.'
        )
      ),
      0,
      16,
      'Where the tokens may be used: the resource indicators (RFC 8707) of the request.'
    ),
    audience: array(
      displayText(
        'realm',
        256,
        'One audience value, as the operator configured it, at most 256 characters as the token endpoint reads it; no markup or control character.'
      ),
      1,
      20,
      'Where the tokens may be used when the request named no resource indicator: the audience an operator configured for the client, exactly the tokens’ `aud`. For any client but the system client it leaves out the QAuth API audiences (`urn:qauth:aud:`), which a user’s token then gets only when the request names them. Absent when the request named resources, which are then the audience, and when the tokens are for the client itself.'
    ).optional(),
    agent: object(
      {
        max_lifespan: integer(
          1,
          Number.MAX_SAFE_INTEGER,
          'The realm’s `sso_max_lifespan`, in seconds: the agent may keep working until the person revokes it, or until this long after they signed in, whichever comes first. Absent when the realm sets none: until the person revokes it.'
        ).optional(),
      },
      'Present when the client is an AI agent (ADR-014 §11, ADR-015 Decision 11): the screen says, in QAuth’s own words, that the app is an AI agent and how long it may keep working once allowed. Nothing in it comes from the client.'
    ).optional(),
    remember_default: z
      .boolean()
      .meta({ description: 'Whether "remember this decision" starts checked.' }),
  }),
  personal: identifierPersonal,
  answer: object({
    decision: closedEnum(['allow', 'deny'], 'The decision.'),
    remember: z.boolean().default(false).meta({
      description:
        'Whether to remember an `allow` for later requests that fit it. In a form post the checkbox sends `true`, and its absence means `false`.',
    }),
  }),
  errors: [],
  amr: [],
});

export const deviceCode = defineStep({
  name: 'device_code',
  transports: ['interaction'],
  params: object({
    length: integerEnum([8], 'How many characters the code has, without the dash.'),
  }),
  personal: EMPTY_OBJECT,
  answer: object({
    user_code: matching(z.string().min(1).max(32), '^[A-Za-z -]+$').meta({
      description: 'The code as typed. The server ignores case, spaces and dashes (RFC 8628 §6.1).',
    }),
  }),
  errors: ['invalid_user_code'],
  amr: [],
});

export const deviceConfirm = defineStep({
  name: 'device_confirm',
  transports: ['interaction'],
  params: object({
    user_code: matching(z.string().min(9).max(9), USER_CODE_PATTERN).meta({
      description: 'The code being confirmed, so the person can compare it with the device.',
    }),
    requested_at: dateTime('When the device started the request.'),
  }),
  personal: object({
    location: object(
      {
        country: matching(z.string().min(2).max(2), '^[A-Z]{2}$')
          .meta({
            description: 'The ISO 3166-1 alpha-2 country of the requesting address.',
          })
          .optional(),
        region: displayText('server', 64, 'The region of the requesting address.').optional(),
      },
      'Where the requesting address is, approximately. Absent when the lookup knows nothing.'
    ).optional(),
    network: object(
      {
        asn: integer(
          1,
          4294967295,
          'The autonomous system number of the requesting address.'
        ).optional(),
        name: displayText(
          'declared',
          128,
          'The name of that network, as its registrant declared it in the address registry. The registrant chose it, so the screen marks it as declared.'
        ).optional(),
      },
      'The network the request came from.'
    ).optional(),
    user_agent: displayText(
      'declared',
      256,
      'The user agent the device declared, cut and stripped. The device chose it, so the screen marks it as declared.'
    ).optional(),
  }),
  answer: object({ decision: closedEnum(['confirm', 'deny'], 'The decision.') }),
  errors: [],
  amr: [],
});

export const logoutConfirm = defineStep({
  name: 'logout_confirm',
  transports: ['interaction'],
  params: EMPTY_OBJECT,
  personal: object({
    accounts: array(
      object({
        identifier: accountIdentifier,
        current: z
          .boolean()
          .meta({ description: 'Whether this is the account the logout request is for.' }),
      }),
      1,
      16,
      'The accounts signed in on this browser, the one being signed out first.'
    ),
  }),
  answer: object({
    decision: closedEnum(
      ['logout', 'logout_all', 'stay'],
      'Sign out of this account, of every account on the browser, or stay signed in.'
    ),
  }),
  errors: [],
  amr: [],
});
