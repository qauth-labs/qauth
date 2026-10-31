import {
  absoluteUriWithoutFragment,
  closedEnum,
  closedObject,
  dateTime,
  declared,
  displayText,
  EMPTY_OBJECT,
  object,
} from '../schema-kit';
import { defineStep } from '../step-definition';
import { accountIdentifier, identifierPersonal } from './shared';
import { EXAMPLE_REDIRECT } from './sign-in';

/**
 * The steps that decide what a signed-in person allows: consent, the device
 * authorization grant and logout. Only the Interaction API serves them. Each
 * names the client through the interaction's `client` member, built by one
 * function from the auth server's own records (#593), never from what the
 * client declared about itself.
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
  summary: 'Asks the person to allow or deny what the client asks for.',
  description:
    'The OAuth consent decision (#629). The interaction’s `client` names the client, verified domain first (ADR-019 Decision 6). The grant is exactly the scope set shown here, which the interaction holds: the answer cannot add a scope. A dangerous scope and `prompt=consent` always reach this step; a first-party client may skip it only through the administrative waiver (ADR-017 Decision 9). Works without JavaScript.',
  params: object(
    {
      scopes: {
        type: 'array',
        description: 'The scopes asked for, in the order the screen lists them.',
        minItems: 1,
        maxItems: 64,
        items: object(
          {
            scope: {
              type: 'string',
              minLength: 1,
              maxLength: 128,
              pattern: SCOPE_TOKEN_PATTERN,
              description:
                'The scope value (RFC 6749 §3.3), from its alphabet without `<` and `>`. A requested scope outside it never reaches this step: the request is refused first.',
            },
            text: displayText(
              'realm',
              280,
              'The consent text the realm’s scope catalog holds for this scope, in the interaction’s locale. Absent when the catalog has none: the screen shows the scope value.'
            ),
            sensitive: {
              type: 'boolean',
              description: 'Whether the realm flagged the scope as sensitive.',
            },
            dangerous: {
              type: 'boolean',
              description:
                'Whether the scope is dangerous (`write:*`, `agent:admin`, `agent:exec`): it always needs consent and a fresh sign-in.',
            },
          },
          ['scope', 'sensitive', 'dangerous']
        ),
      },
      resources: {
        type: 'array',
        description:
          'Where the tokens may be used: the resource indicators (RFC 8707) of the request.',
        minItems: 0,
        maxItems: 16,
        items: declared(
          absoluteUriWithoutFragment(
            2048,
            'One resource indicator, as the request named it. The request chose it, so the screen marks it as asked for by the app.'
          )
        ),
      },
      remember_default: {
        type: 'boolean',
        description: 'Whether "remember this decision" starts checked.',
      },
    },
    ['scopes', 'resources', 'remember_default']
  ),
  personal: identifierPersonal,
  answer: closedObject(
    {
      decision: closedEnum(['allow', 'deny'], 'The decision.'),
      remember: {
        type: 'boolean',
        default: false,
        description:
          'Whether to remember an `allow` for later requests that fit it. In a form post the checkbox sends `true`, and its absence means `false`.',
      },
    },
    ['decision']
  ),
  errors: [],
  amr: [],
  example: {
    params: {
      scopes: [
        { scope: 'openid', sensitive: false, dangerous: false },
        {
          scope: 'notes:read',
          text: 'Read your notes',
          sensitive: false,
          dangerous: false,
        },
        {
          scope: 'write:notes',
          text: 'Change and delete your notes',
          sensitive: true,
          dangerous: true,
        },
      ],
      resources: ['https://notes.example.com/'],
      remember_default: true,
    },
    answer: { decision: 'allow', remember: true },
    personal: { identifier: 'alice@example.com' },
    next: { redirect: EXAMPLE_REDIRECT },
  },
});

export const deviceCode = defineStep({
  name: 'device_code',
  transports: ['interaction'],
  summary: 'Asks for the code the device shows.',
  description:
    'Code entry for the OAuth 2.0 device authorization grant (RFC 8628 §3.3). Unknown, expired and used codes give the same `invalid_user_code`. Entry is rate-limited per code, per session and per address. A person who arrives through `verification_uri_complete` skips this step and still confirms on `device_confirm` (ADR-020 §3). Works without JavaScript.',
  params: object(
    {
      length: {
        type: 'integer',
        enum: [8],
        description: 'How many characters the code has, without the dash.',
      },
    },
    ['length']
  ),
  personal: EMPTY_OBJECT,
  answer: closedObject(
    {
      user_code: {
        type: 'string',
        minLength: 1,
        maxLength: 32,
        pattern: '^[A-Za-z -]+$',
        description:
          'The code as typed. The server ignores case, spaces and dashes (RFC 8628 §6.1).',
      },
    },
    ['user_code']
  ),
  errors: ['invalid_user_code'],
  amr: [],
  example: {
    params: { length: 8 },
    answer: { user_code: 'wdjb-mjht' },
    next: { step: 'device_confirm' },
  },
});

export const deviceConfirm = defineStep({
  name: 'device_confirm',
  transports: ['interaction'],
  summary: 'Asks the person to confirm the device in front of them.',
  description:
    'The explicit confirmation of a device authorization, always asked, also after `verification_uri_complete` (ADR-020 §3). The screen warns that nobody else should have given the person the code, and shows where the request came from: the requesting device’s approximate location, network and user agent, which are personal data, and its start time. The consent step always follows, even for a client that may skip consent elsewhere. The device details come with the personal data, so this step needs JavaScript: a page shows them before it offers `confirm`.',
  params: object(
    {
      user_code: {
        type: 'string',
        minLength: 9,
        maxLength: 9,
        pattern: USER_CODE_PATTERN,
        description: 'The code being confirmed, so the person can compare it with the device.',
      },
      requested_at: dateTime('When the device started the request.'),
    },
    ['user_code', 'requested_at']
  ),
  personal: object(
    {
      location: object(
        {
          country: {
            type: 'string',
            minLength: 2,
            maxLength: 2,
            pattern: '^[A-Z]{2}$',
            description: 'The ISO 3166-1 alpha-2 country of the requesting address.',
          },
          region: displayText('server', 64, 'The region of the requesting address.'),
        },
        [],
        'Where the requesting address is, approximately. Absent when the lookup knows nothing.'
      ),
      network: object(
        {
          asn: {
            type: 'integer',
            minimum: 1,
            maximum: 4294967295,
            description: 'The autonomous system number of the requesting address.',
          },
          name: displayText(
            'declared',
            128,
            'The name of that network, as its registrant declared it in the address registry. The registrant chose it, so the screen marks it as declared.'
          ),
        },
        [],
        'The network the request came from.'
      ),
      user_agent: displayText(
        'declared',
        256,
        'The user agent the device declared, cut and stripped. The device chose it, so the screen marks it as declared.'
      ),
    },
    []
  ),
  answer: closedObject({ decision: closedEnum(['confirm', 'deny'], 'The decision.') }, [
    'decision',
  ]),
  errors: [],
  amr: [],
  example: {
    params: { user_code: 'WDJB-MJHT', requested_at: '2026-10-26T09:29:12Z' },
    answer: { decision: 'confirm' },
    personal: {
      location: { country: 'DE', region: 'Bavaria' },
      network: { asn: 64500, name: 'Example Broadband' },
      user_agent: 'ExampleTV/4.2 (Linux; Android 14)',
    },
    next: { step: 'consent' },
  },
});

export const logoutConfirm = defineStep({
  name: 'logout_confirm',
  transports: ['interaction'],
  summary: 'Asks the person to confirm signing out.',
  description:
    'The confirmation of an RP-initiated logout (ADR-019 Decision 4). The interaction’s `client` names the app that asked, when the request identified one. A browser may hold several accounts’ sessions, so the person signs out of this account or of every account on the browser (ADR-019 Decision 3). Works without JavaScript, without the account list.',
  params: EMPTY_OBJECT,
  personal: object(
    {
      accounts: {
        type: 'array',
        description: 'The accounts signed in on this browser, the one being signed out first.',
        minItems: 1,
        maxItems: 16,
        items: object(
          {
            identifier: accountIdentifier,
            current: {
              type: 'boolean',
              description: 'Whether this is the account the logout request is for.',
            },
          },
          ['identifier', 'current']
        ),
      },
    },
    ['accounts']
  ),
  answer: closedObject(
    {
      decision: closedEnum(
        ['logout', 'logout_all', 'stay'],
        'Sign out of this account, of every account on the browser, or stay signed in.'
      ),
    },
    ['decision']
  ),
  errors: [],
  amr: [],
  example: {
    params: {},
    answer: { decision: 'logout' },
    personal: {
      accounts: [
        { identifier: 'alice@example.com', current: true },
        { identifier: 'alice@work.example', current: false },
      ],
    },
    next: { redirect: 'https://app.example.com/signed-out?state=b8f2c1' },
  },
});
