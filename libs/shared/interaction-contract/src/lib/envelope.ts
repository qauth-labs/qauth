import { INTERACTION_PROBLEM_CODES, STATUS_TITLES } from './problems';
import {
  absoluteUri,
  array,
  base64url,
  closedEnum,
  closedObject,
  dateTime,
  displayText,
  extensibleEnum,
  host,
  httpsUrl,
  type JsonSchema,
  object,
  sameOriginPath,
} from './schema-kit';

/**
 * The Interaction API's own envelope: what wraps the steps. Its members are
 * `camelCase`, like the other API families (`reference/api-conventions`);
 * `trace_id` keeps the name ADR-019 Decision 7 fixed. Each schema here is one
 * component of the OpenAPI document, under the name its key gives it.
 */

/** A 32-byte random value, base64url: the shape of an interaction id and of a CSRF value. */
const RANDOM_256 = (description: string) => base64url(43, 43, description);

export const interactionIdSchema = RANDOM_256(
  'The opaque interaction id: 32 random bytes the authorization endpoint created (#592). The server stores only its hash. Any other value gets the same `interaction_expired` as an unknown id.'
);

export const csrfSchema = RANDOM_256(
  'The CSRF value of the step read it came with: valid for one answer to that step view, bound to the interaction, and never put in a URL. The ceremony app embeds it; it cannot mint one.'
);

/** BCP 47 language tag, as `ui_locales` (OpenID Connect Core 1.0 §3.1.2.1) carries one. */
const localeTag: JsonSchema = {
  type: 'string',
  minLength: 2,
  maxLength: 35,
  pattern: '^[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*$',
  description: 'A BCP 47 language tag.',
};

const hexColor = (description: string): JsonSchema => ({
  type: 'string',
  minLength: 7,
  maxLength: 7,
  pattern: '^#[0-9a-f]{6}$',
  description,
});

/** The fonts the reference ceremony app ships, served from the realm origin. */
export const BRAND_FONTS = [
  'system',
  'inter',
  'noto_sans',
  'atkinson_hyperlegible',
  'ibm_plex_sans',
  'source_sans_3',
] as const;

export const assetSchema = object(
  {
    url: sameOriginPath('Where the realm origin serves the image.'),
    width: { type: 'integer', minimum: 1, maximum: 2048, description: 'Its width in pixels.' },
    height: { type: 'integer', minimum: 1, maximum: 2048, description: 'Its height in pixels.' },
  },
  ['url', 'width', 'height'],
  'An image an admin uploaded, re-encoded by the server and served from the realm origin. Never a URL a client supplied (ADR-019 Decision 6).'
);

const brandColors = object(
  {
    primary: hexColor('The brand colour of buttons and links.'),
    background: hexColor('The page background.'),
  },
  [],
  'Colours for one colour scheme. A colour left out keeps the ceremony app’s default.'
);

export const brandStringsSchema = object(
  {
    name: displayText(
      'realm',
      64,
      'The service’s display name, in headings and as the logo’s text alternative.'
    ),
    title: displayText('realm', 120, 'The sign-in page heading.'),
    footer: displayText('realm', 280, 'A short notice at the foot of every page.'),
  },
  [],
  'The realm’s own strings for one locale. A string left out keeps the ceremony app’s text.'
);

export const brandSchema = object(
  {
    logo: object(
      {
        light: { $ref: '#/components/schemas/Asset' },
        dark: { $ref: '#/components/schemas/Asset' },
      },
      ['light'],
      'The realm’s logo, for light and, optionally, dark mode. Absent when no admin uploaded one: the page shows the service’s name.'
    ),
    colors: object(
      { light: brandColors, dark: brandColors },
      [],
      'The brand colours. The ceremony app derives text colours from them and keeps WCAG 2.2 AA contrast.'
    ),
    font: {
      ...extensibleEnum(
        BRAND_FONTS,
        '^[a-z][a-z0-9_]{0,31}$',
        32,
        'A font from the safe list the ceremony app serves from the realm origin. `system` loads none and uses the platform’s interface font. A page that does not know a value uses `system`.'
      ),
      default: 'system',
    },
    links: object(
      {
        terms: httpsUrl(2048, 'The terms of service.'),
        privacy: httpsUrl(2048, 'The privacy notice.'),
        help: httpsUrl(2048, 'Where to get help.'),
      },
      [],
      'Links the pages show in their footer, when set.'
    ),
    strings: {
      type: 'object',
      description:
        'The realm’s strings, by locale. The page picks the first of the interaction’s `uiLocales` it has strings for, then its own default.',
      maxProperties: 32,
      propertyNames: localeTag,
      additionalProperties: { $ref: '#/components/schemas/BrandStrings' },
    },
    darkMode: {
      ...closedEnum(
        ['enabled', 'disabled'],
        '`enabled`: the pages follow the system setting and offer a switch. `disabled`: the realm turned dark mode off on its sign-in pages (ADR-020 §5).'
      ),
      default: 'enabled',
    },
  },
  ['font', 'darkMode'],
  'The realm’s brand settings, the theme tier of ADR-019 Decision 5: a logo, colours, a font from a safe list, links, per-locale strings and dark mode. No uploaded templates, CSS or script. Admins set them in the admin console; a realm that set nothing gets the defaults, and every member left out keeps the ceremony app’s own.'
);

export const clientDisplaySchema = object(
  {
    kind: closedEnum(
      ['cimd', 'admin_registered', 'federation', 'unverified'],
      'How the client is known, which decides what is verified (ADR-019 Decision 6): a Client ID Metadata Document client (the host of its client id URL), a client an admin registered (the domain the admin set), a federation client (its entity id and trust marks), or a dynamically registered or developer-portal client (nothing: the screen says the app is unverified).'
    ),
    verifiedDomain: object(
      {
        host: host('The verified host, in ASCII (punycode) form.'),
        registrableDomain: host(
          'The part of `host` the screen highlights: its registrable domain.'
        ),
        sharedHosting: {
          type: 'boolean',
          description:
            'Whether `host` sits under a shared-hosting suffix, from the private section of the Public Suffix List: the screen flags it.',
        },
      },
      ['host', 'registrableDomain', 'sharedHosting'],
      'For `cimd` and `admin_registered`: the verified domain, which the screen shows first.'
    ),
    federation: object(
      {
        entityId: httpsUrl(2048, 'The federation entity id.'),
        trustMarks: array(
          object(
            {
              id: absoluteUri(2048, 'The trust mark type.'),
              issuer: httpsUrl(2048, 'The trust mark issuer’s entity id.'),
            },
            ['id', 'issuer']
          ),
          0,
          16,
          'The trust marks the server validated.'
        ),
      },
      ['entityId', 'trustMarks'],
      'For `federation`: the entity id and its validated trust marks.'
    ),
    redirect: object(
      {
        target: closedEnum(
          ['host', 'this_device', 'app'],
          'Where the authorization code goes: a web host, a loopback address (shown as "this device", with a warning), or a native app’s own URI scheme.'
        ),
        host: host('For `host`: the host that receives the code.'),
        scheme: {
          type: 'string',
          minLength: 1,
          maxLength: 64,
          pattern: '^[a-z][a-z0-9+.-]*$',
          description: 'For `app`: the URI scheme of the app.',
        },
      },
      ['target'],
      'Where the code goes, from the redirect URI the request was bound to. Absent when no code goes anywhere, as on a logout.'
    ),
    declaredName: displayText(
      'declared',
      64,
      'The name the client declared about itself: length-capped and stripped. The screen marks it as declared and never shows it above or instead of the verified data.'
    ),
    logo: { $ref: '#/components/schemas/Asset' },
    newClient: {
      type: 'boolean',
      description: 'Whether the client registered itself recently: the screen shows a badge.',
    },
  },
  ['kind', 'newClient'],
  'Who the client is, as the auth server’s own records say (#593). Client-supplied text is untrusted: no logo comes from a client-supplied URL, and an unverified client shows none.'
);

export const interactionSchema = object(
  {
    step: { $ref: '#/components/schemas/Step' },
    alternatives: {
      type: 'array',
      description:
        'The other steps the engine accepts as the next answer, preferred first: "try another way" and the paths a page links to (a reset, a resend). Never the current step, and never with `error`.',
      minItems: 0,
      maxItems: 15,
      items: { $ref: '#/components/schemas/Step' },
    },
    csrf: { $ref: '#/components/schemas/Csrf' },
    client: { $ref: '#/components/schemas/ClientDisplay' },
    brand: { $ref: '#/components/schemas/Brand' },
    uiLocales: {
      type: 'array',
      description: 'The `ui_locales` of the authorization request, validated, in order.',
      minItems: 0,
      maxItems: 8,
      items: localeTag,
    },
    expiresAt: dateTime('When the interaction expires.'),
  },
  ['step', 'alternatives', 'csrf', 'brand', 'expiresAt'],
  'An interaction as its current step shows it: the step, the alternatives, the CSRF value for one answer, who the client is and the realm’s brand. No personal data.'
);

export const nextStepResultSchema = object(
  {
    result: { const: 'step', description: 'Another step comes next, or the same one again.' },
    interaction: { $ref: '#/components/schemas/Interaction' },
  },
  ['result', 'interaction'],
  'The next step: the same as a step read now returns. A refused answer gets the same step back, with its `error` set and a new CSRF value.'
);

export const redirectResultSchema = object(
  {
    result: { const: 'redirect', description: 'The interaction is finished.' },
    location: absoluteUri(
      8192,
      'Where the browser goes now: the authorization response to the client, the post-logout redirect, or a page of the ceremony app when no client waits, as at the end of a device authorization. Taken from the interaction record and the realm, never from the request.'
    ),
  },
  ['result', 'location'],
  'The final redirect. The page navigates to `location`.'
);

export const answerResultSchema: JsonSchema = {
  description:
    'What a JSON answer leads to. A form post gets the same as a `303 See Other` instead (#616).',
  oneOf: [
    { $ref: '#/components/schemas/NextStepResult' },
    { $ref: '#/components/schemas/RedirectResult' },
  ],
  discriminator: {
    propertyName: 'result',
    mapping: {
      step: '#/components/schemas/NextStepResult',
      redirect: '#/components/schemas/RedirectResult',
    },
  },
};

export const cancelRequestSchema = closedObject(
  { csrf: { $ref: '#/components/schemas/Csrf' } },
  ['csrf'],
  'Cancel the interaction. The client gets `access_denied` with its `state` and `iss`; a logout ends with the person still signed in.'
);

const statuses = [
  ...new Set(Object.values(INTERACTION_PROBLEM_CODES).map((entry) => entry.status)),
];

export const problemSchema = object(
  {
    type: {
      const: 'about:blank',
      description: 'RFC 9457 §4.2.1: no type beyond the HTTP status. Branch on `code`.',
    },
    title: closedEnum(
      statuses.map((status) => STATUS_TITLES[status] ?? 'Error'),
      'The HTTP status phrase. Not for branching, and not for a screen.'
    ),
    status: { type: 'integer', enum: statuses, description: 'The HTTP status, repeated.' },
    code: extensibleEnum(
      Object.keys(INTERACTION_PROBLEM_CODES),
      '^[a-z][a-z0-9_]{0,63}$',
      64,
      'The error, from the published list. A page shows its own text for it, and treats a code it does not know by its HTTP status.'
    ),
    trace_id: {
      type: 'string',
      minLength: 1,
      maxLength: 128,
      pattern: '^[!#-;=?-~]+$',
      description:
        'The id the server logged the request under. A page shows it, so an operator can find the failure (ADR-020 §3).',
    },
  },
  ['type', 'title', 'status', 'code', 'trace_id'],
  'An RFC 9457 problem details document with a stable `code` and a `trace_id`, and no prose: no `detail`, no `instance`, no `errors`.'
);

// ---------------------------------------------------------------------------
// Examples
// ---------------------------------------------------------------------------

export const EXAMPLE_CSRF = 'cGVyLXN0ZXAtY3NyZi12YWx1ZS1vZi0zMi1ieXRlcyE';

export const EXAMPLE_INTERACTION_ID = 'aW50ZXJhY3Rpb24taWQtb2YtMzItcmFuZG9tLWJ5dGU';

export const EXAMPLE_TRACE_ID = '7f3a9c1e-2b4d-4e6f-8a0b-1c2d3e4f5a6b';

export const EXAMPLE_EXPIRES_AT = '2026-10-26T10:00:00Z';

export const EXAMPLE_BRAND = {
  logo: { light: { url: '/ui/assets/logo-3f9a1c2e.svg', width: 160, height: 40 } },
  colors: { light: { primary: '#1f5fbf' }, dark: { primary: '#7aa7ef', background: '#10141a' } },
  font: 'inter',
  links: { privacy: 'https://example.com/privacy', help: 'https://example.com/help' },
  strings: { en: { name: 'Example', title: 'Sign in to Example' } },
  darkMode: 'enabled',
} as const;

/** A client known by its Client ID Metadata Document. */
export const EXAMPLE_CLIENT = {
  kind: 'cimd',
  verifiedDomain: {
    host: 'app.example.com',
    registrableDomain: 'example.com',
    sharedHosting: false,
  },
  redirect: { target: 'host', host: 'app.example.com' },
  declaredName: 'Example Notes',
  newClient: false,
} as const;

/** A dynamically registered client: nothing about it is verified. */
export const EXAMPLE_UNVERIFIED_CLIENT = {
  kind: 'unverified',
  redirect: { target: 'this_device' },
  declaredName: 'Notes Helper',
  newClient: true,
} as const;
