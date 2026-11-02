import {
  absoluteUri,
  array,
  closedEnum,
  displayText,
  host,
  httpsUrl,
  NEVER,
  object,
  sameOriginPath,
  whenEquals,
} from './schema-kit';

/**
 * Who a connected app is, as the auth server's own records say (#593), and
 * its logo: the Interaction API's `ClientDisplay` and `Asset`, which a
 * connected app of the account API shows the same way (ADR-019 Decision 6).
 *
 * A copy of `libs/shared/interaction-contract/src/lib/envelope.ts`'s two
 * schemas and its example client: shared libraries are leaves of the module
 * graph, so the account contract cannot import them. The auth server's
 * `account-contract.test.ts` keeps the copies equal to the originals.
 */

export const assetSchema = object(
  {
    url: sameOriginPath('Where the realm origin serves the image.'),
    width: { type: 'integer', minimum: 1, maximum: 2048, description: 'Its width in pixels.' },
    height: { type: 'integer', minimum: 1, maximum: 2048, description: 'Its height in pixels.' },
  },
  ['url', 'width', 'height'],
  'An image an admin uploaded, re-encoded by the server and served from the realm origin. Never a URL a client supplied (ADR-019 Decision 6).'
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
      'Where the code goes, from the redirect URI the request was bound to. Absent when no code goes anywhere, as on a logout. Always present on the `consent` step of an `unverified` client, whose screen shows where the code goes as the only fact it can check (ADR-019 Decision 6).',
      [
        whenEquals('target', ['host'], { required: ['host'] }),
        whenEquals('target', ['app'], { required: ['scheme'] }),
      ]
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
  'Who the client is, as the auth server’s own records say (#593). Client-supplied text is untrusted: no logo comes from a client-supplied URL, and an unverified client shows none.',
  [
    whenEquals('kind', ['cimd', 'admin_registered'], {
      required: ['verifiedDomain'],
      properties: { federation: NEVER },
    }),
    whenEquals('kind', ['federation'], {
      required: ['federation'],
      properties: { verifiedDomain: NEVER },
    }),
    whenEquals('kind', ['unverified'], {
      properties: { verifiedDomain: NEVER, federation: NEVER, logo: NEVER },
    }),
  ]
);

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
