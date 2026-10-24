import { defineKeys } from '../types';

/**
 * Passkeys (ADR-017 Decision 14, ADR-019 Decision 2, issue #467): the keys of
 * `webauthnEnvSchema`.
 *
 * All `advanced` while phase F2b is incomplete: the switch is refused, and the
 * names may still change before passkeys ship.
 */
export const PASSKEY_KEYS = defineKeys([
  {
    name: 'WEBAUTHN_ENABLED',
    tier: 'advanced',
    role: 'deployment',
    owner: 'passkeys',
    default: 'false',
    since: '0.2.0',
    docs: 'Turn passkeys on; refused at boot until passkey sign-in (ADR-017 phase F2b) is complete.',
  },
  {
    name: 'WEBAUTHN_RP_ID',
    tier: 'advanced',
    role: 'deployment',
    owner: 'passkeys',
    default: { computed: "the default realm's host, from `JWT_ISSUER`" },
    since: '0.2.0',
    docs: "The default realm's passkey RP ID, stored on the realm at boot: its host, or a parent domain that is not a public suffix, with `WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN`; locked once the realm has a passkey, after which another value refuses to boot.",
  },
  {
    name: 'WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN',
    tier: 'advanced',
    role: 'deployment',
    owner: 'passkeys',
    default: 'false',
    since: '0.2.0',
    docs: "Allow a parent domain of the realm host as the RP ID, which lets every host under it ask for the realm's passkeys; the server warns at every boot.",
  },
  {
    name: 'WEBAUTHN_APPLE_APP_IDS',
    tier: 'advanced',
    role: 'deployment',
    owner: 'passkeys',
    default: '',
    since: '0.2.0',
    docs: 'Apple app identifiers (`<Team ID>.<bundle id>`), comma-separated, served in `/.well-known/apple-app-site-association` while the RP ID is the realm host.',
  },
  {
    name: 'WEBAUTHN_ANDROID_APPS',
    tier: 'advanced',
    role: 'deployment',
    owner: 'passkeys',
    default: '',
    since: '0.2.0',
    docs: 'Android apps as JSON, package name to SHA-256 signing-certificate fingerprints, served in `/.well-known/assetlinks.json` while the RP ID is the realm host.',
  },
]);
