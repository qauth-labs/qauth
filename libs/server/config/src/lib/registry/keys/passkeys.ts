import { defineKeys } from '../types';

/**
 * Passkeys (ADR-017 Decision 14, ADR-019 Decision 2, issue #467): the keys of
 * `webauthnEnvSchema`.
 *
 * All `advanced`: passkeys are off by default, and the RP ID and the
 * association files are a deployment's deliberate choice.
 * `PASSKEY_OFFER_AFTER_SIGN_IN` only seeds a realm's policy (#1083).
 */
export const PASSKEY_KEYS = defineKeys([
  {
    name: 'WEBAUTHN_ENABLED',
    tier: 'advanced',
    role: 'deployment',
    owner: 'passkeys',
    default: 'false',
    since: '0.2.0',
    docs: 'Turn passkeys on: passkey sign-in, the offer to add one after a password sign-in where the realm keeps it (`passkeys.offerAfterSignIn`), and sign-up with a passkey alone (no email address) where the realm allows sign-up; only the hosted pages (`INTERACTION_UI_ENABLED`) offer a passkey, and while they are off the server warns at every boot.',
  },
  {
    name: 'PASSKEY_OFFER_AFTER_SIGN_IN',
    tier: 'advanced',
    role: 'realm-seed',
    seeds: 'passkeys.offerAfterSignIn',
    owner: 'passkeys',
    default: 'true',
    since: '0.2.4',
    docs: "Whether the hosted sign-in offers to add a passkey after a password sign-in, to a verified account whose only factor is that password, while `WEBAUTHN_ENABLED` is on (a passkey added from the account page is not affected), that seeds `passkeys.offerAfterSignIn` of a new realm, and of a realm whose stored policies lack it at the first boot of the release that added it; once the realm has it, the server reads the realm row's value, never this key, so a later change leaves every such realm as it is.",
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
