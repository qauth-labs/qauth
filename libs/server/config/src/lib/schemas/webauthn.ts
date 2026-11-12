import { InvalidRealmHostError, normaliseRealmHost } from '@qauth-labs/shared-validation';
import { z } from 'zod';

/**
 * Passkey (WebAuthn) settings (ADR-017 Decision 14 and phase F2b, ADR-019
 * Decision 2, issue #467).
 *
 * A plain `z.object` with per-field transforms, so the auth server can spread
 * its `.shape`. Rules that need the realm host (is the RP ID the host, a parent
 * of it, or unrelated) cannot run here, where no realm exists: the auth server
 * checks them at boot, with the RP ID rules of `@qauth-labs/server-federation`.
 */

/** Same parsing as `REQUIRE_VERIFIED_ACCOUNT`: `'true'` / `'false'`, blank is unset. */
function strictBoolean(defaultValue: boolean) {
  return z
    .preprocess(
      (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
      z.enum(['true', 'false']).optional()
    )
    .transform((value) => (value === undefined ? defaultValue : value === 'true'));
}

/**
 * An Apple application identifier: the 10-character App ID prefix (the Team
 * ID), a dot, and the bundle identifier, as the `webcredentials.apps` array of
 * `apple-app-site-association` lists it (`ABCDE12345.com.example.app`).
 */
const APPLE_APP_ID = /^[A-Z0-9]{10}\.[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/;

/** Most app identifiers of one platform an operator may list. */
const MAX_APPS = 50;

/**
 * An Android application id: at least two dot-separated segments, each
 * starting with a letter.
 */
const ANDROID_PACKAGE_NAME = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/;

/**
 * A SHA-256 signing-certificate fingerprint as `keytool` prints it: 32 bytes in
 * hex, colon-separated. Stored upper case, the form `assetlinks.json` shows.
 */
const SHA256_FINGERPRINT = /^[0-9A-F]{2}(?::[0-9A-F]{2}){31}$/;

/** Android apps by package name, each with its signing-certificate fingerprints. */
export type AndroidAppFingerprints = Readonly<Record<string, readonly string[]>>;

function parseRpId(raw: string | undefined, ctx: z.RefinementCtx): string | undefined {
  const value = raw?.trim();
  if (value === undefined || value === '') return undefined;
  try {
    return normaliseRealmHost(value, 'primary');
  } catch (error) {
    if (!(error instanceof InvalidRealmHostError)) throw error;
    ctx.addIssue({
      code: 'custom',
      message: `WEBAUTHN_RP_ID "${value}" is not a host name: ${error.message}. Write a bare domain name, such as auth.example.com, with no scheme, port or path; unset, it is the realm's host.`,
    });
    return z.NEVER;
  }
}

function parseAppleAppIds(raw: string, ctx: z.RefinementCtx): readonly string[] {
  const ids = new Set<string>();
  let valid = true;
  for (const entry of raw.split(',').map((value) => value.trim())) {
    if (entry.length === 0) continue;
    if (!APPLE_APP_ID.test(entry)) {
      ctx.addIssue({
        code: 'custom',
        message: `WEBAUTHN_APPLE_APP_IDS entry "${entry}" is not an Apple app identifier. Write the 10-character Team ID, a dot and the bundle identifier, such as ABCDE12345.com.example.app.`,
      });
      valid = false;
      continue;
    }
    ids.add(entry);
  }
  if (ids.size > MAX_APPS) {
    ctx.addIssue({
      code: 'custom',
      message: `WEBAUTHN_APPLE_APP_IDS lists more than ${MAX_APPS} apps.`,
    });
    valid = false;
  }
  return valid ? Object.freeze([...ids]) : z.NEVER;
}

function parseAndroidApps(raw: string, ctx: z.RefinementCtx): AndroidAppFingerprints {
  const value = raw.trim();
  if (value === '') return Object.freeze({});

  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    ctx.addIssue({
      code: 'custom',
      message:
        'WEBAUTHN_ANDROID_APPS is not JSON. Write an object from package name to signing-certificate fingerprints, such as {"com.example.app":["AB:CD:…"]}.',
    });
    return z.NEVER;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    ctx.addIssue({
      code: 'custom',
      message: 'WEBAUTHN_ANDROID_APPS must be a JSON object from package name to fingerprints.',
    });
    return z.NEVER;
  }

  const apps: Record<string, readonly string[]> = Object.create(null);
  let valid = true;
  const entries = Object.entries(parsed);
  if (entries.length > MAX_APPS) {
    ctx.addIssue({
      code: 'custom',
      message: `WEBAUTHN_ANDROID_APPS lists more than ${MAX_APPS} apps.`,
    });
    return z.NEVER;
  }
  for (const [packageName, fingerprints] of entries) {
    if (!ANDROID_PACKAGE_NAME.test(packageName)) {
      ctx.addIssue({
        code: 'custom',
        message: `WEBAUTHN_ANDROID_APPS key "${packageName}" is not an Android package name, such as com.example.app.`,
      });
      valid = false;
      continue;
    }
    if (
      !Array.isArray(fingerprints) ||
      fingerprints.length === 0 ||
      fingerprints.length > 10 ||
      !fingerprints.every((fingerprint) => typeof fingerprint === 'string')
    ) {
      ctx.addIssue({
        code: 'custom',
        message: `WEBAUTHN_ANDROID_APPS "${packageName}" must list 1 to 10 signing-certificate fingerprints as strings.`,
      });
      valid = false;
      continue;
    }
    const normalised = fingerprints.map((fingerprint: string) => fingerprint.trim().toUpperCase());
    const bad = normalised.find((fingerprint) => !SHA256_FINGERPRINT.test(fingerprint));
    if (bad !== undefined) {
      ctx.addIssue({
        code: 'custom',
        message: `WEBAUTHN_ANDROID_APPS "${packageName}" has "${bad}", which is not a SHA-256 fingerprint: 32 hex bytes separated by colons, as keytool prints it.`,
      });
      valid = false;
      continue;
    }
    apps[packageName] = Object.freeze([...new Set(normalised)]);
  }
  return valid ? Object.freeze(apps) : z.NEVER;
}

/**
 * WebAuthn environment configuration schema.
 */
export const webauthnEnvSchema = z.object({
  /**
   * Turn passkeys on (ADR-017 phase F2b, complete with #655): passkey sign-in,
   * the enrolment offer after a password sign-in, and the registration of an
   * account by passkey alone. Default off. Until the FiPA endpoint ships
   * (#646), only the hosted pages (`INTERACTION_UI_ENABLED`) offer a passkey:
   * on without them, the boot warns ({@link passkeyPostureWarnings}). The RP
   * ID settings and the association files below do not depend on it: they
   * are checked, and the files served, either way.
   */
  WEBAUTHN_ENABLED: strictBoolean(false),

  /**
   * Seeds a new realm's `passkeys.offerAfterSignIn` (#1083): whether the
   * hosted sign-in offers to add a passkey after a password sign-in of a
   * verified account whose only factor is that password. The auth server
   * reads each realm's own policy from the realm row. Defaults to `true`, the
   * offer of #651; a passkey added from the account page (#844) does not
   * read it. Parsed by {@link strictBoolean}; unset and blank mean `true`.
   */
  PASSKEY_OFFER_AFTER_SIGN_IN: strictBoolean(true),

  /**
   * The default realm's passkey RP ID (ADR-019 Decision 2). Unset: the realm's
   * exact host, the host of `JWT_ISSUER`. A parent domain of that host needs
   * `WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN=true` and logs a warning at every
   * boot. Locked once the realm's first passkey is enrolled: a later value
   * that differs refuses to boot.
   */
  WEBAUTHN_RP_ID: z.string().optional().transform(parseRpId),

  /**
   * The operator's explicit opt-in to a parent-domain RP ID. A parent domain
   * lets every host under it ask for assertions of the realm's passkeys.
   */
  WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN: strictBoolean(false),

  /**
   * Apple app identifiers (`<Team ID>.<bundle id>`), comma-separated, listed in
   * the `webcredentials` section of `/.well-known/apple-app-site-association`.
   * Served only while the RP ID is the realm host.
   */
  WEBAUTHN_APPLE_APP_IDS: z.string().default('').transform(parseAppleAppIds),

  /**
   * Android apps as JSON, from package name to SHA-256 signing-certificate
   * fingerprints, listed with the `delegate_permission/common.get_login_creds`
   * relation in `/.well-known/assetlinks.json`. Served only while the RP ID is
   * the realm host.
   */
  WEBAUTHN_ANDROID_APPS: z.string().default('').transform(parseAndroidApps),
});

export type WebAuthnEnv = z.infer<typeof webauthnEnvSchema>;

/** A warning the boot logs about the passkey settings, naming its variable. */
export interface PasskeyPostureWarning {
  readonly variable: string;
  readonly message: string;
}

/**
 * What the boot warns about in the passkey settings (#655): `WEBAUTHN_ENABLED`
 * on while `INTERACTION_UI_ENABLED` is off. Only the hosted pages offer a
 * passkey until the FiPA endpoint ships (#646); the server-rendered pages ask
 * for a password and refuse a right one of an account that holds a passkey.
 * So nothing offers a passkey, and an account whose only credential is a
 * passkey, registered while the hosted pages were on, cannot sign in. Not a
 * refusal: the switch gates the FiPA endpoint's passkeys too (ADR-017
 * Phasing), which need no hosted page.
 */
export function passkeyPostureWarnings(
  env: Pick<WebAuthnEnv, 'WEBAUTHN_ENABLED'> & { readonly INTERACTION_UI_ENABLED: boolean }
): PasskeyPostureWarning[] {
  if (!env.WEBAUTHN_ENABLED || env.INTERACTION_UI_ENABLED) return [];
  return [
    {
      variable: 'WEBAUTHN_ENABLED',
      message:
        'WEBAUTHN_ENABLED is on while INTERACTION_UI_ENABLED is off: only the hosted pages offer a passkey, so no page asks for one, and an account whose only credential is a passkey cannot sign in',
    },
  ];
}
