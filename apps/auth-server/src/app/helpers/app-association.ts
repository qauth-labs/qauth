import type { AndroidAppFingerprints } from '@qauth-labs/server-config';

/**
 * The platform association files (ADR-017 Decision 14, issue #467): the
 * documents that let a native app use the passkeys of the realm's RP ID, so
 * one passkey works in every first-party app and on the hosted `/ui/login`.
 *
 * Platform rules, re-read for this change (2026-10-22):
 *
 * - Apple, "Supporting associated domains": the file is
 *   `https://<fully qualified domain>/.well-known/apple-app-site-association`,
 *   with no extension, served over https with a valid certificate and no
 *   redirects. Since iOS 14 and macOS 11 devices fetch it through Apple's CDN,
 *   not from the server, so the host must be reachable from the internet. Each
 *   subdomain serves its own file. Passkeys and passwords use the
 *   `webcredentials` service, whose `apps` list holds
 *   `<Application Identifier Prefix>.<Bundle Identifier>` values.
 * - Android, Credential Manager "Digital Asset Links": the file is
 *   `https://domain[:optional_port]/.well-known/assetlinks.json`; it must
 *   answer `200` with `Content-Type: application/json`, and verification fails
 *   on a `301` or `302`. The relation for sharing sign-in credentials is
 *   `delegate_permission/common.get_login_creds`. The other relation the guide
 *   shows, `delegate_permission/common.handle_all_urls`, enables App Links,
 *   which would hand the auth server's own URLs to the app; QAuth does not
 *   declare it.
 *
 * Both are served only while the RP ID is the realm host (see
 * `servesAssociationFiles`), and only when the operator listed apps.
 */

/** Discovery-like documents that change only with configuration: cache for an hour. */
export const ASSOCIATION_FILES_CACHE_CONTROL = 'public, max-age=3600';

/** The Digital Asset Links relation for sharing sign-in credentials, passkeys included. */
export const ANDROID_GET_LOGIN_CREDS_RELATION = 'delegate_permission/common.get_login_creds';

/** `apple-app-site-association` with the `webcredentials` service only. */
export function buildAppleAppSiteAssociation(appIds: readonly string[]): {
  webcredentials: { apps: string[] };
} {
  return { webcredentials: { apps: [...appIds] } };
}

/** One Digital Asset Links statement. */
export interface AssetLinksStatement {
  relation: string[];
  target: { namespace: 'android_app'; package_name: string; sha256_cert_fingerprints: string[] };
}

/**
 * `assetlinks.json`: one statement per app, each with its signing-certificate
 * fingerprints, in a stable order.
 */
export function buildAssetLinks(apps: AndroidAppFingerprints): AssetLinksStatement[] {
  return Object.keys(apps)
    .sort()
    .map((packageName) => ({
      relation: [ANDROID_GET_LOGIN_CREDS_RELATION],
      target: {
        namespace: 'android_app',
        package_name: packageName,
        sha256_cert_fingerprints: [...apps[packageName]],
      },
    }));
}
