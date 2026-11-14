import type { RealmPolicyStoreOfRealms } from '@qauth-labs/fastify-plugin-realm-policy';
import type { FastifyInstance } from 'fastify';

import type { RealmRow } from './request-realm';

/**
 * The realm policies the auth server reads from the realm row (ADR-019
 * Decision 10, #516), by their path in the realm policy schema.
 *
 * Since #516 every realm stores its policies, and the environment only
 * seeds a new realm. The flows move to the stored values one area at a time:
 * the token lifetimes (#527, moved), the verified-account, password and
 * brute-force policy (#528, moved), the mail transport and sender (#529,
 * moved) and CIMD (#534, moved). Until an area has moved, the server still
 * reads its keys from the environment for every realm, so the default realm's
 * boot step says a set key is ignored only for a path listed here; for any
 * other it says the server still applies the key. The issue that moves an
 * area adds its paths.
 */
export const POLICIES_READ_FROM_REALM_ROW: ReadonlySet<string> = new Set([
  // `/oauth/register` and the clients API (`routes/clients/index.ts`) cap a
  // client's scopes with the realm's list; the environment's list fills an
  // empty one only while the realm has no policies.
  'registration.dynamicRegistrationAllowedScopes',
  // Client resolution (`resolveClient`, at the authorization, consent and
  // token endpoints) and discovery (`cimdPolicyOf`, #534): whether a URL
  // `client_id` is a CIMD client, and which hosts may name one. The CIMD
  // fetch's cache lifetimes, size and timeout stay deployment settings.
  'registration.cimd.enabled',
  'registration.cimd.trustPolicy',
  'registration.cimd.trustedDomains',
  // `resolveEnvironmentPolicy` (ADR-008): the realm's environment ceiling.
  'posture.maxEnvironmentLaxity',
  // The token endpoint and the legacy `/auth/login` (`tokenLifetimesOf`,
  // #527): access, ID and refresh token lifetimes.
  'tokens.accessTokenLifespanSeconds',
  'tokens.developmentAccessTokenLifespanSeconds',
  'tokens.refreshTokenLifespanSeconds',
  // The token endpoint: the ceiling of a token for the admin API (ADR-019
  // Decision 7), which no environment key seeds.
  'tokens.adminAccessTokenLifespanSeconds',
  // The password sign-ins (`/auth/login`, `/ui/login`) and the email
  // verification (`accountPoliciesOf` in `helpers/account-policies.ts`,
  // #528): the verified-account gate and the failed-login lockout.
  // Registration: the password policy's minimum length (#634) and lowest
  // score.
  'accounts.requireVerifiedAccount',
  'password.minLength',
  'password.minScore',
  'bruteForce.enabled',
  'bruteForce.maxAttempts',
  'bruteForce.windowSeconds',
  'bruteForce.lockoutSeconds',
  // The realm's mail sender (`helpers/realm-secrets.ts`, #529): its
  // transport and sender, read for every mail. The SMTP password and the
  // Resend API key are secrets, seeded once into the realm's secret store,
  // not listed here. The verification link's lifetime and the resend rule
  // (`mail.verificationTokenExpirySeconds`,
  // `mail.invalidateExistingTokensOnResend`) are still read from the
  // environment.
  'mail.provider',
  'mail.fromAddress',
  'mail.fromName',
  'mail.smtp.host',
  'mail.smtp.port',
  'mail.smtp.secure',
  'mail.smtp.user',
  // The bot challenge (`helpers/bot-challenge.ts`, #643): whether every
  // registration passes it first, and the built-in proof of work's
  // difficulty, read for every challenge.
  'botChallenge.requiredAtSignUp',
  'botChallenge.difficulty',
  // The passkey offer after a password sign-in (`createServerPasskeys` in
  // `helpers/passkey-sign-in.ts`, #1083), read on the round that would make
  // it.
  'passkeys.offerAfterSignIn',
  // The window of a factor bound after a password-only sign-in
  // (`newFactorWindowOf` in `helpers/new-factors.ts`, #1064), read at the
  // binding.
  'accounts.newFactorWindowDays',
  // The ceremony app's error page (`ceremonyErrorPageOf` in
  // `helpers/ceremony-error-page.ts`, #1106), seeded by
  // `CEREMONY_APP_ERROR_PAGE` (#1118): read by an upstream provider's
  // callback that finds no interaction left, and by the logout's endings.
  'ceremonyApp.errorPage',
  // The two-admin rule (`admin/approvals/two-admin.ts`, #521), which no
  // environment key seeds: the operations that need a second admin's
  // approval, read when an approval is filed, at the approval gate and in a
  // change preview.
  'admin.twoAdminMandatoryOperations',
]);

/**
 * A realm's dynamic registration allowlist (#516), which `/oauth/register`
 * and the clients API cap a client's scopes with. A realm that has its
 * policies keeps the list in its row. One that has none yet (counter 0: from
 * before migration 0046, or created by a node of the previous release during
 * a rolling upgrade) reads as its fill will leave it: the list its row holds
 * when it holds a scope, the environment's seed otherwise.
 *
 * Nothing is written here. The boot step stores the fill, the first node to
 * boot winning, so a request can neither overwrite that fill with its own
 * node's environment nor give an empty list a scope.
 *
 * @throws PolicyValidationError when the fill of a realm with no policies is
 *   not a valid policy document, such as a scope written into its row by hand
 */
export function dynamicRegistrationScopesOf(
  policies: Pick<RealmPolicyStoreOfRealms, 'ofRealm'>,
  realm: RealmRow
): string[] {
  if (realm.policiesVersion !== 0) return [...(realm.dynamicRegistrationAllowedScopes ?? [])];
  return [...policies.ofRealm(realm).policies.registration.dynamicRegistrationAllowedScopes];
}

/** A realm's token lifetimes in seconds (#527): the `tokens` policies the token flows read. */
export interface TokenLifetimes {
  /**
   * The access token lifetime of a staging or production client (the ADR-008
   * `short` tier), and the lifetime of every ID token.
   */
  readonly accessTokenLifespanSeconds: number;
  /** The access token lifetime of a development client (the ADR-008 `long` tier). */
  readonly developmentAccessTokenLifespanSeconds: number;
  /** How long a newly issued or rotated refresh token is valid, from its issue. */
  readonly refreshTokenLifespanSeconds: number;
  /**
   * The longest an access token whose audience is the admin API may live
   * (ADR-019 Decision 7: at most 900 s), whatever its client's tier gives.
   */
  readonly adminAccessTokenLifespanSeconds: number;
}

/**
 * The longest an access token for the admin API ever lives, in seconds
 * (ADR-019 Decision 7, #520): the bound of the realm policy
 * `tokens.adminAccessTokenLifespanSeconds`, applied again here, so that no
 * stored value, not even one written by hand past the policy schema, lets an
 * admin token live longer.
 */
export const ADMIN_ACCESS_TOKEN_MAX_LIFESPAN_SECONDS = 900;

/**
 * A realm's token lifetimes (ADR-019 Decision 10, #527), from the realm row
 * the flow already loaded (the realm resolver's, which the environment
 * policy reads too): no query. So two realms of one deployment can issue
 * tokens with different lifetimes, and a change of a realm's policies
 * reaches its next token once the row is read again (the resolver's cache
 * time), without a restart.
 *
 * A realm that has its policies keeps the three lifetimes in them; the
 * environment keys (`ACCESS_TOKEN_LIFESPAN`, `DEV_ACCESS_TOKEN_LIFESPAN`,
 * `REFRESH_TOKEN_LIFESPAN`) only seeded them. One that has none yet (counter
 * 0: created by a node of the previous release during a rolling upgrade,
 * until a boot fills it) runs on the JWT plugin's lifespans, which the
 * environment gave at registration, as every realm did before #527, and on
 * the development and admin lifetimes its fill will store, the environment's
 * seed and the schema's default. The fill moves the same values onto the row,
 * so the lifetimes do not change when it lands.
 *
 * The admin lifetime is never above {@link ADMIN_ACCESS_TOKEN_MAX_LIFESPAN_SECONDS}
 * (#520), whatever the policy holds.
 *
 * The store reads the whole document, so a value the schema refuses in any
 * group, not only `tokens`, fails the request (a server error, logged) rather
 * than let the server guess what the realm meant. The policy store writes no
 * value the schema refuses; such a value comes from a row written by hand, or
 * by a node of another release.
 *
 * @throws PolicyValidationError when the realm's stored policies are not a
 *   valid policy document
 */
export function tokenLifetimesOf(
  sources: {
    readonly policyStore: Pick<RealmPolicyStoreOfRealms, 'ofRealm'>;
    readonly jwtUtils: Pick<
      FastifyInstance['jwtUtils'],
      'getAccessTokenLifespan' | 'getRefreshTokenLifespan'
    >;
  },
  realm: RealmRow
): TokenLifetimes {
  const { tokens } = sources.policyStore.ofRealm(realm).policies;
  const adminAccessTokenLifespanSeconds = Math.min(
    tokens.adminAccessTokenLifespanSeconds,
    ADMIN_ACCESS_TOKEN_MAX_LIFESPAN_SECONDS
  );
  if (realm.policiesVersion > 0) {
    return Object.freeze({
      accessTokenLifespanSeconds: tokens.accessTokenLifespanSeconds,
      developmentAccessTokenLifespanSeconds: tokens.developmentAccessTokenLifespanSeconds,
      refreshTokenLifespanSeconds: tokens.refreshTokenLifespanSeconds,
      adminAccessTokenLifespanSeconds,
    });
  }
  return Object.freeze({
    accessTokenLifespanSeconds: sources.jwtUtils.getAccessTokenLifespan(),
    developmentAccessTokenLifespanSeconds: tokens.developmentAccessTokenLifespanSeconds,
    refreshTokenLifespanSeconds: sources.jwtUtils.getRefreshTokenLifespan(),
    adminAccessTokenLifespanSeconds,
  });
}

/**
 * A client's own token lifetimes (#632), as `oauth_clients` holds them:
 * `null`, or absent, takes the realm's.
 */
export interface ClientTokenLifetimes {
  readonly accessTokenLifespanSeconds?: number | null;
  readonly refreshTokenLifespanSeconds?: number | null;
}

/**
 * `lifetimes` as one client gets them (ADR-020 §3, #632): each the shorter of
 * the realm's and the client's own, which an admin may set only shorter than
 * the realm's. A client's access lifetime caps every access tier, the admin
 * one too, and with it the ID token's; its refresh lifetime caps a new or
 * rotated refresh token. The realm's lifetime still wins when an admin
 * shortened the realm after the client: the client never lives longer than
 * its realm allows, whatever its row holds.
 */
export function withClientTokenLifetimes(
  lifetimes: TokenLifetimes,
  client: ClientTokenLifetimes
): TokenLifetimes {
  const access = client.accessTokenLifespanSeconds ?? null;
  const refresh = client.refreshTokenLifespanSeconds ?? null;
  if (access === null && refresh === null) return lifetimes;
  const capAccess = (seconds: number): number =>
    access === null ? seconds : Math.min(seconds, access);
  return Object.freeze({
    accessTokenLifespanSeconds: capAccess(lifetimes.accessTokenLifespanSeconds),
    developmentAccessTokenLifespanSeconds: capAccess(
      lifetimes.developmentAccessTokenLifespanSeconds
    ),
    refreshTokenLifespanSeconds:
      refresh === null
        ? lifetimes.refreshTokenLifespanSeconds
        : Math.min(lifetimes.refreshTokenLifespanSeconds, refresh),
    adminAccessTokenLifespanSeconds: capAccess(lifetimes.adminAccessTokenLifespanSeconds),
  });
}
