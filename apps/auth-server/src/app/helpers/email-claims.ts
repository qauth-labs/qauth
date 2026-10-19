import {
  EMAIL_ATTR_KEY,
  selectTrustedAttribute,
  WALLET_SOURCE,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

import { isWalletAttributeIssuerStillTrusted } from './wallet-verification';

/**
 * Trust-ordered OIDC email claim resolution (ADR-002, issue #229).
 *
 * The BREAKING #229 semantics in one place: `email`/`email_verified` resolve
 * exclusively from VERIFIED `user_attributes` rows using the ADR-002 trust
 * order (`wallet > oidc_* > self_reported`, expiry-aware — see
 * `selectTrustedAttribute`). When no verified email attribute exists, BOTH
 * claims are OMITTED entirely — never null, never present-but-false. There is
 * deliberately no compatibility flag.
 *
 * A `wallet` row is asserted only while the realm still trusts the issuer it
 * rests on (`isWalletAttributeIssuerStillTrusted`, ANT-2026-ULJIA4P4). The
 * issuer-trust gate otherwise runs at presentation only, and none of the sites
 * below presents anything. A row that fails it is treated as absent, so the
 * next source in the trust order answers. Revocation is NOT re-checked here,
 * because that would put a status-list fetch on every token grant; the
 * account's next wallet sign-in withdraws a revoked credential's rows.
 *
 * The pair is typed with `email_verified: true` as a literal: an email claim
 * is only ever asserted for a verified value, so email-present-plus-
 * verified-false is unrepresentable at compile time. Presence IS the
 * verification signal (OIDC Core 1.0 §5.1).
 *
 * Release is a separate question, decided by the granted scopes: the pair
 * reaches a token or a response only under the `email` scope (OIDC Core §5.4).
 * Every emission site therefore calls {@link resolveEmailClaimsForScopes}:
 * authorization_code (access + ID token from ONE call), refresh rotation,
 * RFC 8693 token exchange, the RFC 7523 jwt-bearer grant, and userinfo. The
 * `/auth/login` token is granted no scope and carries neither claim. The
 * login-time REQUIRE_VERIFIED_ACCOUNT gate is a separate control and does not
 * read this.
 */
export type EmailClaims = { email: string; email_verified: true } | Record<string, never>;

/** The OIDC scope that releases `email` / `email_verified` (OIDC Core §5.4). */
export const EMAIL_SCOPE = 'email';

/**
 * The email claims a token or response with `grantedScopes` may carry: the
 * trust-ordered pair of {@link resolveEmailClaims} when `email` was granted,
 * nothing otherwise. The attribute lookup is skipped when the scope is absent.
 *
 * This is the one rule for every emission site, access tokens included
 * (ANT-2026-2O0T72HY, decided 2026-10-19). An access token is a JWT the client
 * can read, so a claim gated in the ID token and at userinfo but not in the
 * access token would be gated nowhere.
 */
export async function resolveEmailClaimsForScopes(
  fastify: FastifyInstance,
  userId: string,
  grantedScopes: Iterable<string>
): Promise<EmailClaims> {
  for (const scope of grantedScopes) {
    if (scope === EMAIL_SCOPE) {
      return resolveEmailClaims(fastify, userId);
    }
  }
  return {};
}

export async function resolveEmailClaims(
  fastify: FastifyInstance,
  userId: string
): Promise<EmailClaims> {
  const rows = await fastify.repositories.userAttributes.findVerifiedByUserIdAndKey(
    userId,
    EMAIL_ATTR_KEY
  );
  const now = Date.now();
  let winner = selectTrustedAttribute(rows, now);
  if (
    winner?.source === WALLET_SOURCE &&
    !(await isWalletAttributeIssuerStillTrusted(fastify, userId, winner.provenance))
  ) {
    winner = selectTrustedAttribute(
      rows.filter((row) => row.source !== WALLET_SOURCE),
      now
    );
  }
  if (!winner) {
    return {};
  }
  return { email: winner.attrValue, email_verified: true };
}
