import { EMAIL_ATTR_KEY, selectTrustedAttribute } from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

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
 * The pair is typed with `email_verified: true` as a literal: an email claim
 * is only ever asserted for a verified value, so email-present-plus-
 * verified-false is unrepresentable at compile time. Presence IS the
 * verification signal (OIDC Core 1.0 §5.1).
 *
 * Every user-bound emission site consumes this as a one-line spread:
 * password login, authorization_code (access + ID token from ONE call),
 * refresh rotation, RFC 8693 token exchange, and userinfo (under the `email`
 * scope). The login-time REQUIRE_EMAIL_VERIFIED gate is a separate control
 * and does not read this.
 */
export type EmailClaims = { email: string; email_verified: true } | Record<string, never>;

export async function resolveEmailClaims(
  fastify: FastifyInstance,
  userId: string
): Promise<EmailClaims> {
  const rows = await fastify.repositories.userAttributes.findVerifiedByUserIdAndKey(
    userId,
    EMAIL_ATTR_KEY
  );
  const winner = selectTrustedAttribute(rows, Date.now());
  if (!winner) {
    return {};
  }
  return { email: winner.attrValue, email_verified: true };
}
