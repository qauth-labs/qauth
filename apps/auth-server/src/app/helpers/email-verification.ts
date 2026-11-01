import {
  EMAIL_ATTR_KEY,
  passwordCredentialDataSchema,
  SELF_REPORTED_SOURCE,
} from '@qauth-labs/fastify-plugin-federation';
import {
  EmailAlreadyVerifiedError,
  InvalidCredentialsError,
  InvalidTokenError,
  TooManyRequestsError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import { hashEmail } from './auth-events';
import { clientAddressKey, type ClientAddressSource } from './client-address';
import { recordSuccessfulLogin, registerLoginAttempt } from './failed-login';
import type { BruteForcePolicy } from './realm-policy-readers';

/** What a verification request carries: the mailed token and the account's password. */
export interface EmailVerificationInput {
  /**
   * The id of the realm the request's host named (`requestRealm`, #487). The
   * token, its credential and its user are looked up in this realm only (#489):
   * a token mailed for another realm's account is an unknown token here.
   */
  readonly realmId: string;
  /**
   * That realm's brute-force policy (`accountPoliciesOf`, #528): the password
   * check here counts against the login routes' lockout, under the policy
   * they count with.
   */
  readonly bruteForce: BruteForcePolicy;
  /** The 64-hex-character token from the verification mail, already format-checked. */
  readonly token: string;
  /** The password chosen at registration. */
  readonly password: string;
}

/** What a completed verification returns. */
export interface EmailVerificationResult {
  /** The verified address: the credential's `external_sub` (#230). */
  readonly email: string;
}

/** The one reply method {@link verifyEmailAddress} uses: `Retry-After` on a lockout. */
export interface RetryAfterReply {
  header(name: string, value: string): unknown;
}

/**
 * Verify an email address with the mailed token and the account's password.
 *
 * The one implementation of the rules below. `POST /auth/verify` (JSON) and
 * `POST /ui/verify` (the form of the emailed link's page) both call it and
 * differ only in how they answer: the JSON route lets the errors reach the
 * error handler, the form renders a page with the same status for each.
 *
 * Security considerations:
 * - Token is hashed (SHA-256) before database lookup
 * - Generic error messages prevent token enumeration
 * - 256-bit random tokens make guessing infeasible (2^256 combinations)
 * - Single-use tokens prevent replay attacks
 *
 * Note on timing attacks: Database index lookups have consistent timing.
 * Combined with rate limiting and high-entropy tokens, timing-based
 * enumeration is not a practical attack vector for this endpoint.
 *
 * Token AND password. The token proves control of the mailbox; it cannot say
 * who registered. Someone who registers with another person's address holds
 * the password, and the mailbox owner holds the token; a confirm button alone
 * would let the owner verify the other person's account by clicking it. So the
 * request must also carry the account's password, checked against the
 * credential the token targets: only a person who has both the mailbox and the
 * password (the genuine registrant) can verify. A wrong password consumes
 * nothing, so the registrant can retry within the token's lifetime.
 *
 * The token must not become a password oracle, though: the per-IP rate limit
 * of the calling route caps guesses per address, not per account. So the
 * password check sits under the failed-login lockout (#115) with the SAME
 * identifiers as POST /auth/login and POST /ui/login: wrong passwords here
 * count against the account, and an account locked on either login route is
 * locked here too.
 *
 * The realm is the request's (#489): the token, its credential and its user
 * are found in the realm the request's host named, so a token mailed for
 * another realm's account answers as an unknown token. The account is then of
 * that realm, and the lockout is counted in it (#487), as the login routes
 * count it. So a link verifies only at a host of its account's realm, the
 * issuer the link names (#870); at another realm's host its token is
 * unknown.
 *
 * @throws InvalidTokenError (400) for an unknown, expired or used token, a
 *   token of a disabled account, a missing credential or malformed credential
 *   data — one generic error for all of them.
 * @throws EmailAlreadyVerifiedError (409) when the address is already verified.
 * @throws TooManyRequestsError (429) when the account or the address is locked
 *   out; `Retry-After` is set on `reply` first.
 * @throws InvalidCredentialsError (401) for a wrong password; nothing is consumed.
 */
export async function verifyEmailAddress(
  fastify: FastifyInstance,
  request: ClientAddressSource,
  reply: RetryAfterReply,
  { realmId, bruteForce, token, password }: EmailVerificationInput
): Promise<EmailVerificationResult> {
  // Token format already validated by the caller's Zod schema (64-char hex
  // string). This prevents CVE-2025-12374 style attacks at schema level.

  // 1. Hash token before database lookup
  const tokenHash = fastify.emailVerificationTokenUtils.hashToken(token);

  // 2. Find token in database (returns undefined if not found, expired, or used)
  const verificationToken = await fastify.repositories.emailVerificationTokens.findByTokenHash(
    realmId,
    tokenHash
  );

  if (!verificationToken) {
    // Generic error to prevent token enumeration (security: don't reveal why it failed)
    throw new InvalidTokenError('Invalid or expired token');
  }

  // 3. Resolve the password credential this token targets (#228,
  // ADR-002). credential_id is NOT NULL since #230, so the lookup is
  // unconditional; a genuinely missing credential fails closed with the
  // generic token error (no enumeration signal).
  const credential = await fastify.repositories.userCredentials.findById(
    realmId,
    verificationToken.credentialId
  );
  if (!credential) {
    throw new InvalidTokenError('Invalid or expired token');
  }

  // 3b. A disabled account must not change its verified state or have its
  // password checked: same generic token error, and the token is left
  // unconsumed so it still works if the operator enables the account again.
  const user = await fastify.repositories.users.findById(realmId, credential.userId);
  if (!user || !user.enabled) {
    throw new InvalidTokenError('Invalid or expired token');
  }

  // 4. Check if email already verified — credential_data is the sole
  // authoritative source (the legacy users.email_verified dual-write
  // ended with #230). Malformed credential_data is operator-alerting
  // data corruption; the wire stays the generic token error.
  const parsed = passwordCredentialDataSchema.safeParse(credential.credentialData);
  if (!parsed.success) {
    fastify.log.error(
      { credentialId: credential.id },
      'malformed credential_data on password credential'
    );
    throw new InvalidTokenError('Invalid or expired token');
  }
  if (parsed.data.email_verified) {
    throw new EmailAlreadyVerifiedError();
  }

  // 4b. The registrant, not just the mailbox (see above). Checked BEFORE the
  // completion transaction, so a wrong password leaves the token unconsumed
  // and nothing verified.
  //
  // Under the failed-login lockout (#115), keyed as the login routes key
  // it: external_sub IS the normalized registered address (#230), so the
  // email hash matches theirs, the address is the client address key
  // (an IPv6 client by its /64), and the realm is the account's (#487),
  // the realm the login routes count it in. The attempt is counted before
  // the password is compared; a wrong one stays counted.
  const emailIdentifier = `email:${hashEmail(credential.externalSub)}`;
  const lockout = await registerLoginAttempt(fastify.redis, credential.realmId, bruteForce, [
    emailIdentifier,
    `ip:${clientAddressKey(request)}`,
  ]);
  if (lockout.locked) {
    if (lockout.retryAfterSeconds !== undefined) {
      reply.header('Retry-After', String(lockout.retryAfterSeconds));
    }
    throw new TooManyRequestsError('Too many failed attempts. Please try again later.');
  }

  const passwordValid = await fastify.passwordHasher.verifyPassword(
    parsed.data.password_hash,
    password
  );
  if (!passwordValid) {
    throw new InvalidCredentialsError('Incorrect password for this account');
  }
  // The password is proved: settle the attempt as a successful login does.
  await recordSuccessfulLogin(fastify.redis, credential.realmId, bruteForce, lockout, [
    emailIdentifier,
  ]);

  // 5.-6. Completion write set (one transaction): consume the token and
  // flip credential_data.email_verified + the attribute's verified flag —
  // the authoritative verified state since #228 (the legacy users
  // dual-write ended with #230).
  await fastify.db.transaction(async (tx) => {
    // Single-use CAS (#258): losing the race to a concurrent attempt with
    // the same token rolls the whole completion back and surfaces the
    // same generic error as an invalid/expired token — no state leak.
    const consumed = await fastify.repositories.emailVerificationTokens.markUsed(
      verificationToken.id,
      tx
    );
    if (!consumed) {
      throw new InvalidTokenError('Invalid or expired token');
    }
    await fastify.repositories.userCredentials.setEmailVerified(credential.id, tx);
    const attribute = await fastify.repositories.userAttributes.setVerified(
      credential.userId,
      SELF_REPORTED_SOURCE,
      EMAIL_ATTR_KEY,
      true,
      tx
    );
    if (!attribute) {
      // Register/backfill guarantee the row; absence is log-worthy data
      // inconsistency but must not fail the user's verification.
      fastify.log.warn(
        { userId: credential.userId },
        'no self_reported email attribute to mark verified'
      );
    }
  });

  // 7. The credential's external_sub IS the registered normalized address
  // (#230: users.email no longer exists).
  return { email: credential.externalSub };
}
