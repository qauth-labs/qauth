import {
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  presentedPasswordFor,
  type VerifiedIdentity,
  WEBAUTHN_PROVIDER_TYPE,
} from '@qauth-labs/fastify-plugin-federation';
import { TOTP_PROVIDER_TYPE } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { isOperatorVerified, normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';

import { verifyAgainstDecoyHash } from './decoy-hash';

/**
 * Credential row type, derived from the decorated repository so this app-scope
 * file never imports the infra lib directly (Nx module boundaries).
 */
type UserCredential = NonNullable<
  Awaited<ReturnType<FastifyInstance['repositories']['userCredentials']['findById']>>
>;

/**
 * Shared password-credential check for both login surfaces (#228, ADR-002/003).
 *
 * Replaces the legacy `users.findByEmail` + `users.password_hash` read path
 * with the `user_credentials` lookup. Used by `routes/auth/login.ts` and
 * `routes/ui/login.ts`; every surrounding security behavior (lockout, timing
 * floor, audit, metrics, response bodies) stays in the routes, byte-identical.
 *
 * Every outcome costs exactly one argon2 verification. The routes' fixed
 * `ensureMinimumResponseTime` floor only pads fast answers, so it hides
 * nothing once argon2 jobs queue up (see `verifyAgainstDecoyHash`):
 * - credential missing → argon2 against a decoy hash, not a stored one
 * - malformed `credential_data` → the same decoy, `log.error` for operators,
 *   and a generic invalid result — the client sees the same 401 as a wrong
 *   password, never a 500 (a distinct status would leak account state)
 * - a credential that records the NFC marker (#634) is verified on the
 *   presented password in NFC, one without it on the password as typed
 * - a right password of an account that holds a passkey (#651) → a generic
 *   invalid result naming no account: the downgrade rule asks for the
 *   passkey, which these routes cannot
 * - a password the failure ladder's hard action disabled
 *   (`user_credentials.disabled_at`, #615) → the same decoy and a generic
 *   invalid result, but only while the hard action is armed; while it is not,
 *   the mark is ignored and reported (`ignoredMark`), so a successful sign-in
 *   clears it
 */

export type PasswordCredentialCheck =
  /** No password credential exists for this email in the realm. */
  | { status: 'not_found' }
  /** Credential exists but the check failed (bad password, malformed data, a disabled mark, invariant breach). */
  | {
      status: 'invalid';
      /**
       * The account whose usable password was refused: the failure ladder's
       * hard action may disable it (#615). Absent when the password was not
       * usable: malformed, or already disabled.
       */
      userId?: string;
    }
  | {
      status: 'ok';
      credential: UserCredential;
      /**
       * The credential carries a disabled mark the lookup ignored because the
       * hard action is unarmed (#615): the sign-in clears it.
       */
      ignoredMark: boolean;
      /**
       * Whether the account is verified: its primary identity is proved
       * (ADR-017 Decision 5), or an operator verified it (ADR-015 Decision 8,
       * amended 2026-11-08; #1052). A password account's identifier is its
       * address, so for it the proof is the confirmed address,
       * `credential_data.email_verified`. What the verified-account gate (the
       * realm's `accounts.requireVerifiedAccount`) reads.
       */
      accountVerified: boolean;
      identity: VerifiedIdentity;
    };

export async function verifyPasswordCredential(
  fastify: FastifyInstance,
  params: { realmId: string; email: string; password: string }
): Promise<PasswordCredentialCheck> {
  const normalizedEmail = normalizeEmail(params.email);

  const credential = await fastify.repositories.userCredentials.findByRealmProviderSub(
    params.realmId,
    PASSWORD_PROVIDER_TYPE,
    normalizedEmail
  );
  if (!credential) {
    await verifyAgainstDecoyHash(fastify, params.password);
    return { status: 'not_found' };
  }

  // The failure ladder's disabled mark (#615), honoured only while the hard
  // action is armed, asked only when a mark is there. An error refuses the
  // sign-in (fail closed).
  const marked = credential.disabledAt !== null && credential.disabledAt !== undefined;
  if (marked && (await fastify.passwordAttempts.hardActionArmed(params.realmId))) {
    await verifyAgainstDecoyHash(fastify, params.password);
    return { status: 'invalid' };
  }

  const parsed = passwordCredentialDataSchema.safeParse(credential.credentialData);
  if (!parsed.success) {
    // Data corruption, not user error: surface loudly to operators (this log
    // line is the alerting hook) while the wire stays a generic 401.
    fastify.log.error(
      { credentialId: credential.id },
      'malformed credential_data on password credential'
    );
    await verifyAgainstDecoyHash(fastify, params.password);
    return { status: 'invalid' };
  }

  // In NFC when the credential records the marker of the one password
  // policy, as typed when it records none (#634).
  const passwordValid = await fastify.passwordHasher.verifyPassword(
    parsed.data.password_hash,
    presentedPasswordFor(parsed.data, params.password)
  );
  if (!passwordValid) {
    return { status: 'invalid', userId: credential.userId };
  }

  // A passkey-bound account (#651; ADR-017 Decision 4, the downgrade rule)
  // or one with an authenticator app (#653): a login completes only after the
  // account's strongest bound factor, a disabled one included, and these
  // password-only routes cannot ask for it. Refused as a wrong password,
  // naming no account, so the failure ladder's hard action never disables a
  // right password and nothing tells the caller what else the account holds.
  // The sign-in engine's pages ask for the factor instead.
  for (const [providerType, held] of [
    [WEBAUTHN_PROVIDER_TYPE, 'a passkey'],
    [TOTP_PROVIDER_TYPE, 'an authenticator app'],
  ] as const) {
    const factors = await fastify.repositories.userCredentials.findAllByUserIdAndType(
      credential.userId,
      providerType
    );
    if (factors.some((row) => row.realmId === params.realmId)) {
      fastify.log.info(
        { credentialId: credential.id },
        `a password login was refused: the account holds ${held}`
      );
      return { status: 'invalid' };
    }
  }

  const provider = fastify.providerRegistry.resolve(PASSWORD_PROVIDER_TYPE);
  const identity = await provider.verify({
    email: normalizedEmail,
    passwordHash: parsed.data.password_hash,
    emailVerified: parsed.data.email_verified,
  });

  if (identity.externalSub !== credential.externalSub) {
    // Provider/lookup invariant breach — cannot happen unless normalization
    // drifted. Fail closed as a generic invalid; never a 500 on a login path.
    fastify.log.error(
      { credentialId: credential.id },
      'externalSub invariant violation between provider and credential row'
    );
    return { status: 'invalid' };
  }

  // An operator's verification (#1052) is on the account, not the
  // credential: read only when the address is not confirmed, so a verified
  // address costs no second read.
  const accountVerified =
    parsed.data.email_verified ||
    isOperatorVerified(
      (await fastify.repositories.users.findById(params.realmId, credential.userId)) ?? {}
    );

  return {
    status: 'ok',
    credential,
    ignoredMark: marked,
    accountVerified,
    identity,
  };
}
