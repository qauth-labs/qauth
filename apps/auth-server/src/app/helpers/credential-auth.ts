import {
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  type VerifiedIdentity,
} from '@qauth-labs/fastify-plugin-federation';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';

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
 * Timing profile parity with the legacy path is deliberate:
 * - credential missing → NO argon2 call (matches the old no-user path; the
 *   routes' fixed `ensureMinimumResponseTime` floor remains the equalizer)
 * - malformed `credential_data` → NO argon2 call, `log.error` for operators,
 *   and a generic invalid result — the client sees the same 401 as a wrong
 *   password, never a 500 (a distinct status would leak account state)
 */

export type PasswordCredentialCheck =
  /** No password credential exists for this email in the realm. */
  | { status: 'not_found' }
  /** Credential exists but the check failed (bad password, malformed data, invariant breach). */
  | { status: 'invalid' }
  | {
      status: 'ok';
      credential: UserCredential;
      /** `credential_data.email_verified` — the REQUIRE_EMAIL_VERIFIED gate source. */
      emailVerified: boolean;
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
    return { status: 'not_found' };
  }

  const parsed = passwordCredentialDataSchema.safeParse(credential.credentialData);
  if (!parsed.success) {
    // Data corruption, not user error: surface loudly to operators (this log
    // line is the alerting hook) while the wire stays a generic 401.
    fastify.log.error(
      { credentialId: credential.id },
      'malformed credential_data on password credential'
    );
    return { status: 'invalid' };
  }

  const passwordValid = await fastify.passwordHasher.verifyPassword(
    parsed.data.password_hash,
    params.password
  );
  if (!passwordValid) {
    return { status: 'invalid' };
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

  return {
    status: 'ok',
    credential,
    emailVerified: parsed.data.email_verified,
    identity,
  };
}
