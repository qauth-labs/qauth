import {
  type CookieSecretSource as DigestSecretSource,
  createCookieSecretIdentifierDigest,
  createHardActionArming,
  createPasswordAttempts,
  createPasswordHardAction,
  createRedisFailureLadder,
  END_USER_IP_HMAC_LABEL,
  type PasswordAttempts,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance } from 'fastify';

import { cookieKeyRing } from './cookie-keys';

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The per-account failure ladder (#615, ADR-017 Decision 7) as the legacy
     * login routes use it: `/auth/login` and `/ui/login` reserve an attempt on
     * it before the password is read, beside their own lock, and settle it
     * after. Registered by the `failureLadder` role plugin.
     */
    passwordAttempts: PasswordAttempts;
  }
}

/**
 * The realm's current cookie HMAC secret through the process's cookie key
 * ring: the identifier and end-user IP digests derive their keys from it
 * (no new secret, ADR-017 Decision 7), and the ring reads the signer at most
 * once a minute per realm, so a login costs no signer call. The ring hands out
 * a copy of the secret, which the digest zeroes once used.
 */
function cookieRingSecrets(fastify: FastifyInstance): DigestSecretSource {
  return {
    async getCookieSecrets(_caller, realmId) {
      const { current } = await cookieKeyRing(fastify).keys(realmId);
      return { current: { kid: current.kid, secret: current.key.export() }, previous: null };
    },
  };
}

/**
 * The failure ladder of this process, over its Redis, its cookie keys and its
 * `user_credentials` repository.
 *
 * The hard action is never armed yet: it needs the owner's hosted password
 * reset (#642), the only way back from the disable, and the notice that tells
 * the owner (#637), and neither exists. So the ladder counts and makes
 * attempts wait, the 100th consecutive failure only logs a warning, and a
 * disabled mark is ignored and cleared by the next successful sign-in.
 *
 * A rotation of the realm's cookie key changes every digest: every account's
 * run of failures and known IPs start afresh within a minute of it.
 */
export function createServerPasswordAttempts(fastify: FastifyInstance): PasswordAttempts {
  const secrets = cookieRingSecrets(fastify);
  const hardActionArmed = createHardActionArming({
    // The hosted reset (#642) is not built: nothing can turn it on.
    hostedReset: () => false,
    // No notice template (#637) yet: the deployment cannot tell the owner.
    notices: undefined,
  });
  return createPasswordAttempts({
    identifierDigest: createCookieSecretIdentifierDigest(secrets, 'local'),
    ladder: createRedisFailureLadder(fastify.redis, {
      ipDigest: createCookieSecretIdentifierDigest(secrets, 'local', END_USER_IP_HMAC_LABEL),
    }),
    hardAction: createPasswordHardAction({
      credentials: fastify.repositories.userCredentials,
      armed: hardActionArmed,
      log: fastify.log,
    }),
    hardActionArmed,
    log: fastify.log,
  });
}
