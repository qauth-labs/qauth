import {
  createDerivedKeyEmailCodeDigest,
  createDerivedKeyIdentifierDigest,
  createHardActionArming,
  createPasswordAttempts,
  createPasswordHardAction,
  createRedisFailureLadder,
  type EmailCodeDigest,
  END_USER_IP_HMAC_LABEL,
  type HardActionArming,
  type HardActionArmingSources,
  type IdentifierDigest,
  type PasswordAttempts,
  type PasswordDisabledNotices,
  type PasswordHardAction,
  type RedisFailureLadder,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance } from 'fastify';

import {
  clientAddressKey,
  type ClientAddressSource,
  UNKNOWN_CLIENT_ADDRESS,
} from './client-address';
import { cookieDerivedKeyRing } from './cookie-derived-keys';

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
 * The end-user IP a password attempt hands the failure ladder (#615), as the
 * fields of `fastify.passwordAttempts.reserve`: the client address key
 * (`clientAddressKey`, an IPv6 client by its /64), or no `endUserIp` at all
 * when the request carries no client address.
 *
 * `clientAddressKey` keys every address-less request as one constant
 * (`UNKNOWN_CLIENT_ADDRESS`), as a listener on a Unix socket sees every
 * client. Handed to the ladder, that constant would make all such clients one
 * known IP: a single successful sign-in from any of them would exempt every
 * other from the account's wait for 30 days. Without an `endUserIp` the
 * attempt still counts, but is neither exempted nor recorded as a known IP.
 *
 * Every route that reserves a password attempt passes its request through
 * here, so none hands the ladder the constant.
 */
export function ladderEndUserIp(request: ClientAddressSource): { readonly endUserIp?: string } {
  const key = clientAddressKey(request);
  return key === UNKNOWN_CLIENT_ADDRESS ? {} : { endUserIp: key };
}

/** The keyed HMACs of a process, under the realm's cookie key (ADR-017 Decision 7). */
export interface ServerDigests {
  /** The identifier's HMAC: the ladder's and the send caps' account key. */
  readonly identifierDigest: IdentifierDigest;
  /** The end-user IP's HMAC: how the ladder keeps an IP known, and the send caps key one. */
  readonly ipDigest: IdentifierDigest;
}

/**
 * The identifier and end-user IP digests of this process, under keys the
 * signer derives from the realm's cookie key (`cookie-derived-keys.ts`; no new
 * secret, ADR-017 Decision 7): the failure ladder (#615) and the send caps
 * (#637) key the same account by the same HMAC, so a known IP the ladder
 * recorded is the one a send cap exempts. A process that may not hold the
 * cookie secret, `api` (#497), makes the same digests, and a sign-in with a
 * warm cache makes no signer call.
 */
export function createServerDigests(fastify: FastifyInstance): ServerDigests {
  const keys = cookieDerivedKeyRing(fastify);
  return {
    identifierDigest: createDerivedKeyIdentifierDigest(keys),
    ipDigest: createDerivedKeyIdentifierDigest(keys, END_USER_IP_HMAC_LABEL),
  };
}

/**
 * The email-code digest of this process (#638), under a key derived from the
 * realm's cookie key as the identifier's: the sign-in transaction holds an
 * emailed code only as this keyed HMAC, under a label of its own.
 */
export function createServerEmailCodeDigest(fastify: FastifyInstance): EmailCodeDigest {
  return createDerivedKeyEmailCodeDigest(cookieDerivedKeyRing(fastify));
}

/** The parts of the per-account failure ladder (#615) every password route of a process shares. */
export interface ServerLadderParts {
  /** The identifier's HMAC under the realm's cookie key, the ladder's account key. */
  readonly identifierDigest: IdentifierDigest;
  readonly ladder: RedisFailureLadder;
  readonly hardAction: PasswordHardAction;
  readonly hardActionArmed: HardActionArming;
}

/**
 * The failure ladder's parts over the process's Redis, its cookie keys and its
 * `user_credentials` repository: the legacy login routes reach them through
 * {@link createServerPasswordAttempts}, the sign-in engine of the Interaction
 * API directly (#616). Both key an account by the same HMAC of the same
 * cookie key, so one run of failures counts across them.
 *
 * The hard action is never armed yet. ADR-017 Decision 7 arms it only while
 * every account it can reach has a way back that a third party cannot
 * exhaust. The hosted reset exists now (#642), and clears the mark, but the
 * start the disable notice's mailed pass carries is not answerable yet
 * (`mailed_pass` interactions): without it, someone who keeps the address at
 * its per-address send ceiling also keeps the owner's reset code from going
 * out. The notice that tells the owner (`notices`, #637) is wired, so the
 * hard action arms once that start is built and the realm can send it. Until
 * then the ladder counts and makes attempts wait, the 100th consecutive
 * failure only logs a warning, and a disabled mark is ignored and cleared by
 * the next successful sign-in or reset.
 *
 * A rotation of the realm's cookie key changes every digest: every account's
 * run of failures and known IPs start afresh within a minute of it.
 *
 * @param notices - the owner's password-disabled notice (`createEngineMailer`)
 */
export function createServerLadderParts(
  fastify: FastifyInstance,
  notices: PasswordDisabledNotices
): ServerLadderParts {
  const { identifierDigest, ipDigest } = createServerDigests(fastify);
  // One source for the arming and for the notice the hard action sends.
  const arming: HardActionArmingSources = {
    // The hosted reset (#642) exists, but the reset start a mailed pass
    // carries does not yet: nothing can turn it on (see above).
    hostedReset: () => false,
    notices,
  };
  return {
    identifierDigest,
    ladder: createRedisFailureLadder(fastify.redis, { ipDigest }),
    hardAction: createPasswordHardAction({
      credentials: fastify.repositories.userCredentials,
      arming,
      log: fastify.log,
    }),
    hardActionArmed: createHardActionArming(arming),
  };
}

/**
 * The failure ladder of this process as the legacy login routes use it
 * (`fastify.passwordAttempts`), over {@link createServerLadderParts}.
 */
export function createServerPasswordAttempts(
  fastify: FastifyInstance,
  notices: PasswordDisabledNotices
): PasswordAttempts {
  return createPasswordAttempts({ ...createServerLadderParts(fastify, notices), log: fastify.log });
}
