import type {
  RedisFailureLadder,
  RepositoryRecoveryCodes,
  TotpCredentials,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import type { EngineMailer, MailRealm } from './engine-mail';
import { createServerRecoveryCodes } from './recovery-codes';
import { createServerTotp } from './totp-sign-in';

/**
 * THE AUTHENTICATOR APP AND THE RECOVERY CODES OF A PROCESS (#649, #653,
 * #1109): the sign-in engine's `TotpCredentials` and `RecoveryCodes` ports
 * over the auth server's repositories, built in one place for the two
 * callers that change them.
 *
 * - The sign-in engines (`interaction-engines.ts`) ask for a code at
 *   sign-in, bind an authenticator app at a set-up step and show a set of
 *   recovery codes once; the hosted account page reaches them through an
 *   account interaction and regenerates a set through them.
 * - The account API (`account-factors.ts`) starts and confirms an
 *   authenticator-app enrolment and regenerates the set, with the same
 *   secret, the same binding and the same set.
 *
 * Each caller hands the request its writes run for (`requestOf`), whose
 * trace id and address the events carry.
 */

/** The two ports. */
export interface ServerFactorPorts {
  readonly recoveryCodes: RepositoryRecoveryCodes;
  readonly totp: TotpCredentials;
}

/** What {@link createServerFactorPorts} works with. */
export interface ServerFactorPortsDependencies {
  readonly mailer: EngineMailer;
  /** The realm row a notice is sent for. */
  readonly realmOf: (realmId: string) => Promise<MailRealm>;
  /** The failure ladder: a binding ends the TOTP counter's run. */
  readonly ladder: Pick<RedisFailureLadder, 'resetAccount'>;
  /** The request a write runs for, which its event carries. */
  readonly requestOf: () => FastifyRequest | undefined;
  /** The OAuth client a binding's request came through, which its event names. */
  readonly clientIdOf?: (request: FastifyRequest) => string | null;
  /** Whether the hosted pages, where a recovery code is redeemed, are on. */
  readonly hostedPages: boolean;
  /** Whether passkey sign-in is on, so a passkey is a usable second factor. */
  readonly passkeys: boolean;
}

/** The authenticator app and recovery codes of this process. */
export function createServerFactorPorts(
  fastify: FastifyInstance,
  deps: ServerFactorPortsDependencies
): ServerFactorPorts {
  const { mailer, realmOf, requestOf } = deps;
  // The recovery codes (#649): taken with their event, and told to the user.
  const recoveryCodes = createServerRecoveryCodes(fastify, { mailer, realmOf, requestOf });
  // The authenticator app (#653). Its hard action is armed only while the
  // hosted pages, where a recovery code is redeemed, are on.
  const totp = createServerTotp(fastify, {
    mailer,
    realmOf,
    recoveryCodes,
    ladder: deps.ladder,
    hostedPages: deps.hostedPages,
    passkeys: deps.passkeys,
    requestOf,
    ...(deps.clientIdOf === undefined ? {} : { clientIdOf: deps.clientIdOf }),
  });
  return Object.freeze({ recoveryCodes, totp });
}
