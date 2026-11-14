import {
  NotFoundError,
  TemporarilyUnavailableError,
  TooManyRequestsError,
  WeakPasswordError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { rfc3339 } from '../../api-conventions/time';
import { InvalidCurrentPasswordError } from '../../helpers/account-operation-errors';
import {
  ACCOUNT_LOOKUP_RETRY_SECONDS,
  accountOperation,
} from '../../helpers/account-operation-guard';
import { changePassword } from '../../helpers/account-password-change';
import { readSignInMethods } from '../../helpers/account-sign-in-methods';
import { createEngineMailer } from '../../helpers/engine-mail';
import { requestRealm } from '../../helpers/request-realm';
import { tokenUserIdOf } from './token-subject';

/**
 * The account API's sign-in methods (#1107; ADR-020 §3, ADR-017 Decision 8,
 * ADR-019 Decision 7): what the token's user can sign in with, and the
 * password change. Both run on the logic the hosted account page uses
 * (`helpers/account-sign-in-methods.ts`, `helpers/account-password-change.ts`).
 *
 *   GET  /sign-in-methods   — read them, at a glance
 *   POST /password/change   — change the password, with the current one
 *
 * The change needs a fresh sign-in with the account's strongest factor and
 * refuses an act-chain token (`accountOperation`). Afterwards every other
 * browser session of the account ends and the one the token names in `sid`
 * stays; every refresh-token family ends, as the page's change ends them.
 */

/** The most passkeys, linked accounts and recovery codes the contract counts. */
const MAX_PASSKEYS = 100;
const MAX_LINKED_ACCOUNTS = 100;
const MAX_RECOVERY_CODES = 10;

/** The sign-in methods, as the account contract's `SignInMethods` states them. */
const signInMethodsSchema = z.strictObject({
  password: z.strictObject({
    set: z.boolean(),
    changedAt: z.iso.datetime().nullable(),
  }),
  passkeys: z.strictObject({ count: z.int().min(0).max(MAX_PASSKEYS) }),
  totp: z.strictObject({ enabled: z.boolean() }),
  recoveryCodes: z.strictObject({ remaining: z.int().min(0).max(MAX_RECOVERY_CODES) }),
  linkedAccounts: z.strictObject({ count: z.int().min(0).max(MAX_LINKED_ACCOUNTS) }),
  hasContactAddress: z.boolean(),
  freshAuthenticationFactor: z.enum(['pop', 'otp', 'pwd']),
});

/** A password, as the contract bounds one in a request: write-only, never shown. */
function passwordField(description: string) {
  return z.string().min(1).max(256).meta({ format: 'password', writeOnly: true, description });
}

/** A password change, as the contract's `PasswordChangeRequest` states it. */
const passwordChangeBodySchema = z.strictObject({
  currentPassword: passwordField('The password the account has now.'),
  newPassword: passwordField(
    'The new password. The realm’s password policy and breach list apply.'
  ),
});

type PasswordChangeBody = z.infer<typeof passwordChangeBodySchema>;

export function registerAccountSignInMethodRoutes(fastify: FastifyInstance): void {
  // The "password changed" notice goes out after the answer, through the
  // engine's mail; its background tasks register a hook, so it is built at
  // registration.
  const mailer = createEngineMailer(fastify);
  const read = accountOperation({
    operationId: 'account.signInMethods.get',
    operationClass: 'read',
    permission: 'signInMethods.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  const change = accountOperation({
    operationId: 'account.password.change',
    operationClass: 'write',
    permission: 'password.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
  });
  const tags = ['Account API'];

  fastify.get('/sign-in-methods', {
    preValidation: read.guard,
    schema: {
      description:
        "Read the token's user's sign-in methods at a glance: whether a password is set and when it was last set, how many passkeys, whether an authenticator app (TOTP) is on, how many recovery codes are left, how many upstream accounts and wallets are linked, whether there is a contact address, and the factor a fresh authentication must hold.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...read.schema,
      'x-qauth-errors': [400, 401, 403],
      response: { 200: signInMethodsSchema },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const methods = await readSignInMethods(
        fastify,
        requestRealm(request).id,
        tokenUserIdOf(request)
      );
      // `Cache-Control: no-store` comes from the account API's own hook.
      return reply.send({
        password: {
          set: methods.password.set,
          changedAt: methods.password.setAt === undefined ? null : rfc3339(methods.password.setAt),
        },
        passkeys: { count: Math.min(methods.passkeys.length, MAX_PASSKEYS) },
        totp: { enabled: methods.totp.set },
        recoveryCodes: {
          remaining: Math.min(methods.recoveryCodes.unused, MAX_RECOVERY_CODES),
        },
        linkedAccounts: { count: Math.min(methods.linkedCount, MAX_LINKED_ACCOUNTS) },
        // The account's notices go to its password's address.
        hasContactAddress: methods.password.address !== undefined,
        freshAuthenticationFactor: methods.requiredFactor,
      });
    },
  });

  fastify.post<{ Body: PasswordChangeBody }>('/password/change', {
    preValidation: change.guard,
    schema: {
      description:
        "Change the token's user's password, with the current one. Needs a fresh sign-in with the account's strongest factor and refuses an act-chain token. A wrong current password is 400 invalid_current_password and counts on the account's failure ladder; a new password the realm's password policy or breach list refuses is 422 weak_password with its reasons. Afterwards the account's other browser sessions and its refresh-token families end, the session the token names stays, and the owner is told. An account without a password is 404.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...change.schema,
      'x-qauth-errors': [400, 401, 403, 404, 422, 429, 503],
      body: passwordChangeBodySchema,
      response: { 204: z.null() },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const userId = tokenUserIdOf(request);
      const claims = request.jwtPayload;
      const result = await changePassword(
        fastify,
        request,
        {
          userId,
          // The session the token names stays signed in; every other ends.
          ...(typeof claims?.sid === 'string' && claims.sid.length > 0 ? { sid: claims.sid } : {}),
          clientId: claims?.clientId ?? null,
          // No end-user address: the request comes from the caller's
          // backend, whose address the failure ladder must not record as
          // the person's known one.
        },
        { current: request.body.currentPassword, next: request.body.newPassword, mailer }
      );
      switch (result.kind) {
        case 'changed':
          reply.code(204);
          return reply.send(null);
        case 'no_password':
          // Setting a first password is no account API operation.
          throw new NotFoundError('Password of user', userId);
        case 'wrong_password':
          throw new InvalidCurrentPasswordError();
        case 'rejected':
          // The reasons alone: the account API's documents carry no prose
          // field errors (`libs/shared/account-contract`).
          throw new WeakPasswordError(
            'The new password does not meet the password policy',
            undefined,
            result.reasons
          );
        case 'wait':
          reply.header('Retry-After', String(result.retryAfterSeconds));
          throw new TooManyRequestsError('Too many wrong passwords. Try again later.');
        case 'unavailable':
          throw new TemporarilyUnavailableError(ACCOUNT_LOOKUP_RETRY_SECONDS, {
            reason: 'account password change: sign-in failure ladder unavailable',
          });
      }
    },
  });
}
