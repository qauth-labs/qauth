import { NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { rfc3339 } from '../../api-conventions/time';
import { removeCredential } from '../../helpers/account-credentials';
import {
  type AccountFactors,
  confirmTotpEnrolment,
  startTotpEnrolment,
} from '../../helpers/account-factors';
import {
  AccountFactorConflictError,
  InvalidCodeError,
  LastCredentialError,
  SecondFactorRequiredError,
} from '../../helpers/account-operation-errors';
import { accountOperation } from '../../helpers/account-operation-guard';
import type { EngineMailer } from '../../helpers/engine-mail';
import { requestRealm } from '../../helpers/request-realm';
import { recoveryCodeSetSchema, toRecoveryCodeSet } from './recovery-code-set';
import { tokenUserIdOf } from './token-subject';

/**
 * The account API's authenticator app (#1109; ADR-017 Decision 8, ADR-020
 * §3, ADR-019 Decision 7): its enrolment and its removal, on the logic the
 * sign-in engine's set-up step and the hosted account page use
 * (`helpers/account-factors.ts`, `helpers/account-credentials.ts`).
 *
 *   POST   /totp/enrollment           — start one: the secret, shown once
 *   POST   /totp/enrollment/confirm   — bind it with a first valid code
 *   DELETE /totp                      — remove the bound one
 *
 * Each needs a fresh sign-in with the account's strongest factor, or one
 * that used a recovery code in place of a lost factor, and refuses an
 * act-chain token (`accountOperation`). The secret and its `otpauth://` URI
 * are answered once, at the start, and the account's first set of recovery
 * codes once, at the confirmation; none is logged, and every answer carries
 * `Cache-Control: no-store` (the account API's own hook).
 *
 * The account decides whether an app may bind, never a channel (ADR-017
 * Decision 8, amended 2026-11-08): a claimed account binds its first second
 * factor with no mailed code, so an enrolment always answers `emailCode:
 * "not_required"`, and an unclaimed account starts none (`conflict`).
 */

/** The digits of a code an authenticator app shows (ADR-020 §3). */
const TOTP_DIGITS = 6;

/** The time step of an authenticator app's codes, in seconds (ADR-020 §3). */
const TOTP_PERIOD_SECONDS = 30;

/** A started enrolment, as the contract's `TotpEnrollment` states it. */
const totpEnrollmentSchema = z.strictObject({
  secret: z
    .string()
    .regex(/^[A-Z2-7]{32}$/)
    .meta({ description: 'The shared secret, base32 without padding: 160 bits. Shown once.' }),
  otpauthUri: z
    .string()
    .min(16)
    .max(1024)
    .regex(/^otpauth:\/\/totp\/[!#-;=?-~]+$/)
    .meta({ description: 'The same secret as an `otpauth://totp/` URI. Shown once.' }),
  algorithm: z.literal('SHA1'),
  digits: z.literal(TOTP_DIGITS),
  period: z.literal(TOTP_PERIOD_SECONDS),
  expiresAt: z.iso.datetime().meta({ description: 'When the enrolment lapses unless confirmed.' }),
  emailCode: z.enum(['required', 'not_required']).meta({
    description:
      'Whether confirming also needs a mailed code. Always `not_required`: the account, not a mailbox, decides (ADR-017 Decision 8).',
  }),
});

/** The confirmation, as the contract's `TotpConfirmRequest` states it. */
const totpConfirmBodySchema = z.strictObject({
  code: z
    .string()
    .regex(/^[0-9]{6}$/)
    .meta({ description: 'The first code the authenticator app shows.' }),
  emailCode: z
    .string()
    .regex(/^[0-9]{8}$/)
    .meta({ description: 'A mailed code. No enrolment asks for one; it is ignored.' })
    .optional(),
});

type TotpConfirmBody = z.infer<typeof totpConfirmBodySchema>;

/** A bound app, as the contract's `TotpConfirmResult` states it. */
const totpConfirmResultSchema = z.strictObject({
  enabledAt: z.iso.datetime().meta({ description: 'When the authenticator app was bound.' }),
  recoveryCodes: recoveryCodeSetSchema.optional(),
});

/** The account the token names, and the client it came through. */
function ownerOf(request: FastifyRequest) {
  return {
    realmId: requestRealm(request).id,
    userId: tokenUserIdOf(request),
    clientId: request.jwtPayload?.clientId ?? null,
  };
}

export function registerAccountTotpRoutes(
  fastify: FastifyInstance,
  factors: AccountFactors,
  mailer: EngineMailer
): void {
  const freshFactor = {
    operationClass: 'write',
    permission: 'totp.write',
    freshAuthentication: 'strongest-factor-or-recovery-code',
    actChain: 'refused',
  } as const;
  const start = accountOperation({ operationId: 'account.totp.enrollment.create', ...freshFactor });
  const confirm = accountOperation({
    operationId: 'account.totp.enrollment.confirm',
    ...freshFactor,
  });
  const remove = accountOperation(
    { operationId: 'account.totp.delete', ...freshFactor },
    // An app still new (#1064): a fresh sign-in with the password removes it.
    { removing: () => ({ type: 'totp' }) }
  );
  const tags = ['Account API'];

  fastify.post('/totp/enrollment', {
    preValidation: start.guard,
    schema: {
      description:
        "Start an authenticator-app enrolment for the token's user: a new secret, answered once as text and as an `otpauth://` URI. Nothing is bound until the enrolment is confirmed with a first code within ten minutes; a new enrolment replaces one not yet confirmed. Needs a fresh sign-in with the account's strongest factor, or one that used a recovery code in place of a lost one, and refuses an act-chain token. An account that holds an authenticator app, an unclaimed account, and one with no address the app could show are 409 conflict.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...start.schema,
      'x-qauth-errors': [400, 401, 403, 409, 503],
      response: { 201: totpEnrollmentSchema },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const started = await startTotpEnrolment(fastify, factors, ownerOf(request));
      if (started.kind === 'conflict') throw new AccountFactorConflictError(started.reason);
      reply.code(201);
      return reply.send({
        secret: started.secret,
        otpauthUri: started.otpauthUri,
        algorithm: 'SHA1',
        digits: TOTP_DIGITS,
        period: TOTP_PERIOD_SECONDS,
        expiresAt: rfc3339(started.expiresAt),
        emailCode: 'not_required',
      });
    },
  });

  fastify.post<{ Body: TotpConfirmBody }>('/totp/enrollment/confirm', {
    preValidation: confirm.guard,
    schema: {
      description:
        'Bind the started enrolment\'s secret with a first valid code. A wrong code is 400 invalid_code and binds nothing; the enrolment waits for another. The account\'s first second factor also issues its first set of recovery codes, answered once. The "authenticator app added" notice goes out. Without a started enrolment, or after it lapsed, the answer is 404. Needs a fresh sign-in as the start does, and refuses an act-chain token.',
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...confirm.schema,
      'x-qauth-errors': [400, 401, 403, 404, 503],
      body: totpConfirmBodySchema,
      response: { 200: totpConfirmResultSchema },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const owner = ownerOf(request);
      const result = await confirmTotpEnrolment(
        fastify,
        request,
        factors,
        owner,
        request.body.code
      );
      switch (result.kind) {
        case 'invalid_code':
          throw new InvalidCodeError();
        case 'not_found':
          throw new NotFoundError('Authenticator app enrolment of user', owner.userId);
        case 'bound':
          return reply.send({
            enabledAt: rfc3339(result.enabledAt),
            ...(result.recoveryCodes === undefined
              ? {}
              : { recoveryCodes: toRecoveryCodeSet(result.recoveryCodes) }),
          });
      }
    },
  });

  fastify.delete('/totp', {
    preValidation: remove.guard,
    schema: {
      description:
        "Remove the token's user's authenticator app. Needs a fresh sign-in with the account's strongest factor, or one that used a recovery code in place of a lost app, the first half of a rebind; an app still new (bound after a sign-in that proved only the password) is removed after a fresh sign-in with the password, and its removal ends the sessions whose sign-in bound or proved it. Refuses an act-chain token. The last second factor the realm requires is 409 second_factor_required. The owner gets the \"authenticator app removed\" notice. An account without one is 404.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...remove.schema,
      'x-qauth-errors': [400, 401, 403, 404, 409, 503],
      response: { 204: z.null() },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const owner = ownerOf(request);
      const result = await removeCredential(fastify, request, owner, { type: 'totp' }, mailer);
      switch (result.kind) {
        case 'removed':
          reply.code(204);
          return reply.send(null);
        case 'not_found':
          throw new NotFoundError('Authenticator app of user', owner.userId);
        case 'last_credential':
          throw new LastCredentialError();
        case 'second_factor_required':
          throw new SecondFactorRequiredError();
      }
    },
  });
}
