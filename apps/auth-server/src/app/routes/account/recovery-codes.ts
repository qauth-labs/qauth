import { RECOVERY_CODE_COUNT } from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { rfc3339OrNull } from '../../api-conventions/time';
import {
  type AccountFactors,
  readRecoveryCodeSummary,
  regenerateAnsweredRecoveryCodes,
} from '../../helpers/account-factors';
import { AccountFactorConflictError } from '../../helpers/account-operation-errors';
import { accountOperation } from '../../helpers/account-operation-guard';
import { requestRealm } from '../../helpers/request-realm';
import { recoveryCodeSetSchema, toRecoveryCodeSet } from './recovery-code-set';
import { tokenUserIdOf } from './token-subject';

/**
 * The account API's recovery codes (#1109; ADR-017 Decision 8, ADR-019
 * Decision 7), on the logic the hosted account page uses
 * (`helpers/account-factors.ts`).
 *
 *   GET  /recovery-codes              — how many are left: never the codes
 *   POST /recovery-codes/regenerate   — a new set, answered once
 *
 * The read takes an act-chain token and no fresh sign-in. The regeneration
 * needs a fresh sign-in with the account's strongest factor, refuses an
 * act-chain token, and stops every code of the old set at once. Its codes
 * are answered once, never logged, with `Cache-Control: no-store` (the
 * account API's own hook); the server keeps only their hashes.
 */

/** The status, as the contract's `RecoveryCodeStatus` states it. */
const recoveryCodeStatusSchema = z.strictObject({
  remaining: z
    .int()
    .min(0)
    .max(RECOVERY_CODE_COUNT)
    .meta({ description: 'How many unused codes are left.' }),
  issuedAt: z.iso
    .datetime()
    .nullable()
    .meta({ description: 'When the current set was issued; `null` without one.' }),
});

export function registerAccountRecoveryCodeRoutes(
  fastify: FastifyInstance,
  factors: AccountFactors
): void {
  const read = accountOperation({
    operationId: 'account.recoveryCodes.get',
    operationClass: 'read',
    permission: 'recoveryCodes.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  const regenerate = accountOperation({
    operationId: 'account.recoveryCodes.regenerate',
    operationClass: 'write',
    permission: 'recoveryCodes.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
  });
  const tags = ['Account API'];

  fastify.get('/recovery-codes', {
    preValidation: read.guard,
    schema: {
      description:
        "How many of the token's user's recovery codes are left, and when the set was issued. Never the codes.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...read.schema,
      'x-qauth-errors': [400, 401, 403],
      response: { 200: recoveryCodeStatusSchema },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const summary = await readRecoveryCodeSummary(
        fastify,
        requestRealm(request).id,
        tokenUserIdOf(request)
      );
      return reply.send({
        remaining: Math.min(summary.remaining, RECOVERY_CODE_COUNT),
        issuedAt: rfc3339OrNull(summary.issuedAt),
      });
    },
  });

  fastify.post('/recovery-codes/regenerate', {
    preValidation: regenerate.guard,
    schema: {
      description:
        'Issue a new set of ten recovery codes for the token\'s user, answered once; every code of the old set stops working. Needs a fresh sign-in with the account\'s strongest factor and refuses an act-chain token. An account without a second factor or a passkey is 409 conflict. The "recovery codes regenerated" notice goes out.',
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...regenerate.schema,
      'x-qauth-errors': [400, 401, 403, 409],
      response: { 200: recoveryCodeSetSchema },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const set = await regenerateAnsweredRecoveryCodes(fastify, request, factors, {
        realmId: requestRealm(request).id,
        userId: tokenUserIdOf(request),
        clientId: request.jwtPayload?.clientId ?? null,
      });
      if (set === 'conflict') throw new AccountFactorConflictError('no second factor');
      return reply.send(toRecoveryCodeSet(set));
    },
  });
}
