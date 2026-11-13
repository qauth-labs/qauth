import { NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { type PageQuery, pageQuerySchema, pageSchema } from '../../api-conventions/paging';
import { rfc3339 } from '../../api-conventions/time';
import { LastCredentialError } from '../../helpers/account-operation-errors';
import { accountOperation } from '../../helpers/account-operation-guard';
import { createEngineMailer } from '../../helpers/engine-mail';
import { requestRealm } from '../../helpers/request-realm';
import { pageLinkedAccounts, unlinkUpstreamIdentity } from '../../helpers/upstream-links';
import { tokenUserIdOf } from './token-subject';

/**
 * The account API's linked upstream accounts (#670; ADR-020 Appendix "Linked
 * accounts", ADR-019 Decision 7): the upstream identities the token's user
 * can sign in through, and their removal. Linking one is no route here: it
 * runs on the realm host, as an authorization request with `qauth_link`,
 * where the person signs in to the account again (`helpers/upstream-sign-in.ts`).
 *
 *   GET    /linked-accounts                     — list, a page at a time
 *   DELETE /linked-accounts/{linkedAccountId}   — unlink one
 *
 * The unlink is a change to the ways into the account: a fresh sign-in with
 * the account's strongest factor, and no act-chain token (`accountOperation`).
 * One of another user, or no upstream identity, is 404 as one that does not
 * exist; the account's last way to sign in is 409 `last_credential`.
 */

/** One linked account, in the API conventions' representation. */
const linkedAccountSchema = z.object({
  id: z.uuid(),
  provider: z.string(),
  providerName: z.string().optional(),
  createdAt: z.iso.datetime(),
});

/** The path parameters of one linked account. */
const linkedAccountParamsSchema = z.object({ linkedAccountId: z.uuid() });

export function registerAccountLinkedAccountRoutes(fastify: FastifyInstance): void {
  // The unlink notice goes out after the answer, through the engine's mail;
  // its background tasks register a hook, so it is built at registration.
  const mailer = createEngineMailer(fastify);
  const list = accountOperation({
    operationId: 'account.linkedAccounts.list',
    operationClass: 'read',
    permission: 'linkedAccounts.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  const unlink = accountOperation({
    operationId: 'account.linkedAccounts.delete',
    operationClass: 'write',
    permission: 'linkedAccounts.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
  });
  const tags = ['Account API'];

  fastify.get<{ Querystring: PageQuery }>('/linked-accounts', {
    preValidation: list.guard,
    schema: {
      description:
        "List the upstream accounts linked to the token's user, newest first: the provider and when it was linked, never the identity's subject at the provider.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...list.schema,
      'x-qauth-errors': [400, 401, 403],
      querystring: pageQuerySchema,
      response: { 200: pageSchema(linkedAccountSchema) },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const page = await pageLinkedAccounts(
        fastify,
        requestRealm(request).id,
        tokenUserIdOf(request),
        {
          list: 'account.linkedAccounts',
          limit: request.query.limit,
          cursor: request.query.cursor,
        }
      );
      // Per-user data: keep it out of any shared or proxy cache.
      reply.header('Cache-Control', 'no-store');
      return reply.send({
        items: page.items.map((item) => ({
          id: item.id,
          provider: item.provider,
          ...(item.providerName === undefined ? {} : { providerName: item.providerName }),
          createdAt: rfc3339(item.createdAt),
        })),
        nextCursor: page.nextCursor,
      });
    },
  });

  fastify.delete<{ Params: { linkedAccountId: string } }>('/linked-accounts/:linkedAccountId', {
    preValidation: unlink.guard,
    schema: {
      description:
        "Unlink one of the token's user's upstream accounts: the account no longer signs in through its provider. Needs a fresh sign-in with the account's strongest factor and refuses an act-chain token. The account's last way to sign in is 409 last_credential; one of another user is 404, as one that does not exist.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...unlink.schema,
      'x-qauth-errors': [400, 401, 403, 404, 409],
      params: linkedAccountParamsSchema,
      response: { 204: z.null() },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const realm = requestRealm(request);
      const result = await unlinkUpstreamIdentity(fastify, request, {
        realm,
        userId: tokenUserIdOf(request),
        credentialId: request.params.linkedAccountId,
        mailer,
      });
      if (result.kind === 'not_found') {
        throw new NotFoundError('LinkedAccount', request.params.linkedAccountId);
      }
      if (result.kind === 'last_credential') throw new LastCredentialError();
      reply.code(204);
      return reply.send(null);
    },
  });
}
