import { NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { type PageQuery, pageQuerySchema, pageSchema } from '../../api-conventions/paging';
import { rfc3339 } from '../../api-conventions/time';
import { accountOperation } from '../../helpers/account-operation-guard';
import {
  type AccountSessionOwner,
  endAccountSession,
  endAllAccountSessions,
  pageAccountSessions,
} from '../../helpers/account-sessions';
import { deviceLabelOf } from '../../helpers/device-label';
import { requestRealm } from '../../helpers/request-realm';
import { tokenUserIdOf } from './token-subject';

/**
 * The account API's sessions (#1110; ADR-017 Decision 8, ADR-019 Decisions 3
 * and 7, ADR-020 §3): where the token's user is signed in, ending one of
 * those sessions, and signing out everywhere, on the logic the hosted account
 * page uses (`helpers/account-sessions.ts`).
 *
 *   GET    /sessions               — the live sessions, most recently used first
 *   DELETE /sessions/{sessionId}   — end one
 *   POST   /sessions/end-all       — sign out everywhere
 *
 * None needs a fresh sign-in, and each takes an act-chain token: ending a
 * session only takes access away (`accountOperation`). "This session" is the
 * one the token came through, by its `sid`. A session of another user, or
 * one that has ended, is 404, as one that does not exist.
 */

/** The longest device label the contract's `Device.label` holds. */
const DEVICE_LABEL_MAX_LENGTH = 96;

/** A UUID, as a token's `sid` names a session. */
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A session, as the contract's `Session` states it. */
const sessionSchema = z.object({
  id: z.uuid().meta({ description: 'The session’s id: its record’s, never the cookie value.' }),
  current: z.boolean().meta({
    description: 'Whether the token in this request was issued through this session (its `sid`).',
  }),
  createdAt: z.iso.datetime().meta({ description: 'When the session started.' }),
  lastSeenAt: z.iso.datetime().meta({ description: 'When it was last used.' }),
  device: z
    .object({
      label: z
        .string()
        .min(1)
        .max(DEVICE_LABEL_MAX_LENGTH)
        .meta({ description: 'A label from the user agent, such as `Firefox on Linux`.' }),
    })
    .meta({ description: 'The device the session came from.' }),
});

/**
 * "Sign out everywhere", as the contract's `EndAllSessionsRequest` states
 * it. The body is optional: none ends every session. The route takes it
 * nullish, since Fastify validates a request with no body as `null`.
 */
const endAllSessionsRequestSchema = z
  .strictObject({
    keepCurrent: z.boolean().default(false).meta({
      description: 'Keep the session this request’s token was issued through. Default: end it too.',
    }),
  })
  .meta({ description: '"Sign out everywhere".' });

/** The path parameters of one session. */
const sessionParamsSchema = z.object({ sessionId: z.uuid() });

type SessionParams = z.infer<typeof sessionParamsSchema>;

/** The end-all body as the handler sees it: none arrives as `null`. */
type EndAllSessionsBody = z.input<typeof endAllSessionsRequestSchema> | null | undefined;

/** The token's user, and the client and act chain the call came through. */
function ownerOf(request: FastifyRequest): AccountSessionOwner {
  const act = request.jwtPayload?.act;
  return {
    realmId: requestRealm(request).id,
    userId: tokenUserIdOf(request),
    clientId: request.jwtPayload?.clientId ?? null,
    ...(act === undefined || act === null ? {} : { act }),
  };
}

/** The session the token came through: its `sid`, when it names one. */
function tokenSessionIdOf(request: FastifyRequest): string | undefined {
  const sid = request.jwtPayload?.sid;
  if (typeof sid !== 'string') return undefined;
  const normalised = sid.toLowerCase();
  return SESSION_ID.test(normalised) ? normalised : undefined;
}

export function registerAccountSessionRoutes(fastify: FastifyInstance): void {
  const list = accountOperation({
    operationId: 'account.sessions.list',
    operationClass: 'read',
    permission: 'sessions.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  const end = accountOperation({
    operationId: 'account.sessions.delete',
    operationClass: 'write',
    permission: 'sessions.write',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  const endAll = accountOperation({
    operationId: 'account.sessions.endAll',
    operationClass: 'write',
    permission: 'sessions.write',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  const tags = ['Account API'];

  fastify.get<{ Querystring: PageQuery }>('/sessions', {
    preValidation: list.guard,
    schema: {
      description:
        "List the token's user's live browser sessions, most recently used first: each one's device label, when it started and when it was last used, and `current` on the one the token came through (its `sid`). Never the session's address or cookie.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...list.schema,
      'x-qauth-errors': [400, 401, 403],
      querystring: pageQuerySchema,
      response: { 200: pageSchema(sessionSchema) },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const currentSid = tokenSessionIdOf(request);
      const page = await pageAccountSessions(
        fastify,
        { realmId: requestRealm(request).id, userId: tokenUserIdOf(request) },
        {
          limit: request.query.limit,
          ...(request.query.cursor === undefined ? {} : { cursor: request.query.cursor }),
          ...(currentSid === undefined ? {} : { currentSid }),
        }
      );
      // `Cache-Control: no-store` comes from the account API's own hook.
      return reply.send({
        items: page.items.map((item) => ({
          id: item.sid,
          current: item.current,
          createdAt: rfc3339(item.createdAt),
          lastSeenAt: rfc3339(item.lastSeenAt),
          device: { label: deviceLabelOf(item.userAgent) },
        })),
        nextCursor: page.nextCursor,
      });
    },
  });

  fastify.delete<{ Params: SessionParams }>('/sessions/:sessionId', {
    preValidation: end.guard,
    schema: {
      description:
        "End one of the token's user's sessions: its cookie stops working, its refresh-token families end, and every app it signed in to with a back-channel logout URI is sent a logout token. Needs no fresh sign-in and takes an act-chain token: ending a session only takes access away. A session of another user, or one that has ended, is 404.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...end.schema,
      'x-qauth-errors': [400, 401, 403, 404],
      params: sessionParamsSchema,
      response: { 204: z.null() },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const { sessionId } = request.params;
      const result = await endAccountSession(fastify, request, ownerOf(request), sessionId);
      if (result.kind === 'not_found') throw new NotFoundError('Session', sessionId);
      reply.code(204);
      return reply.send(null);
    },
  });

  fastify.post<{ Body: EndAllSessionsBody }>('/sessions/end-all', {
    preValidation: endAll.guard,
    schema: {
      description:
        "Sign out everywhere: every session of the token's user ends, each app a session signed in to with a back-channel logout URI is sent a logout token, and every unredeemed code and refresh-token family of the user is revoked. The session the token came through stays only when `keepCurrent` is true. Needs no fresh sign-in and takes an act-chain token.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...endAll.schema,
      'x-qauth-errors': [400, 401, 403],
      body: endAllSessionsRequestSchema.nullish(),
      response: { 204: z.null() },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const keepSid = request.body?.keepCurrent === true ? tokenSessionIdOf(request) : undefined;
      await endAllAccountSessions(
        fastify,
        request,
        ownerOf(request),
        keepSid === undefined ? {} : { keepSid }
      );
      reply.code(204);
      return reply.send(null);
    },
  });
}
