import { NotFoundError, PreconditionFailedError } from '@qauth-labs/shared-errors';
import { DISPLAY_TEXT_PATTERN } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import {
  entityTagOf,
  entityTagValue,
  ifMatchAllows,
  ifMatchHeadersSchema,
  MERGE_PATCH_MEDIA_TYPE,
  requireIfMatch,
  requireMergePatch,
} from '../../api-conventions/conditional-requests';
import { readPage } from '../../api-conventions/cursor';
import { type PageQuery, pageQuerySchema, pageSchema } from '../../api-conventions/paging';
import { rfc3339, rfc3339OrNull } from '../../api-conventions/time';
import { removeCredential, renamePasskey } from '../../helpers/account-credentials';
import {
  LastCredentialError,
  SecondFactorRequiredError,
} from '../../helpers/account-operation-errors';
import { accountOperation, type CredentialTarget } from '../../helpers/account-operation-guard';
import {
  accountCredentials,
  type AccountPasskey,
  passkeysOf,
} from '../../helpers/account-sign-in-methods';
import { createEngineMailer } from '../../helpers/engine-mail';
import { requestRealm } from '../../helpers/request-realm';
import { tokenUserIdOf } from './token-subject';

/**
 * The account API's passkeys (#1108; ADR-020 §1 and §3, ADR-017 Decision 8,
 * ADR-019 Decision 7): the passkeys bound to the token's user, their rename
 * and their removal, on the logic the hosted account page uses
 * (`helpers/account-credentials.ts`).
 *
 *   GET    /passkeys                 — list, newest first, a page at a time
 *   GET    /passkeys/{passkeyId}     — read one, with its ETag
 *   PATCH  /passkeys/{passkeyId}     — rename one (JSON Merge Patch, If-Match)
 *   DELETE /passkeys/{passkeyId}     — remove one
 *
 * Adding a passkey is no route here: the passkey's relying-party ID is the
 * realm host, so the ceremony runs in the ceremony app on the realm origin
 * (ADR-020 §1). A backend sends the person there with an authorization
 * request that asks for it (`qauth_action=setup_passkey`).
 *
 * A name is no credential, so the rename needs no fresh sign-in (ADR-020 §3);
 * like every change to a credential's record it refuses an act-chain token.
 * The removal needs a fresh sign-in with the account's strongest factor, or a
 * recovery code in place of a lost one; while the passkey is new (#1064), a
 * fresh sign-in with the password alone. It refuses the account's last way to
 * sign in (`last_credential`) and the last second factor the realm requires
 * (`second_factor_required`). A passkey of another user is 404, as one that
 * does not exist.
 */

/** The longest name the contract's `Passkey.nickname` holds. */
const NICKNAME_MAX_LENGTH = 64;

/** The name a passkey the person never named is shown with, as on the account page. */
export const UNNAMED_PASSKEY_NICKNAME = 'Passkey';

/** The contract's display text, compiled once. */
const DISPLAY_TEXT = new RegExp(DISPLAY_TEXT_PATTERN, 'u');

/**
 * What display text never carries: markup brackets, every character of the
 * Unicode category Other, and the Hangul fillers and the blank braille
 * pattern, which render as nothing.
 */
const NOT_SHOWN = /[<>\p{C}ᅟᅠ⠀ㅤﾠ]/gu;

/**
 * A passkey's name as the contract's display rule takes it (`x-qauth-display:
 * account`): one line, no markup, no control or format characters, at most
 * {@link NICKNAME_MAX_LENGTH} UTF-16 units, never cut inside a surrogate
 * pair. A passkey with no name, or one whose stored name is left blank, reads
 * as {@link UNNAMED_PASSKEY_NICKNAME}. A name set through this API already
 * meets the rule; one an older enrolment stored may not.
 */
export function displayNicknameOf(nickname: string | null): string {
  if (nickname === null) return UNNAMED_PASSKEY_NICKNAME;
  let cleaned = nickname
    .replace(NOT_SHOWN, '')
    .replace(/\p{Z}+/gu, ' ')
    .trim();
  if (cleaned.length > NICKNAME_MAX_LENGTH) {
    const last = cleaned.charCodeAt(NICKNAME_MAX_LENGTH - 1);
    const highSurrogate = last >= 0xd800 && last <= 0xdbff;
    cleaned = cleaned
      .slice(0, highSurrogate ? NICKNAME_MAX_LENGTH - 1 : NICKNAME_MAX_LENGTH)
      .trim();
  }
  return cleaned !== '' && DISPLAY_TEXT.test(cleaned) ? cleaned : UNNAMED_PASSKEY_NICKNAME;
}

/** A passkey, as the contract's `Passkey` states it. */
const passkeySchema = z.object({
  id: z.uuid(),
  nickname: z.string().min(1).max(NICKNAME_MAX_LENGTH),
  backedUp: z.boolean(),
  createdAt: z.iso.datetime(),
  lastUsedAt: z.iso.datetime().nullable(),
});

type PasskeyRepresentation = z.infer<typeof passkeySchema>;

/**
 * A rename, as the contract's `PasskeyPatch` states it: a JSON Merge Patch
 * (RFC 7396) whose one member is the new name, in display text. A member
 * left out keeps the name; `null` is no name the contract takes.
 */
const passkeyPatchSchema = z.strictObject({
  nickname: z
    .string()
    .min(1)
    .max(NICKNAME_MAX_LENGTH)
    .regex(DISPLAY_TEXT)
    .meta({ description: 'The new name, as display text.' })
    .optional(),
});

type PasskeyPatch = z.infer<typeof passkeyPatchSchema>;

/** The path parameters of one passkey. */
const passkeyParamsSchema = z.object({ passkeyId: z.uuid() });

type PasskeyParams = z.infer<typeof passkeyParamsSchema>;

/**
 * One passkey in the API's representation. The authenticator's maker
 * (`provider`) is left out: the server keeps no list to name it from an
 * AAGUID, and the contract leaves it out when it is unknown.
 */
function toRepresentation(passkey: AccountPasskey): PasskeyRepresentation {
  return {
    id: passkey.id,
    nickname: displayNicknameOf(passkey.nickname),
    backedUp: passkey.backedUp,
    createdAt: rfc3339(passkey.createdAt),
    lastUsedAt: rfc3339OrNull(passkey.lastUsedAt),
  };
}

/**
 * A passkey's `ETag`: the strong tag of its representation, `lastUsedAt`
 * left out. A sign-in with the passkey writes its last use, which no rename
 * reads: were it in the tag, every sign-in would make a pending rename stale.
 */
export function passkeyEntityTag(passkey: PasskeyRepresentation): string {
  return entityTagOf({ ...passkey, lastUsedAt: undefined });
}

/** The passkey a removal's path names, read before validation, for the guard's rule of a new one. */
function removedPasskeyOf(request: FastifyRequest): CredentialTarget | undefined {
  const params = request.params as Record<string, unknown> | undefined;
  const id = params?.['passkeyId'];
  return typeof id === 'string' && id.length > 0 ? { type: 'passkey', id } : undefined;
}

/** The account the token names, and the client it came through. */
function ownerOf(request: FastifyRequest) {
  return {
    realmId: requestRealm(request).id,
    userId: tokenUserIdOf(request),
    clientId: request.jwtPayload?.clientId ?? null,
  };
}

export function registerAccountPasskeyRoutes(fastify: FastifyInstance): void {
  // The "passkey removed" notice goes out after the answer, through the
  // engine's mail; its background tasks register a hook, so it is built at
  // registration.
  const mailer = createEngineMailer(fastify);
  const list = accountOperation({
    operationId: 'account.passkeys.list',
    operationClass: 'read',
    permission: 'passkeys.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  const read = accountOperation({
    operationId: 'account.passkeys.get',
    operationClass: 'read',
    permission: 'passkeys.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  const rename = accountOperation({
    operationId: 'account.passkeys.update',
    operationClass: 'write',
    permission: 'passkeys.write',
    freshAuthentication: 'none',
    actChain: 'refused',
  });
  const remove = accountOperation(
    {
      operationId: 'account.passkeys.delete',
      operationClass: 'write',
      permission: 'passkeys.write',
      freshAuthentication: 'strongest-factor-or-recovery-code',
      actChain: 'refused',
    },
    // A passkey still new (#1064): a fresh sign-in with the password removes it.
    { removing: removedPasskeyOf }
  );
  const tags = ['Account API'];

  /** The passkeys of the token's user, newest first. */
  const passkeysOfToken = async (request: FastifyRequest, now: number = Date.now()) =>
    passkeysOf(
      await accountCredentials(fastify, requestRealm(request).id, tokenUserIdOf(request)),
      now
    );

  fastify.get<{ Querystring: PageQuery }>('/passkeys', {
    preValidation: list.guard,
    schema: {
      description:
        "List the passkeys bound to the token's user, newest first: each one's name, whether it syncs to other devices, when it was added and when it last signed in. Adding one is no operation here: it runs in the ceremony app on the realm host, through an authorization request with `qauth_action=setup_passkey`.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...list.schema,
      'x-qauth-errors': [400, 401, 403],
      querystring: pageQuerySchema,
      response: { 200: pageSchema(passkeySchema) },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const passkeys = await passkeysOfToken(request);
      const page = await readPage<AccountPasskey, PasskeyRepresentation>(
        {
          list: 'account.passkeys',
          limit: request.query.limit,
          cursor: request.query.cursor,
          position: (passkey) => ({ at: passkey.createdAt, id: passkey.id }),
          item: toRepresentation,
        },
        async ({ limit, after }) =>
          passkeys
            .filter(
              (passkey) =>
                after === undefined ||
                passkey.createdAt < after.at ||
                (passkey.createdAt === after.at && passkey.id < after.id)
            )
            .slice(0, limit)
      );
      // `Cache-Control: no-store` comes from the account API's own hook.
      return reply.send(page);
    },
  });

  fastify.get<{ Params: PasskeyParams }>('/passkeys/:passkeyId', {
    preValidation: read.guard,
    schema: {
      description:
        "Read one of the token's user's passkeys, with the `ETag` a rename names. A passkey of another user is 404, as one that does not exist.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...read.schema,
      'x-qauth-errors': [400, 401, 403, 404],
      params: passkeyParamsSchema,
      response: { 200: passkeySchema },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const { passkeyId } = request.params;
      const passkey = (await passkeysOfToken(request)).find(
        (candidate) => candidate.id === passkeyId
      );
      if (passkey === undefined) throw new NotFoundError('Passkey', passkeyId);
      const representation = toRepresentation(passkey);
      return reply.header('ETag', passkeyEntityTag(representation)).send(representation);
    },
  });

  fastify.patch<{ Params: PasskeyParams; Body: PasskeyPatch }>('/passkeys/:passkeyId', {
    // The token first, then the media type and `If-Match`, all before the
    // body is validated: 401, then 415, then 428, then 400.
    preValidation: [rename.guard, requireMergePatch, requireIfMatch],
    schema: {
      description:
        "Rename one of the token's user's passkeys with a JSON Merge Patch (RFC 7396) of its `nickname`. `If-Match` must name the passkey's current `ETag`: 428 without it, 412 when the passkey changed since. A name is no credential, so it needs no fresh sign-in, but an act-chain token is refused. A passkey of another user is 404.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...rename.schema,
      'x-qauth-errors': [400, 401, 403, 404, 412, 415, 428],
      consumes: [MERGE_PATCH_MEDIA_TYPE],
      params: passkeyParamsSchema,
      headers: ifMatchHeadersSchema,
      body: passkeyPatchSchema,
      response: { 200: passkeySchema },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const { passkeyId } = request.params;
      const matches = (passkey: AccountPasskey) =>
        ifMatchAllows(
          request.headers['if-match'],
          entityTagValue(passkeyEntityTag(toRepresentation(passkey)))
        );
      const { nickname } = request.body;
      let passkey: AccountPasskey;
      if (nickname === undefined) {
        // A patch that changes nothing: the passkey as it is, under the same
        // precondition, and no event.
        const found = (await passkeysOfToken(request)).find(
          (candidate) => candidate.id === passkeyId
        );
        if (found === undefined) throw new NotFoundError('Passkey', passkeyId);
        if (!matches(found)) throw new PreconditionFailedError();
        passkey = found;
      } else {
        // Compared and written under the user's row lock, so no other change
        // lands between the version `If-Match` names and this write.
        const result = await renamePasskey(fastify, request, ownerOf(request), {
          id: passkeyId,
          nickname,
          precondition: matches,
        });
        if (result.kind === 'not_found') throw new NotFoundError('Passkey', passkeyId);
        if (result.kind === 'precondition_failed') throw new PreconditionFailedError();
        passkey = result.passkey;
      }
      const representation = toRepresentation(passkey);
      return reply.header('ETag', passkeyEntityTag(representation)).send(representation);
    },
  });

  fastify.delete<{ Params: PasskeyParams }>('/passkeys/:passkeyId', {
    preValidation: remove.guard,
    schema: {
      description:
        "Remove one of the token's user's passkeys. Needs a fresh sign-in with the account's strongest factor, or one that used a recovery code in place of a lost factor; a passkey still new (bound after a sign-in that proved only the password) is removed after a fresh sign-in with the password, and its removal ends the sessions whose sign-in bound or proved it, their codes and refresh tokens, the account's recovery codes and every sign-in in progress. Refuses an act-chain token. The account's last way to sign in is 409 last_credential; the last second factor the realm requires, 409 second_factor_required. The owner gets the \"passkey removed\" notice. A passkey of another user is 404.",
      tags,
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      ...remove.schema,
      'x-qauth-errors': [400, 401, 403, 404, 409, 503],
      params: passkeyParamsSchema,
      response: { 204: z.null() },
    },
    config: { surface: 'api' },
    handler: async (request, reply) => {
      const { passkeyId } = request.params;
      const result = await removeCredential(
        fastify,
        request,
        ownerOf(request),
        { type: 'passkey', id: passkeyId },
        mailer
      );
      switch (result.kind) {
        case 'removed':
          reply.code(204);
          return reply.send(null);
        case 'not_found':
          throw new NotFoundError('Passkey', passkeyId);
        case 'last_credential':
          throw new LastCredentialError();
        case 'second_factor_required':
          throw new SecondFactorRequiredError();
      }
    },
  });
}
