import { signInAuditEvent } from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import type { AuthorizeQuery } from '../schemas/oauth';
import { accountPoliciesOf } from './account-policies';
import type { BackgroundTasks } from './background-tasks';
import type { StartInteractionInput } from './interaction';
import {
  createInteractionEngines,
  decisionOf,
  type InteractionEngines,
} from './interaction-engines';
import { EVENT_CLIENT_ID_MAX_LENGTH } from './interaction-record';
import { ladderEndUserIp } from './password-attempts';
import type { RealmRow } from './request-realm';
import { roundEnvironment } from './round-limits';
import { emitUserEvent } from './user-events';

/** What a passkey-first start puts in the interaction in place of the identifier step. */
export type PasskeyFirstStart = Required<
  Pick<StartInteractionInput, 'step' | 'personal' | 'signInTransaction'>
>;

/** Starts a sign-in interaction passkey-first, or answers `null` for the identifier step. */
export type PasskeyFirstStarter = (
  request: FastifyRequest,
  reply: FastifyReply,
  realm: RealmRow,
  query: AuthorizeQuery
) => Promise<PasskeyFirstStart | null>;

/**
 * Passkey-first on the hosted pages (#651; ADR-017 Decision 4): while
 * passkey sign-in is on, an authorization request's sign-in with no
 * `login_hint` starts at the sign-in engine's first round, not at the
 * identifier step every sign-in otherwise starts at. That round reads no
 * account: it asks for a discoverable passkey (`webauthn_get`, whose
 * ceremony it holds in the engine's transaction) and offers the password,
 * the identifier and the realm's upstream providers beside it. Like every
 * round it waits the engine's timing floor.
 *
 * With a `login_hint`, or with passkey sign-in off, the answer is `null`: the
 * identifier step, the hint as its prefill, from which the engine asks for
 * the password and offers the passkey beside it, the same for every account.
 * So is a first round that could not offer a step (a store it needs failed):
 * the sign-in still starts, without the passkey first.
 *
 * The engines are built on the first such request; `tasks` must have been
 * created while the route registered (their mail registers a hook).
 */
export function passkeyFirstStarter(
  fastify: FastifyInstance,
  tasks: BackgroundTasks
): PasskeyFirstStarter {
  let engines: InteractionEngines | undefined;
  return async (request, reply, realm, query) => {
    if (fastify.passkeySignIn !== true || query.login_hint !== undefined) return null;
    if (query.prompt === 'create') return null;
    engines ??= createInteractionEngines(fastify, { tasks });
    const built = engines;
    const clientId = query.client_id;
    const eventClientId = clientId.length <= EVENT_CLIENT_ID_MAX_LENGTH ? clientId : null;
    const environment = await roundEnvironment(fastify, realm, clientId);
    const result = await built.forRequest(request, () =>
      built.of(accountPoliciesOf(fastify, realm).requireVerifiedAccount).advance(null, null, {
        realm: { id: realm.id },
        client: { id: clientId },
        ...(query.prompt === 'login' || query.max_age !== undefined ? { freshSignIn: true } : {}),
        receivedAt: Date.now(),
        ...ladderEndUserIp(request),
        environment,
        // The first round answers nothing, so it starts no provider; the
        // starter only tells the engine that this transport can, so the
        // providers are offered beside the passkey. The answer round starts
        // the one picked, with its own starter.
        startUpstream: async () => {
          throw new Error('the first sign-in round starts no upstream provider');
        },
        audit: async (record) => {
          const event = signInAuditEvent(record);
          await emitUserEvent(request, event.type, event.data, {
            realmId: realm.id,
            clientId: eventClientId,
            userId: event.userId,
            actor: 'user',
          });
        },
      })
    );
    if (result.kind !== 'step') {
      fastify.log.warn(
        { realmId: realm.id, result: result.kind },
        'the first sign-in round offered no step: the sign-in starts at the identifier'
      );
      return null;
    }
    const decided = decisionOf(reply, result, Date.now());
    if (decided.kind !== 'step' || decided.signInTransaction == null) return null;
    return {
      step: decided.step,
      personal: decided.personal ?? {},
      signInTransaction: decided.signInTransaction,
    };
  };
}
