import { getEventType, parseEvent, type RegisteredEventType } from '@qauth-labs/shared-events';
import type { FastifyRequest } from 'fastify';

import type { userEventFor, UserEventOptions } from '../app/helpers/user-events';

/** The realm a checked event is built in when the test names none that is a UUID. */
export const CHECKED_EVENT_REALM_ID = '00000000-0000-4000-8000-000000000001';

/** The id a checked emitter returns, a UUIDv7. */
export const CHECKED_EVENT_ID = '01920000-0000-7000-8000-000000000001';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * A stand-in for `emitUserEvent` in a unit test that mocks it: it builds the
 * event the real emitter would write and checks it against the event contract
 * (`parseEvent`: the type, the payload's schema, the payload rules and the
 * subject), but writes nothing. A route whose event would be refused at run
 * time fails its unit test instead.
 *
 * Wrap it in `vi.fn` inside the test's `vi.mock` factory:
 *
 * ```ts
 * vi.mock('../../helpers/user-events', async (importOriginal) => {
 *   const actual = await importOriginal<typeof import('../../helpers/user-events')>();
 *   const { checkedEmitUserEvent } = await import('../../../testing/user-events');
 *   return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
 * });
 * ```
 *
 * @param build - the real `userEventFor`, from the module's original exports
 */
export function checkedEmitUserEvent(build: typeof userEventFor) {
  return async <Type extends RegisteredEventType>(
    request: FastifyRequest,
    type: Type,
    data: Parameters<typeof userEventFor<Type>>[2],
    options: UserEventOptions = {}
  ): Promise<string> => {
    const realmId =
      typeof options.realmId === 'string' && UUID.test(options.realmId)
        ? options.realmId
        : CHECKED_EVENT_REALM_ID;
    const event = build(request, type, data, options, realmId);
    parseEvent({
      id: CHECKED_EVENT_ID,
      time: new Date(0).toISOString(),
      category: getEventType(type)?.category,
      ...event,
    });
    return CHECKED_EVENT_ID;
  };
}
