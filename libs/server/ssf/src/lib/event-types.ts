import { EVENT_TYPES, type EventTypeDefinition } from '@qauth-labs/shared-events';

/**
 * Which QAuth event types a stream can receive (issue #410).
 *
 * A registered type reaches SSF streams through its `ssf` slot: a type whose
 * slot names an SSF event URI is offered as that event. EVT-11 (#540) fills
 * the slots; until then no type has one, `events_supported` is empty and a
 * stream receives its verification events only.
 */

/** The SSF event URI of a registered type, or `undefined` when it has none. */
function ssfEventOf(definition: EventTypeDefinition): string | undefined {
  return typeof definition.ssf === 'object' ? definition.ssf.event : undefined;
}

/** The SSF event URIs the transmitter can send: its `events_supported`, sorted. */
export function ssfEventsSupported(
  definitions: readonly EventTypeDefinition[] = EVENT_TYPES
): string[] {
  const uris = new Set<string>();
  for (const definition of definitions) {
    const uri = ssfEventOf(definition);
    if (uri !== undefined) uris.add(uri);
  }
  return [...uris].sort();
}

/**
 * The QAuth event types whose SSF events are among `uris`: what the fan-out
 * gives a stream that requested `uris`. The verification event is never one:
 * it reaches only the stream that asked for it, not through the fan-out.
 */
export function eventTypesFor(
  uris: readonly string[],
  definitions: readonly EventTypeDefinition[] = EVENT_TYPES
): string[] {
  const wanted = new Set(uris);
  return definitions
    .filter((definition) => {
      const uri = ssfEventOf(definition);
      return uri !== undefined && wanted.has(uri);
    })
    .map((definition) => definition.type);
}
