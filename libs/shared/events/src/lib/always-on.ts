import { fieldNameWords } from './payload-rules';

/**
 * Admin events are always on (ADR-020 §3, issue #459): no environment key and
 * no realm setting turns them off. Nothing in the code reads such a switch,
 * and these helpers keep one from being added unnoticed: the configuration
 * key registry's tests and the realm table's run {@link findEventSwitches}
 * over every name they hold.
 *
 * The check reads names, so it is a gate, not a proof. A name that is about
 * events or the audit log and also reads like a switch is reported. A key
 * that only tunes delivery or retention, and turns nothing off, is listed by
 * the test that scans it, with the reason.
 */

/** Words that name events, the event store or the audit log. */
const EVENT_WORDS: ReadonlySet<string> = new Set([
  'event',
  'events',
  'audit',
  'audits',
  'outbox',
  'journal',
]);

/** Words that make a name a switch, or a way around one. */
const SWITCH_WORDS: ReadonlySet<string> = new Set([
  'enable',
  'enabled',
  'disable',
  'disabled',
  'on',
  'off',
  'switch',
  'toggle',
  'skip',
  'skipped',
  'suppress',
  'suppressed',
  'mute',
  'muted',
  'silence',
  'silent',
  'pause',
  'paused',
  'bypass',
  'noop',
  'optout',
]);

/**
 * Whether a configuration key or a realm field reads like a switch for
 * events or the audit log: one of its words names events and another a
 * switch, as in `ADMIN_EVENTS_ENABLED`, `auditLogDisabled` or `skipEvents`.
 */
export function namesAnEventSwitch(name: string): boolean {
  const words = fieldNameWords(name);
  return (
    words.some((word) => EVENT_WORDS.has(word)) && words.some((word) => SWITCH_WORDS.has(word))
  );
}

/**
 * The names that read like a switch for events or the audit log, in the
 * order given.
 *
 * @param names - Every key or field name a configuration surface holds.
 */
export function findEventSwitches(names: Iterable<string>): string[] {
  return [...names].filter(namesAnEventSwitch);
}
