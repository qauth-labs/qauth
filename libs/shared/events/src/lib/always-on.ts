import { fieldNameWords } from './payload-rules';

/**
 * Admin events are always on (ADR-020 §3, issues #459 and #827): no
 * environment key and no realm setting turns them off. Nothing in the code
 * reads such a switch, and these helpers keep one from being added
 * unnoticed: the configuration key registry's tests and the realm tables'
 * run {@link findEventNames} over every name they hold.
 *
 * The check refuses by default. Any name that holds an event word is
 * reported, whatever its other words, unless the test that scans it lists the
 * name in its allow list with the reason it turns nothing off. A switch need
 * not say "enabled": `ADMIN_EVENTS=false`, `AUDIT_LOG=false`,
 * `EVENT_STORE_MODE=off` and `EVENTS_SINK=none` are switches too.
 *
 * The check reads names, so it is a gate, not a proof: a name that holds no
 * event word, or a member of a free-form `jsonb` column that no type
 * declares, is not seen.
 */

/** Words that name events, the event store, the audit log or where events go. */
export const EVENT_WORDS: ReadonlySet<string> = new Set([
  'event',
  'events',
  'audit',
  'audits',
  'log',
  'logs',
  'logging',
  'logger',
  'sink',
  'sinks',
  'outbox',
  'journal',
]);

/**
 * Beginnings of a word that name events or the audit log in any form,
 * written with or without a separator: `AUDITING`, `AUDITLOG_ENABLED`,
 * `EVENTSTORE_MODE`. Only at the start of a word, so `prevent` is no event
 * word; `log` is matched as whole words only, as `login` and `logo` are not.
 */
const EVENT_WORD_STARTS: readonly string[] = ['event', 'audit'];

/**
 * Whether a configuration key or a realm field names events, the audit log or
 * where events go: one of its words is an {@link EVENT_WORDS} word or starts
 * like one ({@link EVENT_WORD_STARTS}), as in `ADMIN_EVENTS`, `AUDIT_LOG`,
 * `EVENTS_SINK`, `ADMIN_LOGGING` or `metadata.auditEnabled`.
 */
export function namesEvents(name: string): boolean {
  return fieldNameWords(name).some(
    (word) => EVENT_WORDS.has(word) || EVENT_WORD_STARTS.some((start) => word.startsWith(start))
  );
}

/**
 * The names that name events and are not in `allowed`, in the order given,
 * each once.
 *
 * @param names - Every key or field name a configuration surface holds.
 * @param allowed - Names that hold an event word but turn nothing off, each
 *   with the reason.
 * @throws TypeError when an allowed name gives no reason
 */
export function findEventNames(
  names: Iterable<string>,
  allowed: Readonly<Record<string, string>> = {}
): string[] {
  for (const [name, reason] of Object.entries(allowed)) {
    if (typeof reason !== 'string' || reason.trim() === '') {
      throw new TypeError(`findEventNames: "${name}" is allowed without a reason`);
    }
  }
  return [...new Set(names)].filter((name) => namesEvents(name) && !Object.hasOwn(allowed, name));
}
