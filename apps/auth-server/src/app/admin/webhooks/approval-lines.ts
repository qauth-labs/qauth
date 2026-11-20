import type { RenderedField } from '../../helpers/admin-operations';

/**
 * THE LINES AN APPROVER IS SHOWN OF A WEBHOOK SUBSCRIPTION CHANGE (#537):
 * every value whole, as for a client or a resource server
 * (`../resource-servers/approval-lines.ts`).
 *
 * An approver sees only the display the approval stored, and the display
 * cuts a longer value to `…` (`admin/approvals/display.ts`). A cut URL could
 * hide where the realm's events go. So the URL and the list of event types
 * are split over as many lines as they need, each marked as its part, and a
 * description, which an admin writes in any script, must fit one line: one
 * that does not is refused by the body schema (400) before it is filed.
 *
 * Kept apart from `./operations.ts` so the route schemas can use it too; it
 * imports no value from the registry or the approval engine.
 */

/** The longest value a line shows in full: the display's cap (`DISPLAY_LIMITS.value`). */
const LINE_VALUE_MAX = 1000;
/** The length the display may give one code point it escapes (`\u{10ffff}`). */
const LONGEST_ESCAPE = 10;

/** A letter, digit, punctuation mark or symbol: shown as it is, unless it renders as nothing. */
const SHOWN_AS_IS = /^[\p{L}\p{N}\p{P}\p{S}]$/u;
/** What the display escapes although it is a letter or a symbol (`UNSAFE_CODE_POINT`). */
const ESCAPED_ANYWAY = /^[\p{Default_Ignorable_Code_Point}⠀￼]$/u;

/**
 * The length the display gives `character` at most: one for a printable
 * ASCII character and for a letter, digit, punctuation mark or symbol it
 * shows as it is, two for a backslash, which it doubles, and the longest
 * escape for any other.
 */
function shownLength(character: string): number {
  if (character === '\\') return 2;
  const code = character.codePointAt(0) ?? 0;
  if (code >= 0x20 && code <= 0x7e) return 1;
  if (SHOWN_AS_IS.test(character) && !ESCAPED_ANYWAY.test(character)) return 1;
  return LONGEST_ESCAPE;
}

/** Whether `text` is shown in full on one line. */
export function fitsApprovalLine(text: string): boolean {
  let length = 0;
  for (const character of text) {
    length += shownLength(character);
    if (length > LINE_VALUE_MAX) return false;
  }
  return true;
}

/** `text` in the parts it is shown in, each fitting a line. */
function partsOf(text: string): string[] {
  const parts: string[] = [];
  let part = '';
  let length = 0;
  for (const character of text) {
    const next = shownLength(character);
    if (length + next > LINE_VALUE_MAX) {
      parts.push(part);
      part = '';
      length = 0;
    }
    part += character;
    length += next;
  }
  parts.push(part);
  return parts;
}

/** `items`, joined by `, `, packed into lines that each fit, an item never split unless it alone is too long. */
function packedLines(items: readonly string[]): string[] {
  const lines: string[] = [];
  let line = '';
  for (const item of items) {
    const next = line === '' ? item : `${line}, ${item}`;
    if (fitsApprovalLine(next)) {
      line = next;
      continue;
    }
    if (line !== '') lines.push(line);
    if (fitsApprovalLine(item)) {
      line = item;
    } else {
      const parts = partsOf(item);
      lines.push(...parts.slice(0, -1));
      line = parts[parts.length - 1] ?? '';
    }
  }
  lines.push(line);
  return lines;
}

/** `values` as lines labelled `label`, each marked as its part when there is more than one. */
function labelled(label: string, values: readonly string[]): RenderedField[] {
  return values.map((value, index) => ({
    label: values.length === 1 ? label : `${label}, part ${index + 1} of ${values.length}`,
    value,
  }));
}

/** The settings an approver is shown of a subscription. */
export interface WebhookShownSettings {
  readonly url: string;
  readonly description: string | null;
  readonly eventTypes: 'all' | readonly string[];
  readonly categories: readonly string[];
  readonly enabled: boolean;
}

/** What `eventTypes` reads as on a line. */
function eventTypesText(eventTypes: WebhookShownSettings['eventTypes']): readonly string[] {
  return eventTypes === 'all' ? ['every type of the categories'] : eventTypes;
}

/** The lines of the URL: one, or its parts. */
export function urlLines(label: string, url: string): RenderedField[] {
  return labelled(label, partsOf(url));
}

/** The lines of a subscription's settings, each value whole. */
export function settingsLines(settings: WebhookShownSettings): RenderedField[] {
  return [
    ...urlLines('url', settings.url),
    { label: 'description', value: settings.description ?? '(none)' },
    { label: 'categories', value: settings.categories.join(', ') },
    ...labelled('event types', packedLines(eventTypesText(settings.eventTypes))),
    { label: 'enabled', value: settings.enabled ? 'yes' : 'no' },
  ];
}

const sameList = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((value, index) => value === b[index]);

/**
 * The lines of a change from `before` to `after`: each member that changes,
 * with the value it replaces. The URL and the event types, which may need
 * more than a line, show what they were on lines of their own before what
 * they become.
 */
export function changeLines(
  before: WebhookShownSettings,
  after: WebhookShownSettings
): RenderedField[] {
  const fields: RenderedField[] = [];
  if (before.url !== after.url) {
    fields.push(...urlLines('url before', before.url), ...urlLines('url', after.url));
  } else {
    fields.push(...urlLines('url (unchanged)', after.url));
  }
  if (before.description !== after.description) {
    fields.push({
      label: 'description',
      value: after.description ?? '(none)',
      before: before.description ?? '(none)',
    });
  }
  if (!sameList(before.categories, after.categories)) {
    fields.push({
      label: 'categories',
      value: after.categories.join(', '),
      before: before.categories.join(', '),
    });
  }
  const typesBefore = eventTypesText(before.eventTypes);
  const typesAfter = eventTypesText(after.eventTypes);
  if (!sameList(typesBefore, typesAfter)) {
    fields.push(
      ...labelled('event types before', packedLines(typesBefore)),
      ...labelled('event types', packedLines(typesAfter))
    );
  }
  if (before.enabled !== after.enabled) {
    fields.push({
      label: 'enabled',
      value: after.enabled ? 'yes' : 'no',
      before: before.enabled ? 'yes' : 'no',
    });
  }
  return fields;
}
