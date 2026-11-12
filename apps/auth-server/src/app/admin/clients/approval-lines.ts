import { isDeepStrictEqual } from 'node:util';

import type { RenderedField } from '../../helpers/admin-operations';
import { CLIENT_FIELDS, type ClientFieldName, type ClientFieldProblem } from './fields';
import type { AdminClient } from './representation';

/**
 * THE LINES AN APPROVER IS SHOWN OF A CLIENT CHANGE (#632): every change in
 * full, or no approval at all.
 *
 * An approver sees only the display the approval stored (#901), and the
 * display cuts a longer value to `…` (`admin/approvals/display.ts`). A cut
 * value could hide what the change writes: the third redirect URI behind a
 * padded second one. So a list is shown one entry per line, each one added
 * or removed, a key set one key per line, and a change that would need more
 * lines than the display holds, or a value longer than one line shows, is
 * refused before it is filed: an update in its state check (422), a
 * registration by its body schema (400). The renderers draw the same lines.
 *
 * Kept apart from `./operations.ts` so the route schemas can use it too; it
 * imports no value from the registry or the approval engine, which import
 * the operations.
 */

/**
 * The longest value a line shows in full: the display's cap
 * (`DISPLAY_LIMITS.value`, 1000 code points), with every code point outside
 * printable ASCII counted as the longest escape the display may write for it.
 */
const LINE_VALUE_MAX = 1000;
/** The display's cap on the lines of one approval (`DISPLAY_LIMITS.fields`). */
const LINES_MAX = 50;
/** The length the display may give one code point it escapes (`\u{10ffff}`). */
const LONGEST_ESCAPE = 10;

/** Whether `text` is shown in full: its longest escaped form fits one line. */
function fitsLine(text: string): boolean {
  let length = 0;
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if (character === '\\') length += 2;
    else if (code >= 0x20 && code <= 0x7e) length += 1;
    else length += LONGEST_ESCAPE;
    if (length > LINE_VALUE_MAX) return false;
  }
  return true;
}

/** A value as one line shows it: a string as it is, anything else as JSON. */
export function shownValue(value: unknown): string {
  return typeof value === 'string' ? value : (JSON.stringify(value) ?? 'null');
}

/** The lines of a change, and what keeps them from being shown in full. */
export interface ClientChangeLines {
  readonly fields: readonly RenderedField[];
  readonly problems: readonly ClientFieldProblem[];
}

/** The fields whose value is a list of strings, shown one entry per line. */
const LIST_FIELDS: ReadonlySet<ClientFieldName> = new Set<ClientFieldName>([
  'redirectUris',
  'postLogoutRedirectUris',
  'scopes',
  'clientCredentialsScopes',
  'grantTypes',
  'responseTypes',
]);

const listOf = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

/** The keys of a key set, or none. */
const keysOf = (value: unknown): unknown[] =>
  typeof value === 'object' && value !== null && Array.isArray((value as { keys?: unknown }).keys)
    ? (value as { keys: unknown[] }).keys
    : [];

/** The entries of `after` not in `before`, by value. */
const missingFrom = (from: readonly unknown[], entries: readonly unknown[]): unknown[] =>
  entries.filter((entry) => !from.some((other) => isDeepStrictEqual(entry, other)));

/** Collect `fields`, refusing each value that would not be shown in full. */
class LineCollector {
  readonly fields: RenderedField[] = [];
  readonly problems: ClientFieldProblem[] = [];

  add(name: ClientFieldName, field: RenderedField): void {
    const cut = [field.value, field.before].some((text) => text !== undefined && !fitsLine(text));
    if (cut) {
      this.problems.push({
        pointer: `/${name}`,
        message: `${name} holds a value too long to show an approver in full: an approval shows every value whole`,
      });
    }
    this.fields.push(field);
  }

  /** The lines, refused as a whole when there are more than the display holds. */
  done(headerLines: number): ClientChangeLines {
    const problems = [...this.problems];
    if (this.fields.length + headerLines > LINES_MAX) {
      problems.push({
        pointer: '',
        message: `the change needs ${this.fields.length} lines to show an approver, more than ${LINES_MAX - headerLines}: file it as smaller changes, each shown in full`,
      });
    }
    return { fields: this.fields, problems };
  }
}

/** A list or key set that is set where it was null, or the reverse. */
function presenceLine(name: ClientFieldName, before: unknown, after: unknown): RenderedField {
  const state = (value: unknown) =>
    value === null
      ? 'null'
      : `${name === 'jwks' ? keysOf(value).length : listOf(value).length} entries`;
  return { label: name, before: state(before), value: state(after) };
}

/**
 * The lines of a change from `state` to `client`, after `headerLines` lines
 * that name the client: each changed field in the order of the field table;
 * a list as the entries it removes and adds, a key set as its keys, any
 * other field beside the value it replaces.
 */
export function clientChangeLines(
  state: AdminClient,
  client: AdminClient,
  headerLines: number
): ClientChangeLines {
  const lines = new LineCollector();
  for (const name of Object.keys(CLIENT_FIELDS) as ClientFieldName[]) {
    if (CLIENT_FIELDS[name].class === 'read-only') continue;
    const before = state[name];
    const after = client[name];
    if (isDeepStrictEqual(before, after)) continue;
    if (LIST_FIELDS.has(name) || name === 'jwks') {
      const entries = name === 'jwks' ? keysOf : listOf;
      const label = name === 'jwks' ? 'jwks key' : name;
      if (before === null || after === null) lines.add(name, presenceLine(name, before, after));
      for (const entry of missingFrom(entries(after), entries(before))) {
        lines.add(name, { label: `${label} removed`, value: shownValue(entry) });
      }
      for (const entry of missingFrom(entries(before), entries(after))) {
        lines.add(name, { label: `${label} added`, value: shownValue(entry) });
      }
      continue;
    }
    lines.add(name, { label: name, before: shownValue(before), value: shownValue(after) });
  }
  return lines.done(headerLines);
}

/**
 * The lines of a registration's settings, after `headerLines` lines: each
 * member the body names, in the order of the field table; a list one entry
 * per line, a key set one key per line.
 */
export function clientCreateLines(body: unknown, headerLines: number): ClientChangeLines {
  const named = (typeof body === 'object' && body !== null ? body : {}) as Record<string, unknown>;
  const lines = new LineCollector();
  for (const name of Object.keys(CLIENT_FIELDS) as ClientFieldName[]) {
    if (!Object.hasOwn(named, name)) continue;
    const value = named[name];
    if ((LIST_FIELDS.has(name) || name === 'jwks') && value !== null) {
      const entries = name === 'jwks' ? keysOf(value) : listOf(value);
      for (const entry of entries) {
        lines.add(name, { label: name === 'jwks' ? 'jwks key' : name, value: shownValue(entry) });
      }
      continue;
    }
    lines.add(name, { label: name, value: shownValue(value) });
  }
  return lines.done(headerLines);
}

/** The lines that name the client of an update, a deletion or a switch. */
export const CLIENT_HEADER_LINES = 2;

/** The lines a registration starts with: what it does. */
export const CREATE_HEADER_LINES = 1;
