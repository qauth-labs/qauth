import { ANY_CLIENT } from '@qauth-labs/shared-validation';

import type { RenderedField } from '../../helpers/admin-operations';
import type { AdminResourceServer, AdminResourceServerScope } from './representation';

/**
 * THE LINES AN APPROVER IS SHOWN OF A RESOURCE SERVER CHANGE (#1087): every
 * change in full, or no approval at all, as for a client (`../clients/approval-lines.ts`).
 *
 * An approver sees only the display the approval stored (#901), and the
 * display cuts a longer value to `…` (`admin/approvals/display.ts`). A cut
 * value could hide what the change grants: a scope behind a padded consent
 * text, a client behind another. So each scope is a line of its own, with
 * whether it is sensitive in its label, each of its consent texts a line,
 * naming the scope and the locale, and each listed client a line. A change
 * that needs more lines than the display holds, or a value longer than one
 * line shows, is refused before it is filed: an update or its preview in its
 * state check (422), a registration by its body schema (400). The renderers
 * draw the same lines.
 *
 * The resource indicator is the one value split over lines, each marked as
 * its part, when it is longer than one line: it names the resource server an
 * approval acts on, so a long one stored by the seed manifest never blocks
 * its own change or deletion.
 *
 * Kept apart from `./operations.ts` so the route schemas can use it too; it
 * imports no value from the registry or the approval engine, which import
 * the operations.
 */

/** The longest value a line shows in full: the display's cap (`DISPLAY_LIMITS.value`). */
const LINE_VALUE_MAX = 1000;
/** The display's cap on the lines of one approval (`DISPLAY_LIMITS.fields`). */
const LINES_MAX = 50;
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
 * escape for any other, combining marks and spaces besides U+0020 included.
 * A consent text in any script so fits as its length says.
 */
function shownLength(character: string): number {
  if (character === '\\') return 2;
  const code = character.codePointAt(0) ?? 0;
  if (code >= 0x20 && code <= 0x7e) return 1;
  if (SHOWN_AS_IS.test(character) && !ESCAPED_ANYWAY.test(character)) return 1;
  return LONGEST_ESCAPE;
}

/** Whether `text` is shown in full: its longest shown form fits one line. */
function fitsLine(text: string): boolean {
  let length = 0;
  for (const character of text) {
    length += shownLength(character);
    if (length > LINE_VALUE_MAX) return false;
  }
  return true;
}

/** `text` in the parts it is shown in, each one fitting a line. */
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

/** What a line shows for a resource server open to every client of the realm. */
export const ANY_CLIENT_LINE =
  'any client of the realm, those registered from a metadata document and dynamically registered ones included';

/** One refused member: a JSON Pointer into the body, and why. */
export interface ResourceServerLineProblem {
  readonly pointer: string;
  readonly message: string;
}

/** The lines of a change, and what keeps them from being shown in full. */
export interface ResourceServerLines {
  readonly fields: readonly RenderedField[];
  readonly problems: readonly ResourceServerLineProblem[];
}

/** Who may ask, as the lines read it: `any_client` or the listed `client_id`s. */
type Clients = AdminResourceServer['clients'];

/** A scope as a body or a state holds it: `sensitive` may be absent in a body. */
type ScopeEntry = Pick<AdminResourceServerScope, 'scope' | 'text'> & {
  readonly sensitive?: boolean;
};

/** Collect `fields`, refusing each value that would not be shown in full. */
class LineCollector {
  readonly fields: RenderedField[] = [];
  readonly problems: ResourceServerLineProblem[] = [];

  add(pointer: string, field: RenderedField): void {
    const cut = [field.value, field.before].some((text) => text !== undefined && !fitsLine(text));
    if (cut) {
      this.problems.push({
        pointer,
        message: `${pointer.slice(1) || 'the change'} holds a value too long to show an approver in full: an approval shows every value whole`,
      });
    }
    this.fields.push(field);
  }

  /** The resource indicator, in as many lines as it needs, each marked as its part. */
  resource(resource: string): void {
    const parts = partsOf(resource);
    parts.forEach((part, index) =>
      this.fields.push({
        label: parts.length === 1 ? 'resource' : `resource, part ${index + 1} of ${parts.length}`,
        value: part,
      })
    );
  }

  /** The lines, refused as a whole when there are more than the display holds. */
  done(headerLines: number): ResourceServerLines {
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

/** A consent text as a line shows it: the scope it is for, then the text. */
const textLine = (scope: string, text: string): string => `${scope} — ${text}`;

/** Whether the realm flags `entry` as sensitive. */
const isSensitive = (entry: ScopeEntry): boolean => entry.sensitive === true;

/** A whole scope, a line for it and one for each of its consent texts. */
function addScope(lines: LineCollector, pointer: string, entry: ScopeEntry, label: string): void {
  lines.add(`${pointer}/scope`, {
    label: isSensitive(entry) ? `${label}, sensitive` : label,
    value: entry.scope,
  });
  for (const [locale, text] of Object.entries(entry.text)) {
    lines.add(`${pointer}/text`, {
      label: `consent text (${locale})`,
      value: textLine(entry.scope, text),
    });
  }
}

/** Each listed client, a line for each. */
function addClients(lines: LineCollector, clients: Clients, label: string): void {
  if (clients === ANY_CLIENT) {
    lines.add('/clients', { label: 'clients', value: ANY_CLIENT_LINE });
    return;
  }
  clients.forEach((clientId, index) => lines.add(`/clients/${index}`, { label, value: clientId }));
}

/**
 * The lines of a registration, after `headerLines` lines: the resource, each
 * scope with its consent texts, and who may ask for them, each whole.
 */
export function resourceServerCreateLines(body: unknown, headerLines: number): ResourceServerLines {
  const named = (typeof body === 'object' && body !== null ? body : {}) as {
    resource?: unknown;
    scopes?: unknown;
    clients?: unknown;
  };
  const lines = new LineCollector();
  if (typeof named.resource === 'string') lines.resource(named.resource);
  const scopes = Array.isArray(named.scopes) ? (named.scopes as ScopeEntry[]) : [];
  scopes.forEach((entry, index) => addScope(lines, `/scopes/${index}`, entry, 'scope'));
  if (named.clients === ANY_CLIENT || Array.isArray(named.clients)) {
    addClients(lines, named.clients as Clients, 'client');
  }
  return lines.done(headerLines);
}

/**
 * The lines of a change from `state` to `next`, after `headerLines` lines:
 * the resource it acts on; each scope removed, each one added whole, and for
 * a scope kept its sensitive flag and each consent text it changes, beside
 * the value it replaces; and who may ask, each client removed and added.
 */
export function resourceServerChangeLines(
  state: AdminResourceServer,
  next: { readonly scopes: readonly ScopeEntry[]; readonly clients: Clients },
  headerLines: number
): ResourceServerLines {
  const lines = new LineCollector();
  lines.resource(state.resource);

  const before = new Map(state.scopes.map((entry) => [entry.scope, entry]));
  const after = new Map(next.scopes.map((entry) => [entry.scope, entry]));
  state.scopes.forEach((entry, index) => {
    if (!after.has(entry.scope)) {
      lines.add(`/scopes/${index}`, { label: 'scope removed', value: entry.scope });
    }
  });
  next.scopes.forEach((entry, index) => {
    const pointer = `/scopes/${index}`;
    const was = before.get(entry.scope);
    if (was === undefined) {
      addScope(lines, pointer, entry, 'scope added');
      return;
    }
    if (isSensitive(was) !== isSensitive(entry)) {
      lines.add(`${pointer}/sensitive`, {
        label: 'sensitive',
        before: `${entry.scope}: ${isSensitive(was) ? 'yes' : 'no'}`,
        value: `${entry.scope}: ${isSensitive(entry) ? 'yes' : 'no'}`,
      });
    }
    for (const [locale, text] of Object.entries(was.text)) {
      if (!Object.hasOwn(entry.text, locale)) {
        lines.add(`${pointer}/text`, {
          label: `consent text removed (${locale})`,
          value: textLine(entry.scope, text),
        });
      }
    }
    for (const [locale, text] of Object.entries(entry.text)) {
      if (!Object.hasOwn(was.text, locale)) {
        lines.add(`${pointer}/text`, {
          label: `consent text added (${locale})`,
          value: textLine(entry.scope, text),
        });
      } else if (was.text[locale] !== text) {
        lines.add(`${pointer}/text`, {
          label: `consent text (${locale})`,
          before: textLine(entry.scope, was.text[locale]),
          value: textLine(entry.scope, text),
        });
      }
    }
  });

  const from = state.clients;
  const to = next.clients;
  if (from === ANY_CLIENT && to !== ANY_CLIENT) {
    lines.add('/clients', {
      label: 'clients',
      before: ANY_CLIENT_LINE,
      value: 'only the clients listed below',
    });
    addClients(lines, to, 'client listed');
  } else if (from !== ANY_CLIENT && to === ANY_CLIENT) {
    lines.add('/clients', {
      label: 'clients',
      before: 'only the clients listed',
      value: ANY_CLIENT_LINE,
    });
  } else if (from !== ANY_CLIENT && to !== ANY_CLIENT) {
    for (const clientId of from) {
      if (!to.includes(clientId))
        lines.add('/clients', { label: 'client removed', value: clientId });
    }
    to.forEach((clientId, index) => {
      if (!from.includes(clientId)) {
        lines.add(`/clients/${index}`, { label: 'client added', value: clientId });
      }
    });
  }
  return lines.done(headerLines);
}

/** A list, whole when it fits a line, or how many entries it holds. */
function listLine(label: string, values: readonly string[], noun: string): RenderedField {
  const whole = values.join(' ');
  return { label, value: fitsLine(whole) ? whole : `${values.length} ${noun}` };
}

/**
 * The lines of a deletion: the resource, whole, its scopes and who may ask
 * for them, each list whole when it fits a line and counted otherwise. A
 * deletion grants nothing, so nothing it removes keeps it from being filed.
 */
export function resourceServerDeleteLines(state: AdminResourceServer): readonly RenderedField[] {
  const lines = new LineCollector();
  lines.resource(state.resource);
  return [
    ...lines.fields,
    listLine(
      'scopes',
      state.scopes.map((entry) => entry.scope),
      'scopes'
    ),
    state.clients === ANY_CLIENT
      ? { label: 'clients', value: ANY_CLIENT_LINE }
      : listLine('clients', state.clients, 'clients'),
  ];
}

/** The lines a registration starts with: what it does. */
export const CREATE_HEADER_LINES = 1;

/** The lines an update starts with beside the resource: none. */
export const UPDATE_HEADER_LINES = 0;
