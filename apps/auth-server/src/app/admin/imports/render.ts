import { displayText } from '../approvals/display';
import { type ImportChange, type ImportPlan, maskUrlCredentials } from './plan';

/**
 * THE TEXT OF AN IMPORT PLAN (ADR-019 Decision 11, issue #518): what the CLI
 * prints and the approval page shows, one line per change, grouped by
 * section in the plan's order.
 *
 * Each change line starts with two marks: `!` when it loosens (a change of
 * unknown direction counts as loosening), and `+` for an item created, `-`
 * for one deleted, `~` for a field changed. The line then names the item and
 * field, the value before and after, and in brackets its direction, its
 * class with its effects, and whether it describes the environment or needs
 * a secret. A created or deleted item lists its fields below it. Every value
 * is shown whole, as JSON; a secret field shows only `set` or `not set`, and
 * a URL's user name and password show as `***`: the text never holds a
 * secret. A control character or a mark that reorders text, which a file's
 * strings may hold, shows as a `\u{XXXX}` escape, so no line can be forged.
 */

/**
 * `line` as the approval display shows a string (`displayText`): a control,
 * a line break, a mark that reorders text and every other code point that
 * renders as nothing or cannot be vouched for escaped as `\u{XXXX}`, a
 * backslash doubled, and nothing cut. A file's `client_id` or realm name
 * could otherwise forge a line of the plan.
 */
const printable = (line: string): string => displayText(line, Number.POSITIVE_INFINITY);

/** The mark of a change that loosens. */
export const LOOSENING_MARK = '!';

const OP_MARKS: Readonly<Record<ImportChange['op'], string>> = Object.freeze({
  create: '+',
  delete: '-',
  update: '~',
});

/** A value as the text shows it: JSON, a URL's credentials masked. */
const shown = (value: unknown): string => JSON.stringify(maskUrlCredentials(value)) ?? 'null';

/** A secret field's value: whether one is set, never what it is. */
function shownSecret(value: unknown): string {
  return value === true || value === 'set' ? 'set' : 'not set';
}

/** What a change is, in brackets: its direction, class and effects, and its flags. */
function annotationOf(change: ImportChange): string {
  const parts = [
    change.direction,
    change.effects.length > 0 ? `${change.class}: ${change.effects.join(', ')}` : change.class,
  ];
  if (change.environmentBound) parts.push('describes the environment');
  if (change.needsSecret) parts.push('needs a secret');
  return `[${parts.join('; ')}]`;
}

/** The name of the item a change is about, within its section. */
const itemOf = (change: ImportChange): string =>
  change.key === null
    ? change.path
    : change.path === ''
      ? change.key
      : `${change.key} ${change.path}`;

/** The lines of one change. */
function changeLines(change: ImportChange): string[] {
  const marks = `${change.direction === 'loosening' ? LOOSENING_MARK : ' '} ${OP_MARKS[change.op]}`;
  if (change.op === 'update') {
    const before = change.secret ? shownSecret(change.before) : shown(change.before);
    const after = change.secret ? shownSecret(change.after) : shown(change.after);
    return [`${marks} ${itemOf(change)}: ${before} → ${after}  ${annotationOf(change)}`];
  }
  const item = change.op === 'create' ? change.after : change.before;
  const lines = [`${marks} ${itemOf(change)}  ${annotationOf(change)}`];
  if (typeof item === 'object' && item !== null && !Array.isArray(item)) {
    for (const [member, value] of Object.entries(item)) {
      lines.push(`      ${member}: ${shown(value)}`);
    }
  }
  return lines;
}

/** What applying the plan needs, in a line. */
function needsLine(plan: ImportPlan): string {
  if (plan.changes.length === 0) return 'Needs: nothing; applying it changes nothing.';
  const approval = plan.approvalRequired ? ', with an approval' : ', with no approval';
  return `Needs: ${plan.class}${approval}; scopes ${plan.scopes.join(', ')}; permissions ${plan.permissions.join(', ')}`;
}

/** How many changes move each way. */
function countsLine(plan: ImportPlan): string {
  const count = (direction: ImportChange['direction']) =>
    plan.changes.filter((change) => change.direction === direction).length;
  const total = plan.changes.length;
  return `${total} ${total === 1 ? 'change' : 'changes'}: ${count('loosening')} loosening (marked ${LOOSENING_MARK}), ${count('tightening')} tightening, ${count('neutral')} neutral`;
}

/** The text of `plan`, lines joined by `\n`, with a final newline. */
export function renderPlan(plan: ImportPlan): string {
  const lines = [
    `Import plan for realm ${plan.realmId}`,
    `Base: policies version ${plan.baseVersion}; prune: ${plan.prune ? 'yes, items the file leaves out are deleted' : 'no, items the file leaves out stay'}`,
    `Digest: ${plan.digest}`,
    needsLine(plan),
  ];
  if (plan.effects.length > 0) lines.push(`Effects: ${plan.effects.join(', ')}`);
  if (plan.changes.length === 0) {
    lines.push('', 'No change: the file matches the realm.');
  } else {
    lines.push(countsLine(plan));
    const sections = [...new Set(plan.changes.map((change) => change.section))];
    for (const section of sections) {
      const changes = plan.changes.filter((change) => change.section === section);
      lines.push('', `${section} (${changes.length})`);
      for (const change of changes) lines.push(...changeLines(change));
    }
  }
  if (plan.secretsToSet.length > 0) {
    lines.push('', `Secrets to set on the realm itself: ${plan.secretsToSet.join(', ')}`);
  }
  for (const warning of plan.warnings) lines.push('', `Warning: ${warning}`);
  return `${lines.map(printable).join('\n')}\n`;
}
