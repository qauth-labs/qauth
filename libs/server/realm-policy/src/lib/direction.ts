import type { Direction } from './field';

/**
 * Which way one change of a field moves (ADR-019 Decision 11: "the diff marks
 * each change as tightening, loosening or neutral").
 */
export type ChangeDirection = 'tightening' | 'loosening' | 'neutral';

const isNumber = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

/** The JSON text of `value` with every object's members sorted by name: equal values, equal text. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    const members = Object.keys(value)
      .sort()
      .map((name) => `${JSON.stringify(name)}:${canonicalJson(value[name])}`);
    return `{${members.join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

/**
 * The entries of a set-valued field, or `undefined` when the value is not a
 * list of strings or a list of objects. An object entry, such as a trusted
 * workload issuer (#526), is one entry by its whole value, whatever the order
 * of its members. The two kinds never compare equal, and a list that mixes
 * them is no set.
 */
export function entriesOf(value: unknown): ReadonlySet<string> | undefined {
  if (!Array.isArray(value)) return undefined;
  if (value.every((entry) => typeof entry === 'string')) {
    return new Set(value.map((entry) => `s${entry as string}`));
  }
  if (value.every(isRecord)) return new Set(value.map((entry) => `o${canonicalJson(entry)}`));
  return undefined;
}

function isSubsetOf(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  for (const entry of a) if (!b.has(entry)) return false;
  return true;
}

/** Whether two values are the same set of entries, in any order. */
export function sameEntries(before: unknown, after: unknown): boolean {
  const a = entriesOf(before);
  const b = entriesOf(after);
  return a !== undefined && b !== undefined && a.size === b.size && isSubsetOf(a, b);
}

/**
 * The direction of a change from `before` to `after` under `direction`. The
 * caller has already found the two values different.
 *
 * FAIL CLOSED: a change this function cannot place counts as a loosening.
 * That covers an unknown direction kind, a value of the wrong type for its
 * direction (a string under `lower-is-stricter`, a list that mixes strings
 * with other entries), and a value outside an `ordered` direction's order. A set change
 * that both adds and removes entries adds one, so it loosens a
 * `subset-is-stricter` field; one that removes an entry loosens a
 * `superset-is-stricter` field whatever else it adds.
 */
export function compareDirection(
  direction: Direction,
  before: unknown,
  after: unknown
): ChangeDirection {
  const kind: unknown = typeof direction === 'string' ? direction : direction?.kind;
  switch (kind) {
    case 'opaque':
      return 'neutral';
    case 'lower-is-stricter':
    case 'higher-is-stricter': {
      if (!isNumber(before) || !isNumber(after) || before === after) return 'loosening';
      const lower = after < before;
      return lower === (kind === 'lower-is-stricter') ? 'tightening' : 'loosening';
    }
    case 'true-is-stricter':
    case 'false-is-stricter': {
      if (typeof before !== 'boolean' || typeof after !== 'boolean' || before === after) {
        return 'loosening';
      }
      return after === (kind === 'true-is-stricter') ? 'tightening' : 'loosening';
    }
    case 'ordered': {
      const order = (direction as { order?: unknown }).order;
      if (!Array.isArray(order)) return 'loosening';
      const from = order.indexOf(before);
      const to = order.indexOf(after);
      if (from === -1 || to === -1 || from === to) return 'loosening';
      return to > from ? 'tightening' : 'loosening';
    }
    case 'subset-is-stricter':
    case 'superset-is-stricter': {
      const a = entriesOf(before);
      const b = entriesOf(after);
      if (a === undefined || b === undefined) return 'loosening';
      // subset-is-stricter tightens only when nothing is added; superset-is-stricter
      // only when nothing is removed.
      const tightens = kind === 'subset-is-stricter' ? isSubsetOf(b, a) : isSubsetOf(a, b);
      return tightens ? 'tightening' : 'loosening';
    }
    default:
      return 'loosening';
  }
}
