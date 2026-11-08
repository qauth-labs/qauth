import type { Classification, ClassifyInput, OperationClass } from './admin-operations';
import { PERMISSION_CLASSES } from './admin-scopes';

/**
 * The building blocks of a request-dependent `classify` (ADR-019 Decision 7,
 * #508): the order of the classes, the error a `classify` throws on a field
 * it has no rule for, and the field-table classifier a merge-patch operation
 * builds its `classify` from. `admin-operations.ts` re-exports them.
 *
 * They live apart from the registry so that an operation's definition module,
 * which the registry imports, can use them without importing the registry
 * back (#517): a module in that cycle would read the registry's operations
 * before they exist.
 */

/** The rank of a class: `read` < `write` < `security`. */
export const classRank = (operationClass: OperationClass): number =>
  PERMISSION_CLASSES.indexOf(operationClass);

/** The strictest of `classes`, or `undefined` for none. */
export function strictestClass(classes: Iterable<OperationClass>): OperationClass | undefined {
  let strictest: OperationClass | undefined;
  for (const candidate of classes) {
    if (strictest === undefined || classRank(candidate) > classRank(strictest)) {
      strictest = candidate;
    }
  }
  return strictest;
}

const UNKNOWN_FIELD_BRAND = Symbol.for('qauth.adminOperations.unknownField');

/**
 * Thrown by a `classify` that meets a field it has no rule for. The request
 * then fails closed, with the reason `unknown-field`. Branded with a
 * registered symbol, not checked with `instanceof`, so a copy of this module
 * loaded twice (the E2E harness resets modules) still recognizes it.
 */
export class UnknownFieldError extends Error {
  override readonly name = 'UnknownFieldError';
  readonly [UNKNOWN_FIELD_BRAND] = true;

  constructor(readonly field: string) {
    super(`classify has no rule for the field ${JSON.stringify(field)}`);
  }
}

/** Whether `error` is an {@link UnknownFieldError}; `false` for a value whose brand cannot be read. */
export function isUnknownFieldError(error: unknown): boolean {
  try {
    return (
      typeof error === 'object' &&
      error !== null &&
      (error as Record<symbol, unknown>)[UNKNOWN_FIELD_BRAND] === true
    );
  } catch {
    return false;
  }
}

/**
 * The classification of a request made of several changes: the strictest
 * class, and every effect and permission of any change. Pure;
 * {@link classifyRequest} checks the result.
 */
export function mergeClassifications(parts: readonly Classification[]): Classification {
  return {
    class: strictestClass(parts.map((part) => part.class)) ?? 'read',
    effects: [...new Set(parts.flatMap((part) => part.effects))],
    permissions: [...new Set(parts.flatMap((part) => part.permissions))],
  };
}

/** A JSON Pointer token (RFC 6901): `~` and `/` escaped. */
const pointerToken = (key: string): string => key.replace(/~/g, '~0').replace(/\//g, '~1');

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

/**
 * The fields a JSON Merge Patch (RFC 7396) changes, as JSON Pointers
 * (`/passwordPolicy/minLength`), walked from the BODY's own keys, never from a
 * list of fields the classifier expects: so a field the classifier has no
 * rule for still comes out, and {@link classifyByField} fails it closed.
 *
 * - A member whose value is a non-empty plain object is walked into.
 * - Every other member is a changed field: a primitive, an array (an array
 *   replaces the target's array whole, so it is one leaf), `null` (which
 *   removes the member) and an empty object (which may replace a non-object
 *   member).
 * - A body that is not a plain object replaces the whole target: `['']`.
 *   An absent body changes nothing: `[]`.
 *
 * The canonical `changedFields` of a request-dependent operation whose
 * request is a merge patch.
 */
export function mergePatchLeafPaths(body: unknown): string[] {
  if (body === undefined) return [];
  if (!isPlainObject(body)) return [''];
  const paths: string[] = [];
  const pending: Array<[string, Record<string, unknown>]> = [['', body]];
  while (pending.length > 0) {
    const [prefix, object] = pending.pop() as [string, Record<string, unknown>];
    for (const key of Object.keys(object)) {
      const path = `${prefix}/${pointerToken(key)}`;
      const value = object[key];
      if (isPlainObject(value) && Object.keys(value).length > 0) {
        pending.push([path, value]);
      } else {
        paths.push(path);
      }
    }
  }
  return paths.sort();
}

/** A field's classification, fixed or computed from the request and the state. */
export type FieldRule<State> =
  | Classification
  | ((request: ClassifyInput, currentState: State) => Classification);

/** How {@link classifyByField} classifies a request. */
export interface FieldClassifierSpec<State> {
  /** The fields one request changes, such as the leaf paths of a merge patch. */
  changedFields(request: ClassifyInput, currentState: State): Iterable<string>;
  /** Each field's classification. A changed field without an entry fails the request closed. */
  readonly fields: Readonly<Record<string, FieldRule<State>>>;
  /** The classification of a request that changes no field. */
  readonly unchanged: Classification;
}

/**
 * A `classify` built from a table of fields: each changed field is classified
 * by its entry, and the request needs what all of them need together
 * ({@link mergeClassifications}). A field the table does not hold, as an own
 * entry, throws {@link UnknownFieldError}, so the request fails closed: an
 * unknown field counts as a security change, never as a write.
 */
export function classifyByField<State>(
  spec: FieldClassifierSpec<State>
): (request: ClassifyInput, currentState: State) => Classification {
  return (request, currentState) => {
    const parts: Classification[] = [];
    for (const field of spec.changedFields(request, currentState)) {
      if (!Object.hasOwn(spec.fields, field)) throw new UnknownFieldError(field);
      const rule = spec.fields[field];
      parts.push(typeof rule === 'function' ? rule(request, currentState) : rule);
    }
    return parts.length === 0 ? spec.unchanged : mergeClassifications(parts);
  };
}
