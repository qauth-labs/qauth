import type { AuthMethodParameters } from './auth-method.interface';
import {
  MAX_AUTH_METHOD_PARAMETER_LENGTH,
  MAX_AUTH_METHOD_PARAMETER_VALUES,
  MAX_AUTH_METHOD_PARAMETERS,
} from './contract';

/**
 * The parameters a method's route handler sees (#599): the string and
 * string-list members of a parsed query or form, within the caps, in a
 * frozen object with no prototype, so a parameter named `__proto__` stays a
 * parameter. Anything else is dropped: a method that misses a parameter it
 * needs refuses the request.
 *
 * The route mount builds every handler's `query` and `form` with it, and the
 * contract test kit does the same, so a method meets in its tests exactly the
 * objects the host hands it.
 *
 * - at most {@link MAX_AUTH_METHOD_PARAMETERS} parameters, the first ones;
 * - a value longer than {@link MAX_AUTH_METHOD_PARAMETER_LENGTH} drops its
 *   parameter;
 * - a repeated parameter is a frozen list of at most
 *   {@link MAX_AUTH_METHOD_PARAMETER_VALUES} values; more drops it.
 *
 * @experimental
 */
export function authMethodParameters(value: unknown): AuthMethodParameters {
  const parameters = Object.create(null) as Record<string, string | readonly string[]>;
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    let count = 0;
    for (const [name, member] of Object.entries(value)) {
      if (count >= MAX_AUTH_METHOD_PARAMETERS) break;
      if (typeof member === 'string') {
        if (member.length > MAX_AUTH_METHOD_PARAMETER_LENGTH) continue;
        parameters[name] = member;
        count += 1;
      } else if (Array.isArray(member)) {
        const values = stringList(member);
        if (values === undefined) continue;
        parameters[name] = values;
        count += 1;
      }
    }
  }
  return Object.freeze(parameters);
}

/** A frozen copy of a list of capped strings, read by index; `undefined` otherwise. */
function stringList(member: readonly unknown[]): readonly string[] | undefined {
  const length: unknown = member.length;
  if (
    typeof length !== 'number' ||
    !Number.isSafeInteger(length) ||
    length > MAX_AUTH_METHOD_PARAMETER_VALUES
  ) {
    return undefined;
  }
  const values: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const item: unknown = member[index];
    if (typeof item !== 'string' || item.length > MAX_AUTH_METHOD_PARAMETER_LENGTH) {
      return undefined;
    }
    values[index] = item;
  }
  return Object.freeze(values);
}
