/**
 * JSON Canonicalization Scheme, RFC 8785 (JCS).
 *
 * The admin audit log hashes each row over its canonical JSON (ADR-019
 * Decision 7, issue #448), so two writers, or a writer and a verifier reading
 * the row back from `jsonb`, must produce the same bytes for the same data.
 * JCS gives that: object members sorted by their UTF-16 code units, no
 * whitespace, strings escaped as ECMAScript's `JSON.stringify` escapes them,
 * and numbers in ECMAScript's shortest round-trip form (RFC 8785 §3.2).
 *
 * Input is restricted to the I-JSON data model (RFC 7493) that JCS assumes
 * and that `jsonb` stores: `null`, booleans, finite numbers, well-formed
 * strings, arrays and plain objects. Anything else throws, so a value that
 * would serialize one way here and another way on the way into `jsonb` (a
 * `Date`, a `Buffer`, `NaN`, a lone surrogate, a hole in an array) never
 * reaches a hash. As in `JSON.stringify`, an object member whose value is
 * `undefined` is absent.
 */

/** A lone UTF-16 surrogate: not well-formed Unicode, refused by I-JSON. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function serializeString(value: string, path: string): string {
  if (LONE_SURROGATE.test(value)) {
    throw new TypeError(`canonicalizeJson: lone surrogate in a string at ${path}`);
  }
  // ECMAScript's string serialization is the one RFC 8785 §3.2.2.2 specifies.
  return JSON.stringify(value);
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function serialize(value: unknown, path: string): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError(`canonicalizeJson: ${value} at ${path} is not a JSON number`);
      }
      // Number::toString, as RFC 8785 §3.2.2.3 specifies; -0 becomes "0".
      return JSON.stringify(value);
    case 'string':
      return serializeString(value, path);
    case 'object': {
      if (Array.isArray(value)) {
        // `map` skips a hole and `join` writes it as nothing, which is not
        // JSON, while `JSON.stringify` writes it as `null`: refuse it.
        const items: string[] = [];
        for (let index = 0; index < value.length; index += 1) {
          if (!Object.hasOwn(value, index)) {
            throw new TypeError(`canonicalizeJson: hole at ${path}[${index}]`);
          }
          items.push(serialize(value[index], `${path}[${index}]`));
        }
        return `[${items.join(',')}]`;
      }
      if (!isPlainObject(value)) {
        throw new TypeError(`canonicalizeJson: ${path} is not a plain object`);
      }
      // The default sort compares UTF-16 code units, which is the order
      // RFC 8785 §3.2.3 requires.
      const members = Object.keys(value)
        .filter((key) => value[key] !== undefined)
        .sort()
        .map((key) => `${serializeString(key, path)}:${serialize(value[key], `${path}.${key}`)}`);
      return `{${members.join(',')}}`;
    }
    default:
      throw new TypeError(`canonicalizeJson: ${path} is a ${typeof value}, not a JSON value`);
  }
}

/**
 * Serialize a JSON value to its RFC 8785 canonical form.
 *
 * @param value - `null`, a boolean, a finite number, a string, an array or a
 *   plain object, recursively.
 * @returns The canonical JSON text. Hash it as UTF-8.
 * @throws TypeError when the value holds anything outside the I-JSON model.
 */
export function canonicalizeJson(value: unknown): string {
  return serialize(value, '$');
}
