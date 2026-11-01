import { z } from 'zod';

import type { AuthMethod } from './auth-method.interface';
import { AuthMethodContractError } from './errors';

/**
 * The secret members of a method's config (#600, EXPERIMENTAL): the members
 * its `configSchema` marks `.meta({ writeOnly: true })`, such as a client
 * secret. The plugin runtime keeps them write-only: an admin sets or clears
 * one, the server stores it encrypted at rest, and no response, event or log
 * shows its value.
 *
 * The marks are read from the schema's JSON Schema, which Zod writes with
 * the metadata of every Zod copy of the same major version (Zod keeps one
 * registry for all of them), so a plugin that bundles its own Zod 4 is read
 * the same way.
 *
 * Supported: a secret is a string member (or a nullable one) of the config
 * object, at any depth of nested objects. A config whose schema is not an
 * object, or that marks a member inside a list, a union, a record or a
 * recursive schema, cannot be split into members safely: the method is
 * refused, so the boot fails rather than store a secret in the clear.
 *
 * @experimental
 */

/**
 * A secret member's path: its member names from the config's root, joined by
 * `.`, such as `clientSecret` or `mtls.keyPassword`.
 *
 * @experimental
 */
export type AuthMethodSecretPath = string;

/**
 * A member name a secret's path may hold: ASCII letters, digits, `_` and `-`,
 * starting with a letter, at most 64 characters. A name with a `.` would read
 * as two segments.
 *
 * @experimental
 */
export const AUTH_METHOD_SECRET_SEGMENT_PATTERN = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

/**
 * The most secret members a method's config may have.
 *
 * @experimental
 */
export const MAX_AUTH_METHOD_SECRET_MEMBERS = 16;

/**
 * The longest value a secret member may hold, in UTF-16 code units.
 *
 * @experimental
 */
export const MAX_AUTH_METHOD_SECRET_LENGTH = 8192;

type JsonSchemaNode = Readonly<Record<string, unknown>>;

const isNode = (value: unknown): value is JsonSchemaNode =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Whether `node`, or a branch of its `anyOf`/`oneOf`, is marked write-only. */
function marksWriteOnly(node: JsonSchemaNode): boolean {
  if (node['writeOnly'] === true) return true;
  return (['anyOf', 'oneOf'] as const).some((key) => {
    const branches = node[key];
    return Array.isArray(branches) && branches.some((b) => isNode(b) && b['writeOnly'] === true);
  });
}

/** Whether a write-only mark, or a `$ref`, appears anywhere in `node`. */
function holdsMarkOrRef(value: unknown, depth = 0): boolean {
  if (depth > 64) return true;
  if (Array.isArray(value)) return value.some((item) => holdsMarkOrRef(item, depth + 1));
  if (!isNode(value)) return false;
  if (value['writeOnly'] === true || '$ref' in value) return true;
  return Object.values(value).some((item) => holdsMarkOrRef(item, depth + 1));
}

/** Whether every branch of `node` is a string or `null`, with at least one string. */
function isStringMember(node: JsonSchemaNode): boolean {
  const branches = [node, ...['anyOf', 'oneOf'].flatMap((key) => (node[key] as unknown[]) ?? [])]
    .filter(isNode)
    .filter((branch) => branch['type'] !== undefined);
  const types = branches.flatMap((branch) =>
    Array.isArray(branch['type']) ? (branch['type'] as unknown[]) : [branch['type']]
  );
  return types.includes('string') && types.every((type) => type === 'string' || type === 'null');
}

/**
 * The paths of every secret member of `method`'s config, in schema order.
 *
 * @throws AuthMethodContractError when the schema has no JSON Schema form, is
 *   not an object, or marks a member it cannot be split by: inside a list, a
 *   union, a record or a recursive part, one that is not a string, or one
 *   whose path holds a member name outside
 *   {@link AUTH_METHOD_SECRET_SEGMENT_PATTERN}; and when it marks more than
 *   {@link MAX_AUTH_METHOD_SECRET_MEMBERS}
 * @experimental
 */
export function authMethodSecretPaths(method: Pick<AuthMethod, 'type' | 'configSchema'>): string[] {
  const subject = `The AuthMethod ${method.type}`;
  let document: unknown;
  try {
    document = z.toJSONSchema(method.configSchema as z.ZodType, {
      io: 'input',
      unrepresentable: 'any',
    });
  } catch {
    throw new AuthMethodContractError(subject, [
      'configSchema has no JSON Schema form, so its secret members cannot be told apart',
    ]);
  }
  if (!isNode(document) || document['type'] !== 'object') {
    throw new AuthMethodContractError(subject, [
      'configSchema must describe an object of members: the realm stores it member by member',
    ]);
  }

  const paths: string[] = [];
  const problems: string[] = [];
  const walk = (node: JsonSchemaNode, path: readonly string[]): void => {
    const properties = node['properties'];
    if (node['type'] === 'object' && isNode(properties)) {
      for (const [name, child] of Object.entries(properties)) {
        if (!isNode(child)) continue;
        walk(child, [...path, name]);
      }
      // A mark below anything but `properties` (additionalProperties, a
      // pattern, a union of objects) has no member path.
      const rest = Object.fromEntries(Object.entries(node).filter(([key]) => key !== 'properties'));
      if (holdsMarkOrRef(rest)) {
        problems.push(
          `configSchema marks a secret member${path.length > 0 ? ` under ${path.join('.')}` : ''} that is not a named member of an object`
        );
      }
      return;
    }
    if (marksWriteOnly(node)) {
      const at = path.join('.');
      if (!path.every((segment) => AUTH_METHOD_SECRET_SEGMENT_PATTERN.test(segment))) {
        problems.push(
          `the secret member ${at} has a member name outside ${AUTH_METHOD_SECRET_SEGMENT_PATTERN.source}`
        );
      } else if (!isStringMember(node)) {
        problems.push(`the secret member ${at} must be a string (or a nullable string)`);
      } else {
        paths.push(at);
      }
      return;
    }
    if (holdsMarkOrRef(node)) {
      problems.push(
        `configSchema marks a secret member inside ${path.join('.') || 'the config'} (a list, a union, a record or a recursive part), which cannot be kept write-only`
      );
    }
  };
  walk(document, []);

  if (paths.length > MAX_AUTH_METHOD_SECRET_MEMBERS) {
    problems.push(`configSchema marks more than ${MAX_AUTH_METHOD_SECRET_MEMBERS} secret members`);
  }
  if (problems.length > 0) throw new AuthMethodContractError(subject, problems);
  return paths;
}

/**
 * The value at `path` of a plain config object, or `undefined`.
 *
 * @experimental
 */
export function configMemberAt(config: unknown, path: AuthMethodSecretPath): unknown {
  let node: unknown = config;
  for (const segment of path.split('.')) {
    if (typeof node !== 'object' || node === null || Array.isArray(node)) return undefined;
    if (!Object.hasOwn(node, segment)) return undefined;
    node = (node as Record<string, unknown>)[segment];
  }
  return node;
}

/**
 * A copy of the plain config object `config` without the members at
 * `paths`: what a realm stores in the clear, and what an admin API shows. An
 * object left empty by a removed member stays, empty.
 *
 * @experimental
 */
export function withoutConfigMembers(
  config: Readonly<Record<string, unknown>>,
  paths: readonly AuthMethodSecretPath[]
): Record<string, unknown> {
  const copy = structuredClone(config) as Record<string, unknown>;
  for (const path of paths) {
    const segments = path.split('.');
    const last = segments.pop() as string;
    let node: unknown = copy;
    for (const segment of segments) {
      node =
        typeof node === 'object' && node !== null && Object.hasOwn(node, segment)
          ? (node as Record<string, unknown>)[segment]
          : undefined;
    }
    if (typeof node === 'object' && node !== null && !Array.isArray(node)) {
      delete (node as Record<string, unknown>)[last];
    }
  }
  return copy;
}

/**
 * A copy of the plain config object `config` with each value of `members`
 * set at its path, creating the objects on the way: the config a method's
 * schema parses, once the realm's secrets are read back.
 *
 * @experimental
 */
export function withConfigMembers(
  config: Readonly<Record<string, unknown>>,
  members: ReadonlyMap<AuthMethodSecretPath, string>
): Record<string, unknown> {
  const copy = structuredClone(config) as Record<string, unknown>;
  for (const [path, value] of members) {
    const segments = path.split('.');
    const last = segments.pop() as string;
    let node: Record<string, unknown> = copy;
    for (const segment of segments) {
      const next = Object.hasOwn(node, segment) ? node[segment] : undefined;
      if (typeof next === 'object' && next !== null && !Array.isArray(next)) {
        node = next as Record<string, unknown>;
      } else {
        const created: Record<string, unknown> = {};
        Object.defineProperty(node, segment, {
          value: created,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        node = created;
      }
    }
    Object.defineProperty(node, last, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return copy;
}
