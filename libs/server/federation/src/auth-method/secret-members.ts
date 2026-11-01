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
 * One JSON Schema document Zod wrote for the config, with its local `$ref`s
 * (`#`, `#/$defs/<name>`) resolved: what a schema with an `id` in its
 * metadata, or a recursive one, refers to.
 */
interface SchemaDocument {
  readonly root: JsonSchemaNode;
  /** The node a `$ref` names, or `undefined` for one outside the document. */
  resolve(ref: unknown): JsonSchemaNode | undefined;
}

function schemaDocument(root: JsonSchemaNode): SchemaDocument {
  const defs = isNode(root['$defs']) ? root['$defs'] : {};
  return {
    root,
    resolve(ref) {
      if (ref === '#') return root;
      if (typeof ref !== 'string' || !ref.startsWith('#/$defs/')) return undefined;
      const name = decodeURIComponent(ref.slice('#/$defs/'.length));
      const found = Object.hasOwn(defs, name) ? defs[name] : undefined;
      return isNode(found) ? found : undefined;
    },
  };
}

/**
 * `node` with the node its `$ref` names merged under its own members, and
 * the ref; `undefined` as the node when the ref names nothing in the
 * document.
 */
function dereferenced(
  node: JsonSchemaNode,
  document: SchemaDocument
): { node: JsonSchemaNode | undefined; ref: string | undefined } {
  if (!('$ref' in node)) return { node, ref: undefined };
  const ref = node['$ref'];
  const target = document.resolve(ref);
  if (target === undefined) return { node: undefined, ref: String(ref) };
  const { $ref: _ref, ...siblings } = node;
  return { node: { ...target, ...siblings }, ref: String(ref) };
}

/**
 * Whether a write-only mark appears anywhere in `value`, through the local
 * `$ref`s it holds; a `$ref` that names nothing in the document counts as a
 * mark, since what it names cannot be read.
 */
function holdsMark(
  value: unknown,
  document: SchemaDocument,
  seen: Set<string>,
  depth = 0
): boolean {
  if (depth > 64) return true;
  if (Array.isArray(value)) return value.some((item) => holdsMark(item, document, seen, depth + 1));
  if (!isNode(value)) return false;
  if (value['writeOnly'] === true) return true;
  if ('$ref' in value) {
    const { node, ref } = dereferenced(value, document);
    if (node === undefined) return true;
    if (ref !== undefined) {
      if (seen.has(ref)) return false;
      seen.add(ref);
    }
    const { $ref: _ref, ...rest } = node;
    return holdsMark(rest, document, seen, depth + 1);
  }
  return Object.entries(value).some(
    ([key, item]) => key !== '$defs' && holdsMark(item, document, seen, depth + 1)
  );
}

/** The secret paths one document marks, and the problems it shows. */
function walkDocument(document: SchemaDocument): { paths: string[]; problems: string[] } {
  const paths: string[] = [];
  const problems: string[] = [];
  const walk = (
    given: JsonSchemaNode,
    path: readonly string[],
    refs: ReadonlySet<string>
  ): void => {
    const { node, ref } = dereferenced(given, document);
    if (node === undefined) {
      if (holdsMark(given, document, new Set())) {
        problems.push(
          `configSchema refers to a part it does not hold at ${path.join('.') || 'its root'}`
        );
      }
      return;
    }
    if (ref !== undefined && refs.has(ref)) {
      // A recursive part has no finite member path.
      if (holdsMark(node, document, new Set([ref]))) {
        problems.push(
          `configSchema marks a secret member inside a recursive part at ${path.join('.') || 'its root'}, which cannot be kept write-only`
        );
      }
      return;
    }
    const inside = ref === undefined ? refs : new Set([...refs, ref]);
    const properties = node['properties'];
    if (node['type'] === 'object' && isNode(properties)) {
      for (const [name, child] of Object.entries(properties)) {
        if (!isNode(child)) continue;
        walk(child, [...path, name], inside);
      }
      // A mark below anything but `properties` (additionalProperties, a
      // pattern, a union of objects) has no member path.
      const rest = Object.fromEntries(
        Object.entries(node).filter(([key]) => key !== 'properties' && key !== '$defs')
      );
      if (holdsMark(rest, document, new Set(inside))) {
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
    if (holdsMark(node, document, new Set(inside))) {
      problems.push(
        `configSchema marks a secret member inside ${path.join('.') || 'the config'} (a list, a union or a record), which cannot be kept write-only`
      );
    }
  };
  walk(document.root, [], new Set());
  return { paths, problems };
}

/**
 * The paths of every secret member of `method`'s config, in schema order.
 *
 * The marks are read twice: from the JSON Schema of what the config schema
 * takes (its input) and from the one of what it gives (its output), so a mark
 * on either side of a pipe counts. The input form must exist whole: a config
 * schema with a part JSON Schema cannot describe (a `Set`, a `Map`, a date, a
 * custom check) is refused, since a mark inside it could not be seen. A
 * transform's output, which no schema describes, holds no mark.
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
  let input: unknown;
  let output: unknown;
  try {
    input = z.toJSONSchema(method.configSchema as z.ZodType, {
      io: 'input',
      unrepresentable: 'throw',
    });
    output = z.toJSONSchema(method.configSchema as z.ZodType, {
      io: 'output',
      unrepresentable: 'any',
    });
  } catch {
    throw new AuthMethodContractError(subject, [
      'configSchema has no JSON Schema form (it holds a Set, a Map, a date, a function or a custom check), so its secret members cannot be told apart',
    ]);
  }
  if (!isNode(input) || input['type'] !== 'object' || !isNode(output)) {
    throw new AuthMethodContractError(subject, [
      'configSchema must describe an object of members: the realm stores it member by member',
    ]);
  }

  const fromInput = walkDocument(schemaDocument(input));
  const outputDocument = schemaDocument(output);
  // An output that is no object (a transform of the whole config) holds no
  // member path; it may hold no mark either.
  const fromOutput =
    output['type'] === 'object'
      ? walkDocument(outputDocument)
      : {
          paths: [],
          problems: holdsMark(output, outputDocument, new Set())
            ? [
                'configSchema marks a secret member in the output of a transform of the whole config',
              ]
            : [],
        };
  const paths = [...new Set([...fromInput.paths, ...fromOutput.paths])];
  const problems = [...new Set([...fromInput.problems, ...fromOutput.problems])];

  if (paths.length > MAX_AUTH_METHOD_SECRET_MEMBERS) {
    problems.push(`configSchema marks more than ${MAX_AUTH_METHOD_SECRET_MEMBERS} secret members`);
  }
  if (problems.length > 0) throw new AuthMethodContractError(subject, problems);
  return paths;
}

/**
 * Whether `config` holds a value at one of `paths`, however it is spelled:
 * nested (`{ mtls: { keyPassword } }`) or with the dots in one member's name
 * (`{ "mtls.keyPassword": … }`). A config sent with a secret there would
 * store it with the plain members.
 *
 * @experimental
 */
export function configSpellsMemberOf(
  config: unknown,
  paths: readonly AuthMethodSecretPath[]
): boolean {
  if (paths.length === 0) return false;
  const wanted = new Set(paths);
  const walk = (value: unknown, prefix: string, depth: number): boolean => {
    if (typeof value !== 'object' || value === null || Array.isArray(value) || depth > 32) {
      return false;
    }
    return Object.entries(value).some(([key, item]) => {
      const at = prefix === '' ? key : `${prefix}.${key}`;
      return wanted.has(at) || walk(item, at, depth + 1);
    });
  };
  return walk(config, '', 0);
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
