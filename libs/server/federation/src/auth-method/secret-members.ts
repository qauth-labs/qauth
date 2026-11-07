import { type AuthMethod, AuthMethodContractError } from '@qauth-labs/plugin-sdk';
import { z } from 'zod';

/**
 * The secret members of a method's config (#600, EXPERIMENTAL): the members
 * its `configSchema` marks `.meta({ writeOnly: true })`, such as a client
 * secret. The plugin runtime keeps them write-only: an admin sets or clears
 * one, the server stores it encrypted at rest, and no response, event or log
 * shows its value.
 *
 * The marks are read from the schema's JSON Schema, input and output side.
 * Zod 4.6 keeps one metadata registry for every copy that shares it
 * (`globalThis.__zod_globalRegistry`); a schema built with a copy that keeps
 * its own, whose marks the server would not see, is refused.
 *
 * Supported: a secret is a string member (or a nullable one) of the config
 * object, at any depth of nested objects, marked on the input side or on the
 * output side of a pipe that keeps its path and its string. It may sit
 * inside a union whose branches are all objects, such as a discriminated
 * union of client authentication methods (#951), when every branch that has
 * a member at its path marks it there: a branch without the member, such as
 * `private_key_jwt`, takes no secret, and no branch takes the same member in
 * the clear. A config whose schema is not an object, holds a part JSON
 * Schema cannot describe, or marks a member inside a list, a record, a
 * recursive part or a union with a branch that is not an object, or behind
 * a pipe that reshapes it, cannot be split into members safely: the method
 * is refused, so the boot fails rather than store a secret in the clear.
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

/** What one walk of a document, or of one branch of a union in it, found. */
interface DocumentWalk {
  /** The secret paths it marks. */
  readonly paths: string[];
  /** The paths of every string member (a leaf whose values are strings or null). */
  readonly stringPaths: string[];
  /** The path of every named member met, whatever its schema. */
  readonly members: Set<string>;
  /** The paths of the members that are objects, or unions of objects. */
  readonly objects: Set<string>;
  readonly problems: string[];
}

function emptyWalk(): DocumentWalk {
  return { paths: [], stringPaths: [], members: new Set(), objects: new Set(), problems: [] };
}

/**
 * The branches of a union node (`anyOf` or `oneOf`, never both) when each of
 * them is an object of named members: the union a secret member may sit
 * inside, such as a discriminated union. `undefined` for any other node, a
 * union with a `null`, a string or a record among its branches included: a
 * secret member inside one of those is refused.
 */
function objectUnionBranches(
  node: JsonSchemaNode,
  document: SchemaDocument
): readonly JsonSchemaNode[] | undefined {
  const anyOf = node['anyOf'];
  const oneOf = node['oneOf'];
  if (Array.isArray(anyOf) === Array.isArray(oneOf)) return undefined;
  const branches = (Array.isArray(anyOf) ? anyOf : oneOf) as unknown[];
  if (branches.length === 0) return undefined;
  for (const branch of branches) {
    if (!isNode(branch)) return undefined;
    const { node: target } = dereferenced(branch, document);
    if (target === undefined || target['type'] !== 'object' || !isNode(target['properties'])) {
      return undefined;
    }
  }
  return branches as JsonSchemaNode[];
}

/**
 * The secret paths one document marks, its string members, and the problems
 * it shows. For the output form, `inputStrings` holds the string members of
 * the input form: a member marked on the output side counts only where the
 * input takes a string at the same path, the value a request names as a
 * secret. A mark on the output of a pipe that reshapes or renames the value
 * has no such member, and is refused: its value could only be sent among the
 * plain members.
 */
function walkDocument(document: SchemaDocument, inputStrings?: ReadonlySet<string>): DocumentWalk {
  const walk = (
    given: JsonSchemaNode,
    path: readonly string[],
    refs: ReadonlySet<string>,
    found: DocumentWalk
  ): void => {
    const { paths, stringPaths, problems } = found;
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
      if (path.length > 0) found.objects.add(path.join('.'));
      for (const [name, child] of Object.entries(properties)) {
        if (!isNode(child)) continue;
        found.members.add([...path, name].join('.'));
        walk(child, [...path, name], inside, found);
      }
      // A mark below anything but `properties` (additionalProperties, a
      // pattern, a union of objects) has no member path.
      const rest = Object.fromEntries(
        Object.entries(node).filter(([key]) => key !== 'properties' && key !== '$defs')
      );
      // A fresh set: an ancestor's `$ref` met again below (recursion through
      // a list, a record or a nullable) is looked into, not skipped.
      if (holdsMark(rest, document, new Set())) {
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
      } else if (inputStrings !== undefined) {
        if (inputStrings.has(at)) paths.push(at);
        else {
          problems.push(
            `configSchema marks ${at} as a secret on its output side, where its input takes no string member at that path (a pipe that reshapes or renames the value): such a secret could only be sent in the clear`
          );
        }
      } else if (!isStringMember(node)) {
        problems.push(`the secret member ${at} must be a string (or a nullable string)`);
      } else {
        paths.push(at);
        stringPaths.push(at);
      }
      return;
    }
    const branches = objectUnionBranches(node, document);
    if (branches !== undefined) {
      walkUnion(node, branches, path, inside, found);
      return;
    }
    if (isStringMember(node) && path.length > 0) stringPaths.push(path.join('.'));
    if (holdsMark(node, document, new Set())) {
      problems.push(
        `configSchema marks a secret member inside ${path.join('.') || 'the config'} (a list, a record, or a union with a branch that is not an object), which cannot be kept write-only`
      );
    }
  };

  /**
   * A union of objects at `path` (#951): each branch walked on its own, then
   * held to one rule. A path one branch marks secret is marked, as a string,
   * by every branch that has a member there, and no branch holds a member
   * that is not an object on the way to it: so whichever branch a config
   * takes, the value at that path is a secret, or the branch has no such
   * member. A branch without the member (`private_key_jwt` beside
   * `client_secret_basic`) is no problem: the server never puts a secret
   * into a config the plain members do not shape for one, and a config that
   * spells a secret path among its plain members is refused whatever branch
   * it takes (`configSpellsMemberOf`).
   */
  const walkUnion = (
    node: JsonSchemaNode,
    branches: readonly JsonSchemaNode[],
    path: readonly string[],
    refs: ReadonlySet<string>,
    found: DocumentWalk
  ): void => {
    const at = path.join('.') || 'its root';
    // A mark beside the branches (on the union itself, which has a member
    // path only through them) has no member path.
    const rest = Object.fromEntries(
      Object.entries(node).filter(([key]) => key !== 'anyOf' && key !== 'oneOf' && key !== '$defs')
    );
    if (holdsMark(rest, document, new Set())) {
      found.problems.push(
        `configSchema marks a secret member beside the branches of the union at ${at}, which cannot be kept write-only`
      );
    }
    const walks = branches.map((branch) => {
      const branchWalk = emptyWalk();
      walk(branch, path, refs, branchWalk);
      return branchWalk;
    });
    const marked = [...new Set(walks.flatMap((branchWalk) => branchWalk.paths))];
    for (const secret of marked) {
      const segments = secret.split('.');
      // The members on the way to the secret below the union itself.
      const between = segments
        .slice(path.length, -1)
        .map((_, index) => segments.slice(0, path.length + 1 + index).join('.'));
      for (const branchWalk of walks) {
        if (branchWalk.members.has(secret)) {
          if (!branchWalk.paths.includes(secret)) {
            found.problems.push(
              `configSchema marks ${secret} as a secret in one branch of the union at ${at} and not in another, which would take its value in the clear`
            );
          }
        } else if (
          between.some((member) => branchWalk.members.has(member) && !branchWalk.objects.has(member))
        ) {
          found.problems.push(
            `a branch of the union at ${at} holds a member that is not an object on the way to the secret ${secret}`
          );
        }
      }
    }
    found.paths.push(...marked.filter((secret) => !found.paths.includes(secret)));
    for (const branchWalk of walks) {
      found.stringPaths.push(...branchWalk.stringPaths);
      for (const member of branchWalk.members) found.members.add(member);
      for (const member of branchWalk.objects) found.objects.add(member);
      found.problems.push(...branchWalk.problems);
    }
    if (path.length > 0) found.objects.add(path.join('.'));
  };

  const result = emptyWalk();
  walk(document.root, [], new Set(), result);
  return result;
}

/** How many objects of a config schema's tree {@link foreignMarkOf} reads at most. */
const FOREIGN_MARK_VISIT_BUDGET = 20_000;

/** How deep into a config schema's tree {@link foreignMarkOf} reads at most. */
const FOREIGN_MARK_MAX_DEPTH = 64;

/**
 * Whether a schema of `config`'s tree carries a `writeOnly` mark that the
 * server's Zod cannot see: its own `.meta()` (the registry of the Zod copy
 * that built it) says so, and the registry the server reads does not. A
 * plugin that bundles a Zod copy keeping a registry of its own would have
 * every mark invisible here, and every secret would read as plain.
 *
 * It fails closed: a tree it cannot read whole, because it runs past
 * {@link FOREIGN_MARK_VISIT_BUDGET} objects or {@link FOREIGN_MARK_MAX_DEPTH}
 * levels, or because a lazy part's getter or a `.meta()` throws, answers
 * `unreadable`, and the method is refused as for a foreign mark.
 */
function foreignMarkOf(schema: unknown): 'foreign' | 'unreadable' | undefined {
  const seen = new Set<object>();
  let budget = FOREIGN_MARK_VISIT_BUDGET;
  let unreadable = false;
  // `true` stops the walk: a foreign mark found, or a part that cannot be read.
  const visit = (value: unknown, depth: number): boolean => {
    if (typeof value !== 'object' || value === null) return false;
    if (seen.has(value)) return false;
    if (depth > FOREIGN_MARK_MAX_DEPTH || budget-- <= 0) {
      unreadable = true;
      return true;
    }
    seen.add(value);
    if (Array.isArray(value)) return value.some((item) => visit(item, depth + 1));
    const zod = (value as { _zod?: { def?: unknown } })._zod;
    if (zod !== undefined) {
      const meta = (value as { meta?: unknown }).meta;
      let own: unknown;
      try {
        own = typeof meta === 'function' ? (meta as () => unknown).call(value) : undefined;
      } catch {
        unreadable = true;
        return true;
      }
      const ours = z.globalRegistry.get(value as z.ZodType) as { writeOnly?: unknown } | undefined;
      if (
        (own as { writeOnly?: unknown } | undefined)?.writeOnly === true &&
        ours?.writeOnly !== true
      ) {
        return true;
      }
      const def = zod.def as Record<string, unknown> | undefined;
      if (def === undefined) return false;
      // A lazy schema names its inner schema through a getter.
      if (typeof def['getter'] === 'function') {
        let inner: unknown;
        try {
          inner = (def['getter'] as () => unknown)();
        } catch {
          unreadable = true;
          return true;
        }
        if (visit(inner, depth + 1)) return true;
      }
      return Object.entries(def).some(([key, item]) => key !== 'getter' && visit(item, depth + 1));
    }
    return Object.values(value).some((item) => visit(item, depth + 1));
  };
  if (!visit(schema, 0)) return undefined;
  return unreadable ? 'unreadable' : 'foreign';
}

/**
 * The paths of every secret member of `method`'s config, in schema order.
 *
 * The marks are read twice: from the JSON Schema of what the config schema
 * takes (its input) and from the one of what it gives (its output), so a mark
 * on either side of a pipe counts, as long as the input takes a string member
 * at the marked path (a pipe that reshapes or renames a marked value is
 * refused). The input form must exist whole: a config schema with a part
 * JSON Schema cannot describe (a `Set`, a `Map`, a date, a custom check) is
 * refused, since a mark inside it could not be seen. A transform's output,
 * which no schema describes, holds no mark. And a schema built with a Zod
 * copy whose metadata the server cannot read is refused, as is one too large
 * or too deep to read whole for such marks, or whose lazy part or metadata
 * throws.
 *
 * A mark inside a union whose branches are all objects counts (#951) when
 * every branch with a member at the marked path marks it, and no branch
 * holds a member that is not an object on the way to it.
 *
 * @throws AuthMethodContractError when the schema has no JSON Schema form, is
 *   not an object, or marks a member it cannot be split by: inside a list, a
 *   record, a recursive part or a union with a branch that is not an object,
 *   in one branch of a union and not in another that has the member, one
 *   that is not a string, or one whose path holds a member name outside
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
  const foreign = foreignMarkOf(method.configSchema);
  if (foreign === 'foreign') {
    throw new AuthMethodContractError(subject, [
      "configSchema was built with a Zod copy whose metadata this server cannot read, so its secret members would read as plain: build the plugin against the server's Zod (a peer dependency)",
    ]);
  }
  if (foreign === 'unreadable') {
    throw new AuthMethodContractError(subject, [
      `configSchema cannot be read whole for its secret marks (it is larger than ${FOREIGN_MARK_VISIT_BUDGET} parts or deeper than ${FOREIGN_MARK_MAX_DEPTH} levels, or a lazy part or its metadata throws), so its secret members cannot be told apart`,
    ]);
  }

  const fromInput = walkDocument(schemaDocument(input));
  const outputDocument = schemaDocument(output);
  // An output that is no object (a transform of the whole config) holds no
  // member path; it may hold no mark either.
  const fromOutput =
    output['type'] === 'object'
      ? walkDocument(outputDocument, new Set(fromInput.stringPaths))
      : {
          paths: [],
          stringPaths: [],
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
 * A list on the way to a secret path (`{ mtls: [{ keyPassword }] }`) counts
 * too, whatever it holds: no secret member sits inside a list, so such a
 * config is misshaped, and the value inside it could be a secret sent in
 * the clear. So does a way to a secret path deeper than this reads.
 *
 * @experimental
 */
export function configSpellsMemberOf(
  config: unknown,
  paths: readonly AuthMethodSecretPath[]
): boolean {
  if (paths.length === 0) return false;
  const wanted = new Set(paths);
  // Every proper ancestor of a secret path: only below one can a member
  // spell a secret path.
  const ancestors = new Set(
    paths.flatMap((path) => {
      const segments = path.split('.');
      return segments.slice(1).map((_, index) => segments.slice(0, index + 1).join('.'));
    })
  );
  const walk = (value: Record<string, unknown>, prefix: string, depth: number): boolean =>
    Object.entries(value).some(([key, item]) => {
      const at = prefix === '' ? key : `${prefix}.${key}`;
      if (wanted.has(at)) return true;
      if (!ancestors.has(at)) return false;
      if (Array.isArray(item)) return true;
      if (typeof item !== 'object' || item === null) return false;
      // Deeper than any config this reads: refused rather than read as plain.
      if (depth >= 32) return true;
      return walk(item as Record<string, unknown>, at, depth + 1);
    });
  if (typeof config !== 'object' || config === null || Array.isArray(config)) return false;
  return walk(config as Record<string, unknown>, '', 0);
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
