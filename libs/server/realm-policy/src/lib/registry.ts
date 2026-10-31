import { isDeepStrictEqual } from 'node:util';

import { SECURITY_EFFECTS, type SecurityEffect } from '@qauth-labs/shared-validation';
import { z } from 'zod';

import { type ChangeDirection, compareDirection, sameEntries } from './direction';
import {
  directionKind,
  isPolicyField,
  isSetDirection,
  PolicyDefinitionError,
  type PolicyField,
} from './field';
import { isPolicySchemaVersion, REALM_POLICY_SCHEMA_VERSION } from './version';

/**
 * The realm policy registry (ADR-019 Decision 10, issue #514): the groups of
 * fields that make up a realm's policies, and everything built from their
 * annotations.
 *
 * One schema feeds every consumer:
 *
 * - the stored policy document (`document` view), which never holds a secret
 *   and is the realm file's `policies` (ADR-018 §5);
 * - a write (`input` view), where a secret field may be set and is
 *   write-only;
 * - the admin API's realm representation (`representation` view), where a
 *   secret field appears only as `<name>Set: true | false`;
 * - the JSON Schema of each view, for OpenAPI and the realm file;
 * - the diff of two documents, which marks each change as tightening,
 *   loosening or neutral and gives its class and effects, the input of the
 *   approval rule (ADR-019 Decisions 7 and 11);
 * - the seeding of a new realm from the environment.
 *
 * Areas add groups with {@link PolicyRegistry.registerPolicyGroup}. A group
 * is a tree of fields made by `policyField`, and its name is taken once.
 */

/** A group, as registered: fields made by `policyField`, and nested groups of them. */
export interface PolicyGroupShape {
  readonly [member: string]: PolicyField | PolicyGroupShape;
}

/**
 * The forms the schema takes.
 *
 * - `document`: the stored policies and the realm file's `policies`. Every
 *   member is optional and takes its default; no secret field appears.
 * - `input`: a full policy document as a write sends it. A secret field may
 *   be set here, and nowhere else; it is write-only.
 * - `representation`: what the admin API returns. Every member is present;
 *   a secret field `<name>` appears as `<name>Set`, a boolean.
 */
export const POLICY_VIEWS = Object.freeze(['document', 'input', 'representation'] as const);

export type PolicyView = (typeof POLICY_VIEWS)[number];

/** A registered field: where it sits and what it is. */
export interface RegisteredPolicyField {
  /** The dotted path, such as `mail.smtp.password`. */
  readonly path: string;
  /** The path's segments, the group's name first. */
  readonly segments: readonly string[];
  readonly field: PolicyField;
}

/** The class of a change: the scope class it needs (ADR-019 Decision 7). */
export type PolicyChangeClass = 'write' | 'security';

/** One changed field. */
export interface PolicyChange {
  readonly path: string;
  /**
   * The value before and after. For a secret field these are never the
   * values: `before` says whether the before document held one, and `after`
   * is `true`, since a secret field changes only when a value is set.
   */
  readonly before: unknown;
  readonly after: unknown;
  readonly direction: ChangeDirection;
  /** `security` when the field's `securityWhen` makes this change a security operation. */
  readonly class: PolicyChangeClass;
  /** The field's effects when the change is a security operation; empty otherwise. */
  readonly effects: readonly SecurityEffect[];
  readonly secret: boolean;
  readonly environmentBound: boolean;
}

/** The changes between two policy documents, and what the whole change needs. */
export interface PolicyDiff {
  /** The changed fields, in registration order. */
  readonly changes: readonly PolicyChange[];
  /** The strictest class of any change: `security` when one is, otherwise `write`. */
  readonly class: PolicyChangeClass;
  /** Every effect of the security changes, in the order of `SECURITY_EFFECTS`. */
  readonly effects: readonly SecurityEffect[];
}

/** One reason a value is not a valid policy document. */
export interface PolicyIssue {
  /** The dotted path of the member, empty for the document itself. */
  readonly path: string;
  readonly message: string;
}

/**
 * A value the schema refuses. Its issues name the paths and never repeat a
 * value, so a refused secret does not reach a log through it.
 */
export class PolicyValidationError extends Error {
  override readonly name = 'PolicyValidationError';

  constructor(
    message: string,
    readonly issues: readonly PolicyIssue[]
  ) {
    super(message);
  }
}

/** An environment value that cannot seed its field. The message never repeats the value. */
export class PolicySeedError extends Error {
  override readonly name = 'PolicySeedError';

  constructor(
    readonly key: string,
    readonly path: string,
    reason: string
  ) {
    super(`${key} cannot seed the realm policy ${path}: ${reason}`);
  }
}

/** The environment as `defaultsFromEnv` reads it: raw strings, or values the env schema parsed. */
export type PolicySeedEnv = Readonly<Record<string, unknown>>;

/** A JSON Schema object. */
export type JsonSchemaObject = Record<string, unknown>;

/** The registry: register groups, then build from them. */
export interface PolicyRegistry {
  /** The schema version (`1-rc.<M>` before 1.0.0, `1` from it). */
  readonly version: string;
  /**
   * Add a group. Refused with a `PolicyDefinitionError` when `name` is taken,
   * also in another case, or is not a lower camelCase word, when the group is
   * empty, when a member is neither a field nor a nested group, when a member
   * name repeats in another case or clashes with the `<name>Set` member of a
   * secret beside it, or when its seed key already seeds another field.
   * Nothing is registered unless all of it is valid.
   */
  registerPolicyGroup(name: string, shape: PolicyGroupShape): void;
  /** The group names, in registration order. */
  groups(): readonly string[];
  /** Every field, in registration order. */
  fields(): readonly RegisteredPolicyField[];
  /** The field at `path`, if one is registered. */
  field(path: string): RegisteredPolicyField | undefined;
  /** The Zod schema of a view. */
  schema(view: PolicyView): z.ZodType;
  /**
   * Parse `value` as the view (`document` by default): unknown members are
   * refused, and missing ones take their defaults.
   */
  parse(value: unknown, view?: Exclude<PolicyView, 'representation'>): Record<string, unknown>;
  /**
   * The policy document of a new realm: each field from its seed key in
   * `env`, or its default where `env` does not set the key (ADR-019 Decision
   * 10). A value the env schema already parsed is taken as it is; a raw
   * string is read as the environment writes it (numbers, `true`/`false` or
   * `1`/`0`, lists separated by spaces or commas; blank is unset, or the
   * empty list). Secret fields are not in the document; see
   * {@link secretSeedsFromEnv}.
   */
  defaultsFromEnv(env: PolicySeedEnv): Record<string, unknown>;
  /** The secret values `env` seeds, by field path, for the realm's secret store. */
  secretSeedsFromEnv(env: PolicySeedEnv): ReadonlyMap<string, string>;
  /**
   * The changes from `before` to `after`, both parsed as the `input` view
   * (missing members take their defaults, so `{}` is the default policies).
   */
  diffPolicies(before: unknown, after: unknown): PolicyDiff;
  /** The JSON Schema (draft 2020-12) of a view, `representation` by default. */
  toJsonSchema(view?: PolicyView): JsonSchemaObject;
  /**
   * The representation of `document`: its values, with each secret field
   * replaced by `<name>Set`, true for the paths in `setSecrets`. A secret
   * value in `document` is dropped, never copied.
   */
  toRepresentation(document: unknown, setSecrets?: Iterable<string>): Record<string, unknown>;
}

/** A group or field name: one lower camelCase word. */
const MEMBER_NAME_PATTERN = /^[a-z][a-zA-Z0-9]*$/;

/** How deep a group may nest (`registration.cimd.enabled` is depth 3). */
const MAX_DEPTH = 4;

/** A node of the registered tree. */
type TreeNode =
  | { readonly kind: 'group'; readonly members: ReadonlyMap<string, TreeNode> }
  | { readonly kind: 'field'; readonly entry: RegisteredPolicyField };

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

/** The name a secret member takes in the representation. */
const setFlagName = (name: string) => `${name}Set`;

const isUniqueList = (value: unknown) =>
  !Array.isArray(value) || new Set(value).size === value.length;

/** The value at `segments` in `root`, or `undefined`. */
function valueAt(root: unknown, segments: readonly string[]): unknown {
  let node: unknown = root;
  for (const segment of segments) {
    if (!isPlainObject(node) || !Object.hasOwn(node, segment)) return undefined;
    node = node[segment];
  }
  return node;
}

/** Set `value` at `segments` in `root`, creating the groups on the way. */
function setAt(root: Record<string, unknown>, segments: readonly string[], value: unknown): void {
  let node = root;
  for (const segment of segments.slice(0, -1)) {
    if (!isPlainObject(node[segment])) node[segment] = {};
    node = node[segment] as Record<string, unknown>;
  }
  node[segments[segments.length - 1]] = value;
}

/** The kind of value a field's type holds, through optional, nullable, default and pipe wrappers. */
function valueKind(schema: z.ZodType): string {
  let def = (schema as unknown as { def: Record<string, unknown> }).def;
  for (let depth = 0; depth < 16; depth++) {
    const type = def['type'];
    const inner =
      type === 'optional' ||
      type === 'nullable' ||
      type === 'default' ||
      type === 'prefault' ||
      type === 'readonly'
        ? def['innerType']
        : type === 'pipe'
          ? def['in']
          : undefined;
    if (inner === undefined) return String(type);
    def = (inner as { def: Record<string, unknown> }).def;
  }
  return 'unknown';
}

/** A raw environment string, read as the field's kind of value; `undefined` means unset. */
function readEnvString(kind: string, raw: string): unknown {
  const text = raw.trim();
  if (kind === 'array') {
    return text
      .split(/[\s,]+/)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
  }
  if (text === '') return undefined;
  if (kind === 'number') return /^-?\d+(?:\.\d+)?$/.test(text) ? Number(text) : raw;
  if (kind === 'boolean') {
    if (text === 'true' || text === '1') return true;
    if (text === 'false' || text === '0') return false;
    return raw;
  }
  return raw;
}

/** Zod issues as policy issues: paths and messages only. */
function issuesOf(error: z.ZodError): PolicyIssue[] {
  return error.issues.map((issue) => ({
    path: issue.path.map(String).join('.'),
    message: issue.message,
  }));
}

/** Create an empty registry. `version` defaults to {@link REALM_POLICY_SCHEMA_VERSION}. */
export function createPolicyRegistry(options: { readonly version?: string } = {}): PolicyRegistry {
  const version = options.version ?? REALM_POLICY_SCHEMA_VERSION;
  if (!isPolicySchemaVersion(version)) {
    throw new PolicyDefinitionError(
      `"${String(version)}" is not a policy schema version (1-rc.<M>, or 1 from 1.0.0)`
    );
  }

  const roots = new Map<string, TreeNode>();
  const entries: RegisteredPolicyField[] = [];
  const byPath = new Map<string, RegisteredPolicyField>();
  const seedKeys = new Map<string, string>();
  const schemas = new Map<PolicyView, z.ZodType>();

  /** Validate `shape` at `prefix` into a tree, collecting its fields; mutates nothing shared. */
  function buildTree(
    shape: unknown,
    prefix: readonly string[],
    collected: RegisteredPolicyField[]
  ): TreeNode {
    const where = prefix.join('.');
    if (!isPlainObject(shape)) {
      throw new PolicyDefinitionError(`${where}: a group is an object of fields and groups`);
    }
    const names = Object.keys(shape);
    if (names.length === 0) {
      throw new PolicyDefinitionError(`${where}: a group has at least one field`);
    }
    if (prefix.length > MAX_DEPTH) {
      throw new PolicyDefinitionError(`${where}: groups nest at most ${MAX_DEPTH} deep`);
    }
    const folded = new Map<string, string>();
    for (const name of names) {
      if (!MEMBER_NAME_PATTERN.test(name)) {
        throw new PolicyDefinitionError(
          `${where}.${name}: a member name is one lower camelCase word`
        );
      }
      const other = folded.get(name.toLowerCase());
      if (other !== undefined) {
        throw new PolicyDefinitionError(
          `${where}.${name}: differs only in case from ${where}.${other}`
        );
      }
      folded.set(name.toLowerCase(), name);
    }

    const members = new Map<string, TreeNode>();
    for (const name of names) {
      const value = shape[name];
      const segments = [...prefix, name];
      if (isPolicyField(value)) {
        if (value.secret && folded.has(setFlagName(name).toLowerCase())) {
          throw new PolicyDefinitionError(
            `${segments.join('.')}: the representation shows this secret as ${setFlagName(name)}, which another member already is`
          );
        }
        const entry: RegisteredPolicyField = Object.freeze({
          path: segments.join('.'),
          segments: Object.freeze(segments),
          field: value,
        });
        collected.push(entry);
        members.set(name, { kind: 'field', entry });
      } else if (isPlainObject(value)) {
        members.set(name, buildTree(value, segments, collected));
      } else {
        throw new PolicyDefinitionError(
          `${segments.join('.')}: a member is a field made by policyField, or a nested group`
        );
      }
    }
    return { kind: 'group', members };
  }

  function registerPolicyGroup(name: string, shape: PolicyGroupShape): void {
    if (typeof name !== 'string' || !MEMBER_NAME_PATTERN.test(name)) {
      throw new PolicyDefinitionError(
        `"${String(name)}": a group name is one lower camelCase word`
      );
    }
    if (roots.has(name)) {
      throw new PolicyDefinitionError(`a policy group named "${name}" is already registered`);
    }
    for (const existing of roots.keys()) {
      if (existing.toLowerCase() === name.toLowerCase()) {
        throw new PolicyDefinitionError(
          `the policy group "${name}" differs only in case from the registered group "${existing}"`
        );
      }
    }
    const collected: RegisteredPolicyField[] = [];
    const tree = buildTree(shape, [name], collected);
    const newSeeds = new Map<string, string>();
    for (const entry of collected) {
      const key = entry.field.seedEnv;
      if (key === null) continue;
      const seeded = seedKeys.get(key) ?? newSeeds.get(key);
      if (seeded !== undefined) {
        throw new PolicyDefinitionError(
          `${entry.path}: ${key} already seeds ${seeded}; one key seeds one field`
        );
      }
      newSeeds.set(key, entry.path);
    }

    roots.set(name, tree);
    for (const entry of collected) {
      entries.push(entry);
      byPath.set(entry.path, entry);
    }
    for (const [key, path] of newSeeds) seedKeys.set(key, path);
    schemas.clear();
  }

  /** The Zod type of one field in a view, or `undefined` when the view leaves it out. */
  function fieldSchema(entry: RegisteredPolicyField, view: PolicyView): z.ZodType | undefined {
    const { field } = entry;
    let base: z.ZodType = field.schema;
    if (isSetDirection(field.direction)) {
      base = base.refine(isUniqueList, { message: 'lists an entry more than once' });
    }
    if (field.secret) {
      return view === 'input' ? base.optional() : undefined;
    }
    return base.default(() => structuredClone(field.default));
  }

  function groupSchema(node: TreeNode & { kind: 'group' }, view: PolicyView): z.ZodType {
    const shape: Record<string, z.ZodType> = {};
    for (const [name, member] of node.members) {
      if (member.kind === 'group') {
        shape[name] = groupSchema(member, view);
      } else if (member.entry.field.secret && view === 'representation') {
        shape[setFlagName(name)] = z.boolean();
      } else {
        const schema = fieldSchema(member.entry, view);
        if (schema !== undefined) shape[name] = schema;
      }
    }
    // The representation strips what it does not name, so a value that is not
    // in it (a secret above all) never reaches a response serialised with it.
    return view === 'representation'
      ? z.object(shape).prefault({})
      : z.strictObject(shape).prefault({});
  }

  function schema(view: PolicyView): z.ZodType {
    if (!(POLICY_VIEWS as readonly string[]).includes(view)) {
      throw new PolicyDefinitionError(`"${String(view)}" is not a view`);
    }
    let built = schemas.get(view);
    if (built === undefined) {
      const shape: Record<string, z.ZodType> = {};
      for (const [name, node] of roots) {
        shape[name] = groupSchema(node as TreeNode & { kind: 'group' }, view);
      }
      built = view === 'representation' ? z.object(shape) : z.strictObject(shape);
      schemas.set(view, built);
    }
    return built;
  }

  function parse(
    value: unknown,
    view: Exclude<PolicyView, 'representation'> = 'document'
  ): Record<string, unknown> {
    if (view !== 'document' && view !== 'input') {
      throw new PolicyDefinitionError(`"${String(view)}" cannot be parsed; it is an output`);
    }
    const result = schema(view).safeParse(value);
    if (!result.success) {
      throw new PolicyValidationError(
        `The realm policies are not valid (${view})`,
        issuesOf(result.error)
      );
    }
    return result.data as Record<string, unknown>;
  }

  /** The value `raw` seeds into `entry`, or `undefined` for unset. */
  function seedValue(entry: RegisteredPolicyField, key: string, raw: unknown): unknown {
    const { field } = entry;
    let candidate = raw;
    if (typeof raw === 'string') {
      const kind = valueKind(field.schema);
      // A string-valued field takes the string as it is, unless it is blank.
      candidate =
        kind === 'string' || kind === 'enum'
          ? raw.trim() === ''
            ? undefined
            : raw
          : readEnvString(kind, raw);
    }
    if (candidate === undefined) return undefined;
    const base = fieldSchema(entry, 'input') ?? field.schema;
    const result = base.safeParse(candidate);
    if (!result.success) {
      throw new PolicySeedError(
        key,
        entry.path,
        issuesOf(result.error)
          .map((issue) => issue.message)
          .join('; ')
      );
    }
    return result.data;
  }

  function defaultsFromEnv(env: PolicySeedEnv): Record<string, unknown> {
    const document: Record<string, unknown> = {};
    for (const entry of entries) {
      const { field } = entry;
      if (field.secret) continue;
      const key = field.seedEnv;
      const seeded = key === null ? undefined : seedValue(entry, key, env[key]);
      setAt(
        document,
        entry.segments,
        seeded === undefined ? structuredClone(field.default) : seeded
      );
    }
    return parse(document, 'document');
  }

  function secretSeedsFromEnv(env: PolicySeedEnv): ReadonlyMap<string, string> {
    const secrets = new Map<string, string>();
    for (const entry of entries) {
      const { field } = entry;
      if (!field.secret || field.seedEnv === null) continue;
      const raw = env[field.seedEnv];
      if (raw === undefined || (typeof raw === 'string' && raw.trim() === '')) continue;
      const result = field.schema.safeParse(raw);
      if (!result.success || typeof result.data !== 'string') {
        throw new PolicySeedError(field.seedEnv, entry.path, 'not a valid value');
      }
      secrets.set(entry.path, result.data);
    }
    return secrets;
  }

  function diffPolicies(before: unknown, after: unknown): PolicyDiff {
    const from = parse(before, 'input');
    const to = parse(after, 'input');
    const changes: PolicyChange[] = [];
    for (const entry of entries) {
      const { field } = entry;
      const a = valueAt(from, entry.segments);
      const b = valueAt(to, entry.segments);
      let change: Omit<PolicyChange, 'class' | 'effects'>;
      if (field.secret) {
        // A secret changes when a value is set. Only whether one is set is
        // recorded; the values never leave this function.
        if (b === undefined || b === a) continue;
        change = {
          path: entry.path,
          before: a !== undefined,
          after: true,
          direction: 'neutral',
          secret: true,
          environmentBound: field.environmentBound,
        };
      } else {
        const unchanged = isSetDirection(field.direction)
          ? sameEntries(a, b)
          : isDeepStrictEqual(a, b);
        if (unchanged) continue;
        change = {
          path: entry.path,
          before: structuredClone(a),
          after: structuredClone(b),
          direction: compareDirection(field.direction, a, b),
          secret: false,
          environmentBound: field.environmentBound,
        };
      }
      const security =
        field.securityWhen === 'any-change' ||
        (field.securityWhen === 'loosening' && change.direction === 'loosening');
      changes.push(
        Object.freeze({
          ...change,
          class: security ? 'security' : 'write',
          effects: Object.freeze(security ? [...field.effects] : []),
        })
      );
    }
    const effects = new Set(changes.flatMap((change) => change.effects));
    return Object.freeze({
      changes: Object.freeze(changes),
      class: changes.some((change) => change.class === 'security') ? 'security' : 'write',
      effects: Object.freeze(SECURITY_EFFECTS.filter((effect) => effects.has(effect))),
    });
  }

  /** What the JSON Schema says of a field, beside its type. */
  function policyAnnotation(field: PolicyField): JsonSchemaObject {
    const { direction } = field;
    return {
      docs: field.doc.link,
      seedEnv: field.seedEnv,
      direction: directionKind(direction),
      ...(typeof direction === 'string' ? {} : { order: [...direction.order] }),
      securityWhen: field.securityWhen,
      effects: [...field.effects],
      secret: field.secret,
      environmentBound: field.environmentBound,
    };
  }

  function annotate(json: JsonSchemaObject, node: TreeNode, view: PolicyView): void {
    if (node.kind !== 'group') return;
    if (view === 'representation') delete json['additionalProperties'];
    const properties = json['properties'] as Record<string, JsonSchemaObject> | undefined;
    if (properties === undefined) return;
    for (const [name, member] of node.members) {
      if (member.kind === 'group') {
        const child = properties[name];
        if (child !== undefined) annotate(child, member, view);
        continue;
      }
      const { field } = member.entry;
      if (field.secret && view === 'representation') {
        const flag = properties[setFlagName(name)];
        flag['readOnly'] = true;
        flag['description'] =
          `Whether ${member.entry.path} is set. The value is write-only and never returned.`;
        continue;
      }
      const property = properties[name];
      if (property === undefined) continue;
      property['description'] = field.doc.summary;
      if (isSetDirection(field.direction)) property['uniqueItems'] = true;
      if (field.secret) property['writeOnly'] = true;
      property['x-qauth-policy'] = policyAnnotation(field);
    }
  }

  function toJsonSchema(view: PolicyView = 'representation'): JsonSchemaObject {
    const json = z.toJSONSchema(schema(view), {
      target: 'draft-2020-12',
      unrepresentable: 'throw',
      io: view === 'representation' ? 'output' : 'input',
    }) as JsonSchemaObject;
    const properties = json['properties'] as Record<string, JsonSchemaObject> | undefined;
    for (const [name, node] of roots) {
      const group = properties?.[name];
      if (group !== undefined) annotate(group, node, view);
    }
    if (view === 'representation') delete json['additionalProperties'];
    const { $schema, ...rest } = json;
    return {
      $schema,
      title: 'QAuth realm policies',
      description: `The realm policies, schema version ${version} (${view}).`,
      'x-qauth-schema-version': version,
      ...rest,
    };
  }

  function toRepresentation(
    document: unknown,
    setSecrets: Iterable<string> = []
  ): Record<string, unknown> {
    const set = new Set(setSecrets);
    for (const path of set) {
      if (byPath.get(path)?.field.secret !== true) {
        throw new PolicyDefinitionError(`${path} is not a secret field`);
      }
    }
    const values = parse(document, 'input');
    const representation: Record<string, unknown> = {};
    for (const entry of entries) {
      if (entry.field.secret) {
        const segments = [...entry.segments];
        segments[segments.length - 1] = setFlagName(segments[segments.length - 1]);
        setAt(representation, segments, set.has(entry.path));
      } else {
        setAt(representation, entry.segments, structuredClone(valueAt(values, entry.segments)));
      }
    }
    // Groups whose only members are secrets still appear, as in the schema.
    return schema('representation').parse(representation) as Record<string, unknown>;
  }

  return Object.freeze({
    version,
    registerPolicyGroup,
    groups: () => Object.freeze([...roots.keys()]),
    fields: () => Object.freeze([...entries]),
    field: (path: string) => byPath.get(path),
    schema,
    parse,
    defaultsFromEnv,
    secretSeedsFromEnv,
    diffPolicies,
    toJsonSchema,
    toRepresentation,
  });
}
