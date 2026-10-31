import { isDeepStrictEqual } from 'node:util';

import { isSecurityEffect, type SecurityEffect } from '@qauth-labs/shared-validation';
import { z } from 'zod';

/**
 * One realm policy field and its annotations (ADR-019 Decision 10, issue
 * #514).
 *
 * A field is a Zod type plus the annotations that say where its default comes
 * from, which way is stricter and when a change of it is a security operation
 * (ADR-019 Decision 7). The registry (`registry.ts`) builds the policy
 * document, the admin API's realm representation, the JSON Schema, the diff
 * and the seeding from these annotations alone, so a field cannot be added
 * without them: {@link policyField} refuses a definition that leaves one out.
 */

/**
 * How the values of a field are ordered by strictness.
 *
 * - `lower-is-stricter`, `higher-is-stricter`: a number.
 * - `true-is-stricter`, `false-is-stricter`: a flag.
 * - `ordered`: an enum with an explicit order, from the loosest value to the
 *   strictest ({@link OrderedDirection}).
 * - `subset-is-stricter`: a set of allowed values; fewer is stricter.
 * - `superset-is-stricter`: a set of required values; more is stricter.
 * - `opaque`: no order exists, so a change is neither a tightening nor a
 *   loosening.
 */
export const DIRECTION_KINDS = Object.freeze([
  'lower-is-stricter',
  'higher-is-stricter',
  'true-is-stricter',
  'false-is-stricter',
  'ordered',
  'subset-is-stricter',
  'superset-is-stricter',
  'opaque',
] as const);

export type DirectionKind = (typeof DIRECTION_KINDS)[number];

/** An enum direction: `order` lists every value, from the loosest to the strictest. */
export interface OrderedDirection {
  readonly kind: 'ordered';
  readonly order: readonly string[];
}

/** A field's direction: one of {@link DIRECTION_KINDS}, with its order when `ordered`. */
export type Direction = Exclude<DirectionKind, 'ordered'> | OrderedDirection;

/** An `ordered` direction over `order`, given from the loosest value to the strictest. */
export function ordered(order: readonly string[]): OrderedDirection {
  return Object.freeze({ kind: 'ordered', order: Object.freeze([...order]) });
}

/** The kind of `direction`: its string, or `ordered`. */
export function directionKind(direction: Direction): string {
  return typeof direction === 'string' ? direction : direction.kind;
}

/**
 * When a change of the field is a security operation, which needs
 * `qauth:admin:security` (ADR-019 Decision 7).
 *
 * - `never`: every change is a write (`qauth:admin:write`).
 * - `loosening`: a loosening change is a security operation; a tightening is
 *   a write.
 * - `any-change`: every change is a security operation, in either direction.
 */
export const SECURITY_WHEN = Object.freeze(['never', 'loosening', 'any-change'] as const);

export type SecurityWhen = (typeof SECURITY_WHEN)[number];

/** A field's documentation: one sentence, and a link to docs.qauth.dev (ADR-020 §5, criterion 2). */
export interface PolicyFieldDoc {
  /** One sentence: what the setting does. */
  readonly summary: string;
  /** Where docs.qauth.dev explains it, as an absolute `https://docs.qauth.dev/` URL. */
  readonly link: string;
}

/** The annotations every field carries, secret or not. */
interface CommonAnnotations {
  /**
   * The environment key that seeds the field for a new realm, or `null` when
   * no key does. The environment only seeds: once a realm exists, its row owns
   * the value (ADR-019 Decision 10).
   */
  readonly seedEnv: string | null;
  /** Which way is stricter. */
  readonly direction: Direction;
  /** When a change is a security operation. */
  readonly securityWhen: SecurityWhen;
  /**
   * The effects of `@qauth-labs/shared-validation`'s closed list
   * (`SECURITY_EFFECTS`, #508) that make a security change of this field one.
   * Empty exactly when `securityWhen` is `never`.
   */
  readonly effects: readonly SecurityEffect[];
  /**
   * The value describes the environment the realm runs in, such as a mail
   * transport or a trust list, so a sandbox promotion leaves it out unless it
   * is selected on its own (ADR-019 Decision 11).
   */
  readonly environmentBound: boolean;
  readonly doc: PolicyFieldDoc;
}

/**
 * The annotations of a field, as {@link policyField} takes them. Every member
 * is required, `default` included.
 *
 * A secret field is write-only: it is never stored in the policy document and
 * never returned, and the representation shows only whether it is set
 * (`<name>Set`). It has no default (`null`), no order (`opaque`), and every
 * change of it is a security operation (`any-change`).
 */
export type PolicyFieldAnnotations<T> =
  | (CommonAnnotations & {
      readonly secret: false;
      /** The value of a realm whose environment does not set `seedEnv`. */
      readonly default: T;
    })
  | (CommonAnnotations & {
      readonly secret: true;
      readonly default: null;
      readonly direction: 'opaque';
      readonly securityWhen: 'any-change';
    });

/** The names of the annotations, in the order the docs list them. */
export const ANNOTATION_KEYS = Object.freeze([
  'seedEnv',
  'default',
  'direction',
  'securityWhen',
  'effects',
  'secret',
  'environmentBound',
  'doc',
] as const);

/**
 * Brands a field across module copies (`Symbol.for`, not `instanceof`), so a
 * field defined in one copy of this library is still a field to another.
 */
const POLICY_FIELD = Symbol.for('qauth.realm-policy.field');

/** A field: its Zod type and its annotations, frozen. */
export interface PolicyField<T = unknown, Secret extends boolean = boolean> {
  readonly [POLICY_FIELD]: true;
  /** The value's type. For a secret field, the type of the value being set. */
  readonly schema: z.ZodType<T>;
  readonly seedEnv: string | null;
  readonly default: Secret extends true ? null : T;
  readonly direction: Direction;
  readonly securityWhen: SecurityWhen;
  readonly effects: readonly SecurityEffect[];
  readonly secret: Secret;
  readonly environmentBound: boolean;
  readonly doc: PolicyFieldDoc;
}

/** Whether `value` is a field made by {@link policyField}. */
export function isPolicyField(value: unknown): value is PolicyField {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<symbol, unknown>)[POLICY_FIELD] === true
  );
}

/** A definition {@link policyField} or the registry refuses. */
export class PolicyDefinitionError extends Error {
  override readonly name = 'PolicyDefinitionError';
}

/** An environment variable name. */
const ENV_KEY_PATTERN = /^[A-Z][A-Z0-9_]*$/;

/** An absolute link into the docs site. */
const DOCS_LINK_PATTERN = /^https:\/\/docs\.qauth\.dev\/[^\s]*$/;

const SET_DIRECTIONS: ReadonlySet<string> = new Set(['subset-is-stricter', 'superset-is-stricter']);

/** Whether `direction` treats the value as a set of entries. */
export function isSetDirection(direction: Direction): boolean {
  return SET_DIRECTIONS.has(directionKind(direction));
}

function checkDirection(direction: unknown): void {
  if (typeof direction === 'string') {
    if (direction === 'ordered' || !(DIRECTION_KINDS as readonly string[]).includes(direction)) {
      throw new PolicyDefinitionError(
        `direction "${direction}" is not one of ${DIRECTION_KINDS.filter((kind) => kind !== 'ordered').join(', ')}, or ordered([...])`
      );
    }
    return;
  }
  const candidate = direction as Partial<OrderedDirection> | null;
  const order = candidate?.order;
  if (
    typeof candidate !== 'object' ||
    candidate === null ||
    candidate.kind !== 'ordered' ||
    Object.keys(candidate).some((key) => key !== 'kind' && key !== 'order') ||
    !Array.isArray(order) ||
    order.length < 2 ||
    order.some((value) => typeof value !== 'string' || value.length === 0) ||
    new Set(order).size !== order.length
  ) {
    throw new PolicyDefinitionError(
      'an ordered direction lists at least two distinct values, from the loosest to the strictest'
    );
  }
}

/** The value kinds a direction compares, so a default of another kind is refused. */
function checkValueFitsDirection(direction: Direction, value: unknown): void {
  const kind = directionKind(direction);
  const fits =
    kind === 'opaque' ||
    ((kind === 'lower-is-stricter' || kind === 'higher-is-stricter') &&
      typeof value === 'number') ||
    ((kind === 'true-is-stricter' || kind === 'false-is-stricter') && typeof value === 'boolean') ||
    (kind === 'ordered' && (direction as OrderedDirection).order.includes(value as string)) ||
    (SET_DIRECTIONS.has(kind) &&
      Array.isArray(value) &&
      value.every((entry) => typeof entry === 'string'));
  if (!fits) {
    throw new PolicyDefinitionError(`the default does not fit the direction ${kind}`);
  }
}

/**
 * One sentence: a single trimmed line, ending with a full stop, with no
 * second sentence after it.
 */
function isOneSentence(text: unknown): boolean {
  return (
    typeof text === 'string' &&
    text.length > 0 &&
    text.length <= 300 &&
    text === text.trim() &&
    !/[\r\n]/.test(text) &&
    text.endsWith('.') &&
    !/[.!?]\s+[A-Z]/.test(text)
  );
}

/** Whether `value` is plain JSON, as a stored policy document holds it. */
function isJsonValue(value: unknown): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (typeof value !== 'object') return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return (
    (prototype === Object.prototype || prototype === null) &&
    Object.values(value).every(isJsonValue)
  );
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

/**
 * Define a realm policy field: `schema` is the value's Zod type, and
 * `annotations` every annotation of {@link PolicyFieldAnnotations}.
 *
 * Refuses, with a {@link PolicyDefinitionError}, a definition that
 *
 * - has a schema that is not a Zod type, or one with no JSON Schema in a form
 *   a view exports (a transform, a `Date`);
 * - leaves out an annotation, or has one this module does not know;
 * - names an unknown direction, an unknown `securityWhen` or an effect outside
 *   the closed list, or lists effects for a field that is never a security
 *   operation, or none for one that can be;
 * - gives an `opaque` field the rule `loosening`, which could never apply;
 * - is not secret and has a type that accepts `undefined`, which would let a
 *   member of the representation go missing;
 * - has a default that is not plain JSON, that its type refuses or rewrites,
 *   or that does not fit the direction (a number for `lower-is-stricter`, a
 *   value of the order for `ordered`, a list of strings for a set);
 * - is `ordered` over a type that accepts a value outside the order, or
 *   refuses one in it;
 * - is secret without being `opaque`, `any-change` and default `null`;
 * - has a `doc` that is not one sentence plus a docs.qauth.dev link.
 */
export function policyField<S extends z.ZodType, Secret extends boolean>(
  schema: S,
  annotations: PolicyFieldAnnotations<z.output<S>> & { readonly secret: Secret }
): PolicyField<z.output<S>, Secret> {
  checkDefinition(schema, annotations);
  const {
    seedEnv,
    default: defaultValue,
    direction,
    securityWhen,
    effects,
    secret,
    environmentBound,
    doc,
  } = annotations as PolicyFieldAnnotations<unknown>;
  return Object.freeze({
    [POLICY_FIELD]: true as const,
    schema,
    seedEnv,
    default: deepFreeze(structuredClone(defaultValue)),
    direction: typeof direction === 'string' ? direction : ordered(direction.order),
    securityWhen,
    effects: Object.freeze([...effects]),
    secret,
    environmentBound,
    doc: Object.freeze({ summary: doc.summary, link: doc.link }),
  }) as unknown as PolicyField<z.output<S>, Secret>;
}

/**
 * Check a value that carries the field brand as {@link policyField} checks a
 * definition, so a field from another copy of this library, or an object
 * that only carries the brand, is held to the same rules.
 *
 * @throws PolicyDefinitionError when it breaks one
 */
export function assertPolicyField(value: unknown): asserts value is PolicyField {
  copyPolicyField(value);
}

/**
 * A frozen copy of a value that carries the field brand, checked as
 * {@link assertPolicyField} checks it. The registry keeps this copy, never
 * the value it was given: a field from another copy of this library, or one
 * spread into a new object, need not be frozen, and changing it after
 * registration must not change how a change of the field is classified.
 *
 * @throws PolicyDefinitionError when it breaks a rule
 */
export function copyPolicyField(value: unknown): PolicyField {
  if (!isPolicyField(value)) {
    throw new PolicyDefinitionError('not a field made by policyField');
  }
  // Each member is read once, so the copy is the value that was checked.
  const { schema, ...annotations } = value as unknown as Record<string, unknown>;
  return policyField(schema as z.ZodType, annotations as never);
}

/** The rules of {@link policyField}, over a type and its annotations. */
function checkDefinition(schema: z.ZodType, annotations: unknown): void {
  // `instanceof` holds for a Zod type of another copy of Zod too: Zod checks
  // the type's traits, not its prototype.
  if (!(schema instanceof z.ZodType)) {
    throw new PolicyDefinitionError('a policy field needs a Zod type');
  }
  if (typeof annotations !== 'object' || annotations === null) {
    throw new PolicyDefinitionError('a policy field needs its annotations');
  }
  for (const key of ANNOTATION_KEYS) {
    if (!Object.hasOwn(annotations, key)) {
      throw new PolicyDefinitionError(`the annotation "${key}" is missing`);
    }
  }
  for (const key of Object.keys(annotations)) {
    if (!(ANNOTATION_KEYS as readonly string[]).includes(key)) {
      throw new PolicyDefinitionError(`"${key}" is not an annotation`);
    }
  }

  const {
    seedEnv,
    default: defaultValue,
    direction,
    securityWhen,
    effects,
    secret,
    environmentBound,
    doc,
  } = annotations as PolicyFieldAnnotations<unknown>;

  if (seedEnv !== null && (typeof seedEnv !== 'string' || !ENV_KEY_PATTERN.test(seedEnv))) {
    throw new PolicyDefinitionError('seedEnv is an environment variable name, or null');
  }
  checkDirection(direction);
  if (!(SECURITY_WHEN as readonly string[]).includes(securityWhen)) {
    throw new PolicyDefinitionError(
      `securityWhen "${String(securityWhen)}" is not one of ${SECURITY_WHEN.join(', ')}`
    );
  }
  if (
    !Array.isArray(effects) ||
    effects.some((effect) => !isSecurityEffect(effect)) ||
    new Set(effects).size !== effects.length
  ) {
    throw new PolicyDefinitionError(
      'effects are distinct tags of the closed list SECURITY_EFFECTS (@qauth-labs/shared-validation)'
    );
  }
  if (securityWhen === 'never' && effects.length > 0) {
    throw new PolicyDefinitionError('a field that is never a security operation has no effects');
  }
  if (securityWhen !== 'never' && effects.length === 0) {
    throw new PolicyDefinitionError(
      `a field whose ${securityWhen} change is a security operation names the effects that make it one`
    );
  }
  if (directionKind(direction) === 'opaque' && securityWhen === 'loosening') {
    throw new PolicyDefinitionError(
      'an opaque field has no loosening; its rule is never or any-change'
    );
  }
  if (typeof secret !== 'boolean' || typeof environmentBound !== 'boolean') {
    throw new PolicyDefinitionError('secret and environmentBound are booleans');
  }
  if (
    typeof doc !== 'object' ||
    doc === null ||
    Object.keys(doc).some((key) => key !== 'summary' && key !== 'link') ||
    !isOneSentence(doc.summary) ||
    typeof doc.link !== 'string' ||
    !DOCS_LINK_PATTERN.test(doc.link)
  ) {
    throw new PolicyDefinitionError(
      'doc is { summary, link }: one sentence ending with a full stop, and an https://docs.qauth.dev/ link'
    );
  }

  // Every view is exported as JSON Schema: the input form of every field, and
  // the output form (the representation) of a field that is not secret. A
  // type with none, such as a transform or a Date, is refused here rather
  // than when a view is exported.
  for (const io of secret ? (['input'] as const) : (['input', 'output'] as const)) {
    try {
      z.toJSONSchema(schema, { target: 'draft-2020-12', unrepresentable: 'throw', io });
    } catch (error) {
      throw new PolicyDefinitionError(
        `the type has no JSON Schema (${io}): ${error instanceof Error ? error.message : 'not representable'}`
      );
    }
  }

  if (secret) {
    if (direction !== 'opaque' || securityWhen !== 'any-change' || defaultValue !== null) {
      throw new PolicyDefinitionError(
        'a secret field is opaque, any-change and has no default (null)'
      );
    }
  } else {
    // The representation has every member, so its type must not let one be
    // absent, or fill one in.
    if (schema.safeParse(undefined).success) {
      throw new PolicyDefinitionError(
        'a field that is not secret refuses undefined: the representation has every member'
      );
    }
    if (!isJsonValue(defaultValue)) {
      throw new PolicyDefinitionError('the default is plain JSON, as the policy document is');
    }
    const parsed = schema.safeParse(defaultValue);
    if (!parsed.success || !isDeepStrictEqual(parsed.data, defaultValue)) {
      throw new PolicyDefinitionError('the default must be a value of the type, unchanged by it');
    }
    checkValueFitsDirection(direction, defaultValue);
    if (typeof direction !== 'string') {
      for (const value of direction.order) {
        if (!schema.safeParse(value).success) {
          throw new PolicyDefinitionError(
            `the order names "${value}", which the type does not accept`
          );
        }
      }
      // A value the type accepts outside the order could never be compared, so
      // the type must accept a known, finite set of values (an enum or
      // literals), all of them in the order.
      const values = schema._zod.values;
      if (values === undefined) {
        throw new PolicyDefinitionError(
          'an ordered field has an enum type, which accepts only the values of its order'
        );
      }
      for (const value of values) {
        if (!direction.order.includes(value as string)) {
          throw new PolicyDefinitionError(`the order leaves out the value "${String(value)}"`);
        }
      }
    }
  }
}
