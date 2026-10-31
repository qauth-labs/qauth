/**
 * The admin operation registry (ADR-019 Decision 7, issue #508): "security
 * operations, defined by effect", as code.
 *
 * Every admin API operation is defined once, with {@link defineOperation}:
 *
 *   - `id`, its published operation id (`<resource>.<verb>`, the route's
 *     `operationId`);
 *   - `class`, `read`, `write` or `security`;
 *   - `effects`, the effect tags of `@qauth-labs/shared-validation`
 *     (`SECURITY_EFFECTS`) that make it a security operation;
 *   - `permissions`, the permissions of the admin catalog
 *     (`admin-permissions.ts`) a caller needs;
 *   - `description`, one sentence for the docs page;
 *   - when the request decides what the operation needs, `classify` (with
 *     `loadState` to read the current state it compares against);
 *   - and, on a security operation, `render`: what an approver is shown of
 *     one request (#512).
 *
 * THE STATIC RULE. An operation is of class `security` if and only if its
 * `effects` are not empty, and its class is the strictest class among its
 * permissions (`read` < `write` < `security`). A permission of class
 * `security` needs `qauth:admin:security` (`admin-scopes.ts`), so an operation
 * with an effect is never reachable through `qauth:admin:write`. The registry
 * refuses an operation that breaks either rule, so the boot fails.
 *
 * REQUEST-DEPENDENT RULES. A policy patch or a realm-file import needs what
 * its content needs: lowering the password policy is a security operation,
 * and so is lengthening a token or session lifetime or the key rotation
 * interval, or shortening or switching off audit-event retention
 * (`posture-loosening`, by effect); shortening a lifetime or lengthening
 * retention is not. Such an operation declares the strictest
 * classification any request can get (class `security`, every effect it may
 * have, every permission it may need) and a pure, synchronous `classify`
 * that returns what one request needs, within that declaration.
 * {@link classifyRequest} runs it; the admin pipeline calls it before the
 * handler (`plugins/admin-operations.ts`), and the handler cannot lower the
 * result.
 *
 * FAIL CLOSED. A `classify` that throws, meets a field it has no rule for
 * ({@link UnknownFieldError}, as {@link classifyByField} throws), returns
 * anything but a well-formed classification (an unknown member, an unknown
 * effect, class or permission, a class its permissions contradict) or more
 * than its declaration gives the request the operation's declared
 * classification: `security`, every declared effect and every declared
 * permission.
 *
 * STATE BINDING. An operation that reads state to classify (`loadState`)
 * also says which version of that state it read (`stateVersion`). The
 * classification carries the version, the pipeline answers 428 when the
 * request has no `If-Match` and 412 when it names another version, and the
 * handler's write must be
 * conditional on `classification.stateVersion` (or load, classify and write
 * in one transaction under `SELECT … FOR UPDATE`): a write to state that
 * changed after the classification would run under a classification of
 * other state.
 *
 * RESERVED IDS. `admin-operations-reserved.ts` lists, for each effect, the
 * operation ids other areas register later. Registering one of them as
 * anything but a security operation that carries at least its reserved
 * effects fails, and so does an id that differs from one only in case. A
 * reserved operation may `classify` only where its entry says the request
 * decides (`requestDependent`); every other one needs its declaration on
 * every request. A request-dependent entry carries security cases
 * (`vectors`): the registry runs the operation's `classify` on each at boot
 * and refuses one that classifies a case less strictly than its entry says,
 * or fails closed on it (then it tests nothing), so a `classify` that answers
 * `write` for everything cannot take the reservation.
 *
 * The docs page `reference/security-operations.md` is generated from this
 * registry (`admin-operations-page.ts`), and the API conventions check
 * (`api-conventions/openapi-conventions.ts`) fails when an admin operation of
 * the OpenAPI document disagrees with it.
 */
import { createHash } from 'node:crypto';

import {
  isSecurityEffect,
  SECURITY_EFFECTS,
  type SecurityEffect,
} from '@qauth-labs/shared-validation';
import type { FastifyRequest } from 'fastify';

import { approvalOperationDefinitions } from '../admin/approvals/operations';
import {
  RESERVED_OPERATIONS,
  type ReservedOperation,
  type ReservedVector,
} from './admin-operations-reserved';
import {
  PERMISSION_ID_PATTERN,
  PERMISSION_REGISTRY,
  type PermissionRegistry,
} from './admin-permissions';
import { PERMISSION_CLASSES, type PermissionClass } from './admin-scopes';

/**
 * An operation id: `<resource>.<verb>`, the resource possibly dotted, as the
 * API conventions name an `operationId` (`realms.get`,
 * `realms.policies.update`, `keys.rotate`).
 */
export const OPERATION_ID_PATTERN = PERMISSION_ID_PATTERN;

/**
 * The class of an admin operation, or of one request of it. The same three
 * classes as the permissions it needs, ordered from the least to the most
 * sensitive in `PERMISSION_CLASSES`.
 */
export type OperationClass = PermissionClass;

/** What a request of an operation needs. */
export interface Classification {
  readonly class: OperationClass;
  /** The effects that make it a security operation; empty exactly when it is not one. */
  readonly effects: readonly SecurityEffect[];
  /** The permissions of the admin catalog the caller needs, all of them. */
  readonly permissions: readonly string[];
}

/**
 * What `classify` sees of a request: deep copies of its method, path
 * parameters, query and body, after validation, frozen. It reaches neither
 * the request nor the reply, so it cannot change what the handler sees.
 */
export interface ClassifyInput {
  readonly method: string;
  readonly params: unknown;
  readonly query: unknown;
  readonly body: unknown;
}

/**
 * What `render` sees of a request an approval was filed for: the stored
 * canonical request's operation id, method, path parameters, query and body,
 * frozen. Nothing the requester wrote about it (the reason) is in it.
 */
export interface RenderInput {
  readonly operationId: string;
  readonly method: string;
  readonly params: unknown;
  readonly query: unknown;
  readonly body: unknown;
}

/** One line of a rendered operation: a label and its value, with the value it replaces. */
export interface RenderedField {
  readonly label: string;
  readonly value: string;
  /** The value the operation replaces, for a change shown side by side (ADR-020 §5). */
  readonly before?: string;
}

/**
 * What an approver is shown of one request of a security operation: typed
 * display data, never HTML. The approval engine (`admin/approvals/display.ts`)
 * applies the display rules of ADR-019 Decision 6 to every string.
 */
export interface RenderedOperation {
  /** What the operation does, in one line. */
  readonly title: string;
  readonly fields?: readonly RenderedField[];
}

/** A definition, as {@link defineOperation} takes it. */
export interface AdminOperationDefinition<State = unknown> {
  /** The published operation id, also the route's `operationId`. */
  readonly id: string;
  /**
   * The class. With `classify`, the strictest class any request can get,
   * which is always `security`.
   */
  readonly class: OperationClass;
  /** The effects; with `classify`, every effect a request may have. */
  readonly effects: readonly SecurityEffect[];
  /** The permissions; with `classify`, every permission a request may need. */
  readonly permissions: readonly string[];
  /** One sentence for the docs page. */
  readonly description: string;
  /**
   * What one request needs, within the declaration above. Pure and
   * synchronous: it reads only its arguments.
   */
  classify?(request: ClassifyInput, currentState: State): Classification;
  /**
   * Reads the state `classify` compares the request with, such as the realm's
   * current policies. The pipeline awaits it before `classify`; a rejection
   * fails the request, which then runs nothing. Requires `stateVersion`.
   */
  loadState?(request: FastifyRequest): Promise<State>;
  /**
   * The version of a state `loadState` read, such as its row version or a
   * digest of it: an entity-tag's opaque value (`!` and `#` to `~`, at most
   * 256 characters, no quotes), which the route sends quoted as its `ETag`.
   * Required with `loadState`, and pure.
   *
   * The pipeline puts it on the classification (`stateVersion`), answers 428
   * when the request has no `If-Match` and 412 when it names another version.
   * The handler's
   * write MUST be conditional on it (`… WHERE version = stateVersion`, 412
   * when no row matches), or load, classify and write in one transaction
   * under `SELECT … FOR UPDATE`: the classification holds only for the
   * state it was made against.
   */
  stateVersion?(state: State): string;
  /**
   * What an approver is shown of one request (#512), from the stored request
   * alone: pure and synchronous. Required on every security operation an
   * admin route performs: the admin pipeline refuses to boot such a route
   * without it. Only a security operation renders.
   */
  render?(request: RenderInput): RenderedOperation;
}

/** A registered operation: a definition that {@link defineOperation} accepted, frozen. */
export type AdminOperation<State = unknown> = AdminOperationDefinition<State>;

/** The members a definition may have; any other member is refused. */
const DEFINITION_KEYS: ReadonlySet<string> = new Set([
  'id',
  'class',
  'effects',
  'permissions',
  'description',
  'classify',
  'loadState',
  'stateVersion',
  'render',
]);

/** A definition refused by {@link defineOperation} or {@link createOperationRegistry}. */
export class OperationDefinitionError extends Error {
  override readonly name = 'OperationDefinitionError';
}

const classRank = (operationClass: OperationClass): number =>
  PERMISSION_CLASSES.indexOf(operationClass);

/** The strictest of `classes`, or `undefined` for none. */
function strictestClass(classes: Iterable<OperationClass>): OperationClass | undefined {
  let strictest: OperationClass | undefined;
  for (const candidate of classes) {
    if (strictest === undefined || classRank(candidate) > classRank(strictest)) {
      strictest = candidate;
    }
  }
  return strictest;
}

const isOneLine = (text: unknown): text is string =>
  typeof text === 'string' && text.length > 0 && text.trim() === text && !/[\r\n]/.test(text);

/**
 * A plain copy of a definition: each member read once, from an own data
 * property, and each list copied. What is checked is then what is stored: a
 * getter could otherwise answer the checks one way and the copy another.
 *
 * @throws {OperationDefinitionError} when the definition is not an object, or
 *   has an unknown member or an accessor
 */
function snapshotOperation(operation: AdminOperationDefinition): AdminOperationDefinition {
  if (typeof operation !== 'object' || operation === null) {
    throw new OperationDefinitionError('an operation definition is an object');
  }
  const descriptors = Object.getOwnPropertyDescriptors(operation) as Record<
    PropertyKey,
    PropertyDescriptor
  >;
  const keys = Reflect.ownKeys(descriptors);
  const id: unknown = 'value' in (descriptors['id'] ?? {}) ? descriptors['id'].value : undefined;
  const where = `operation ${JSON.stringify(id)}`;
  const unknown = keys.filter((key) => typeof key !== 'string' || !DEFINITION_KEYS.has(key));
  if (unknown.length > 0) {
    throw new OperationDefinitionError(
      `${where}: unknown member ${unknown.map((key) => String(key)).join(', ')}; a definition has ${[...DEFINITION_KEYS].join(', ')}`
    );
  }
  const snapshot: Record<string, unknown> = {};
  for (const key of keys as string[]) {
    const descriptor = descriptors[key];
    if (!('value' in descriptor)) {
      throw new OperationDefinitionError(`${where}: ${key} is a value, not an accessor`);
    }
    snapshot[key] =
      (key === 'effects' || key === 'permissions') && Array.isArray(descriptor.value)
        ? Array.from(descriptor.value as unknown[])
        : descriptor.value;
  }
  return snapshot as unknown as AdminOperationDefinition;
}

/**
 * Throws {@link OperationDefinitionError} when `operation`, a snapshot from
 * {@link snapshotOperation}, breaks a rule it can be checked against alone.
 */
function assertOperation(operation: AdminOperationDefinition): void {
  const where = `operation ${JSON.stringify(operation.id)}`;
  const { id, effects, permissions, description, classify, loadState, stateVersion, render } =
    operation;
  if (typeof id !== 'string' || !OPERATION_ID_PATTERN.test(id)) {
    throw new OperationDefinitionError(
      `${where}: an id is <resource>.<verb>, lower camelCase segments joined by dots, such as realms.get`
    );
  }
  if (!PERMISSION_CLASSES.includes(operation.class)) {
    throw new OperationDefinitionError(
      `${where}: the class must be one of ${PERMISSION_CLASSES.join(', ')}`
    );
  }
  if (!Array.isArray(effects)) {
    throw new OperationDefinitionError(`${where}: effects is a list of effect tags`);
  }
  for (const effect of effects) {
    if (!isSecurityEffect(effect)) {
      throw new OperationDefinitionError(
        `${where}: ${JSON.stringify(effect)} is not an effect tag; the tags are ${SECURITY_EFFECTS.join(', ')}`
      );
    }
  }
  if (new Set(effects).size !== effects.length) {
    throw new OperationDefinitionError(`${where}: an effect is listed twice`);
  }
  // ADR-019 Decision 7: an operation with an effect is a security operation,
  // and a security operation is one because of an effect.
  if (operation.class === 'security' && effects.length === 0) {
    throw new OperationDefinitionError(
      `${where}: a security operation names the effects that make it one`
    );
  }
  if (operation.class !== 'security' && effects.length > 0) {
    throw new OperationDefinitionError(
      `${where}: an operation with the effects ${effects.join(', ')} is a security operation, not ${operation.class}`
    );
  }
  if (
    !Array.isArray(permissions) ||
    permissions.length === 0 ||
    !permissions.every(
      (permission) => typeof permission === 'string' && PERMISSION_ID_PATTERN.test(permission)
    )
  ) {
    throw new OperationDefinitionError(
      `${where}: permissions is a non-empty list of permission ids, such as realms.read`
    );
  }
  if (new Set(permissions).size !== permissions.length) {
    throw new OperationDefinitionError(`${where}: a permission is listed twice`);
  }
  if (!isOneLine(description)) {
    throw new OperationDefinitionError(`${where}: the description is one line of text`);
  }
  if (classify !== undefined && typeof classify !== 'function') {
    throw new OperationDefinitionError(`${where}: classify is a function`);
  }
  if (loadState !== undefined && typeof loadState !== 'function') {
    throw new OperationDefinitionError(`${where}: loadState is a function`);
  }
  if (loadState !== undefined && classify === undefined) {
    throw new OperationDefinitionError(`${where}: loadState is read only by classify`);
  }
  if (stateVersion !== undefined && typeof stateVersion !== 'function') {
    throw new OperationDefinitionError(`${where}: stateVersion is a function`);
  }
  // The classification holds for the state it was made against only; the
  // version is what binds the handler's write to that state.
  if (loadState !== undefined && stateVersion === undefined) {
    throw new OperationDefinitionError(
      `${where}: an operation with loadState names the version of the state it read (stateVersion), so its write can be conditional on it`
    );
  }
  if (stateVersion !== undefined && loadState === undefined) {
    throw new OperationDefinitionError(`${where}: stateVersion is read only with loadState`);
  }
  if (render !== undefined && typeof render !== 'function') {
    throw new OperationDefinitionError(`${where}: render is a function`);
  }
  // Only a security operation is ever approved, so only one is ever shown to
  // an approver.
  if (render !== undefined && operation.class !== 'security') {
    throw new OperationDefinitionError(
      `${where}: only a security operation renders; render shows an approver the operation`
    );
  }
  // A request whose classification fails closed gets the declaration, which
  // must therefore be a security classification: otherwise a broken
  // `classify` would hand a request that may be a security operation the
  // class `write`.
  if (classify !== undefined && operation.class !== 'security') {
    throw new OperationDefinitionError(
      `${where}: an operation with classify declares the strictest case, class security, which a request gets when its classification fails closed`
    );
  }
}

/**
 * Define one admin operation.
 *
 * @throws {OperationDefinitionError} when the definition has an unknown
 *   member, a malformed id, class, permission or description, an unknown
 *   effect, or breaks the static rule: `class: security` if and only if
 *   `effects` is not empty, and only a security operation may `classify`
 */
export function defineOperation<State>(
  operation: AdminOperationDefinition<State>
): AdminOperation<State> {
  const snapshot = snapshotOperation(operation as AdminOperationDefinition);
  assertOperation(snapshot);
  return frozenOperation(snapshot) as AdminOperation<State>;
}

/** `snapshot` frozen, with its lists. */
function frozenOperation(snapshot: AdminOperationDefinition): AdminOperation {
  return Object.freeze({
    ...snapshot,
    effects: Object.freeze([...snapshot.effects]),
    permissions: Object.freeze([...snapshot.permissions]),
  });
}

/** A registry: every admin operation once, looked up by id. */
export interface OperationRegistry {
  /** Every operation, in definition order. */
  readonly all: readonly AdminOperation[];
  /** The catalog the operations' permissions were checked against. */
  readonly permissions: PermissionRegistry;
  /** The reserved table the operations were checked against. */
  readonly reserved: readonly ReservedOperation[];
  /** The operation with this exact id; `undefined` for an unknown id. */
  get(id: string): AdminOperation | undefined;
}

/** Options for {@link createOperationRegistry}; the defaults are the server's own tables. */
export interface OperationRegistryOptions {
  permissions?: PermissionRegistry;
  reserved?: readonly ReservedOperation[];
}

/** The members a reserved entry may have. */
const RESERVED_KEYS: ReadonlySet<string> = new Set([
  'id',
  'effects',
  'requestDependent',
  'vectors',
  'source',
  'description',
]);

/** The members a reserved vector has. */
const VECTOR_KEYS: ReadonlySet<string> = new Set(['name', 'request', 'state', 'effects']);

/** Throws {@link OperationDefinitionError} when a request-dependent entry's vectors are malformed. */
function assertVectors(entry: ReservedOperation, where: string): void {
  if (entry.requestDependent !== true) {
    if (entry.vectors !== undefined) {
      throw new OperationDefinitionError(
        `${where}: only a request-dependent entry has vectors; every request of this one needs its declaration`
      );
    }
    return;
  }
  // Without cases, a `classify` that answers `write` for every request would
  // take the reservation.
  if (!Array.isArray(entry.vectors) || entry.vectors.length === 0) {
    throw new OperationDefinitionError(
      `${where}: a request-dependent entry lists the security cases its classify must meet (vectors)`
    );
  }
  const names = new Set<string>();
  for (const vector of entry.vectors as readonly ReservedVector[]) {
    const unknown =
      typeof vector === 'object' && vector !== null
        ? Reflect.ownKeys(vector).filter((key) => typeof key !== 'string' || !VECTOR_KEYS.has(key))
        : ['(not an object)'];
    const request = (vector as { request?: unknown } | null)?.request;
    if (
      unknown.length > 0 ||
      !isOneLine(vector.name) ||
      names.has(vector.name) ||
      typeof request !== 'object' ||
      request === null ||
      typeof (request as { method?: unknown }).method !== 'string' ||
      !Array.isArray(vector.effects) ||
      vector.effects.length === 0 ||
      !vector.effects.every(
        (effect) => isSecurityEffect(effect) && entry.effects.includes(effect)
      ) ||
      new Set(vector.effects).size !== vector.effects.length
    ) {
      throw new OperationDefinitionError(
        `${where}: a vector has a one-line name of its own, a request with a method, a state and one or more distinct effects of the entry`
      );
    }
    names.add(vector.name);
  }
}

/** Throws {@link OperationDefinitionError} when the reserved table is malformed. */
function assertReservedTable(reserved: readonly ReservedOperation[]): void {
  const ids = new Set<string>();
  for (const entry of reserved) {
    const where = `reserved operation ${JSON.stringify(entry.id)}`;
    const unknown = Reflect.ownKeys(entry).filter(
      (key) => typeof key !== 'string' || !RESERVED_KEYS.has(key)
    );
    if (unknown.length > 0) {
      throw new OperationDefinitionError(
        `${where}: unknown member ${unknown.map((key) => String(key)).join(', ')}`
      );
    }
    if (entry.requestDependent !== undefined && entry.requestDependent !== true) {
      throw new OperationDefinitionError(`${where}: requestDependent is true or absent`);
    }
    if (typeof entry.id !== 'string' || !OPERATION_ID_PATTERN.test(entry.id)) {
      throw new OperationDefinitionError(`${where}: a reserved id is <resource>.<verb>`);
    }
    if (ids.has(entry.id.toLowerCase())) {
      throw new OperationDefinitionError(`${where} is listed twice`);
    }
    ids.add(entry.id.toLowerCase());
    if (
      !Array.isArray(entry.effects) ||
      entry.effects.length === 0 ||
      !entry.effects.every(isSecurityEffect) ||
      new Set(entry.effects).size !== entry.effects.length
    ) {
      throw new OperationDefinitionError(
        `${where}: a reserved id names one or more distinct effect tags`
      );
    }
    if (!isOneLine(entry.source) || !isOneLine(entry.description)) {
      throw new OperationDefinitionError(`${where}: the source and description are one line each`);
    }
    assertVectors(entry, where);
  }
}

/**
 * Throws {@link OperationDefinitionError} when `operation`'s `classify` gives
 * a case of its reservation less than the case needs, or fails closed on it.
 * `classify` is pure and synchronous, so the cases run at boot.
 */
function assertVectorsMet(
  operation: AdminOperation,
  reservation: ReservedOperation,
  permissions: PermissionRegistry,
  where: string
): void {
  for (const vector of reservation.vectors ?? []) {
    const result = classifyRequest({ permissions }, operation, vector.request, vector.state);
    if (result.failedClosed !== null) {
      throw new OperationDefinitionError(
        `${where}: classify fails closed (${result.failedClosed}) on the reserved case "${vector.name}" (${reservation.source}); write the case in the representation the operation ships, so it tests the classification`
      );
    }
    const missing = vector.effects.filter((effect) => !result.effects.includes(effect));
    if (result.class !== 'security' || missing.length > 0) {
      throw new OperationDefinitionError(
        `${where}: classify gives the reserved case "${vector.name}" ${result.class}${result.effects.length > 0 ? ` with ${result.effects.join(', ')}` : ' with no effect'}, but it needs at least security with ${vector.effects.join(', ')} (${reservation.source})`
      );
    }
  }
}

/**
 * Build a registry from its operations.
 *
 * @throws {OperationDefinitionError} when an operation is malformed (see
 *   {@link defineOperation}); when two operations have the same id, or ids
 *   that differ only in case; when an operation names a permission the
 *   catalog cannot grant, or a class that is not the strictest class among
 *   its permissions; when it takes a reserved id with a weaker
 *   classification than the reserved table declares, takes a case variant of
 *   a reserved id, classifies a reserved operation whose entry does not say
 *   the request decides, or classifies one of its entry's security cases
 *   (`vectors`) less strictly than the case says or fails closed on it
 */
export function createOperationRegistry(
  operations: readonly AdminOperation[],
  options: OperationRegistryOptions = {}
): OperationRegistry {
  const permissions = options.permissions ?? PERMISSION_REGISTRY;
  const reserved = Object.freeze([...(options.reserved ?? RESERVED_OPERATIONS)]);
  assertReservedTable(reserved);
  const reservedByFoldedId = new Map(reserved.map((entry) => [entry.id.toLowerCase(), entry]));

  const byId = new Map<string, AdminOperation>();
  const byFoldedId = new Map<string, string>();
  for (const definition of operations) {
    const operation = snapshotOperation(definition);
    assertOperation(operation);
    const where = `operation ${JSON.stringify(operation.id)}`;

    const folded = operation.id.toLowerCase();
    const taken = byFoldedId.get(folded);
    if (taken !== undefined) {
      throw new OperationDefinitionError(
        taken === operation.id
          ? `${where} is defined twice; an id names one operation`
          : `operations ${JSON.stringify(taken)} and ${JSON.stringify(operation.id)} differ only in case`
      );
    }
    byFoldedId.set(folded, operation.id);

    const classes: OperationClass[] = [];
    for (const id of operation.permissions) {
      const permission = permissions.isGrantable(id) ? permissions.get(id) : undefined;
      if (permission === undefined) {
        throw new OperationDefinitionError(
          `${where}: ${id} is not a grantable permission of the admin catalog (admin-permissions.ts)`
        );
      }
      classes.push(permission.class);
    }
    // A security operation that named only a write permission would let
    // `qauth:admin:write` reach it; a write operation that named a security
    // permission would hide a security operation behind a write class.
    const strictest = strictestClass(classes);
    if (strictest !== operation.class) {
      throw new OperationDefinitionError(
        `${where}: the class is ${operation.class}, but the strictest class among its permissions is ${String(strictest)}; they must be the same`
      );
    }

    const reservation = reservedByFoldedId.get(folded);
    if (reservation !== undefined) {
      // A case variant would escape the reservation it was meant to take.
      if (reservation.id !== operation.id) {
        throw new OperationDefinitionError(
          `${where} differs only in case from the reserved id ${JSON.stringify(reservation.id)}`
        );
      }
      const missing = reservation.effects.filter((effect) => !operation.effects.includes(effect));
      if (operation.class !== 'security' || missing.length > 0) {
        throw new OperationDefinitionError(
          `${where} is reserved as a security operation with the effects ${reservation.effects.join(', ')} (${reservation.source}); it is registered as ${operation.class}${operation.effects.length > 0 ? ` with ${operation.effects.join(', ')}` : ' with no effect'}`
        );
      }
      // Its declaration is what every request needs, unless the table says
      // the request decides: a `classify` could otherwise answer `write` for
      // every request of an operation reserved as a security operation.
      if (operation.classify !== undefined && reservation.requestDependent !== true) {
        throw new OperationDefinitionError(
          `${where} is reserved as a security operation on every request (${reservation.source}); it may not classify, unless its entry says the request decides (requestDependent)`
        );
      }
      // A request-dependent reservation still holds its security cases: a
      // `classify` that answered `write` for them would bypass it.
      if (operation.classify !== undefined) {
        assertVectorsMet(operation, reservation, permissions, where);
      }
    }

    byId.set(operation.id, frozenOperation(operation));
  }

  return Object.freeze({
    all: Object.freeze([...byId.values()]),
    permissions,
    reserved,
    get: (id: string) => (typeof id === 'string' ? byId.get(id) : undefined),
  });
}

/**
 * Why a request got its operation's declared classification instead of the
 * one `classify` returned. Logged, never sent.
 *
 * - `threw`: `classify` threw.
 * - `unknown-field`: `classify` met a field it has no rule for, or its result
 *   has a member other than `class`, `effects` and `permissions`.
 * - `unknown-effect`, `unknown-class`, `unknown-permission`: the result names
 *   a value the closed lists do not hold.
 * - `not-synchronous`: `classify` returned a promise or another thenable.
 * - `malformed`: the result is not a plain object of the right shape.
 * - `inconsistent`: its class is not the strictest class of its permissions,
 *   or it is `security` with no effect, or has an effect but is not `security`.
 * - `exceeds-declaration`: it names an effect or permission the operation
 *   does not declare.
 * - `uncloneable-input`: the request or the state could not be copied for
 *   `classify`.
 */
export type FailClosedReason =
  | 'threw'
  | 'unknown-field'
  | 'unknown-effect'
  | 'unknown-class'
  | 'unknown-permission'
  | 'not-synchronous'
  | 'malformed'
  | 'inconsistent'
  | 'exceeds-declaration'
  | 'uncloneable-input';

/** What one request needs, as {@link classifyRequest} decided it. Frozen. */
export interface OperationClassification extends Classification {
  readonly operationId: string;
  /** Why the request got the operation's declaration, or `null` when the classification stood. */
  readonly failedClosed: FailClosedReason | null;
  /**
   * The version of the state the request was classified against
   * (`stateVersion` of what `loadState` read), or `null` for an operation
   * that reads none. The handler's write must be conditional on it.
   */
  readonly stateVersion: string | null;
  /**
   * The SHA-256 digest, base64url, of a binary body (a Buffer, typed array,
   * DataView or ArrayBuffer), or `null` for any other body. A binary body
   * cannot be frozen, so a stage that approves or applies it binds to this
   * digest ({@link bodyDigestOf}) rather than to the bytes it holds.
   */
  readonly bodyDigest: string | null;
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
function isUnknownFieldError(error: unknown): boolean {
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
 * Freeze `value` in place, and every object and array it holds. A typed array
 * (a binary body) is left as it is: one with elements cannot be frozen, which
 * is why the classification carries the digest of a binary body
 * (`bodyDigest`).
 */
export function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  // A typed array with elements cannot be frozen, and a clone's typed array
  // is classify's own copy anyway.
  if (ArrayBuffer.isView(value)) return value;
  Object.freeze(value);
  for (const key of Reflect.ownKeys(value)) {
    deepFreeze((value as Record<PropertyKey, unknown>)[key]);
  }
  return value;
}

const RESULT_KEYS: ReadonlySet<string> = new Set(['class', 'effects', 'permissions']);

/** The value of an own data property; `undefined` for a missing one or an accessor. */
function ownData(object: object, key: string): { value: unknown } | undefined {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor !== undefined && 'value' in descriptor
    ? { value: descriptor.value }
    : undefined;
}

type Checked = { classification: Classification } | { reason: FailClosedReason };

/**
 * Check what `classify` returned against the closed lists, the static rule
 * and the operation's declaration, and put it in canonical order: effects in
 * the order of `SECURITY_EFFECTS`, permissions in the operation's order,
 * each once.
 */
function checkResult(
  result: unknown,
  operation: AdminOperation,
  permissions: PermissionRegistry
): Checked {
  if (
    (typeof result === 'object' || typeof result === 'function') &&
    result !== null &&
    typeof (result as { then?: unknown }).then === 'function'
  ) {
    // A pure classification is synchronous. Keep a rejection from surfacing
    // as an unhandled one.
    Promise.resolve(result).catch(() => undefined);
    return { reason: 'not-synchronous' };
  }
  if (typeof result !== 'object' || result === null || Array.isArray(result)) {
    return { reason: 'malformed' };
  }
  const prototype = Object.getPrototypeOf(result);
  if (prototype !== Object.prototype && prototype !== null) return { reason: 'malformed' };
  if (Reflect.ownKeys(result).some((key) => typeof key !== 'string' || !RESULT_KEYS.has(key))) {
    return { reason: 'unknown-field' };
  }

  const resultClass = ownData(result, 'class');
  const resultEffects = ownData(result, 'effects');
  const resultPermissions = ownData(result, 'permissions');
  if (
    resultClass === undefined ||
    resultEffects === undefined ||
    resultPermissions === undefined ||
    !Array.isArray(resultEffects.value) ||
    !Array.isArray(resultPermissions.value) ||
    resultPermissions.value.length === 0
  ) {
    return { reason: 'malformed' };
  }
  if (!PERMISSION_CLASSES.includes(resultClass.value as OperationClass)) {
    return { reason: 'unknown-class' };
  }
  const operationClass = resultClass.value as OperationClass;

  const effects = new Set<SecurityEffect>();
  for (const effect of resultEffects.value as unknown[]) {
    if (!isSecurityEffect(effect)) return { reason: 'unknown-effect' };
    effects.add(effect);
  }
  const named = new Set<string>();
  for (const permission of resultPermissions.value as unknown[]) {
    if (typeof permission !== 'string' || !permissions.isGrantable(permission)) {
      return { reason: 'unknown-permission' };
    }
    named.add(permission);
  }

  if (
    [...effects].some((effect) => !operation.effects.includes(effect)) ||
    [...named].some((permission) => !operation.permissions.includes(permission))
  ) {
    return { reason: 'exceeds-declaration' };
  }
  const strictest = strictestClass(
    [...named].map((permission) => permissions.get(permission)?.class ?? 'security')
  );
  if (
    strictest !== operationClass ||
    (operationClass === 'security') !== effects.size > 0 ||
    classRank(operationClass) > classRank(operation.class)
  ) {
    return { reason: 'inconsistent' };
  }

  return {
    classification: {
      class: operationClass,
      effects: SECURITY_EFFECTS.filter((effect) => effects.has(effect)),
      permissions: operation.permissions.filter((permission) => named.has(permission)),
    },
  };
}

/** The classification a request gets from its operation, with `failedClosed`, frozen. */
function classificationOf(
  operation: AdminOperation,
  classification: Classification,
  failedClosed: FailClosedReason | null,
  bound: Pick<OperationClassification, 'stateVersion' | 'bodyDigest'>
): OperationClassification {
  return Object.freeze({
    operationId: operation.id,
    class: classification.class,
    effects: Object.freeze([...classification.effects]),
    permissions: Object.freeze([...classification.permissions]),
    failedClosed,
    stateVersion: bound.stateVersion,
    bodyDigest: bound.bodyDigest,
  });
}

/**
 * The SHA-256 digest, base64url, of `body` when it is binary (a Buffer, a
 * typed array, a DataView or an ArrayBuffer), or `null` for any other value.
 */
export function bodyDigestOf(body: unknown): string | null {
  let bytes: Uint8Array;
  if (ArrayBuffer.isView(body)) {
    bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  } else if (body instanceof ArrayBuffer) {
    bytes = new Uint8Array(body);
  } else {
    return null;
  }
  return createHash('sha256').update(bytes).digest('base64url');
}

/** An entity-tag's opaque value: `etagc` of RFC 9110 §8.8.3 without obs-text, bounded. */
const STATE_VERSION_PATTERN = /^[\x21\x23-\x7e]{1,256}$/;

/**
 * The version of `state` as `operation.stateVersion` gives it.
 *
 * @throws {Error} when the operation has no `stateVersion`, or it throws or
 *   returns anything but an entity-tag's opaque value: the request then fails
 *   and runs nothing, since its write could not be bound to the state
 */
export function operationStateVersion(operation: AdminOperation, state: unknown): string {
  if (operation.stateVersion === undefined) {
    throw new Error(`The admin operation ${operation.id} reads state but names no stateVersion`);
  }
  const version: unknown = operation.stateVersion(state);
  if (typeof version !== 'string' || !STATE_VERSION_PATTERN.test(version)) {
    throw new Error(
      `The admin operation ${operation.id} gave a state version that is not an entity-tag's opaque value`
    );
  }
  return version;
}

/** Whether `code` is an `etagc` (RFC 9110 §8.8.3): `%x21 / %x23-7E / obs-text`. */
function isEntityTagChar(code: number): boolean {
  return code === 0x21 || (code >= 0x23 && code <= 0x7e) || (code >= 0x80 && code <= 0xff);
}

/** Whether `char` is optional whitespace (RFC 9110 §5.6.3). */
function isOws(char: string | undefined): boolean {
  return char === ' ' || char === '\t';
}

/**
 * Whether an `If-Match` field (RFC 9110 §13.1.1) lets a request act on the
 * state of version `stateVersion`: absent, `*`, or a list holding the strong
 * entity-tag `"stateVersion"`. A weak tag never matches (strong comparison),
 * empty list elements are skipped, and a field that does not parse matches
 * nothing.
 *
 * Parsed in one pass, without a regular expression: a pattern with repeated
 * whitespace and comma groups is polynomial on a long run of either.
 */
export function ifMatchAllows(field: string | string[] | undefined, stateVersion: string): boolean {
  if (field === undefined) return true;
  const value = (Array.isArray(field) ? field.join(', ') : field).trim();
  if (value === '*') return true;
  if (value === '') return false;
  let matched = false;
  let i = 0;
  while (i < value.length) {
    // Optional whitespace and empty list elements before the next tag.
    while (i < value.length && (isOws(value[i]) || value[i] === ',')) i++;
    if (i >= value.length) break;
    const weak = value.startsWith('W/', i);
    if (weak) i += 2;
    if (value[i] !== '"') return false;
    const start = ++i;
    while (i < value.length && isEntityTagChar(value.charCodeAt(i))) i++;
    if (value[i] !== '"') return false;
    const opaque = value.slice(start, i);
    i++;
    while (i < value.length && isOws(value[i])) i++;
    if (i < value.length && value[i] !== ',') return false;
    if (!weak && opaque === stateVersion) matched = true;
  }
  return matched;
}

/**
 * What one request of `operation` needs.
 *
 * `stateVersion` is the version of `currentState` ({@link operationStateVersion})
 * and the classification carries it, with the digest of a binary body.
 *
 * An operation without `classify` needs its declaration. Otherwise `classify`
 * runs on frozen deep copies of the request and of `currentState`, and its
 * result stands when it is well formed and within the declaration. In every
 * other case the request fails closed: it gets the declaration, which for an
 * operation with `classify` is always `security`, and `failedClosed` says why.
 * Never throws.
 */
export function classifyRequest(
  registry: Pick<OperationRegistry, 'permissions'>,
  operation: AdminOperation,
  request: ClassifyInput,
  currentState?: unknown,
  stateVersion: string | null = null
): OperationClassification {
  const bound = { stateVersion, bodyDigest: bodyDigestOf(request.body) };
  if (operation.classify === undefined) {
    return classificationOf(operation, operation, null, bound);
  }
  const failClosed = (reason: FailClosedReason) =>
    classificationOf(operation, operation, reason, bound);

  let input: ClassifyInput;
  let state: unknown;
  try {
    input = deepFreeze(
      structuredClone({
        method: request.method,
        params: request.params,
        query: request.query,
        body: request.body,
      })
    );
    state = deepFreeze(structuredClone(currentState));
  } catch {
    return failClosed('uncloneable-input');
  }

  let result: unknown;
  try {
    result = operation.classify(input, state);
  } catch (error) {
    return failClosed(isUnknownFieldError(error) ? 'unknown-field' : 'threw');
  }

  let checked: Checked;
  try {
    checked = checkResult(result, operation, registry.permissions);
  } catch {
    // A result whose members throw when read (a proxy) is not a plain value.
    return failClosed('malformed');
  }
  return 'reason' in checked
    ? failClosed(checked.reason)
    : classificationOf(operation, checked.classification, null, bound);
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

/** The OpenAPI members a route of `operation` declares in its schema. */
export interface OperationSchemaExtensions {
  operationId: string;
  'x-qauth-class': OperationClass;
  'x-qauth-permission': string | readonly string[];
  'x-qauth-effects'?: readonly SecurityEffect[];
  'x-qauth-two-admin'?: 'recommended';
}

/**
 * The schema members of a route of `operation`, from the registry: spread
 * them into the route's schema so the OpenAPI document and the registry
 * cannot disagree. A security operation also carries `x-qauth-effects` and
 * `x-qauth-two-admin` (API conventions, #506). The admin pipeline refuses to
 * boot a route whose schema holds any other value for them.
 */
export function operationSchemaExtensions(operation: AdminOperation): OperationSchemaExtensions {
  const extensions: OperationSchemaExtensions = {
    operationId: operation.id,
    'x-qauth-class': operation.class,
    'x-qauth-permission':
      operation.permissions.length === 1 ? operation.permissions[0] : [...operation.permissions],
  };
  if (operation.effects.length > 0) {
    extensions['x-qauth-effects'] = [...operation.effects];
    extensions['x-qauth-two-admin'] = 'recommended';
  }
  return extensions;
}

/**
 * A registry of `operations` and the approval engine's own operations
 * (`approvals.create`, `approvals.get`, `approvals.cancel`, #512), which every
 * admin listener serves: a security operation runs only with an approval
 * filed through them. Filing and cancelling an approval need what the
 * operation it is for needs, so their `classify` looks that operation up in
 * the registry built here.
 *
 * @throws {OperationDefinitionError} as {@link createOperationRegistry} does
 */
export function createAdminOperationRegistry(
  operations: readonly AdminOperation[],
  options: OperationRegistryOptions = {}
): OperationRegistry {
  const built: { registry?: OperationRegistry } = {};
  const engine = approvalOperationDefinitions(options.permissions ?? PERMISSION_REGISTRY, (id) =>
    built.registry?.get(id)
  );
  built.registry = createOperationRegistry([...operations, ...engine], options);
  return built.registry;
}

/**
 * Every admin operation, but the approval engine's own. None is registered
 * yet: the admin API's first operations, reading a realm and patching its
 * policies (#517), register here with the admin listener (#511).
 */
export const ADMIN_OPERATIONS: readonly AdminOperation[] = Object.freeze([]);

/** The registry the admin pipeline classifies against: {@link ADMIN_OPERATIONS} and the approval operations. */
export const OPERATION_REGISTRY: OperationRegistry = createAdminOperationRegistry(ADMIN_OPERATIONS);
