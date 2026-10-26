/**
 * The API conventions check (#506): the rules of the docs site's
 * `reference/api-conventions.md`, enforced over a generated OpenAPI document.
 *
 * Every operation under an API family prefix (`/admin/v<n>`, `/account/v<n>`,
 * `/developer/v<n>`) is checked; nothing else is. `openapi-conventions.test.ts`
 * runs the check over the two documents the exporter writes
 * (`stable-surface/openapi.json` and `apps/docs-site/public/openapi.json`),
 * which CI's stable-surface drift check keeps equal to what the server
 * generates. The check reads the document only, so a rule it enforces is a
 * rule a client can see.
 *
 * Pure: no I/O, no Fastify. It takes the parsed document and returns one
 * violation per broken rule, so a failing test names every problem at once.
 */
import { PERMISSION_ID_PATTERN, PERMISSION_REGISTRY } from '../helpers/admin-permissions';
import type { OperationClass, OperationStability } from '../openapi-options';
import { type ApiFamily, apiFamilyOf, isUnversionedFamilyPath } from './families';
import { PAGE_LIMIT_DEFAULT, PAGE_LIMIT_MAX } from './paging';
import { PROBLEM_MEDIA_TYPE, PROBLEM_SCHEMA_ID, PROBLEM_SCHEMA_REF } from './problem';
import { REGISTERED_NAMES } from './registered-names';

/** The rule a violation breaks; each one is a section of the conventions page. */
export type ConventionRule =
  | 'path-version'
  | 'operation-id'
  | 'security'
  | 'class'
  | 'permission'
  | 'effects'
  | 'two-admin'
  | 'stability'
  | 'naming'
  | 'id-format'
  | 'time-format'
  | 'unknown-fields'
  | 'problem'
  | 'paging'
  | 'merge-patch'
  | 'if-match';

export interface ConventionViolation {
  /** `METHOD /path`, or the path alone for a rule about the path. */
  operation: string;
  rule: ConventionRule;
  message: string;
}

export interface ConventionReport {
  violations: ConventionViolation[];
  /** How many family operations the document holds: a check of zero is visible. */
  checkedOperations: number;
}

const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'] as const;

const OPERATION_CLASSES: readonly OperationClass[] = ['read', 'write', 'security'];
const STABILITIES: readonly OperationStability[] = ['stable', 'experimental'];

/** `<resource>.<verb>`, the resource itself possibly dotted: `realms.get`, `realms.policies.update`. */
const OPERATION_ID = /^[a-z][a-zA-Z0-9]*(?:\.[a-z][a-zA-Z0-9]*)+$/;

/** A permission id has the same shape: `realms.read`, `realms.policies.security`. */
const PERMISSION_ID = PERMISSION_ID_PATTERN;

const CAMEL_CASE = /^[a-z][a-zA-Z0-9]*$/;
const KEBAB_CASE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

/** `id`, or a reference to another resource by its id: `realmId`, `clientId`. */
const ID_NAME = /^(?:id|[a-z][a-zA-Z0-9]*Id)$/;

/** A point in time: `createdAt`, `expiresAt`. */
const TIME_NAME = /^[a-z][a-zA-Z0-9]*At$/;

const MERGE_PATCH_MEDIA_TYPE = 'application/merge-patch+json';

/** Query parameters of offset paging, which the conventions replace with a cursor. */
const OFFSET_PAGING_PARAMETERS = new Set(['offset', 'page', 'pageSize', 'perPage', 'skip']);

type JsonObject = Record<string, unknown>;

const isObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Follow a local `$ref` (`#/components/...`) through the document, up to a bound. */
function resolver(document: JsonObject) {
  const follow = (pointer: string): unknown => {
    let node: unknown = document;
    for (const raw of pointer.slice(2).split('/')) {
      const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
      if (!isObject(node)) return undefined;
      node = node[key];
    }
    return node;
  };

  return (value: unknown): unknown => {
    let node = value;
    for (let depth = 0; depth < 32 && isObject(node); depth++) {
      const ref = node['$ref'];
      if (typeof ref !== 'string' || !ref.startsWith('#/')) return node;
      node = follow(ref);
    }
    return node;
  };
}

type Resolve = ReturnType<typeof resolver>;

/** The non-null alternatives of a schema: `anyOf: [X, {type: null}]` is `[X]`. */
function valueBranches(schema: unknown, resolve: Resolve, depth = 0): JsonObject[] {
  const node = resolve(schema);
  if (!isObject(node) || depth > 16) return [];
  for (const key of ['anyOf', 'oneOf'] as const) {
    const alternatives = node[key];
    if (Array.isArray(alternatives)) {
      return alternatives.flatMap((alternative) => valueBranches(alternative, resolve, depth + 1));
    }
  }
  const type = node['type'];
  if (type === 'null' || (Array.isArray(type) && type.every((t) => t === 'null'))) return [];
  return [node];
}

/** Whether every non-null branch of `schema` is a string of `format`. */
function isStringOfFormat(schema: unknown, format: string, resolve: Resolve): boolean {
  const branches = valueBranches(schema, resolve);
  return (
    branches.length > 0 &&
    branches.every((branch) => {
      const type = branch['type'];
      const types = Array.isArray(type) ? type.filter((t) => t !== 'null') : [type];
      return types.length === 1 && types[0] === 'string' && branch['format'] === format;
    })
  );
}

interface SchemaVisit {
  /** The object schema that declares the property. */
  owner: JsonObject;
  name: string;
  schema: unknown;
  /** Where the property sits, for the message: `response 200 › items[] › createdAt`. */
  at: string;
}

/**
 * Call `visit` for every property declared anywhere inside `schema`, through
 * `$ref`, `items`, `prefixItems`, `additionalProperties` and the combinators.
 * `onObject` sees every object schema that declares `properties`.
 */
function walkSchema(
  schema: unknown,
  at: string,
  resolve: Resolve,
  visit: (property: SchemaVisit) => void,
  onObject: (object: JsonObject, at: string) => void = () => undefined,
  seen = new Set<unknown>()
): void {
  const node = resolve(schema);
  if (!isObject(node) || seen.has(node)) return;
  seen.add(node);

  const properties = node['properties'];
  if (isObject(properties)) {
    onObject(node, at);
    for (const [name, child] of Object.entries(properties)) {
      const childAt = `${at} › ${name}`;
      visit({ owner: node, name, schema: child, at: childAt });
      walkSchema(child, childAt, resolve, visit, onObject, seen);
    }
  }

  const items = node['items'];
  if (isObject(items)) walkSchema(items, `${at}[]`, resolve, visit, onObject, seen);
  const prefixItems = node['prefixItems'];
  if (Array.isArray(prefixItems)) {
    prefixItems.forEach((item, index) =>
      walkSchema(item, `${at}[${index}]`, resolve, visit, onObject, seen)
    );
  }
  const additional = node['additionalProperties'];
  if (isObject(additional)) walkSchema(additional, `${at}{}`, resolve, visit, onObject, seen);
  for (const key of ['anyOf', 'oneOf', 'allOf'] as const) {
    const alternatives = node[key];
    if (Array.isArray(alternatives)) {
      alternatives.forEach((alternative) =>
        walkSchema(alternative, at, resolve, visit, onObject, seen)
      );
    }
  }
  if (isObject(node['not'])) walkSchema(node['not'], at, resolve, visit, onObject, seen);
}

/** The media type map of a request body or a response, resolved. */
function contentOf(holder: unknown, resolve: Resolve): JsonObject {
  const resolved = resolve(holder);
  if (!isObject(resolved)) return {};
  const content = resolved['content'];
  return isObject(content) ? content : {};
}

interface OperationContext {
  key: string;
  method: (typeof HTTP_METHODS)[number];
  family: ApiFamily;
  operation: JsonObject;
  parameters: JsonObject[];
  document: JsonObject;
  resolve: Resolve;
  report: (rule: ConventionRule, message: string) => void;
}

function checkOperationId({ operation, report }: OperationContext): void {
  const id = operation['operationId'];
  if (typeof id !== 'string' || id === '') {
    report('operation-id', 'has no operationId; name it <resource>.<verb>, e.g. realms.get');
  } else if (!OPERATION_ID.test(id)) {
    report('operation-id', `operationId "${id}" is not <resource>.<verb>, e.g. realms.get`);
  }
}

function checkSecurity({ operation, document, report }: OperationContext): void {
  const requirements = operation['security'] ?? document['security'];
  if (!Array.isArray(requirements) || requirements.length === 0) {
    report('security', 'has no security requirement');
    return;
  }
  const components = isObject(document['components']) ? document['components'] : {};
  const schemes = isObject(components['securitySchemes']) ? components['securitySchemes'] : {};
  for (const requirement of requirements) {
    if (!isObject(requirement) || Object.keys(requirement).length === 0) {
      report('security', 'lists an empty security requirement, which lets an anonymous caller in');
      continue;
    }
    for (const name of Object.keys(requirement)) {
      if (!isObject(schemes[name])) {
        report(
          'security',
          `requires the security scheme "${name}", which the document does not define`
        );
      }
    }
  }
}

function checkExtensions({ family, operation, report }: OperationContext): void {
  const stability = operation['x-qauth-stability'];
  if (!STABILITIES.includes(stability as OperationStability)) {
    report('stability', `x-qauth-stability must be one of ${STABILITIES.join(', ')}`);
  }

  const operationClass = operation['x-qauth-class'];
  if (!OPERATION_CLASSES.includes(operationClass as OperationClass)) {
    report('class', `x-qauth-class must be one of ${OPERATION_CLASSES.join(', ')}`);
  } else if (operationClass === 'security' && family !== 'admin') {
    report(
      'class',
      'x-qauth-class "security" belongs to the admin API, where it means qauth:admin:security; account and developer operations are read or write'
    );
  }

  const permission = operation['x-qauth-permission'];
  const permissions = Array.isArray(permission) ? permission : [permission];
  if (
    permissions.length === 0 ||
    !permissions.every((entry) => typeof entry === 'string' && PERMISSION_ID.test(entry)) ||
    new Set(permissions).size !== permissions.length
  ) {
    report(
      'permission',
      'x-qauth-permission must be a permission id such as realms.read, or a list of distinct ids'
    );
  } else if (family === 'admin') {
    // An admin operation needs permissions a role can grant (#507): an id the
    // catalog does not know, or a retired one, could never be authorized.
    const classes = new Set<OperationClass>();
    for (const id of permissions as string[]) {
      const granted = PERMISSION_REGISTRY.isGrantable(id) ? PERMISSION_REGISTRY.get(id) : undefined;
      if (granted === undefined) {
        report(
          'permission',
          `x-qauth-permission names ${id}, which is not a grantable permission of the admin catalog (helpers/admin-permissions.ts)`
        );
      } else {
        classes.add(granted.class);
      }
    }
    // The class is the strictest class among the permissions: a security
    // operation that named only a write permission would let `qauth:admin:write`
    // reach it, and a write operation that named a security permission would
    // escape the effects and two-admin rules (ADR-019 Decision 7).
    const strictest = OPERATION_CLASSES.filter((candidate) => classes.has(candidate)).at(-1);
    if (
      strictest !== undefined &&
      OPERATION_CLASSES.includes(operationClass as OperationClass) &&
      operationClass !== strictest
    ) {
      report(
        'permission',
        `x-qauth-class is ${String(operationClass)}, but the strictest class of its permissions is ${strictest}; they must be the same`
      );
    }
  }

  const effects = operation['x-qauth-effects'];
  const isSecurity = operationClass === 'security';
  if (effects !== undefined) {
    if (
      !Array.isArray(effects) ||
      !effects.every((effect) => typeof effect === 'string' && KEBAB_CASE.test(effect)) ||
      new Set(effects).size !== effects.length
    ) {
      report('effects', 'x-qauth-effects must be a list of distinct kebab-case effect tags');
    }
  }
  const effectCount = Array.isArray(effects) ? effects.length : 0;
  if (isSecurity && effectCount === 0) {
    report('effects', 'is a security operation, so x-qauth-effects must name its effects');
  } else if (!isSecurity && effectCount > 0) {
    report('effects', 'has x-qauth-effects, which only a security operation carries');
  }

  const twoAdmin = operation['x-qauth-two-admin'];
  if (isSecurity && twoAdmin !== 'recommended') {
    report('two-admin', 'is a security operation, so x-qauth-two-admin must be "recommended"');
  } else if (!isSecurity && twoAdmin !== undefined) {
    report('two-admin', 'has x-qauth-two-admin, which only a security operation carries');
  }
}

/** Naming, id and time rules for one property of a representation. */
function checkProperty(
  { resolve, report }: OperationContext,
  { name, schema, at }: SchemaVisit
): void {
  if (!CAMEL_CASE.test(name) && !REGISTERED_NAMES.has(name)) {
    report('naming', `${at}: "${name}" is not camelCase and not a registered OAuth or OIDC name`);
  }
  if (ID_NAME.test(name) && !isStringOfFormat(schema, 'uuid', resolve)) {
    report('id-format', `${at}: an id is an opaque UUID string (type string, format uuid)`);
  }
  if (TIME_NAME.test(name) && !isStringOfFormat(schema, 'date-time', resolve)) {
    report('time-format', `${at}: a time is an RFC 3339 string (type string, format date-time)`);
  }
}

function checkParameters(context: OperationContext): void {
  const { parameters, resolve, report } = context;
  for (const parameter of parameters) {
    const where = parameter['in'];
    const name = parameter['name'];
    if (typeof name !== 'string' || (where !== 'query' && where !== 'path')) continue;
    if (!CAMEL_CASE.test(name) && !REGISTERED_NAMES.has(name)) {
      report('naming', `${where} parameter "${name}" is not camelCase`);
    }
    if (ID_NAME.test(name) && !isStringOfFormat(parameter['schema'], 'uuid', resolve)) {
      report('id-format', `${where} parameter "${name}": an id is an opaque UUID string`);
    }
  }
}

function checkRequestBody(context: OperationContext): void {
  const { operation, method, resolve, report } = context;
  const content = contentOf(operation['requestBody'], resolve);

  if (method === 'patch') {
    const mediaTypes = Object.keys(content);
    if (mediaTypes.length !== 1 || mediaTypes[0] !== MERGE_PATCH_MEDIA_TYPE) {
      report(
        'merge-patch',
        `a PATCH body is a JSON Merge Patch (RFC 7396): its only media type is ${MERGE_PATCH_MEDIA_TYPE}`
      );
    }
  }

  for (const [mediaType, media] of Object.entries(content)) {
    if (!isObject(media)) continue;
    walkSchema(
      media['schema'],
      `request body (${mediaType})`,
      resolve,
      (property) => checkProperty(context, property),
      (object, at) => {
        if (object['additionalProperties'] !== false && object['unevaluatedProperties'] !== false) {
          report(
            'unknown-fields',
            `${at}: a request object refuses unknown members (additionalProperties: false)`
          );
        }
      }
    );
  }
}

function checkResponses(context: OperationContext): void {
  const { operation, document, resolve, report } = context;
  const responses = isObject(operation['responses']) ? operation['responses'] : {};
  const components = isObject(document['components']) ? document['components'] : {};
  const schemas = isObject(components['schemas']) ? components['schemas'] : {};

  for (const [status, response] of Object.entries(responses)) {
    const content = contentOf(response, resolve);
    const isError = /^[45]/.test(status) || status === 'default';

    if (isError) {
      const media = content[PROBLEM_MEDIA_TYPE];
      const others = Object.keys(content).filter((mediaType) => mediaType !== PROBLEM_MEDIA_TYPE);
      if (
        !isObject(media) ||
        !isObject(media['schema']) ||
        media['schema']['$ref'] !== PROBLEM_SCHEMA_REF ||
        others.length > 0
      ) {
        report(
          'problem',
          `response ${status} must be ${PROBLEM_MEDIA_TYPE} with the shared schema ${PROBLEM_SCHEMA_REF}`
        );
      } else if (!isObject(schemas[PROBLEM_SCHEMA_ID])) {
        report('problem', `response ${status} references ${PROBLEM_SCHEMA_REF}, which is missing`);
      }
      continue;
    }

    for (const [mediaType, media] of Object.entries(content)) {
      if (!isObject(media)) continue;
      walkSchema(media['schema'], `response ${status} (${mediaType})`, resolve, (property) =>
        checkProperty(context, property)
      );
    }
  }
}

/** The paging rule for a `GET` whose 200 answer is a list. */
function checkPaging(context: OperationContext): void {
  const { method, operation, parameters, resolve, report } = context;
  if (method !== 'get') return;
  const responses = isObject(operation['responses']) ? operation['responses'] : {};
  const media = contentOf(responses['200'], resolve)['application/json'];
  if (!isObject(media)) return;
  const body = resolve(media['schema']);
  if (!isObject(body)) return;

  if (body['type'] === 'array') {
    report('paging', 'response 200 is a bare array; a list answers { items, nextCursor }');
    return;
  }
  const properties = isObject(body['properties']) ? body['properties'] : {};
  const items = resolve(properties['items']);
  if (!isObject(items) || items['type'] !== 'array') return;

  const required = Array.isArray(body['required']) ? body['required'] : [];
  const names = Object.keys(properties);
  const extra = names.filter((name) => name !== 'items' && name !== 'nextCursor');
  if (
    !('nextCursor' in properties) ||
    !isStringSchema(properties['nextCursor'], resolve) ||
    !allowsNull(properties['nextCursor'], resolve) ||
    !required.includes('items') ||
    !required.includes('nextCursor') ||
    extra.length > 0
  ) {
    report(
      'paging',
      'a list answers exactly { items, nextCursor }, both required, nextCursor a string or null'
    );
  }

  const query = new Map(
    parameters
      .filter((parameter) => parameter['in'] === 'query' && typeof parameter['name'] === 'string')
      .map((parameter) => [parameter['name'] as string, parameter])
  );
  const limit = query.get('limit');
  const limitSchema = isObject(limit) ? resolve(limit['schema']) : undefined;
  if (
    !isObject(limitSchema) ||
    limitSchema['type'] !== 'integer' ||
    limitSchema['default'] !== PAGE_LIMIT_DEFAULT ||
    limitSchema['maximum'] !== PAGE_LIMIT_MAX ||
    typeof limitSchema['minimum'] !== 'number' ||
    limitSchema['minimum'] < 1
  ) {
    report(
      'paging',
      `a list takes limit: an integer from 1, default ${PAGE_LIMIT_DEFAULT}, maximum ${PAGE_LIMIT_MAX}`
    );
  }
  const cursor = query.get('cursor');
  if (!isObject(cursor) || !isStringSchema(cursor['schema'], resolve)) {
    report('paging', 'a list takes cursor: an opaque string');
  }
  for (const name of query.keys()) {
    if (OFFSET_PAGING_PARAMETERS.has(name)) {
      report('paging', `query parameter "${name}" is offset paging; a list pages by cursor`);
    }
  }
}

/**
 * Whether `schema` admits `null`: `null` in its type, or a branch of `anyOf` or
 * `oneOf` that does. `valueBranches` drops the null branches, so a check that
 * needs one asks this.
 */
function allowsNull(schema: unknown, resolve: Resolve, depth = 0): boolean {
  const node = resolve(schema);
  if (!isObject(node) || depth > 16) return false;
  const type = node['type'];
  if (type === 'null' || (Array.isArray(type) && type.includes('null'))) return true;
  return (['anyOf', 'oneOf'] as const).some((key) => {
    const alternatives = node[key];
    return (
      Array.isArray(alternatives) &&
      alternatives.some((alternative) => allowsNull(alternative, resolve, depth + 1))
    );
  });
}

/** Whether every non-null branch of `schema` is a string. */
function isStringSchema(schema: unknown, resolve: Resolve): boolean {
  const branches = valueBranches(schema, resolve);
  return (
    branches.length > 0 &&
    branches.every((branch) => {
      const type = branch['type'];
      const types = Array.isArray(type) ? type.filter((t) => t !== 'null') : [type];
      return types.length === 1 && types[0] === 'string';
    })
  );
}

/** Optimistic concurrency: an update names the version it replaces. */
function checkConditionalUpdate(context: OperationContext): void {
  const { method, operation, parameters, report } = context;
  if (method !== 'patch' && method !== 'put') return;
  const ifMatch = parameters.find(
    (parameter) =>
      parameter['in'] === 'header' &&
      typeof parameter['name'] === 'string' &&
      parameter['name'].toLowerCase() === 'if-match'
  );
  if (!ifMatch || ifMatch['required'] !== true) {
    report('if-match', 'an update requires the If-Match header');
  }
  const responses = isObject(operation['responses']) ? operation['responses'] : {};
  for (const status of ['412', '428']) {
    if (!(status in responses)) {
      report('if-match', `an update declares the ${status} response (stale or missing If-Match)`);
    }
  }
}

/**
 * Check every API family operation of `document` against the conventions.
 *
 * @param document a parsed OpenAPI 3.1 document, such as `stable-surface/openapi.json`
 */
export function checkApiConventions(document: unknown): ConventionReport {
  const root = isObject(document) ? document : {};
  const paths = isObject(root['paths']) ? root['paths'] : {};
  const resolve = resolver(root);
  const violations: ConventionViolation[] = [];
  const operationIds = new Map<string, string>();
  let checkedOperations = 0;

  for (const [path, item] of Object.entries(paths)) {
    if (!isObject(item)) continue;

    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (!isObject(operation) || typeof operation['operationId'] !== 'string') continue;
      const key = `${method.toUpperCase()} ${path}`;
      const id = operation['operationId'];
      const first = operationIds.get(id);
      if (first) {
        violations.push({
          operation: key,
          rule: 'operation-id',
          message: `operationId "${id}" is already used by ${first}`,
        });
      } else {
        operationIds.set(id, key);
      }
    }

    if (isUnversionedFamilyPath(path)) {
      violations.push({
        operation: path,
        rule: 'path-version',
        message: 'starts with an API family name but not /<family>/v<major>',
      });
    }
    const family = apiFamilyOf(path);
    if (!family) continue;

    const pathParameters = Array.isArray(item['parameters']) ? item['parameters'] : [];
    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (!isObject(operation)) continue;
      checkedOperations++;
      const key = `${method.toUpperCase()} ${path}`;
      const ownParameters = Array.isArray(operation['parameters']) ? operation['parameters'] : [];
      const context: OperationContext = {
        key,
        method,
        family: family.family,
        operation,
        parameters: [...pathParameters, ...ownParameters]
          .map((parameter) => resolve(parameter))
          .filter(isObject),
        document: root,
        resolve,
        report: (rule, message) => violations.push({ operation: key, rule, message }),
      };
      checkOperationId(context);
      checkSecurity(context);
      checkExtensions(context);
      checkParameters(context);
      checkRequestBody(context);
      checkResponses(context);
      checkPaging(context);
      checkConditionalUpdate(context);
    }
  }

  return { violations, checkedOperations };
}
