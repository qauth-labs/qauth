/**
 * Generate the typed account API client from its published OpenAPI document
 * (#588). The output is `src/generated/account-api.ts`: one type per component
 * schema, the operation table, and one method per operation. No type of the
 * API is written by hand; `lib/runtime.ts` holds only the generic request
 * code.
 *
 * The generator reads the JSON Schema the contract uses, and refuses anything
 * else, so a construct it cannot type fails the generation instead of turning
 * into `unknown`:
 *
 * - `$ref` to `#/components/schemas/*`, `const`, `enum`, `x-extensible-enum`
 *   (a union of the known values and any other string);
 * - `type` `object` with `properties`, `required` and `additionalProperties`
 *   (an index signature), and rules between its members (`allOf` of
 *   `if`/`then`), which constrain it without changing its type; `array` with
 *   `items`, `string`, `integer`, `number`, `boolean`, and a list of types
 *   with `null` (`['string', 'null']`, a nullable value);
 * - `{ "not": {} }`, a member that is never present, as `never`.
 *
 * Annotations and validation keywords (`pattern`, `maxLength`, `format`, `not`,
 * `writeOnly`, …) carry no type and are left to the server; the descriptions
 * become doc comments.
 *
 * The Interaction API client has a generator of its own: shared libraries are
 * leaves of the module graph, so this one cannot import it. This one adds what
 * the account API uses and the Interaction API does not: query and header
 * parameters, a Merge Patch body, nullable values, and the access token.
 *
 * Pure and deterministic: the script formats the output with Oxfmt, and the
 * drift test does the same.
 */

type Schema = { readonly [keyword: string]: unknown };

/** Keywords that only constrain or describe a value; they do not change its TypeScript type. */
const NON_TYPE_KEYWORDS = new Set([
  'description',
  'title',
  'default',
  'examples',
  'pattern',
  'format',
  'minLength',
  'maxLength',
  'minimum',
  'maximum',
  'minItems',
  'maxItems',
  'uniqueItems',
  'maxProperties',
  'propertyNames',
  'not',
  'writeOnly',
  'readOnly',
  'x-qauth-display',
  'x-qauth-declared',
]);

/** The keywords a rule of an object (`allOf` member) may use: conditions, with no type of their own. */
const RULE_KEYWORDS = new Set(['if', 'then', 'else', 'description']);

const TYPE_KEYWORDS = new Set([
  '$ref',
  'const',
  'enum',
  'x-extensible-enum',
  'type',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'allOf',
]);

const SCHEMA_REF = '#/components/schemas/';

/** A TypeScript identifier for a component: already PascalCase in the document. */
function typeName(ref: string): string {
  if (!ref.startsWith(SCHEMA_REF)) throw new Error(`unsupported reference ${ref}`);
  const name = ref.slice(SCHEMA_REF.length);
  if (!/^[A-Z][A-Za-z0-9]*$/.test(name)) throw new Error(`not a type name: ${name}`);
  return name;
}

const literal = (value: unknown): string => {
  if (typeof value === 'string') return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  throw new Error(`unsupported literal ${JSON.stringify(value)}`);
};

/** A property key: bare when it is an identifier, quoted otherwise. */
const key = (name: string) => (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name) ? name : literal(name));

/** A doc comment for `description` (its first paragraph), or nothing. */
function docComment(description: unknown, indent = ''): string {
  if (typeof description !== 'string' || description === '') return '';
  const text = description.split('\n\n')[0].replace(/\*\//g, '*\\/').replace(/\n/g, ' ');
  return `${indent}/** ${text} */\n`;
}

function assertKnownKeywords(schema: Schema, at: string): void {
  for (const keyword of Object.keys(schema)) {
    if (!TYPE_KEYWORDS.has(keyword) && !NON_TYPE_KEYWORDS.has(keyword)) {
      throw new Error(`${at}: the generator does not know the keyword ${keyword}`);
    }
  }
  const rules = schema['allOf'];
  if (rules === undefined) return;
  if (schema['type'] !== 'object' || !Array.isArray(rules)) {
    throw new Error(`${at}: allOf is only read as the rules of an object`);
  }
  for (const [index, rule] of (rules as Schema[]).entries()) {
    for (const keyword of Object.keys(rule)) {
      if (!RULE_KEYWORDS.has(keyword)) {
        throw new Error(`${at}.allOf[${index}]: a rule may hold only if/then/else, not ${keyword}`);
      }
    }
  }
}

/** Whether `schema` is `{ "not": {} }` (with a description at most): nothing matches it. */
const isNever = (schema: Schema) =>
  typeof schema['not'] === 'object' &&
  schema['not'] !== null &&
  Object.keys(schema['not'] as object).length === 0 &&
  Object.keys(schema).every((keyword) => keyword === 'not' || keyword === 'description');

/** The TypeScript type of one JSON Schema `type` value. */
function primitiveType(schema: Schema, type: unknown, at: string): string {
  switch (type) {
    case 'string':
      return 'string';
    case 'integer':
    case 'number':
      return 'number';
    case 'boolean':
      return 'boolean';
    case 'null':
      return 'null';
    case 'array': {
      const items = schema['items'];
      if (typeof items !== 'object' || items === null)
        throw new Error(`${at}: an array needs items`);
      const item = typeOf(items as Schema, `${at}.items`);
      return /^[A-Za-z0-9_]+$/.test(item) ? `${item}[]` : `Array<${item}>`;
    }
    case 'object':
      return objectType(schema, at, '');
    default:
      throw new Error(`${at}: the generator cannot type ${JSON.stringify(schema)}`);
  }
}

/** The TypeScript type of `schema`. */
export function typeOf(schema: Schema, at: string): string {
  assertKnownKeywords(schema, at);
  if (isNever(schema)) return 'never';
  if (typeof schema['$ref'] === 'string') return typeName(schema['$ref']);
  if ('const' in schema) return literal(schema['const']);
  if (Array.isArray(schema['enum'])) return schema['enum'].map(literal).join(' | ');
  if (Array.isArray(schema['x-extensible-enum'])) {
    return `${schema['x-extensible-enum'].map(literal).join(' | ')} | (string & {})`;
  }
  const type = schema['type'];
  if (Array.isArray(type)) {
    if (type.length !== 2 || type[1] !== 'null' || typeof type[0] !== 'string') {
      throw new Error(`${at}: a list of types is read only as [type, 'null']`);
    }
    return `${primitiveType(schema, type[0], at)} | null`;
  }
  return primitiveType(schema, type, at);
}

/** An object type literal. */
function objectType(schema: Schema, at: string, indent: string): string {
  const properties = (schema['properties'] ?? {}) as Record<string, Schema>;
  const required = new Set((schema['required'] ?? []) as string[]);
  const additional = schema['additionalProperties'];
  const lines: string[] = [];
  for (const [name, property] of Object.entries(properties)) {
    lines.push(
      `${docComment(property['description'], `${indent}  `)}${indent}  ${key(name)}${
        required.has(name) ? '' : '?'
      }: ${typeOf(property, `${at}.${name}`)};`
    );
  }
  if (typeof additional === 'object' && additional !== null) {
    lines.push(`${indent}  [key: string]: ${typeOf(additional as Schema, `${at}[key]`)};`);
  }
  if (lines.length === 0) return 'Record<string, never>';
  return `{\n${lines.join('\n')}\n${indent}}`;
}

/** One exported declaration per component schema, in the document's order. */
function componentDeclarations(schemas: Record<string, Schema>): string[] {
  return Object.entries(schemas).map(([name, schema]) => {
    const at = `components.schemas.${name}`;
    const comment = docComment(schema['description']);
    const isPlainObject =
      schema['type'] === 'object' && Object.keys((schema['properties'] ?? {}) as object).length > 0;
    return isPlainObject
      ? `${comment}export interface ${name} ${objectType(schema, at, '')}`
      : `${comment}export type ${name} = ${typeOf(schema, at)};`;
  });
}

interface Parameter {
  readonly in: string;
  readonly name: string;
  readonly required?: boolean;
  readonly schema: Schema;
}

type OperationObject = {
  operationId: string;
  summary: string;
  parameters?: Parameter[];
  requestBody?: { required?: boolean; content: Record<string, { schema: Schema }> };
  responses: Record<string, { content?: Record<string, { schema: Schema }> }>;
  'x-qauth-fresh-authentication': string;
  'x-qauth-act-chain': string;
};

interface OperationEntry {
  readonly id: string;
  readonly method: string;
  readonly path: string;
  readonly operation: OperationObject;
}

function operationsOf(document: Schema): OperationEntry[] {
  const entries: OperationEntry[] = [];
  const paths = document['paths'] as Record<string, Record<string, OperationObject>>;
  for (const [path, item] of Object.entries(paths)) {
    for (const [method, operation] of Object.entries(item)) {
      entries.push({ id: operation.operationId, method: method.toUpperCase(), path, operation });
    }
  }
  return entries;
}

/** `account.passkeys.update` → `passkeysUpdate`: every method is the account's. */
export function methodName(operationId: string): string {
  const [family, first, ...rest] = operationId.split('.');
  if (family !== 'account' || first === undefined) {
    throw new Error(`not an account operation: ${operationId}`);
  }
  return first + rest.map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('');
}

const parametersIn = (operation: OperationObject, location: string) =>
  (operation.parameters ?? []).filter((parameter) => parameter.in === location);

/** The one media type of the request body, if any. */
function bodyMedia(entry: OperationEntry) {
  const content = entry.operation.requestBody?.content;
  if (content === undefined) return undefined;
  const media = Object.entries(content);
  if (media.length !== 1) throw new Error(`${entry.id}: a request body has one media type`);
  const [[mediaType, { schema }]] = media;
  return { mediaType, schema, required: entry.operation.requestBody?.required === true };
}

/** A member of the request object: the parameters of one location, or the body. */
function parameterMember(id: string, name: string, parameters: Parameter[]): string | undefined {
  if (parameters.length === 0) return undefined;
  const fields = parameters.map(
    (parameter) =>
      `${key(parameter.name)}${parameter.required ? '' : '?'}: ${typeOf(parameter.schema, `${id}.${parameter.name}`)}`
  );
  const optional = parameters.every((parameter) => !parameter.required);
  return `${name}${optional ? '?' : ''}: { ${fields.join('; ')} }`;
}

/** The request type of an operation: its path, query and header parameters and its body. */
function requestType(entry: OperationEntry): { type: string; optional: boolean } {
  const { id, operation } = entry;
  const body = bodyMedia(entry);
  const members = [
    parameterMember(id, 'path', parametersIn(operation, 'path')),
    parameterMember(id, 'query', parametersIn(operation, 'query')),
    parameterMember(id, 'headers', parametersIn(operation, 'header')),
    body === undefined
      ? undefined
      : `body${body.required ? '' : '?'}: ${typeOf(body.schema, `${id}.requestBody`)}`,
  ].filter((member): member is string => member !== undefined);
  if (members.length === 0) return { type: 'Record<string, never>', optional: true };
  return {
    type: `{ ${members.join('; ')} }`,
    optional: members.every((member) => /^[a-z]+\?:/.test(member)),
  };
}

function operationType(entry: OperationEntry): string {
  const { id, method, path, operation } = entry;
  const responses = Object.entries(operation.responses).map(([status, response]) => {
    const media = Object.values(response.content ?? {});
    const data =
      media.length === 0
        ? 'undefined'
        : [...new Set(media.map((item) => typeOf(item.schema, `${id}.${status}`)))].join(' | ');
    return `${status}: ${data};`;
  });
  return [
    `  ${literal(id)}: {`,
    `    method: ${literal(method)};`,
    `    path: ${literal(path)};`,
    `    request: ${requestType(entry).type};`,
    `    responses: { ${responses.join(' ')} };`,
    `  };`,
  ].join('\n');
}

/** The pattern of each path parameter. */
function pathPatterns(entry: OperationEntry): string {
  const entries = parametersIn(entry.operation, 'path').map((parameter) => {
    const pattern = parameter.schema['pattern'];
    if (typeof pattern !== 'string') {
      throw new Error(`${entry.id}: the path parameter ${parameter.name} has no pattern`);
    }
    return `${key(parameter.name)}: ${literal(pattern)}`;
  });
  return `{ ${entries.join(', ')} }`;
}

const names = (parameters: Parameter[]) =>
  `[${parameters.map((parameter) => literal(parameter.name)).join(', ')}]`;

function operationInfo(entry: OperationEntry): string {
  const { id, method, path, operation } = entry;
  const body = bodyMedia(entry);
  return `  ${literal(id)}: { method: ${literal(method)}, path: ${literal(path)}, pathPatterns: ${pathPatterns(
    entry
  )}, query: ${names(parametersIn(operation, 'query'))}, headers: ${names(
    parametersIn(operation, 'header')
  )}, bodyMediaType: ${body === undefined ? 'undefined' : literal(body.mediaType)}, freshAuthentication: ${literal(
    operation['x-qauth-fresh-authentication']
  )}, actChain: ${literal(operation['x-qauth-act-chain'])}, statuses: [${Object.keys(operation.responses).join(', ')}] },`;
}

function clientMethod(entry: OperationEntry): string {
  const { id, operation } = entry;
  const operationType = `Operations[${literal(id)}]`;
  const { optional } = requestType(entry);
  const request = optional
    ? `request: ${operationType}['request'] = {}`
    : `request: ${operationType}['request']`;
  return `${docComment(`${operation.summary}: \`${id}\`.`, '    ')}    ${methodName(id)}: (${request}, init?: CallInit) => callOperation<${operationType}>(options, OPERATIONS[${literal(id)}], request, init),`;
}

/** The generated module, before Oxfmt. */
export function renderClient(document: Schema, source: string): string {
  const info = document['info'] as { title: string; version: string };
  const components = (document['components'] as { schemas: Record<string, Schema> }).schemas;
  const operations = operationsOf(document);
  return `${[
    `/**
 * The typed client of the ${info.title} ${info.version}, generated from
 * \`${source}\` by
 * \`pnpm exec nx run shared-account-client:generate\`. Do not edit it by
 * hand: the tests fail while it differs from what the generator writes.
 */`,
    `import { type AccountClientOptions, type CallInit, callOperation } from '../lib/runtime';`,
    `/** The version label of the document this client was generated from. */
export const ACCOUNT_API_VERSION = ${literal(info.version)};`,
    ...componentDeclarations(components),
    `/** Every operation: its method, path, request (path, query and header parameters, body) and response bodies by status. */
export interface Operations {
${operations.map(operationType).join('\n')}
}`,
    `/** What each operation needs, from the document: parameters, the body's media type, and what it asks of the token. */
export const OPERATIONS = {
${operations.map(operationInfo).join('\n')}
} as const;`,
    `/**
 * A client of the account API, for a backend that holds the person's access
 * token, such as the account console's. \`baseUrl\` is the auth server's origin
 * for the realm; the token goes to it alone.
 */
export function createAccountClient(options: AccountClientOptions) {
  return {
${operations.map(clientMethod).join('\n')}
  };
}`,
    `export type AccountClient = ReturnType<typeof createAccountClient>;`,
  ].join('\n\n')}\n`;
}
