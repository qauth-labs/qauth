/**
 * Generate the typed Interaction API client from its published OpenAPI
 * document (#590). The output is `src/generated/interaction-api.ts`: one type
 * per component schema, the operation table, and one method per operation.
 * No type of the API is written by hand; `lib/runtime.ts` holds only the
 * generic request code.
 *
 * The generator reads the JSON Schema the contract uses, and refuses anything
 * else, so a construct it cannot type fails the generation instead of turning
 * into `unknown`:
 *
 * - `$ref` to `#/components/schemas/*`, `const`, `enum`, `x-extensible-enum`
 *   (a union of the known values and any other string), `oneOf`;
 * - `type` `object` with `properties`, `required` and `additionalProperties`
 *   (an index signature), and rules between its members (`allOf` of
 *   `if`/`then`), which constrain it without changing its type; `array` with
 *   `items`, `string`, `integer`, `number`, `boolean`;
 * - `{ "not": {} }`, a member that is never present, as `never`.
 *
 * Annotations and validation keywords (`pattern`, `maxLength`, `format`, `not`,
 * `contentSchema`, …) carry no type and are left to the server; the
 * descriptions become doc comments.
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
  'contentMediaType',
  'contentSchema',
  'discriminator',
  'x-qauth-display',
  'x-qauth-declared',
  'x-qauth-transports',
  'x-qauth-step',
]);

/** The keywords a rule of an object (`allOf` member) may use: conditions, with no type of their own. */
const RULE_KEYWORDS = new Set(['if', 'then', 'else', 'description']);

const TYPE_KEYWORDS = new Set([
  '$ref',
  'const',
  'enum',
  'x-extensible-enum',
  'oneOf',
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

/** A doc comment for `description`, or nothing. */
function docComment(description: unknown, indent = ''): string {
  if (typeof description !== 'string' || description === '') return '';
  const text = description.replace(/\*\//g, '*\\/');
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

/** A union of `members`; a member that is itself a union is parenthesised. */
const union = (members: string[]) => {
  const unique = [...new Set(members)];
  if (unique.length === 1) return unique[0];
  return unique
    .map((member) => (member.includes('|') && !member.startsWith('{') ? `(${member})` : member))
    .join(' | ');
};

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
  if (Array.isArray(schema['oneOf'])) {
    return union(
      (schema['oneOf'] as Schema[]).map((variant, index) =>
        typeOf(variant, `${at}.oneOf[${index}]`)
      )
    );
  }
  switch (schema['type']) {
    case 'string':
      return 'string';
    case 'integer':
    case 'number':
      return 'number';
    case 'boolean':
      return 'boolean';
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
      schema['type'] === 'object' &&
      !('oneOf' in schema) &&
      Object.keys((schema['properties'] ?? {}) as object).length > 0;
    return isPlainObject
      ? `${comment}export interface ${name} ${objectType(schema, at, '')}`
      : `${comment}export type ${name} = ${typeOf(schema, at)};`;
  });
}

type OperationObject = {
  operationId: string;
  summary: string;
  parameters?: Array<{ in: string; name: string; schema: Schema }>;
  requestBody?: { content: Record<string, { schema: Schema }> };
  responses: Record<string, { content?: Record<string, { schema: Schema }> }>;
  'x-qauth-flow-cookie': string;
  'x-qauth-csrf': string;
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

/** `interactions.personal.get` → `interactionsPersonalGet`. */
export function methodName(operationId: string): string {
  const [first, ...rest] = operationId.split('.');
  return first + rest.map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('');
}

function operationType({ id, method, path, operation }: OperationEntry): string {
  const pathParams = (operation.parameters ?? []).filter((parameter) => parameter.in === 'path');
  const params =
    pathParams.length === 0
      ? 'Record<string, never>'
      : `{ ${pathParams.map((parameter) => `${key(parameter.name)}: ${typeOf(parameter.schema, `${id}.${parameter.name}`)}`).join('; ')} }`;
  const json = operation.requestBody?.content['application/json'];
  const body = json === undefined ? 'never' : typeOf(json.schema, `${id}.requestBody`);
  const responses = Object.entries(operation.responses).map(([status, response]) => {
    const media = Object.values(response.content ?? {});
    const data =
      media.length === 0
        ? 'undefined'
        : union(media.map((entry) => typeOf(entry.schema, `${id}.${status}`)));
    return `${status}: ${data};`;
  });
  return [
    `  ${literal(id)}: {`,
    `    method: ${literal(method)};`,
    `    path: ${literal(path)};`,
    `    pathParams: ${params};`,
    `    requestBody: ${body};`,
    `    responses: { ${responses.join(' ')} };`,
    `  };`,
  ].join('\n');
}

/** The pattern of each path parameter, following a `$ref` to its component. */
function pathPatterns(
  operation: OperationObject,
  components: Record<string, Schema>,
  id: string
): string {
  const entries = (operation.parameters ?? [])
    .filter((parameter) => parameter.in === 'path')
    .map((parameter) => {
      const ref = parameter.schema['$ref'];
      const schema = typeof ref === 'string' ? components[typeName(ref)] : parameter.schema;
      const pattern = schema?.['pattern'];
      if (typeof pattern !== 'string') {
        throw new Error(`${id}: the path parameter ${parameter.name} has no pattern`);
      }
      return `${key(parameter.name)}: ${literal(pattern)}`;
    });
  return `{ ${entries.join(', ')} }`;
}

function operationInfo(
  { id, method, path, operation }: OperationEntry,
  components: Record<string, Schema>
): string {
  return `  ${literal(id)}: { method: ${literal(method)}, path: ${literal(path)}, pathPatterns: ${pathPatterns(
    operation,
    components,
    id
  )}, flowCookie: ${operation['x-qauth-flow-cookie'] === 'required'}, csrf: ${
    operation['x-qauth-csrf'] === 'required'
  }, statuses: [${Object.keys(operation.responses).join(', ')}] },`;
}

function clientMethod({ id, operation }: OperationEntry): string {
  const hasBody = operation.requestBody !== undefined;
  const args = hasBody
    ? `pathParams: Operations[${literal(id)}]['pathParams'], body: Operations[${literal(id)}]['requestBody'], init?: CallInit`
    : `pathParams: Operations[${literal(id)}]['pathParams'], init?: CallInit`;
  const call = hasBody
    ? `callOperation<Operations[${literal(id)}]>(options, OPERATIONS[${literal(id)}], pathParams, body, init)`
    : `callOperation<Operations[${literal(id)}]>(options, OPERATIONS[${literal(id)}], pathParams, undefined, init)`;
  return `${docComment(`${operation.summary}: \`${id}\`.`, '    ')}    ${methodName(id)}: (${args}) => ${call},`;
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
 * \`pnpm exec nx run shared-interaction-client:generate\`. Do not edit it by
 * hand: the tests fail while it differs from what the generator writes.
 */`,
    `import { type CallInit, callOperation, type InteractionClientOptions } from '../lib/runtime';`,
    `/** The version label of the document this client was generated from. */
export const INTERACTION_API_VERSION = ${literal(info.version)};`,
    ...componentDeclarations(components),
    `/** Every operation: its method, path, path parameters, JSON request body and response bodies by status. */
export interface Operations {
${operations.map(operationType).join('\n')}
}`,
    `/** What each operation needs, from the document's \`x-qauth-flow-cookie\` and \`x-qauth-csrf\`. */
export const OPERATIONS = {
${operations.map((entry) => operationInfo(entry, components)).join('\n')}
} as const;`,
    `/**
 * A client of the Interaction API. In a browser, leave \`baseUrl\` out: the API
 * is same-origin, and the flow cookie travels with the request. On the ceremony
 * app's server, set it to the auth server's address; that side holds no flow
 * cookie, so it can only read the current step.
 */
export function createInteractionClient(options: InteractionClientOptions = {}) {
  return {
${operations.map(clientMethod).join('\n')}
  };
}`,
    `export type InteractionClient = ReturnType<typeof createInteractionClient>;`,
  ].join('\n\n')}\n`;
}
