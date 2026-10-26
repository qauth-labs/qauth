import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import Ajv2020, { type ValidateFunction } from 'ajv/dist/2020';
import addFormats from 'ajv-formats';

import type { OpenApiDocument } from '../lib/openapi';
import type { JsonSchema } from '../lib/schema-kit';

/**
 * JSON Schema validation for the contract's tests (#590), with Ajv's draft
 * 2020-12 engine. Test-only: nothing outside the tests imports this module,
 * and ajv is a devDependency.
 */

/** The annotation keywords the contract uses beyond JSON Schema's own. */
const ANNOTATIONS = [
  'x-qauth-display',
  'x-qauth-declared',
  'x-qauth-transports',
  'x-qauth-step',
  'x-extensible-enum',
  // OpenAPI's base vocabulary: an annotation here. Its `mapping` is checked by
  // the lint test, against the `const` of each variant.
  'discriminator',
];

/**
 * A strict validator: an unknown keyword, a keyword on the wrong type or an
 * unknown format fails the compile, so a typo in a schema (`maxLenght`) is an
 * error, not a schema that accepts anything.
 *
 * `strictRequired` is off: an object's rules (`if`/`then`, `whenEquals` in
 * `schema-kit.ts`) require members the enclosing object declares, which that
 * check does not look at. `object()` refuses a required member it does not
 * declare when the contract is built.
 */
export function strictValidator(): Ajv2020 {
  const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: true });
  addFormats(ajv);
  for (const keyword of ANNOTATIONS) ajv.addKeyword(keyword);
  return ajv;
}

const OAS_DIR = join(__dirname, '..', 'lib', 'oas');

const readJson = (file: string) =>
  JSON.parse(readFileSync(join(OAS_DIR, file), 'utf8')) as JsonSchema;

/** The dialect a Schema Object of an OpenAPI 3.1 document is written in. */
const OAS_DIALECT_ID = 'https://spec.openapis.org/oas/3.1/dialect/2024-11-10';

/** Replace every `{ "$dynamicRef": "#meta" }` with a static reference to `target`. */
function pinDynamicRefs(value: unknown, target: string): unknown {
  if (Array.isArray(value)) return value.map((item) => pinDynamicRefs(item, target));
  if (typeof value !== 'object' || value === null) return value;
  const entries = Object.entries(value);
  if (entries.length === 1 && entries[0][0] === '$dynamicRef' && entries[0][1] === '#meta') {
    return { $ref: target };
  }
  return Object.fromEntries(entries.map(([key, inner]) => [key, pinDynamicRefs(inner, target)]));
}

/** RFC 9110 §12.5.1 `media-range`, the format the OpenAPI schema gives a media type key. */
const MEDIA_RANGE = /^(?:\*\/\*|[\w!#$%&'*+.^`|~-]+\/(?:\*|[\w!#$%&'*+.^`|~-]+))(?:\s*;.*)?$/;

/**
 * The official OpenAPI 3.1 schema, the iteration of 2026-08-03, validating
 * every Schema Object against the OpenAPI dialect (JSON Schema 2020-12 plus
 * OpenAPI's base vocabulary), as its `schema-base` variant does. Vendored
 * under `src/lib/oas/`; see the README.
 *
 * The official schema reaches a Schema Object through `$dynamicRef: "#meta"`,
 * whose `$dynamicAnchor` it declares in `$defs`. Ajv supports a dynamic anchor
 * only at a schema's root, so it would resolve the reference wrongly and
 * refuse every schema. The validator therefore replaces each such reference
 * with the static reference `schema-base` makes it resolve to: the dialect.
 * The one other thing `schema-base` adds, a fixed `jsonSchemaDialect` value,
 * does not apply: the document declares none.
 */
export function openApiDocumentValidator(): ValidateFunction {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addFormat('media-range', MEDIA_RANGE);
  ajv.addSchema(readJson('meta-2024-11-10.json'));
  ajv.addSchema(readJson('dialect-2024-11-10.json'));
  const official = readJson('schema-2026-08-03.json');
  // What schema-base's own `meta` anchor resolves to: keep the substitution honest.
  const base = readJson('schema-base-2026-08-03.json') as { $defs?: { schema?: JsonSchema } };
  if (base.$defs?.schema?.['$ref'] !== OAS_DIALECT_ID) {
    throw new Error(`schema-base no longer anchors Schema Objects to ${OAS_DIALECT_ID}`);
  }
  return ajv.compile(pinDynamicRefs(official, OAS_DIALECT_ID) as JsonSchema);
}

/** The `$id` under which {@link componentValidator} registers the document's schemas. */
const COMPONENTS_ID = 'urn:qauth:test:interaction-components';

/** Rewrite `#/components/schemas/X` into `#/$defs/X`, deeply. */
function rewriteRefs(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(rewriteRefs);
  if (typeof value !== 'object' || value === null) return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, inner]) => [
      key,
      key === '$ref' && typeof inner === 'string'
        ? inner.replace('#/components/schemas/', `${COMPONENTS_ID}#/$defs/`)
        : rewriteRefs(inner),
    ])
  );
}

/**
 * A strict validator that knows every schema of the document's
 * `components.schemas`, so a test validates a value against one by name.
 */
export function componentValidator(document: OpenApiDocument) {
  const ajv = strictValidator();
  const components = (document['components'] as { schemas: Record<string, JsonSchema> }).schemas;
  ajv.addSchema({ $id: COMPONENTS_ID, $defs: rewriteRefs(components) });
  return {
    names: Object.keys(components),
    /** The compiled schema of one component. Compiling is where strict mode checks it. */
    schema(name: string): ValidateFunction {
      const validate = ajv.getSchema(`${COMPONENTS_ID}#/$defs/${name}`);
      if (validate === undefined) throw new Error(`no component ${name}`);
      return validate;
    },
    /** A schema written against the document's components, such as a media type's inline schema. */
    compile(schema: unknown): ValidateFunction {
      return ajv.compile(rewriteRefs(schema) as JsonSchema);
    },
  };
}

/** Ajv's errors as one line each, for an assertion message. */
export function describeErrors(validate: ValidateFunction): string {
  return (validate.errors ?? [])
    .map((error) => `${error.instancePath || '/'} ${error.message ?? ''}`)
    .join('\n');
}
