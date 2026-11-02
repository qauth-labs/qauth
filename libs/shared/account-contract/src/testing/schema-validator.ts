import Ajv2020, { type ValidateFunction } from 'ajv/dist/2020';
import addFormats from 'ajv-formats';

import type { OpenApiDocument } from '../lib/openapi';
import type { JsonSchema } from '../lib/schema-kit';

/**
 * JSON Schema validation for the contract's tests (#588), with Ajv's draft
 * 2020-12 engine. Test-only: nothing outside the tests imports this module,
 * and ajv is a devDependency. The document's validation against the official
 * OpenAPI 3.1 schema runs in the auth server's `account-contract.test.ts`,
 * with the Interaction API contract's vendored copy of that schema.
 */

/** The annotation keywords the contract uses beyond JSON Schema's own. */
const ANNOTATIONS = ['x-qauth-display', 'x-qauth-declared', 'x-extensible-enum'];

/**
 * A strict validator: an unknown keyword, a keyword on the wrong type or an
 * unknown format fails the compile, so a typo in a schema (`maxLenght`) is an
 * error, not a schema that accepts anything. `strictRequired` is off, as in
 * the Interaction API contract's validator: an object's rules (`whenEquals`)
 * require members the enclosing object declares.
 */
export function strictValidator(): Ajv2020 {
  const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: true });
  addFormats(ajv);
  for (const keyword of ANNOTATIONS) ajv.addKeyword(keyword);
  return ajv;
}

/** The `$id` under which {@link componentValidator} registers the document's schemas. */
const COMPONENTS_ID = 'urn:qauth:test:account-components';

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
    /** A schema written against the document's components, such as a parameter's inline schema. */
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
