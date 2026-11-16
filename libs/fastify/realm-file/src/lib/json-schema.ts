import { publicJwkSchema } from '@qauth-labs/infra-db/seed-manifest';
import { REALM_POLICY_REGISTRY } from '@qauth-labs/server-realm-policy';
import { PRIVATE_JWK_MEMBERS } from '@qauth-labs/shared-validation';
import { z } from 'zod';

import { REALM_FILE_FORMAT, REALM_FILE_SCHEMA_ID } from './format';
import { realmFileSchema } from './realm-file';
import { REALM_FILE_SECTIONS } from './sections';

/**
 * The JSON Schema (draft 2020-12) of the realm file (#515), generated from
 * its Zod schema and published at `REALM_FILE_SCHEMA_PATH`, so an editor can
 * check a file as it is written.
 *
 * It states the shape: every member, type, enum, length and range, that no
 * member beyond them appears, so no secret either, and that no JWK carries
 * private key material. `policies` is the policy registry's own JSON Schema
 * of its `document` view, with each field's annotations. The rules that
 * relate one value to another, such as a `client_id` listed once in a file,
 * `jwks` or `jwks_uri` but not both, or a redirect URI the consent screen can
 * show, are the parser's alone ({@link parseRealmFile}), which every import
 * runs first.
 */
export function realmFileJsonSchema(): Record<string, unknown> {
  const generated = z.toJSONSchema(realmFileSchema(), {
    target: 'draft-2020-12',
    io: 'input',
    unrepresentable: 'throw',
    override: ({ zodSchema, jsonSchema }) => {
      // The parser refuses a private member with a refinement, which JSON
      // Schema cannot carry, so the schema says it in its own terms.
      if (zodSchema === publicJwkSchema) {
        jsonSchema.description = `A public JWK. A member of private key material (${PRIVATE_JWK_MEMBERS.join(', ')}) is refused: a realm file holds no secret value.`;
        jsonSchema.not = {
          anyOf: PRIVATE_JWK_MEMBERS.map((member) => ({ required: [member] })),
        };
      }
    },
  }) as Record<string, unknown>;
  const { $schema, ...rest } = generated;
  const properties = rest['properties'] as Record<string, Record<string, unknown>>;
  const { $schema: _policySchemaDialect, ...policies } =
    REALM_POLICY_REGISTRY.toJsonSchema('document');
  properties['policies'] = policies;
  for (const section of REALM_FILE_SECTIONS) {
    const property = properties[section.name];
    if (property !== undefined) property['description'] = section.summary;
  }
  return {
    $schema,
    $id: REALM_FILE_SCHEMA_ID,
    title: REALM_FILE_FORMAT,
    description: `The declarative realm file, format ${REALM_FILE_FORMAT}: a realm's configuration, without any secret value (ADR-018 §5). Generated from libs/fastify/realm-file; the docs page reference/realm-file describes every section, its natural key and the rules of growth. A member this schema does not name is refused, a section of a later release included.`,
    ...rest,
  };
}

/** The published file's text: `JSON.stringify` output with a final newline, as the other generated schemas. */
export function realmFileJsonSchemaText(): string {
  return `${JSON.stringify(realmFileJsonSchema(), null, 2)}\n`;
}
