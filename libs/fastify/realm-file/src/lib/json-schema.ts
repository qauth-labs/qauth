import { publicJwkSchema } from '@qauth-labs/infra-db/seed-manifest';
import { REALM_POLICY_REGISTRY } from '@qauth-labs/server-realm-policy';
import { PRIVATE_JWK_MEMBERS } from '@qauth-labs/shared-validation';
import { z } from 'zod';

import { URL_CREDENTIALS_PATTERN } from './credentials';
import { REALM_FILE_FORMAT, REALM_FILE_SCHEMA_ID } from './format';
import { realmFileSchema } from './realm-file';
import { REALM_FILE_SECTIONS } from './sections';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * `node` and every schema in it with each string refusing a URL with a user
 * name or password, the rule the parser applies to every string of a file
 * (`./credentials`): a member typed as a string, and an open member of a JWK,
 * which may hold any value (`additionalProperties: {}`), when it is a string.
 * Not inside `propertyNames`: the rule is about values. A node is changed
 * after its children, so a refusal it gains is never visited.
 */
function refusingUrlCredentials(node: unknown): void {
  if (Array.isArray(node)) {
    for (const member of node) refusingUrlCredentials(member);
    return;
  }
  if (!isRecord(node)) return;
  for (const [keyword, value] of Object.entries(node)) {
    if (keyword !== 'propertyNames') refusingUrlCredentials(value);
  }
  const open = node['additionalProperties'];
  if (isRecord(open) && Object.keys(open).length === 0) {
    node['additionalProperties'] = {
      not: { type: 'string', pattern: URL_CREDENTIALS_PATTERN },
    };
  }
  const type = node['type'];
  if (type !== 'string' && !(Array.isArray(type) && type.includes('string'))) return;
  const refusal = { type: 'string', pattern: URL_CREDENTIALS_PATTERN };
  if (node['not'] === undefined) node['not'] = refusal;
  else node['allOf'] = [...((node['allOf'] as unknown[] | undefined) ?? []), { not: refusal }];
}

/**
 * The JSON Schema (draft 2020-12) of the realm file (#515), generated from
 * its Zod schema and published at `REALM_FILE_SCHEMA_PATH`, so an editor can
 * check a file as it is written.
 *
 * It states the shape: every member, type, enum, length and range, that no
 * member beyond them appears, so no secret either, and that no JWK carries
 * private key material, and that no string is a URL with a user name or
 * password in its usual form. `policies` is the policy registry's own JSON
 * Schema of its `document` view, with each field's annotations. Some rules are
 * the parser's alone ({@link parseRealmFile}), which every import runs first:
 * those that relate one value to another, such as a `client_id` listed once
 * in a file or `jwks` or `jwks_uri` but not both, and those a JSON Schema
 * keyword does not state, such as a redirect URI the consent screen can show
 * or the members a JWK of each key type needs.
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
  refusingUrlCredentials(rest);
  return {
    $schema,
    $id: REALM_FILE_SCHEMA_ID,
    title: REALM_FILE_FORMAT,
    description: `The declarative realm file, format ${REALM_FILE_FORMAT}: a realm's configuration, without any secret value (ADR-018 §5). Generated from libs/fastify/realm-file; the docs page reference/realm-file describes every section, its natural key and the rules of growth. A member this schema does not name is refused, a section of a later release included, and so is a URL with a user name or password.`,
    ...rest,
  };
}

/** The published file's text: `JSON.stringify` output with a final newline, as the other generated schemas. */
export function realmFileJsonSchemaText(): string {
  return `${JSON.stringify(realmFileJsonSchema(), null, 2)}\n`;
}
