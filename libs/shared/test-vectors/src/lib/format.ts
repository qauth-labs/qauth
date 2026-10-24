import { z } from 'zod';

/**
 * The shared test vector format, `qauth-vectors/1` (ADR-018 §6 and §7).
 *
 * A vector file is plain JSON that any language reads: a header (`schema`,
 * `id`, `description`, `source`) and a list of cases, each an `input` and the
 * `expected` result. This Zod schema is the source of record; the published
 * JSON Schema (`test-vectors/schema/vector-file.schema.json`) is generated
 * from it, so the two cannot drift.
 *
 * Both objects are closed. A new member is a new format version, never a
 * silent addition, because a reader in another language must be able to
 * refuse a file it does not understand.
 */

/** The format version every file names in its `schema` member. */
export const VECTOR_SCHEMA_ID = 'qauth-vectors/1';

/**
 * The prefix of a JWK's `kid` in a vector file. Every key in a file is a
 * throwaway test key, and a JWK says so in its `kid`.
 */
export const THROWAWAY_KID_PREFIX = 'throwaway-test-';

/** One lower-case, hyphenated segment: `s256`, `act-chain`, `rfc7636-appendix-b`. */
const SEGMENT = '[a-z0-9]+(?:-[a-z0-9]+)*';

/** A file id is its path under `test-vectors/` without `.json`: `pkce/s256`. */
export const VECTOR_FILE_ID_PATTERN = new RegExp(`^${SEGMENT}(?:/${SEGMENT})+$`);

/** A case id is one segment, unique within its file. */
export const VECTOR_CASE_ID_PATTERN = new RegExp(`^${SEGMENT}$`);

const jsonObject = z.record(z.string(), z.unknown());

const nonEmptyText = z.string().trim().min(1);

export const vectorCaseSchema = z
  .strictObject({
    id: z.string().regex(VECTOR_CASE_ID_PATTERN).meta({
      description:
        'Lower-case and hyphenated, unique within the file. A merged case id always means the same input and the same expected result.',
    }),
    input: jsonObject.meta({
      description: "What the code under test receives. The file's description says what it means.",
    }),
    expected: jsonObject.meta({
      description: 'What the code under test must produce from the input.',
    }),
    notes: nonEmptyText.optional().meta({
      description: 'Why the case exists, or where its values come from.',
    }),
  })
  .meta({ description: 'One case: an input and the result expected from it.' });

/** The shape alone, without the cross-field rules; the JSON Schema is generated from it. */
export const vectorFileShapeSchema = z
  .strictObject({
    schema: z.literal(VECTOR_SCHEMA_ID).meta({
      description: 'The format version. A reader refuses a file whose version it does not know.',
    }),
    id: z.string().regex(VECTOR_FILE_ID_PATTERN).meta({
      description: 'The path of the file under test-vectors/, without .json, such as pkce/s256.',
    }),
    description: nonEmptyText.meta({
      description:
        'What the cases test, and what input and expected mean in this file. A reader in another language implements the check from this text.',
    }),
    source: nonEmptyText.meta({
      description:
        'Where the cases come from: a specification section, or the tool and version that generated them.',
    }),
    cases: z.array(vectorCaseSchema).min(1).meta({
      description: 'At least one case. Case ids are unique within the file.',
    }),
  })
  .meta({
    title: VECTOR_SCHEMA_ID,
    description:
      'A QAuth shared test vector file. Two rules sit outside this schema and are checked by the validator: case ids are unique within a file, and every JWK (an object with a kty member) has a kid that starts with "throwaway-test-".',
  });

type JsonPath = (string | number)[];

/** Every object under `value` that has a string `kty` member, with its path. */
function findJwks(value: unknown, path: JsonPath, found: { path: JsonPath; jwk: object }[]): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => findJwks(item, [...path, index], found));
    return;
  }
  if (typeof value !== 'object' || value === null) return;
  const record = value as Record<string, unknown>;
  if (typeof record['kty'] === 'string') found.push({ path, jwk: record });
  for (const [key, child] of Object.entries(record)) findJwks(child, [...path, key], found);
}

/**
 * A vector file: the shape, plus the two rules JSON Schema cannot state —
 * case ids are unique, and every JWK is marked as a throwaway test key.
 */
export const vectorFileSchema = vectorFileShapeSchema.superRefine((file, ctx) => {
  const firstIndex = new Map<string, number>();
  file.cases.forEach((vectorCase, index) => {
    const first = firstIndex.get(vectorCase.id);
    if (first === undefined) {
      firstIndex.set(vectorCase.id, index);
      return;
    }
    ctx.addIssue({
      code: 'custom',
      path: ['cases', index, 'id'],
      message: `duplicate case id "${vectorCase.id}" (first used by cases[${first}])`,
    });
  });

  const jwks: { path: JsonPath; jwk: object }[] = [];
  file.cases.forEach((vectorCase, index) => findJwks(vectorCase, ['cases', index], jwks));
  for (const { path, jwk } of jwks) {
    const kid = (jwk as Record<string, unknown>)['kid'];
    if (typeof kid !== 'string' || !kid.startsWith(THROWAWAY_KID_PREFIX)) {
      ctx.addIssue({
        code: 'custom',
        path: [...path, 'kid'],
        message: `a JWK in a vector file must be marked as a throwaway test key: its kid must start with "${THROWAWAY_KID_PREFIX}"`,
      });
    }
  }
});

/** One case of a vector file, typed by what its file says `input` and `expected` hold. */
export interface VectorCase<TInput = Record<string, unknown>, TExpected = Record<string, unknown>> {
  readonly id: string;
  readonly input: TInput;
  readonly expected: TExpected;
  readonly notes?: string;
}

/** A parsed and validated vector file. */
export interface VectorFile<TInput = Record<string, unknown>, TExpected = Record<string, unknown>> {
  readonly schema: typeof VECTOR_SCHEMA_ID;
  readonly id: string;
  readonly description: string;
  readonly source: string;
  readonly cases: readonly VectorCase<TInput, TExpected>[];
}
