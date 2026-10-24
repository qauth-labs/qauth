/**
 * Write `test-vectors/schema/vector-file.schema.json` from the Zod schema.
 * Run through `pnpm exec nx run shared-test-vectors:schema-export`; a test
 * fails when the committed file differs. The output is plain
 * `JSON.stringify`, which `.oxfmtrc.json` leaves alone. Nothing imports
 * this script.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { VECTOR_JSON_SCHEMA_PATH, vectorFileJsonSchemaText } from '../lib/json-schema';
import { findRepositoryRoot } from '../lib/validate';

writeFileSync(join(findRepositoryRoot(), VECTOR_JSON_SCHEMA_PATH), vectorFileJsonSchemaText());
console.log(`shared-test-vectors: wrote ${VECTOR_JSON_SCHEMA_PATH}`);
