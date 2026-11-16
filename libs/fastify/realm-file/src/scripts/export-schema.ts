/**
 * Write the realm file's JSON Schema (#515), `REALM_FILE_SCHEMA_PATH`, from
 * its Zod schema. Run through `pnpm exec nx run realm-file:schema-export`; the
 * stable-surface check runs it too, fails when the committed file differs,
 * and compares the file with the latest release. The file stays plain
 * `JSON.stringify` output, which `.oxfmtrc.json` leaves alone, like the event
 * schemas. This script is the library's only I/O, and nothing imports it.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { REALM_FILE_SCHEMA_PATH } from '../lib/format';
import { realmFileJsonSchemaText } from '../lib/json-schema';

const repoRoot = resolve(__dirname, '..', '..', '..', '..', '..');
const target = join(repoRoot, REALM_FILE_SCHEMA_PATH);
mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, realmFileJsonSchemaText());
console.log(`realm-file: wrote ${REALM_FILE_SCHEMA_PATH}`);
