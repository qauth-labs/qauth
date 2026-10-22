// The fixture's generator: writes each surface from `source/`, as a real
// generator writes its committed file.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

mkdirSync('stable-surface', { recursive: true });
for (const [from, to] of [
  ['source/openapi.json', 'stable-surface/openapi.json'],
  ['source/events.schema.json', 'stable-surface/events.schema.json'],
]) {
  writeFileSync(to, `${JSON.stringify(JSON.parse(readFileSync(from, 'utf8')), null, 2)}\n`);
}
