#!/usr/bin/env node
/**
 * Emit a `<addon>.node.sha256` sidecar for every built native addon in the
 * package directory (#277, F4).
 *
 * The sidecar is what `src/addon-integrity.ts` verifies before `dlopen`, so a
 * local `build-native` produces the same load-time contract as the attested CI
 * prebuild. Format is `sha256sum`-compatible (`<hex>  <basename>`) so
 * `sha256sum -c` works on it verbatim in CI.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageDir = dirname(dirname(fileURLToPath(import.meta.url)));

const addons = readdirSync(packageDir).filter(
  (name) => name.startsWith('qauth-crypto-native.') && name.endsWith('.node')
);

if (addons.length === 0) {
  console.error(
    `[crypto-native] no qauth-crypto-native.*.node found in ${packageDir}; ` +
      'run `napi build --platform --release` first.'
  );
  process.exit(1);
}

for (const name of addons) {
  const file = join(packageDir, name);
  const digest = createHash('sha256').update(readFileSync(file)).digest('hex');
  writeFileSync(`${file}.sha256`, `${digest}  ${name}\n`, 'utf8');
  console.log(`[crypto-native] ${digest}  ${name}`);
}
