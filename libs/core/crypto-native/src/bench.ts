/**
 * ML-DSA-65 native (aws-lc-rs) vs pure-TS (@noble/post-quantum) micro-benchmark
 * (#244 AC: "Benchmark native vs pure-TS performance to justify the added
 * complexity"). Run with the addon built:
 *
 *   pnpm nx run crypto-native:build-native
 *   npx tsx libs/core/crypto-native/src/bench.ts
 *
 * Not a test — it prints ops/sec for keygen/sign/verify on each backend.
 */
import { getSignatureBackend, type SignatureBackend } from '@qauth-labs/core-crypto';

import { isNativeAddonAvailable, mlDsaNativeBackend } from './index';

const ITERATIONS = 200;
const message = new TextEncoder().encode('benchmark message');

function timeOps(label: string, iterations: number, fn: () => void): void {
  // Warm up.
  for (let i = 0; i < 10; i++) fn();
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) fn();
  const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
  const opsPerSec = (iterations / elapsedMs) * 1000;
  console.log(
    `  ${label.padEnd(22)} ${opsPerSec.toFixed(0).padStart(8)} ops/s  (${(elapsedMs / iterations).toFixed(3)} ms/op)`
  );
}

function benchBackend(name: string, backend: SignatureBackend): void {
  console.log(`\n${name}:`);
  const pair = backend.generateKeyPair();
  const sig = backend.sign(pair.privateKey, message);
  timeOps('generateKeyPair', ITERATIONS, () => backend.generateKeyPair());
  timeOps('sign', ITERATIONS, () => backend.sign(pair.privateKey, message));
  timeOps('verify', ITERATIONS, () => backend.verify(pair.publicKey, message, sig));
}

function main(): void {
  console.log(`ML-DSA-65 backend benchmark (${ITERATIONS} iterations)`);
  benchBackend('pure-TS (@noble/post-quantum)', getSignatureBackend('ML-DSA-65', ['ML-DSA-65']));
  if (isNativeAddonAvailable()) {
    benchBackend('native (aws-lc-rs)', mlDsaNativeBackend);
  } else {
    console.log('\nnative (aws-lc-rs): addon not built — run crypto-native:build-native first.');
  }
}

main();
