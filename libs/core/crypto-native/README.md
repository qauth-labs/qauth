# @qauth-labs/crypto-native

Native ML-DSA-65 (FIPS 204) signing backend over [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs),
implementing the same `SignatureBackend` interface as the pure-TS
`@noble/post-quantum` backend in `@qauth-labs/core-crypto` (ADR-005, #244).

Byte-for-byte interoperable with the noble backend: both key off the same
32-byte seed, so keys, exports, and signatures cross-verify. Swapping backends
requires **zero** consumer changes.

## Build

Requires a Rust toolchain (`cargo`) and `cmake` (aws-lc builds from source):

```bash
pnpm nx run crypto-native:build-native
```

This produces a platform-specific `qauth-crypto-native.<platform>.node` (gitignored).
When the addon is not built for a host, `isNativeAddonAvailable()` returns
`false` and consumers fall back to the noble backend.

## Deferred (#244)

The per-platform CI **prebuild matrix** (cross-compilation + publishing prebuilt
`.node` artifacts for every target platform) is the explicitly-deferred half of
#244 — the issue pre-authorizes splitting "binding works locally" from "CI
publishes prebuilds." This package delivers the former; the latter is a
follow-up before the native backend becomes a default in any environment.

## Benchmark (this host, local build)

Native aws-lc-rs is roughly **30–40× faster** than the pure-TS backend:

| op              | pure-TS (@noble) | native (aws-lc-rs) |
| --------------- | ---------------- | ------------------ |
| generateKeyPair | ~535 ops/s       | ~20,000 ops/s      |
| sign            | ~243 ops/s       | ~7,100 ops/s       |
| verify          | ~1,100 ops/s     | ~29,700 ops/s      |

Run `npx tsx libs/core/crypto-native/src/bench.ts` (after building the addon).
This justifies native as the eventual default once the CI prebuild matrix lands.
