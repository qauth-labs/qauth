# @qauth-labs/crypto-native

Native ML-DSA-65 (FIPS 204) signing backend over [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs),
implementing the same `SignatureBackend` interface as the pure-TS
`@noble/post-quantum` backend in `@qauth-labs/core-crypto` (ADR-005, #244).

Byte-for-byte interoperable with the noble backend: both key off the same
32-byte seed, so keys, exports, and signatures cross-verify. Swapping backends
requires **zero** consumer changes.

## Build

Requires a Rust toolchain (pinned by `rust-toolchain.toml`) and `cmake`
(aws-lc builds from source):

```bash
pnpm nx run crypto-native:build-native
```

This produces a platform-specific `qauth-crypto-native.<platform>.node`
(gitignored) **and its `.node.sha256` sidecar**. When the addon is not built for
a host, `isNativeAddonAvailable()` returns `false` and consumers fall back to
the noble backend.

## Supply chain (#277, finding F4)

The addon is `dlopen`-ed into the auth server on the signing path, so its bytes
are part of the trust base. Four controls back that:

1. **Reproducible build from pinned source.** `rust-toolchain.toml` pins the
   exact compiler (never floating `stable`), `CARGO_INCREMENTAL=0`, build paths
   are remapped out of the binary via `.cargo/config.toml`, and CI exports
   `SOURCE_DATE_EPOCH` for the aws-lc-sys cmake/cc sub-build. CI rebuilds the
   linux artifact into a differently-located target directory and fails if the
   two are not byte-identical.

   The napi CLI has **no cargo passthrough** — a trailing `-- --locked` is
   silently dropped — so the lockfile is enforced _around_ the build:
   `cargo fetch --locked` first, `CARGO_NET_OFFLINE=true` during, and
   `git diff --exit-code Cargo.lock` after.

2. **Checksum + provenance.** Every published artifact ships a `sha256sum`-format
   sidecar plus an `actions/attest-build-provenance` (SLSA) attestation. Verify
   a downloaded artifact with
   `gh attestation verify qauth-crypto-native.<triple>.node --repo qauth-labs/qauth`.
3. **Load-time integrity verification.** `src/addon-integrity.ts` hashes the
   `.node` and checks it against the sidecar **before** `require()` — after
   `dlopen` there is nothing left to enforce. Policy comes from
   `QAUTH_NATIVE_ADDON_INTEGRITY`:

   | value                 | missing sidecar    | mismatching sidecar |
   | --------------------- | ------------------ | ------------------- |
   | `enforce` _(default)_ | refuse to load     | refuse to load      |
   | `permissive`          | load + warn loudly | refuse to load      |

   A mismatch is **never** tolerated, in any mode. An unrecognised value is a
   loud error, so a typo cannot silently disable the check.

4. **Rust supply-chain gates.** `pnpm nx run crypto-native:audit-native` runs
   `cargo audit` plus `cargo deny check advisories bans licenses sources` over
   the crate _and its build-time surface_ (`cc`, `cmake`, `pkg-config` execute
   arbitrary code on the builder). `deny.toml` bans re-introducing `bindgen`
   (aws-lc-sys 0.43.0 ships pregenerated bindings) and any second C crypto stack.

### Bumping `aws-lc-rs`

`aws-lc-rs` must stay **exact-pinned** (`version = "=x.y.z"`) — CI fails a
requirement that loosens to a caret range. Any bump re-runs, in
`.github/workflows/crypto-native.yml`: pin/lockfile hygiene → `cargo audit` +
`cargo deny` → reproducible build + determinism probe → the **noble↔native
cross-verification suite against the freshly built addon**. That last gate runs
with `QAUTH_REQUIRE_NATIVE_ADDON=1`, which fails the suite if the addon did not
load integrity-verified — the interop suites `describe.skip` themselves when the
addon is absent and would otherwise pass vacuously.

## Still deferred

Cross-compilation to the full napi triple set (only `linux-x64-gnu`,
`darwin-arm64`, and `win32-x64-msvc` are built) and a published npm
optional-dependency channel. Byte-for-byte determinism is enforced only on
Linux; the macOS/Windows C sub-builds are not yet verified reproducible.

## Benchmark (this host, local build)

Native aws-lc-rs is roughly **30–40× faster** than the pure-TS backend:

| op              | pure-TS (@noble) | native (aws-lc-rs) |
| --------------- | ---------------- | ------------------ |
| generateKeyPair | ~535 ops/s       | ~20,000 ops/s      |
| sign            | ~243 ops/s       | ~7,100 ops/s       |
| verify          | ~1,100 ops/s     | ~29,700 ops/s      |

Run `npx tsx libs/core/crypto-native/src/bench.ts` (after building the addon).
This justifies native as the eventual default once the CI prebuild matrix lands.
