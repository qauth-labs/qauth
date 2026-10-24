# @qauth-labs/shared-test-vectors

The TypeScript side of the shared test vectors (#478, ADR-018 §6 and §7): the `qauth-vectors/1`
format, its validator, and `loadVectors` for tests. The vector files themselves, and how another
language reads them, are in [`test-vectors/`](../../../test-vectors/README.md) at the repository
root.

## What it holds

| Module                        | What                                                                                       |
| ----------------------------- | ------------------------------------------------------------------------------------------ |
| `lib/format.ts`               | The format as a Zod schema, with the two rules JSON Schema cannot state                    |
| `lib/json-schema.ts`          | The published JSON Schema, generated from the Zod schema                                   |
| `lib/validate.ts`             | `validateVectorFile`, `parseVectorFile`, and the tree walk behind `test-vectors:validate`  |
| `lib/load.ts`                 | `loadVectors(id)`: read, validate and type one file                                        |
| `scripts/validate-vectors.ts` | The `test-vectors:validate` target's command                                               |
| `scripts/export-schema.ts`    | The `schema-export` target's command: writes `test-vectors/schema/vector-file.schema.json` |

```ts
import { loadVectors } from '@qauth-labs/shared-test-vectors';

const vectors = loadVectors<
  { code_verifier: string; code_challenge: string },
  { computed_challenge: string | null; accepted: boolean }
>('pkce/s256');

it.each(vectors.cases)('$id', ({ input, expected }) => {
  // Rebuild the whole expected object from the code under test, so a wrong
  // value anywhere in a case fails it.
  expect(check(input)).toEqual(expected);
});
```

`loadVectors` throws on a malformed id, a missing file, or a file the validator rejects, so a test
never runs against a file `test-vectors:validate` would fail.

The library is `scope:shared` and imports no workspace package. It depends on the `test-vectors`
project (`implicitDependencies`), so a change to a vector file invalidates the cached `test` result
of every project that depends on this library.
