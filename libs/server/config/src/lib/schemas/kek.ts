import { z } from 'zod';

/** Blank is read as unset, since Docker Compose passes an absent variable as `''`. */
function blankAsUnset(value: unknown): unknown {
  return typeof value === 'string' && value.trim() === '' ? undefined : value;
}

/**
 * The key-encryption key (KEK) provider (ADR-019 Decision 9, #462).
 *
 * The KEK wraps the data key of every stored key. `@qauth-labs/server-keys`
 * reads these keys when the signer creates its provider: it decodes the KEK,
 * reads the `*_PATH` files (a file wins over its variable), refuses a KEK that
 * is not base64 of 32 bytes, and refuses the development KEK when
 * `NODE_ENV=production`. It also checks the `KEK_PROVIDER` name. This schema
 * only declares the keys, so each rule has one home: the key library may not
 * depend on this one, and this one does not repeat its checks.
 *
 * Plain `z.object`, so an app can spread its `.shape` into its own schema.
 */
export const kekEnvSchema = z.object({
  /**
   * Which provider holds the KEK. `local` reads it from the variables below.
   * Any other name loads the optional package `@qauth-labs/keys-<name>`.
   */
  KEK_PROVIDER: z.preprocess(blankAsUnset, z.string().trim().default('local')),

  /** The KEK as base64 of 32 bytes. Generate one with `openssl rand -base64 32`. */
  KEK: z.string().optional(),

  /** A file holding the KEK as base64; it takes precedence over `KEK`. */
  KEK_PATH: z.string().optional(),

  /**
   * The KEK in use before a rotation, as base64 of 32 bytes. It only unwraps:
   * keys wrapped under it still open until they are re-wrapped.
   */
  KEK_PREVIOUS: z.string().optional(),

  /** A file holding the previous KEK; it takes precedence over `KEK_PREVIOUS`. */
  KEK_PREVIOUS_PATH: z.string().optional(),
});

/** KEK provider environment configuration type. */
export type KekEnv = z.infer<typeof kekEnvSchema>;
