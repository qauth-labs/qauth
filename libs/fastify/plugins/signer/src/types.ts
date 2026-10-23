import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import type { DbClient } from '@qauth-labs/infra-db';
import type { KekEnv } from '@qauth-labs/server-keys/custody';
import type { FastifyPluginOptions } from 'fastify';

/** Options of `signerPlugin`. */
export interface SignerPluginOptions extends FastifyPluginOptions {
  /**
   * The database the keys and realms are read from, usually `fastify.db` of
   * `@qauth-labs/fastify-plugin-db`. The signer only reads it.
   */
  db: DbClient;
  /**
   * The KEK provider's settings: `KEK_PROVIDER`, `KEK`, `KEK_PATH`,
   * `KEK_PREVIOUS`, `KEK_PREVIOUS_PATH`, an adapter's own variables and
   * `NODE_ENV`. Usually `process.env`.
   */
  kekEnv: KekEnv;
  /** `cryptoEnv.enabledSignatureAlgorithms` (`SIGNING_ALGORITHM_MODE`). */
  enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
  /** `HYBRID_SIGNING_ENABLED`. */
  hybridSigning: boolean;
  /** The most unwrapped keys the signer holds at once. */
  keyCacheSize?: number;
  /** How long the signer trusts a key lookup before it reads the store again, in ms. */
  refreshIntervalMs?: number;
}
