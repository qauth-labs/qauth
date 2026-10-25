import { CACHE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-cache';
import {
  createDpopVerifier,
  createRedisDpopReplayStore,
  type DpopAlgorithm,
  type DpopRedisClient,
  dpopRequestUrl,
  type VerifiedDpopProof,
} from '@qauth-labs/server-dpop';
import type { FastifyInstance, FastifyPluginOptions, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The DPoP proof checks of this server (RFC 9449, issue #480), or `null`
     * while `DPOP_ENABLED` is off. Every route that reads a `DPoP` header
     * goes through it; `null` means the server reads none.
     */
    dpop: DpopService | null;
  }
}

/** What a route checks a request's proof against, beside its method and URL. */
export interface DpopRequestCheck {
  /**
   * The access token presented with the proof, at a protected resource: the
   * proof's `ath` must be its hash (RFC 9449 §4.3 step 12).
   */
  readonly accessToken?: string;
  /**
   * The thumbprint the token, code or refresh token is bound to. When set,
   * the proof's key must have it.
   */
  readonly expectedThumbprint?: string;
}

/** The DPoP proof checks of one server. */
export interface DpopService {
  /**
   * The algorithms a proof may use: `dpop_signing_alg_values_supported` in
   * discovery (RFC 9449 §5.1) and the `algs` of a `DPoP` challenge (§7.1).
   */
  readonly algorithms: readonly DpopAlgorithm[];
  /**
   * Check the request's `DPoP` header (RFC 9449 §4.3) against its method and
   * its URL at this server's own origin, and record the proof so it cannot be
   * used again. Resolves with the proof's key thumbprint; rejects with a
   * `DpopProofError` when the proof fails a check, including when the request
   * has none.
   */
  verifyRequest(request: FastifyRequest, check?: DpopRequestCheck): Promise<VerifiedDpopProof>;
}

/** Options for {@link dpopPlugin}. */
export interface DpopPluginOptions extends FastifyPluginOptions {
  /** `DPOP_ENABLED`. Off, the plugin decorates `fastify.dpop` with `null`. */
  readonly enabled: boolean;
  /**
   * The server's own origin, from its configuration (the issuer). A proof's
   * `htu` is compared with this origin and the request path, never with the
   * request's `Host` header.
   */
  readonly origin: string;
  /** The allowlist; default the verifier's `DEFAULT_DPOP_ALGORITHMS`. */
  readonly algorithms?: readonly DpopAlgorithm[];
  /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
  readonly now?: () => number;
}

export const DPOP_PLUGIN_NAME = packageJson.name;

/**
 * The Redis key prefix of the auth server's used proofs. The verifier hashes
 * each proof's key thumbprint and `jti` into the rest of the key.
 */
export const DPOP_REPLAY_KEY_PREFIX = 'dpop-jti:';

/**
 * The shared DPoP verifier (`@qauth-labs/server-dpop`) for Fastify routes,
 * issue #480. Decorates `fastify.dpop` with a {@link DpopService} over the
 * cache plugin's Redis client, which records used proofs (RFC 9449 §11.1), or
 * with `null` when `enabled` is false.
 *
 * With Redis unavailable, every proof is refused: a replay can no longer be
 * ruled out. The verifier itself bounds each Redis call to 250 ms.
 */
export const dpopPlugin = fp<DpopPluginOptions>(
  async (fastify: FastifyInstance, options: DpopPluginOptions) => {
    if (!options.enabled) {
      fastify.decorate('dpop', null);
      return;
    }
    // Refused here, at boot, rather than on the first proof.
    dpopRequestUrl(options.origin, '/');
    const { origin } = options;

    const verifier = createDpopVerifier({
      // ioredis's `set` overloads include `SET key value PX ms NX`, the one
      // command the store sends.
      replayStore: createRedisDpopReplayStore(fastify.redis as unknown as DpopRedisClient, {
        keyPrefix: DPOP_REPLAY_KEY_PREFIX,
      }),
      ...(options.algorithms ? { algorithms: options.algorithms } : {}),
      ...(options.now ? { now: options.now } : {}),
    });

    const service: DpopService = {
      algorithms: verifier.algorithms,
      async verifyRequest(request, check = {}) {
        return verifier.verify({
          proof: request.headers.dpop,
          method: request.method,
          // The origin from the configuration and the request target as the
          // request line gave it. `dpopRequestUrl` refuses an absolute-form
          // target, which would let the client choose what `htu` is compared
          // with.
          url: dpopRequestUrl(origin, request.url),
          ...(check.accessToken === undefined ? {} : { accessToken: check.accessToken }),
          ...(check.expectedThumbprint === undefined
            ? {}
            : { expectedThumbprint: check.expectedThumbprint }),
        });
      },
    };
    fastify.decorate('dpop', service);
  },
  {
    name: DPOP_PLUGIN_NAME,
    // `fastify.redis`.
    dependencies: [CACHE_PLUGIN_NAME],
  }
);

export default dpopPlugin;
