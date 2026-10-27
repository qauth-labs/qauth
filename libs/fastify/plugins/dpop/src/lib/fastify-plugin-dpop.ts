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
   * its URL under this server's base URL, and record the proof so it cannot be
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
   * The server's public base URL: the issuer, path included, as discovery
   * builds every endpoint URL from it. A proof's `htu` is compared with this
   * base and the request path, so it names the endpoint URL discovery
   * publishes. Never the request's `Host` header.
   *
   * A string is one base for every request, checked at boot. A function gives
   * the base of each request, for a server with several issuers: the auth
   * server passes the issuer of the realm the request was resolved to
   * (ADR-019 Decision 1, #490). It must not read the request's authority
   * either; a base it returns is checked when the proof is.
   */
  readonly baseUrl: string | ((request: FastifyRequest) => string);
  /** The allowlist; default the verifier's `DEFAULT_DPOP_ALGORITHMS`. */
  readonly algorithms?: readonly DpopAlgorithm[];
  /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
  readonly now?: () => number;
}

export const DPOP_PLUGIN_NAME = packageJson.name;

/**
 * The URL a request was sent to, as a client that read discovery addresses
 * it: the configured base URL (which may carry a path, such as
 * `https://host/auth`) and the request path as the request line gave it,
 * without query or fragment.
 *
 * `dpopRequestUrl` refuses a target that is not in origin form first: an
 * absolute-form target would let the client choose what `htu` is compared
 * with. The path is not normalized here; the verifier refuses a dot segment
 * or a backslash in it.
 */
function requestUrlUnder(baseUrl: string, target: string): string {
  dpopRequestUrl(baseUrl, target);
  return `${baseUrl}${target.split(/[?#]/, 1)[0]}`;
}

/**
 * A base URL as the request URLs are built on it: checked to be an absolute
 * http(s) URL, and without a trailing slash, as discovery drops it from the
 * issuer (RFC 8414 §2).
 */
function canonicalBaseUrl(baseUrl: string): string {
  dpopRequestUrl(baseUrl, '/');
  return baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
}

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
    // A fixed base is refused here, at boot, rather than on the first proof.
    const { baseUrl: configured } = options;
    const fixedBaseUrl = typeof configured === 'string' ? canonicalBaseUrl(configured) : undefined;
    const baseUrlOf = (request: FastifyRequest): string =>
      fixedBaseUrl ??
      canonicalBaseUrl((configured as (request: FastifyRequest) => string)(request));

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
          url: requestUrlUnder(baseUrlOf(request), request.url),
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
