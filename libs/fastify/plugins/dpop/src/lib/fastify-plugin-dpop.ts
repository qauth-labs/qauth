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

/** Options for {@link createDpopService}. */
export interface DpopServiceOptions {
  /** The base URL of the requests, as {@link DpopPluginOptions.baseUrl}. */
  readonly baseUrl: string | ((request: FastifyRequest) => string);
  /** The allowlist; default the verifier's `DEFAULT_DPOP_ALGORITHMS`. */
  readonly algorithms?: readonly DpopAlgorithm[];
  /**
   * How far a proof's `iat` may be from the server's clock, in seconds, in
   * either direction; the verifier's default (60) when unset. Used proofs are
   * kept for longer than the window allows a proof to pass.
   */
  readonly iatWindowSeconds?: number;
  /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/**
 * A {@link DpopService} over `redis`, which records used proofs under
 * {@link DPOP_REPLAY_KEY_PREFIX} (RFC 9449 §11.1). The plugin builds the
 * server's own with it; a listener whose requests are made to another base
 * URL builds a second one, such as the admin API's, whose proofs name
 * `ADMIN_API_BASE_URL` (#520). Both record proofs in the one store, so a
 * proof is used once whichever checks it.
 *
 * A fixed `baseUrl` is checked here, so a bad one fails at boot. With Redis
 * unavailable, every proof is refused: a replay can no longer be ruled out.
 * The verifier itself bounds each Redis call to 250 ms.
 */
export function createDpopService(
  redis: DpopRedisClient,
  options: DpopServiceOptions
): DpopService {
  const { baseUrl: configured } = options;
  const fixedBaseUrl = typeof configured === 'string' ? canonicalBaseUrl(configured) : undefined;
  const baseUrlOf = (request: FastifyRequest): string =>
    fixedBaseUrl ?? canonicalBaseUrl((configured as (request: FastifyRequest) => string)(request));

  const verifier = createDpopVerifier({
    replayStore: createRedisDpopReplayStore(redis, { keyPrefix: DPOP_REPLAY_KEY_PREFIX }),
    ...(options.algorithms ? { algorithms: options.algorithms } : {}),
    ...(options.iatWindowSeconds === undefined
      ? {}
      : { iatWindowSeconds: options.iatWindowSeconds }),
    ...(options.now ? { now: options.now } : {}),
  });

  return {
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
}

/**
 * The shared DPoP verifier (`@qauth-labs/server-dpop`) for Fastify routes,
 * issue #480. Decorates `fastify.dpop` with a {@link DpopService} over the
 * cache plugin's Redis client ({@link createDpopService}), or with `null`
 * when `enabled` is false.
 */
export const dpopPlugin = fp<DpopPluginOptions>(
  async (fastify: FastifyInstance, options: DpopPluginOptions) => {
    if (!options.enabled) {
      fastify.decorate('dpop', null);
      return;
    }
    fastify.decorate(
      'dpop',
      // ioredis's `set` overloads include `SET key value PX ms NX`, the one
      // command the store sends.
      createDpopService(fastify.redis as unknown as DpopRedisClient, {
        baseUrl: options.baseUrl,
        ...(options.algorithms ? { algorithms: options.algorithms } : {}),
        ...(options.now ? { now: options.now } : {}),
      })
    );
  },
  {
    name: DPOP_PLUGIN_NAME,
    // `fastify.redis`.
    dependencies: [CACHE_PLUGIN_NAME],
  }
);

export default dpopPlugin;
