import {
  importPublicSigningJwk,
  type JwsAlgorithm,
  type SigningKey,
} from '@qauth-labs/core-crypto';
import { type EgressSource, hostForLog, isEgressError } from '@qauth-labs/fastify-plugin-egress';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { ASSERTION_SIGNING_ALG_VALUES_SUPPORTED } from '../schemas/oauth';
import { egressGet } from './egress-get';

/**
 * Signing-key resolution for a JWT whose issuer an allowlist trusts: the
 * shared machinery of the ID-JAG issuer keys (`id-jag-issuer-keys.ts`,
 * ADR-011) and the CI workload issuer keys (`workload-token.ts`, #526).
 *
 * ## The trust model
 *
 * The token is attacker-controlled bytes until a key verifies it, and the only
 * way a key is obtained here is:
 *
 *   1. read the token's CLAIMED `iss` (untrusted text);
 *   2. ask the caller's allowlist ({@link AllowlistedIssuerKeyOptions.allowlist})
 *      for the identifier it trusts for that text; nothing listed, nothing
 *      fetched;
 *   3. only then, run OIDC discovery against THAT IDENTIFIER and fetch the
 *      `jwks_uri` the issuer's own document names.
 *
 * Step 2 happens before any network call, so an unlisted issuer costs one
 * string comparison and never turns the server into a fetch primitive. No URL
 * is taken from the token: it cannot nominate its own metadata, key set or key.
 *
 * ## Every fetch goes through the egress client
 *
 * Both requests go through {@link egressGet}: https only, no credentials in
 * the URL, every address checked and the connection pinned to it, no
 * redirect, a size bound and a deadline. A non-200 is refused here.
 *
 * The two fetches have different sources (ADR-019 Decision 8). The discovery
 * URL is built from the allowlist entry, so its source is whoever wrote the
 * allowlist ({@link AllowlistedIssuerKeyOptions.discoverySource}): the
 * operator for ID-JAG, a realm admin for a workload issuer. Either may reach a
 * private address that a deployment allowlist entry opens for the request's
 * realm. The `jwks_uri` is named by the fetched discovery document, a
 * `remote_document` destination that never uses the allowlist.
 *
 * The discovery cache is per issuer and realm: whether a realm's discovery
 * fetch may reach a private address depends on the deployment allowlist, so a
 * document one realm fetched through an allowlist entry never answers for a
 * realm the allowlist does not open it for. The JWK Set cache and the negative
 * cache are per issuer. A discovery fetch the address check refuses is not a
 * failure of the issuer: it is not written to the negative cache but
 * remembered for that realm alone for {@link REFUSED_FOR_REALM_TTL_SECONDS}.
 * Concurrent discovery fetches are shared only within one realm.
 *
 * ## How often an issuer is dialled
 *
 * Three bounds, all per issuer and held in Redis so they apply across every
 * auth-server process (#433):
 *
 *  - the cache: both documents for {@link IssuerKeyLimits.cacheTtlSeconds};
 *  - the refresh cooldown: an unknown `kid` forces a refresh at most once per
 *    {@link IssuerKeyLimits.refreshCooldownSeconds}, since the refresh happens
 *    BEFORE any signature is checked;
 *  - the negative cache: a failed fetch is remembered for
 *    {@link IssuerKeyLimits.negativeCacheTtlSeconds}, and no fetch is made
 *    for the issuer until it lapses. Concurrent requests in one process share
 *    a fetch that is already running.
 *
 * Every bound fails closed: inside it, resolution answers `undefined` exactly
 * as it does for an unknown key. Each caller keeps its own Redis keys
 * ({@link IssuerKeyCacheKeys}), so the two never answer for each other.
 */

/**
 * JOSE `alg` values a token from an allowlisted issuer may be signed with.
 *
 * DERIVED, not written: the intersection of the workspace-wide
 * `ASSERTION_SIGNING_ALG_VALUES_SUPPORTED` (the single source of truth
 * `discovery.ts` publishes) with the algorithms QAuth's crypto abstraction can
 * carry in a compact JWS (`JwsAlgorithm`). `alg: none` is impossible by
 * construction and every MAC algorithm (`HS*`) is absent: the issuer and this
 * server share no secret. A token whose header names anything else is refused
 * BEFORE any key is resolved.
 */
export const ALLOWLISTED_ISSUER_SIGNING_ALG_VALUES: readonly JwsAlgorithm[] = Object.freeze(
  (['EdDSA', 'RS256', 'ES256'] satisfies JwsAlgorithm[]).filter((alg) =>
    (ASSERTION_SIGNING_ALG_VALUES_SUPPORTED as readonly string[]).includes(alg)
  )
);

/** Whether `alg` is one {@link ALLOWLISTED_ISSUER_SIGNING_ALG_VALUES} names. */
export function isAllowlistedIssuerAlgorithm(alg: unknown): alg is JwsAlgorithm {
  return (
    typeof alg === 'string' &&
    (ALLOWLISTED_ISSUER_SIGNING_ALG_VALUES as readonly string[]).includes(alg)
  );
}

/** Defensive bound on an `iss` claim / configured issuer identifier. */
export const MAX_ISSUER_LENGTH = 2048;

/** Defensive bound on the number of keys accepted from an issuer's JWK Set. */
const MAX_JWKS_KEYS = 50;

/**
 * The two members of an OIDC discovery document key resolution needs.
 *
 * Everything else is stripped (Zod default): it is neither read nor cached, so
 * a large or hostile document contributes nothing but the bytes the size
 * bound already caps.
 */
const issuerMetadataSchema = z.object({
  issuer: z.string().min(1).max(MAX_ISSUER_LENGTH),
  jwks_uri: z.string().min(1).max(MAX_ISSUER_LENGTH),
});

type IssuerMetadata = z.infer<typeof issuerMetadataSchema>;

/**
 * JWK members that carry PRIVATE key material. Mirrors the list
 * `importPublicSigningJwk` refuses on.
 */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as const;

/**
 * A single published verification key.
 *
 *  - a key carrying ANY private member is REFUSED, not repaired. The schema is
 *    `looseObject` precisely so the refusal can see members it does not model;
 *    a plain `z.object` would strip `d` and import the public half, hiding that
 *    an "issuer" published its private key.
 *  - after that check, only the members needed to SELECT and IMPORT a key are
 *    carried forward, so nothing else is held or cached.
 */
const issuerJwkSchema = z
  .looseObject({
    kty: z.string().min(1).max(16),
    kid: z.string().min(1).max(256).optional(),
    alg: z.string().min(1).max(32).optional(),
    use: z.string().min(1).max(16).optional(),
    crv: z.string().min(1).max(32).optional(),
    x: z.string().min(1).max(2048).optional(),
    y: z.string().min(1).max(2048).optional(),
    n: z.string().min(1).max(8192).optional(),
    e: z.string().min(1).max(64).optional(),
  })
  .refine((jwk) => PRIVATE_JWK_MEMBERS.every((member) => jwk[member] === undefined), {
    message: 'a published verification key must not carry private key material',
  })
  .transform((jwk) => ({
    kty: jwk.kty,
    ...(jwk.kid !== undefined ? { kid: jwk.kid } : {}),
    ...(jwk.alg !== undefined ? { alg: jwk.alg } : {}),
    ...(jwk.use !== undefined ? { use: jwk.use } : {}),
    ...(jwk.crv !== undefined ? { crv: jwk.crv } : {}),
    ...(jwk.x !== undefined ? { x: jwk.x } : {}),
    ...(jwk.y !== undefined ? { y: jwk.y } : {}),
    ...(jwk.n !== undefined ? { n: jwk.n } : {}),
    ...(jwk.e !== undefined ? { e: jwk.e } : {}),
  }));

const issuerJwksSchema = z.object({
  keys: z.array(issuerJwkSchema).min(1).max(MAX_JWKS_KEYS),
});

type IssuerJwks = z.infer<typeof issuerJwksSchema>;

/**
 * What a caller knows about a token when it needs a key: all of it
 * UNVERIFIED, because nothing can be verified before a key exists.
 */
export interface IssuerKeyRequest {
  /**
   * The `iss` the token CLAIMS. Attacker-controlled text: used to look a key
   * up against the allowlist, never as an established identity.
   */
  readonly issuer: string;
  /** The protected header's `kid`, when it carried one. */
  readonly keyId?: string;
  /**
   * The algorithm the header declares, ALREADY checked against
   * {@link ALLOWLISTED_ISSUER_SIGNING_ALG_VALUES} by the caller. The key is
   * imported PINNED to it, never left algorithm-ambiguous.
   */
  readonly algorithm: JwsAlgorithm;
  /**
   * Bypass the cache for exactly this attempt: set on the ONE retry a caller
   * makes after a `kid` miss, so a key rotation is picked up before the cache
   * lapses. A request, not a guarantee: the resolver refreshes an issuer at
   * most once per refresh cooldown, across all requests and processes, and
   * not at all while the negative cache holds it. A refused refresh resolves
   * `undefined` without a fetch.
   */
  readonly forceRefresh?: boolean;
}

/** A verification key, plus the issuer identity that obtaining it established. */
export interface ResolvedIssuerKey {
  /** The public key to verify the token with. */
  readonly key: SigningKey;
  /**
   * The issuer identifier this resolution CONFIRMED: the allowlist's, NOT the
   * token's own text. Callers compare the verified `iss` with this.
   */
  readonly identifier: string;
}

/**
 * Resolve the key a token must verify under. Returns `undefined`, never
 * throws, when no key can be obtained, so "untrusted issuer", "issuer
 * unreachable", "no such kid" and "unimportable key" land on one answer.
 */
export type AllowlistedIssuerKeyResolver = (
  request: IssuerKeyRequest
) => Promise<ResolvedIssuerKey | undefined>;

/** The bounds of one resolver, read at each use. */
export interface IssuerKeyLimits {
  /** How long both documents are cached, in seconds; 0 caches nothing. */
  readonly cacheTtlSeconds: number;
  /** How often a `kid` miss may force a refresh of one issuer, in seconds. */
  readonly refreshCooldownSeconds: number;
  /** How long a failed fetch holds the issuer back, in seconds. */
  readonly negativeCacheTtlSeconds: number;
  /** Deadline of one document fetch, in milliseconds. */
  readonly fetchTimeoutMs: number;
  /** Largest document, in bytes. */
  readonly maxDocumentBytes: number;
}

/** The Redis keys of one resolver's caches and markers. */
export interface IssuerKeyCacheKeys {
  /** The discovery document of `issuer`, as `realm` fetched it. */
  discovery(issuer: string, realm: string): string;
  /** `realm`'s discovery fetch of `issuer` was refused by the address check. */
  fetchRefused(issuer: string, realm: string): string;
  /** The JWK Set of `issuer`. */
  jwks(issuer: string): string;
  /** The refresh cooldown of `issuer`. */
  keyRefresh(issuer: string): string;
  /** A fetch for `issuer` failed recently. */
  fetchFailed(issuer: string): string;
}

/** What makes one resolver: its allowlist, its keys, its bounds. */
export interface AllowlistedIssuerKeyOptions {
  /** A fixed label for the log lines, such as `ID-JAG`. */
  readonly label: string;
  /**
   * The identifier the allowlist trusts for a claimed `iss`, or `undefined`
   * when it trusts none. Called before any cache read or fetch.
   */
  readonly allowlist: (issuer: unknown) => string | undefined;
  /** Whether a discovery document's `issuer` member names `identifier` (OIDC Discovery §4.3). */
  readonly documentNames: (documentIssuer: string, identifier: string) => boolean;
  /** The discovery document's URL for `identifier` (OIDC Discovery §4). */
  readonly discoveryUrl: (identifier: string) => string;
  /** Who wrote the allowlist, and so set the discovery URL. */
  readonly discoverySource: Extract<EgressSource, 'operator' | 'admin'>;
  /** The egress purposes of the two fetches, fixed labels for counts and logs. */
  readonly purposes: { readonly discovery: string; readonly jwks: string };
  readonly keys: IssuerKeyCacheKeys;
  readonly limits: () => IssuerKeyLimits;
}

async function readCache<T>(
  fastify: FastifyInstance,
  key: string,
  schema: z.ZodType<T>
): Promise<T | undefined> {
  try {
    const raw = await fastify.redis.get(key);
    if (!raw) return undefined;
    const parsed = schema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : undefined;
  } catch {
    // Best-effort cache: an unreachable store or a corrupt entry behaves
    // exactly like a miss, which re-fetches through the same guarded path.
    // Unlike a `jti` replay store, where a failure MUST fail closed.
    return undefined;
  }
}

async function writeCache(
  fastify: FastifyInstance,
  key: string,
  value: unknown,
  ttl: number
): Promise<void> {
  if (ttl <= 0) return;
  try {
    await fastify.redis.set(key, JSON.stringify(value), 'EX', ttl);
  } catch {
    // Best-effort cache; a write failure only costs a re-fetch.
  }
}

/**
 * Document fetches in flight, per server instance, keyed by resolver, document
 * and issuer. Concurrent requests in one process wait on the one fetch already
 * running and share its answer, so a fetch that hangs until its deadline is
 * still one attempt.
 */
const fetchesInFlight = new WeakMap<FastifyInstance, Map<string, Promise<unknown>>>();

/**
 * What a fetch yields when the address check refused a destination the
 * deployment allowlist may open for another realm: no document, and nothing
 * learnt about the issuer.
 */
const REFUSED_FOR_REALM = Symbol('refused for this realm');

/**
 * How long, in seconds, a realm's refused discovery fetch is remembered: long
 * enough that a burst of requests resolves the name once, short enough that
 * an allowlist change (a restart) or a DNS change is picked up soon.
 */
const REFUSED_FOR_REALM_TTL_SECONDS = 60;

/** A document, `undefined` when the fetch failed, or {@link REFUSED_FOR_REALM}. */
type Fetched<T> = T | undefined | typeof REFUSED_FOR_REALM;

/** Run `fetch` unless the same `key` is already being fetched, then share that. */
function shareInFlight<T>(
  fastify: FastifyInstance,
  key: string,
  fetch: () => Promise<T | undefined>
): Promise<T | undefined> {
  let inFlight = fetchesInFlight.get(fastify);
  if (!inFlight) {
    inFlight = new Map();
    fetchesInFlight.set(fastify, inFlight);
  }
  const running = inFlight.get(key) as Promise<T | undefined> | undefined;
  if (running) return running;

  const started = fetch().finally(() => inFlight.delete(key));
  inFlight.set(key, started);
  return started;
}

/**
 * Build a resolver for the issuers `options.allowlist` trusts.
 *
 * @param fastify - Server instance (redis for the bounded cache, log for
 *   operator-visible refusal reasons, the egress client for the fetches).
 * @param realm - The name of the realm the token is presented to: the
 *   deployment allowlist entries that name it apply to the discovery fetch.
 */
export function createAllowlistedIssuerKeyResolver(
  fastify: FastifyInstance,
  realm: string,
  options: AllowlistedIssuerKeyOptions
): AllowlistedIssuerKeyResolver {
  const { label, keys } = options;

  /** Whether the negative cache holds `issuer`: a fetch for it failed recently. */
  async function fetchRecentlyFailed(issuer: string): Promise<boolean> {
    try {
      return (await fastify.redis.get(keys.fetchFailed(issuer))) !== null;
    } catch {
      // Read as "no failure on record", as an unreachable positive cache
      // reads as a miss: the fetch still goes through the guarded path.
      return false;
    }
  }

  /** Whether `realm`'s discovery fetch for `issuer` was refused recently. */
  async function fetchRecentlyRefused(issuer: string): Promise<boolean> {
    try {
      return (await fastify.redis.get(keys.fetchRefused(issuer, realm))) !== null;
    } catch {
      return false;
    }
  }

  /**
   * Run one document fetch for `issuer` through the negative cache: skip it
   * while a recent failure is on record, and record a failure when it yields
   * nothing. Concurrent calls for the same document share one run. Every way
   * a fetch can fail counts (transport, non-200, a body that does not parse or
   * validate, a discovery document naming another issuer); a discovery fetch
   * the address check refused does not, since it sent nothing to the issuer.
   */
  async function fetchUnlessRecentlyFailed<T>(
    issuer: string,
    what: 'discovery' | 'jwks',
    shareKey: string,
    fetch: () => Promise<Fetched<T>>
  ): Promise<T | undefined> {
    const fetched = await shareInFlight<Fetched<T>>(fastify, `${label} ${shareKey}`, async () => {
      if (await fetchRecentlyFailed(issuer)) {
        fastify.log.debug({ issuer, what }, `${label} issuer fetch skipped: a recent fetch failed`);
        return undefined;
      }

      const document = await fetch();
      if (document === undefined) {
        try {
          await fastify.redis.set(
            keys.fetchFailed(issuer),
            '1',
            'EX',
            options.limits().negativeCacheTtlSeconds
          );
        } catch {
          // Best-effort: an unwritten entry only costs the next request a fetch.
        }
      }
      return document;
    });
    return fetched === REFUSED_FOR_REALM ? undefined : fetched;
  }

  /**
   * Claim the issuer's refresh cooldown: `true` means this request may
   * refresh, `false` that it must fail closed without a fetch. `SET NX EX` is
   * atomic across processes; an unreachable store refuses rather than allows,
   * since this is the bound on attacker-driven traffic. The negative cache is
   * consulted first, so a refresh that would not fetch does not spend it.
   */
  async function claimRefresh(issuer: string): Promise<boolean> {
    if (await fetchRecentlyFailed(issuer)) {
      fastify.log.debug({ issuer }, `${label} issuer key refresh skipped: a recent fetch failed`);
      return false;
    }

    let claimed;
    try {
      claimed = await fastify.redis.set(
        keys.keyRefresh(issuer),
        '1',
        'EX',
        options.limits().refreshCooldownSeconds,
        'NX'
      );
    } catch {
      fastify.log.debug(
        { issuer },
        `${label} issuer key refresh refused: cooldown store unreachable`
      );
      return false;
    }
    if (claimed !== 'OK') {
      fastify.log.debug({ issuer }, `${label} issuer key refresh refused: inside the cooldown`);
      return false;
    }
    return true;
  }

  /**
   * A GET of one small JSON document through the egress client. `undefined`
   * for every failure (blocked, transport, non-200, unparseable, schema
   * mismatch); the reason goes to the debug log, never to the requester, who
   * would learn what the server's network reaches. An admin- or
   * operator-set destination the address check refused yields
   * {@link REFUSED_FOR_REALM}: the allowlist may open it for another realm.
   */
  async function fetchJsonDocument<T>(
    url: string,
    schema: z.ZodType<T>,
    what: 'discovery' | 'jwks',
    source: EgressSource
  ): Promise<Fetched<T>> {
    // The host only: a `jwks_uri` is named by a remote document, and its path
    // and query string are not the server's to log.
    const host = hostForLog(url);
    const limits = options.limits();
    let result;
    try {
      result = await egressGet(fastify, url, {
        purpose: what === 'discovery' ? options.purposes.discovery : options.purposes.jwks,
        source,
        realm,
        timeoutMs: limits.fetchTimeoutMs,
        maxBytes: limits.maxDocumentBytes,
      });
    } catch (err) {
      const blocked = isEgressError(err) && err.outcome === 'blocked';
      fastify.log.debug({ host, what, blocked }, `${label} issuer document fetch failed`);
      if (blocked && err.reason === 'address' && source === options.discoverySource) {
        return REFUSED_FOR_REALM;
      }
      return undefined;
    }

    if (result.status !== 200) {
      fastify.log.debug({ host, what, status: result.status }, `${label} issuer document not 200`);
      return undefined;
    }

    let json: unknown;
    try {
      json = JSON.parse(result.body);
    } catch {
      fastify.log.debug({ host, what }, `${label} issuer document is not valid JSON`);
      return undefined;
    }

    const parsed = schema.safeParse(json);
    if (!parsed.success) {
      fastify.log.debug({ host, what }, `${label} issuer document failed schema validation`);
      return undefined;
    }
    return parsed.data;
  }

  /**
   * Fetch and validate an issuer's discovery document, uncached. The
   * document's own `issuer` member MUST name the identifier it was fetched
   * under (OIDC Discovery §4.3): otherwise an allowlisted host could claim to
   * be ANOTHER issuer and point key resolution at that issuer's key set.
   */
  async function fetchIssuerMetadata(issuer: string): Promise<Fetched<IssuerMetadata>> {
    const metadata = await fetchJsonDocument(
      options.discoveryUrl(issuer),
      issuerMetadataSchema,
      'discovery',
      options.discoverySource
    );
    if (metadata === undefined || metadata === REFUSED_FOR_REALM) return metadata;

    if (!options.documentNames(metadata.issuer, issuer)) {
      fastify.log.debug(
        { issuer, documentIssuer: metadata.issuer },
        `${label} issuer metadata declares a different issuer; refusing`
      );
      return undefined;
    }

    // The jwks_uri comes from the TRUSTED issuer's own metadata, but it is
    // still remote input: re-checked here, then fetched as a
    // `remote_document` destination, which the deployment allowlist never
    // opens. https-only is asserted explicitly for a clear reason.
    let jwksUrl: URL;
    try {
      jwksUrl = new URL(metadata.jwks_uri);
    } catch {
      fastify.log.debug({ issuer }, `${label} issuer metadata has an unparseable jwks_uri`);
      return undefined;
    }
    if (jwksUrl.protocol !== 'https:') {
      fastify.log.debug({ issuer }, `${label} issuer jwks_uri is not https`);
      return undefined;
    }

    return metadata;
  }

  /** The discovery document of an ALREADY ALLOWLISTED issuer, from the cache or fetched. */
  async function resolveIssuerMetadata(
    issuer: string,
    forceRefresh: boolean
  ): Promise<IssuerMetadata | undefined> {
    const cacheKey = keys.discovery(issuer, realm);
    if (!forceRefresh) {
      const cached = await readCache(fastify, cacheKey, issuerMetadataSchema);
      if (cached) return cached;
    }

    if (await fetchRecentlyRefused(issuer)) {
      fastify.log.debug(
        { issuer, realm },
        `${label} issuer discovery skipped: the address check refused it recently`
      );
      return undefined;
    }

    // Shared only within the realm: whether the fetch may reach the issuer
    // depends on the realm (the deployment allowlist).
    const metadata = await fetchUnlessRecentlyFailed(
      issuer,
      'discovery',
      `discovery ${issuer} ${realm}`,
      async () => {
        const fetched = await fetchIssuerMetadata(issuer);
        if (fetched === REFUSED_FOR_REALM) {
          try {
            await fastify.redis.set(
              keys.fetchRefused(issuer, realm),
              '1',
              'EX',
              REFUSED_FOR_REALM_TTL_SECONDS
            );
          } catch {
            // Best-effort: an unwritten entry only costs the next request a lookup.
          }
        }
        return fetched;
      }
    );
    if (!metadata) return undefined;

    await writeCache(fastify, cacheKey, metadata, options.limits().cacheTtlSeconds);
    return metadata;
  }

  /** The JWK Set of an allowlisted issuer, from the `jwks_uri` its discovery document named. */
  async function resolveIssuerJwks(
    issuer: string,
    jwksUri: string,
    forceRefresh: boolean
  ): Promise<IssuerJwks | undefined> {
    const cacheKey = keys.jwks(issuer);
    if (!forceRefresh) {
      const cached = await readCache(fastify, cacheKey, issuerJwksSchema);
      if (cached) return cached;
    }

    // A remote document: the allowlist never applies, so the realm changes
    // nothing and the fetch is shared across realms.
    const jwks = await fetchUnlessRecentlyFailed(issuer, 'jwks', `jwks ${issuer}`, () =>
      fetchJsonDocument(jwksUri, issuerJwksSchema, 'jwks', 'remote_document')
    );
    if (!jwks) return undefined;

    await writeCache(fastify, cacheKey, jwks, options.limits().cacheTtlSeconds);
    return jwks;
  }

  return async (request) => {
    // ALLOWLIST FIRST: before any network call, any cache read, any parsing.
    const identifier = options.allowlist(request.issuer);
    if (identifier === undefined) return undefined;

    // A forced refresh is the one fetch a token's `kid` can cause on a warm
    // cache, and it happens before any signature check: hold it to the
    // per-issuer cooldown, and fail closed inside it.
    const forceRefresh = request.forceRefresh === true;
    if (forceRefresh && !(await claimRefresh(identifier))) return undefined;

    const metadata = await resolveIssuerMetadata(identifier, forceRefresh);
    if (!metadata) return undefined;

    const jwks = await resolveIssuerJwks(identifier, metadata.jwks_uri, forceRefresh);
    if (!jwks) return undefined;

    const jwk = selectJwk(jwks, request.keyId);
    if (jwk === undefined) return undefined;

    try {
      const key = await importPublicSigningJwk(jwk, request.algorithm);
      return { key, identifier };
    } catch {
      // A published key that cannot be imported under the algorithm the token
      // declares is not a match: resolving nothing is the fail-closed answer.
      return undefined;
    }
  };
}

/**
 * Pick the one JWK a token addresses, fail-closed:
 *  - with a `kid`, EXACTLY the key carrying it. A `kid` naming no published
 *    key resolves to nothing rather than "try them all", which would make
 *    `kid` a hint an attacker can drop to widen the key set;
 *  - without a `kid`, the set must hold exactly ONE key: guessing which key
 *    was meant is how a rotated-out key stays live.
 */
function selectJwk(jwks: IssuerJwks, keyId: string | undefined) {
  if (keyId === undefined) {
    return jwks.keys.length === 1 ? jwks.keys[0] : undefined;
  }
  const matches = jwks.keys.filter((candidate) => candidate.kid === keyId);
  return matches.length === 1 ? matches[0] : undefined;
}
