import { type JwsAlgorithm, verifyWithHeader } from '@qauth-labs/core-crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { REDIS_KEYS } from '../constants/redis-keys';
import {
  type AllowlistedIssuerKeyOptions,
  type AllowlistedIssuerKeyResolver,
  createAllowlistedIssuerKeyResolver,
  isAllowlistedIssuerAlgorithm,
  MAX_ISSUER_LENGTH,
} from './allowlisted-issuer-keys';

/**
 * The workload token of a CI job, exchanged at the token endpoint for an
 * admin token of a service account (#526, ADR-019 Decision 7: "CI exchanges
 * its workload OIDC token through RFC 8693 token exchange").
 *
 * The job holds no stored credential: its CI platform signs a short-lived
 * OIDC token naming the job (`iss`, `sub`, `aud`), and the operator realm's
 * policy `admin.workloadIssuers` says which tokens a service account trusts.
 * Each entry names:
 *
 *  - `issuer`: the token's `iss`, matched exactly, byte for byte;
 *  - `audience`: a value the token's `aud` must hold;
 *  - `subject`: the token's `sub`, matched exactly, or by prefix when it ends
 *    in `*` (`repo:acme/infra:*`), the only wildcard;
 *  - `serviceAccount`: the name of the service account the token acts as.
 *
 * Only `iss`, `sub`, `aud`, `iat`, `exp`, `nbf` and `jti` are read; claims
 * such as `repository` or `ref` count for nothing. A token is refused when it
 * is older than {@link WORKLOAD_TOKEN_MAX_AGE_SECONDS} since `iat`, and its
 * `jti` is burned, so a token is exchanged once.
 *
 * Keys come from the issuer's discovery document and JWK Set, through the
 * allowlisted-issuer resolver the ID-JAG grant uses
 * (`allowlisted-issuer-keys.ts`), with the policy's issuers as its allowlist:
 * no fetch is made for an issuer the policy does not list. A realm admin
 * writes that list, so the discovery fetch is an `admin` egress destination.
 */

/** How old, in seconds since its `iat`, a workload token may be when it is exchanged. */
export const WORKLOAD_TOKEN_MAX_AGE_SECONDS = 600;

/**
 * The clock skew, in seconds, allowed between this server and a workload
 * issuer: on `exp` and `nbf`, and on an `iat` in the future.
 */
export const WORKLOAD_TOKEN_CLOCK_SKEW_SECONDS = 30;

/**
 * How long a burned `jti` is kept, in seconds: a token is exchanged at most
 * {@link WORKLOAD_TOKEN_MAX_AGE_SECONDS} after an `iat` that may be one skew
 * ahead of this clock, and a skew more covers a clock that later steps back.
 */
const WORKLOAD_JTI_TTL_SECONDS =
  WORKLOAD_TOKEN_MAX_AGE_SECONDS + 2 * WORKLOAD_TOKEN_CLOCK_SKEW_SECONDS;

/** One trusted workload issuer, as the realm policy `admin.workloadIssuers` holds it. */
export interface WorkloadIssuerEntry {
  readonly issuer: string;
  readonly audience: string;
  readonly subject: string;
  readonly serviceAccount: string;
}

/**
 * Why a workload token was refused. For the event and the log only: the
 * response is one `invalid_request` whatever the reason, so a caller learns
 * neither which issuers are listed, nor which subjects, nor whether a `jti`
 * was seen.
 */
export type WorkloadTokenRejectionReason =
  | 'malformed'
  | 'unsupported_algorithm'
  | 'unsupported_typ'
  | 'issuer_not_listed'
  | 'unresolvable_key'
  | 'signature_invalid'
  | 'claims_invalid'
  | 'issuer_invalid'
  | 'too_old'
  | 'issued_in_future'
  | 'audience_invalid'
  | 'subject_not_listed'
  | 'ambiguous_service_account'
  | 'replayed'
  | 'replay_store_unavailable';

/** A workload token was refused; {@link reason} says why. */
export class WorkloadTokenError extends Error {
  readonly reason: WorkloadTokenRejectionReason;

  constructor(reason: WorkloadTokenRejectionReason, message: string) {
    super(message);
    this.name = 'WorkloadTokenError';
    this.reason = reason;
    Object.setPrototypeOf(this, WorkloadTokenError.prototype);
  }
}

/** A workload token that verified, matched an entry, and was burned. */
export interface ValidatedWorkloadToken {
  /** The `iss`, as the policy lists it. */
  readonly issuer: string;
  readonly subject: string;
  /** The entry's audience the token's `aud` holds. */
  readonly audience: string;
  /** The entry's `subject`: the exact subject or the prefix pattern that matched. */
  readonly subjectPattern: string;
  /** The name of the service account the token acts as. */
  readonly serviceAccount: string;
  readonly jti: string;
  readonly issuedAt: number;
}

/**
 * The verified claims a workload token must carry. Not strict: a CI platform
 * adds claims of its own (`repository`, `ref`, `job_workflow_ref` …), which
 * are read for nothing.
 */
const workloadClaimsSchema = z.object({
  iss: z.string().min(1).max(MAX_ISSUER_LENGTH),
  sub: z.string().min(1).max(255),
  aud: z.union([z.string().min(1).max(2048), z.array(z.string().min(1).max(2048)).min(1).max(10)]),
  iat: z.number().int(),
  exp: z.number().int(),
  nbf: z.number().int().optional(),
  jti: z.string().min(1).max(255),
});

/**
 * Whether `subject` matches an entry's `subject`: exactly, or, for a pattern
 * ending in `*`, by starting with what precedes it. No other character is a
 * wildcard; the policy schema refuses a `*` anywhere but at the end, a
 * pattern that is `*` alone, and a prefix that does not end at a `:` or `/`.
 */
export function workloadSubjectMatches(pattern: string, subject: string): boolean {
  if (!pattern.endsWith('*')) return subject === pattern;
  const prefix = pattern.slice(0, -1);
  // The schema refuses these prefixes; checked again, so a hand-written row
  // can never make a pattern match every subject, or another tenant's name
  // that only starts like the one meant.
  return (
    prefix.length > 1 &&
    (prefix.endsWith(':') || prefix.endsWith('/')) &&
    subject.startsWith(prefix)
  );
}

/** How specific a matching pattern is: an exact subject above any prefix, a longer prefix above a shorter. */
function specificity(pattern: string): number {
  return pattern.endsWith('*') ? pattern.length - 1 : Number.POSITIVE_INFINITY;
}

/** The entry a workload token's claims select, or why none does. */
export type WorkloadEntryMatch =
  | { readonly entry: WorkloadIssuerEntry; readonly audience: string }
  | {
      readonly refusal: Extract<
        WorkloadTokenRejectionReason,
        | 'issuer_not_listed'
        | 'audience_invalid'
        | 'subject_not_listed'
        | 'ambiguous_service_account'
      >;
    };

/**
 * The entry of `entries` the claims select: same issuer (exactly), an
 * audience the token's `aud` holds, and a subject that matches. The most
 * specific subject wins: an exact one over any prefix, a longer prefix over a
 * shorter. Two entries as specific that name different service accounts
 * select none: which account acts is never a guess.
 */
export function matchWorkloadEntry(
  entries: readonly WorkloadIssuerEntry[],
  claims: { readonly iss: string; readonly sub: string; readonly aud: readonly string[] }
): WorkloadEntryMatch {
  const ofIssuer = entries.filter((entry) => entry.issuer === claims.iss);
  if (ofIssuer.length === 0) return { refusal: 'issuer_not_listed' };
  const ofAudience = ofIssuer.filter((entry) => claims.aud.includes(entry.audience));
  if (ofAudience.length === 0) return { refusal: 'audience_invalid' };
  const matching = ofAudience.filter((entry) => workloadSubjectMatches(entry.subject, claims.sub));
  if (matching.length === 0) return { refusal: 'subject_not_listed' };

  const best = Math.max(...matching.map((entry) => specificity(entry.subject)));
  const chosen = matching.filter((entry) => specificity(entry.subject) === best);
  if (new Set(chosen.map((entry) => entry.serviceAccount)).size > 1) {
    return { refusal: 'ambiguous_service_account' };
  }
  return { entry: chosen[0], audience: chosen[0].audience };
}

/**
 * The resolver's options for the issuers `entries` lists: the policy is the
 * allowlist, matched exactly; the discovery document is the issuer's own
 * (OIDC Discovery §4, a trailing `/` of the issuer dropped before the
 * well-known path) and must name the issuer exactly (§4.3).
 */
function workloadIssuerKeyOptions(
  entries: readonly WorkloadIssuerEntry[]
): AllowlistedIssuerKeyOptions {
  const listed = new Set(entries.map((entry) => entry.issuer));
  return {
    label: 'Workload',
    allowlist: (issuer) =>
      typeof issuer === 'string' && issuer.length <= MAX_ISSUER_LENGTH && listed.has(issuer)
        ? issuer
        : undefined,
    documentNames: (documentIssuer, identifier) => documentIssuer === identifier,
    discoveryUrl: (identifier) =>
      `${identifier.endsWith('/') ? identifier.slice(0, -1) : identifier}/.well-known/openid-configuration`,
    discoverySource: 'admin',
    purposes: { discovery: 'workload-discovery', jwks: 'workload-jwks' },
    keys: {
      discovery: REDIS_KEYS.WORKLOAD_DISCOVERY,
      fetchRefused: REDIS_KEYS.WORKLOAD_FETCH_REFUSED,
      jwks: REDIS_KEYS.WORKLOAD_JWKS,
      keyRefresh: REDIS_KEYS.WORKLOAD_KEY_REFRESH,
      fetchFailed: REDIS_KEYS.WORKLOAD_FETCH_FAILED,
    },
    // Fixed, not configuration: a CI issuer rotates its keys rarely and
    // publishes the next one ahead, and its tokens are exchanged a few times
    // a run, not on every request of a user.
    limits: () => ({
      cacheTtlSeconds: 300,
      refreshCooldownSeconds: 30,
      negativeCacheTtlSeconds: 30,
      fetchTimeoutMs: 5000,
      maxDocumentBytes: 65536,
    }),
  };
}

/**
 * The key resolver for the issuers `entries` lists, as the realm `realm`
 * (its name) fetches them.
 */
export function createWorkloadIssuerKeyResolver(
  fastify: FastifyInstance,
  realm: string,
  entries: readonly WorkloadIssuerEntry[]
): AllowlistedIssuerKeyResolver {
  return createAllowlistedIssuerKeyResolver(fastify, realm, workloadIssuerKeyOptions(entries));
}

/**
 * Decode a compact JWS's header and payload WITHOUT verifying: to choose a key
 * (`alg`, `kid`) and consult the policy (`iss`) before any network call.
 * Everything read here is checked again on the verified token.
 */
function decodeUnverified(
  token: string
): { header: Record<string, unknown>; payload: Record<string, unknown> } | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  try {
    const header: unknown = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload: unknown = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (typeof header !== 'object' || header === null || Array.isArray(header)) return undefined;
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return undefined;
    return {
      header: header as Record<string, unknown>,
      payload: payload as Record<string, unknown>,
    };
  } catch {
    return undefined;
  }
}

/**
 * Whether a JOSE `typ` is one a workload token may carry: none, or `JWT`
 * (compared without case, as a media type is). A token typed as something
 * else, such as an access token (`at+jwt`) or an identity assertion grant
 * (`oauth-id-jag+jwt`), is not a workload token, whoever signed it (RFC 8725
 * §3.11).
 */
function isWorkloadTyp(typ: unknown): boolean {
  return typ === undefined || (typeof typ === 'string' && typ.toLowerCase() === 'jwt');
}

/**
 * Burn a workload token's `jti`: `true` for the first exchange alone. `SET NX
 * EX` is atomic, so two concurrent exchanges of one token cannot both win. An
 * unreachable store refuses: accepting would accept a replay.
 */
async function consumeWorkloadJti(
  fastify: FastifyInstance,
  issuer: string,
  jti: string
): Promise<void> {
  let stored: string | null;
  try {
    stored = await fastify.redis.set(
      REDIS_KEYS.WORKLOAD_JTI(issuer, jti),
      '1',
      'EX',
      WORKLOAD_JTI_TTL_SECONDS,
      'NX'
    );
  } catch (err) {
    fastify.log.error({ err }, 'workload token replay store unavailable; refusing the token');
    throw new WorkloadTokenError(
      'replay_store_unavailable',
      'replay protection is unavailable for this token'
    );
  }
  if (stored === null) {
    throw new WorkloadTokenError('replayed', 'the workload token was exchanged before');
  }
}

/** What {@link validateWorkloadToken} needs. */
export interface ValidateWorkloadTokenOptions {
  /** The token, as the request's `subject_token`. */
  readonly token: string;
  /** The operator realm's `admin.workloadIssuers`. */
  readonly entries: readonly WorkloadIssuerEntry[];
  /** The name of the realm the token is presented to, for the egress allowlist. */
  readonly realm: string;
  /** A resolver to use instead of the one the entries make (tests). */
  readonly resolver?: AllowlistedIssuerKeyResolver;
}

/**
 * Verify a CI workload token against the trusted issuers, select the entry it
 * matches and burn its `jti`.
 *
 * In order, all before any write: the `alg` and `typ`, the issuer's listing
 * (before any fetch), the key (one forced refresh on a miss, under the
 * resolver's cooldown), the signature with `exp` and `nbf`, the claims, the
 * age since `iat`, the entry (audience, then subject). The `jti` is burned
 * last, so a token refused for any other reason costs no store write, and a
 * burned token is never exchanged again, whatever the later steps decide.
 *
 * @throws WorkloadTokenError for every refusal, with its reason
 */
export async function validateWorkloadToken(
  fastify: FastifyInstance,
  options: ValidateWorkloadTokenOptions
): Promise<ValidatedWorkloadToken> {
  const decoded = decodeUnverified(options.token);
  if (!decoded) throw new WorkloadTokenError('malformed', 'the token is not a compact JWS');

  const alg = decoded.header['alg'];
  if (!isAllowlistedIssuerAlgorithm(alg)) {
    throw new WorkloadTokenError('unsupported_algorithm', 'the token alg is not supported');
  }
  if (!isWorkloadTyp(decoded.header['typ'])) {
    throw new WorkloadTokenError('unsupported_typ', 'the token typ is not JWT');
  }
  const claimedIssuer = decoded.payload['iss'];
  if (typeof claimedIssuer !== 'string' || claimedIssuer.length === 0) {
    throw new WorkloadTokenError('malformed', 'the token has no iss claim');
  }
  // The policy first: an issuer it does not list costs no fetch.
  if (!options.entries.some((entry) => entry.issuer === claimedIssuer)) {
    throw new WorkloadTokenError('issuer_not_listed', 'the token issuer is not trusted');
  }

  const resolver =
    options.resolver ?? createWorkloadIssuerKeyResolver(fastify, options.realm, options.entries);
  const keyId = typeof decoded.header['kid'] === 'string' ? decoded.header['kid'] : undefined;
  const request = { issuer: claimedIssuer, keyId, algorithm: alg as JwsAlgorithm };
  const resolved =
    (await resolver(request)) ?? (await resolver({ ...request, forceRefresh: true }));
  if (!resolved) {
    throw new WorkloadTokenError('unresolvable_key', 'no signing key resolves for the token');
  }

  let verified;
  try {
    verified = await verifyWithHeader(options.token, resolved.key, {
      algorithms: [alg],
      clockTolerance: WORKLOAD_TOKEN_CLOCK_SKEW_SECONDS,
    });
  } catch {
    throw new WorkloadTokenError('signature_invalid', 'the token failed verification or expired');
  }
  if (!isWorkloadTyp(verified.protectedHeader['typ'])) {
    throw new WorkloadTokenError('unsupported_typ', 'the token typ is not JWT');
  }

  const parsed = workloadClaimsSchema.safeParse(verified.claims);
  if (!parsed.success) {
    throw new WorkloadTokenError('claims_invalid', 'the token lacks a required claim');
  }
  const claims = parsed.data;
  if (claims.iss !== resolved.identifier) {
    throw new WorkloadTokenError('issuer_invalid', 'the token iss is not the issuer of its key');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (claims.iat > nowSeconds + WORKLOAD_TOKEN_CLOCK_SKEW_SECONDS) {
    throw new WorkloadTokenError('issued_in_future', 'the token is issued in the future');
  }
  if (nowSeconds - claims.iat > WORKLOAD_TOKEN_MAX_AGE_SECONDS) {
    throw new WorkloadTokenError('too_old', 'the token is too old to exchange');
  }

  const match = matchWorkloadEntry(options.entries, {
    iss: claims.iss,
    sub: claims.sub,
    aud: Array.isArray(claims.aud) ? claims.aud : [claims.aud],
  });
  if ('refusal' in match) {
    throw new WorkloadTokenError(match.refusal, 'the token matches no trusted workload');
  }

  await consumeWorkloadJti(fastify, claims.iss, claims.jti);

  return {
    issuer: claims.iss,
    subject: claims.sub,
    audience: match.audience,
    subjectPattern: match.entry.subject,
    serviceAccount: match.entry.serviceAccount,
    jti: claims.jti,
    issuedAt: claims.iat,
  };
}
