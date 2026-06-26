import { randomBytes } from 'node:crypto';

import { ForbiddenError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import { MIN_RESPONSE_TIME_MS } from '../constants/security';
import {
  type EnvironmentClientLike,
  type EnvironmentRealmLike,
  resolveEnvironmentPolicy,
} from './environment-policy';
import { ensureMinimumResponseTime } from './timing';

/**
 * Static developer API keys (ADR-008 §6, issue #97).
 *
 * An API key is the environment-gated DX convenience half of ADR-008 — NOT a
 * parallel to OAuth `client_credentials` (the production machine-to-machine
 * path). Every issuance and every authentication is gated through the single
 * resolver {@link resolveEnvironmentPolicy}: a key may exist or authenticate
 * ONLY while its client resolves to `staticApiKeysAllowed` (development today;
 * staging/production are off). The gate is FAIL-SAFE — a client whose
 * environment is unset or `production`, or whose realm ceiling forces
 * `production`, can neither mint nor use a key. There is no ad-hoc environment
 * check anywhere in this module; the resolver is the only source of truth.
 *
 * Plaintext handling mirrors `client_secret`: only the argon2id hash is stored,
 * and the plaintext is surfaced exactly once at creation.
 */

/** Human-facing scheme prefix on every key — also the Bearer token discriminator. */
export const API_KEY_SCHEME = 'qauth';

/** Bytes of entropy in the public key id (8 bytes → 16 hex chars). */
const KEY_ID_BYTES = 8;
/** Bytes of entropy in the secret portion (32 bytes → 256 bits, 64 hex chars). */
const KEY_SECRET_BYTES = 32;

/**
 * A freshly minted API key. The plaintext `key` is returned to the caller
 * exactly once; only `keyHash` / `prefix` / `last4` are ever persisted.
 */
export interface GeneratedApiKey {
  /** Full plaintext key — `qauth_<id>_<secret>`. Surfaced once, never stored. */
  key: string;
  /** argon2id hash of the full plaintext key (the only verifiable material stored). */
  keyHash: string;
  /** Public, non-secret lookup handle (`qauth_<id>`) — indexed, safe to display. */
  prefix: string;
  /** Trailing 4 chars of the secret portion, for masked display. */
  last4: string;
}

/**
 * Generate a new API key and its argon2id hash.
 *
 * Layout: `qauth_<keyId>_<secret>` where `keyId` is 16 hex chars (the public,
 * indexed lookup handle, embedded as `prefix = qauth_<keyId>`) and `secret` is
 * 64 hex chars (256 bits of entropy). The hash covers the FULL string, so a
 * known prefix alone never lets an attacker pass verification.
 *
 * @param fastify - decorated instance providing the shared argon2id hasher
 * @returns the one-time plaintext key plus the storable hash / display handles
 */
export async function generateApiKey(fastify: FastifyInstance): Promise<GeneratedApiKey> {
  const keyId = randomBytes(KEY_ID_BYTES).toString('hex');
  const secret = randomBytes(KEY_SECRET_BYTES).toString('hex');
  const prefix = `${API_KEY_SCHEME}_${keyId}`;
  const key = `${prefix}_${secret}`;
  const keyHash = await fastify.passwordHasher.hashPassword(key);
  return { key, keyHash, prefix, last4: secret.slice(-4) };
}

/**
 * Enforce the ADR-008 static-API-key gate for a client in its realm.
 *
 * Throws {@link ForbiddenError} (HTTP 403) when the resolved environment policy
 * does not permit static API keys — i.e. the effective environment is `staging`
 * or `production`, or any fail-safe fallback (unset client environment / realm
 * ceiling) lands on `production`. The message steers the developer to the
 * production path, OAuth `client_credentials`.
 *
 * The check routes exclusively through {@link resolveEnvironmentPolicy}; callers
 * MUST NOT re-derive the rule from the raw `environment` column.
 *
 * @throws ForbiddenError when `staticApiKeysAllowed` is false for the client
 */
export function assertStaticApiKeysAllowed(
  client: EnvironmentClientLike | null | undefined,
  realm: EnvironmentRealmLike | null | undefined
): void {
  const policy = resolveEnvironmentPolicy(client, realm);
  if (!policy.staticApiKeysAllowed) {
    throw new ForbiddenError(
      `Static API keys are disabled for ${policy.environment} clients. ` +
        'Use the OAuth client_credentials grant for machine-to-machine access in this environment.'
    );
  }
}

/**
 * Parse a presented credential into the public lookup `prefix`, or null when it
 * is not a well-formed QAuth API key.
 *
 * Accepts either a raw key or an `Authorization: Bearer <key>` header value, so
 * a route may hand either form. Returns null (rather than throwing) so the
 * caller can fall through to other authentication schemes without leaking which
 * branch failed.
 */
export function parseApiKeyPrefix(presented: string | undefined): string | null {
  if (!presented) {
    return null;
  }
  const bearer = presented.match(/^Bearer\s+(.+)$/i);
  const raw = (bearer ? bearer[1] : presented).trim();
  // `qauth_<16 hex>_<secret>` — the prefix is the scheme + key id.
  const match = raw.match(/^(qauth_[0-9a-f]{16})_[0-9a-f]+$/);
  return match ? match[1] : null;
}

/** The successfully authenticated client behind a valid API key. */
export interface AuthenticatedApiKey {
  /** The owning OAuth client's `oauth_clients.id`. */
  clientId: string;
  /** The owning OAuth client's external `client_id`. */
  clientClientId: string;
  /** The authenticated `api_keys.id`. */
  apiKeyId: string;
  /** The developer (`users.id`) who created the key, when still present. */
  developerId: string | null;
}

/**
 * Authenticate a request credential as a static API key (ADR-008 §6, #97).
 *
 * Pipeline (every failure returns null — never reveals which check failed):
 *   1. Parse the public prefix; bail if not a QAuth key.
 *   2. Resolve the single candidate row by indexed prefix lookup.
 *   3. Constant-time verify the FULL presented key against the argon2id hash.
 *   4. Reject if the key is revoked.
 *   5. Re-resolve the owning client + realm and re-apply the environment gate:
 *      a key minted while `development` MUST stop working the moment the client
 *      (or its realm ceiling) is moved to `staging`/`production`. The gate is
 *      authoritative on every use, not only at issuance.
 *   6. Best-effort `lastUsedAt` touch.
 *
 * The whole path is padded to {@link MIN_RESPONSE_TIME_MS.API_KEY_AUTH} so an
 * unknown prefix, a wrong secret, a revoked key, and a now-forbidden client are
 * indistinguishable by timing (the verify itself uses argon2's constant-time
 * comparison).
 *
 * @returns the authenticated client/key context, or null on any failure
 */
export async function authenticateApiKey(
  fastify: FastifyInstance,
  presented: string | undefined
): Promise<AuthenticatedApiKey | null> {
  const startTime = Date.now();
  const result = await resolveApiKey(fastify, presented);
  await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.API_KEY_AUTH);
  return result;
}

/**
 * Inner resolution for {@link authenticateApiKey}, without the timing pad. Kept
 * separate so the public entry point owns the constant-time envelope and this
 * function stays a clean, testable sequence of checks.
 */
async function resolveApiKey(
  fastify: FastifyInstance,
  presented: string | undefined
): Promise<AuthenticatedApiKey | null> {
  const prefix = parseApiKeyPrefix(presented);
  if (!prefix) {
    return null;
  }
  const raw = presented?.replace(/^Bearer\s+/i, '').trim();
  if (!raw) {
    return null;
  }

  const apiKey = await fastify.repositories.apiKeys.findByPrefix(prefix);
  if (!apiKey) {
    return null;
  }

  const valid = await fastify.passwordHasher.verifyPassword(apiKey.keyHash, raw);
  if (!valid) {
    return null;
  }

  // Revoked keys never authenticate (checked AFTER the constant-time verify so
  // a revoked key is not distinguishable from a wrong secret by timing).
  if (apiKey.revokedAt !== null) {
    return null;
  }

  // Re-apply the environment gate on every use. The owning client may have been
  // promoted out of `development` (directly, or via its realm ceiling) since the
  // key was minted; a key must not outlive its client's eligibility.
  const client = await fastify.repositories.oauthClients.findById(apiKey.clientId);
  if (!client || !client.enabled) {
    return null;
  }
  const realm = await fastify.repositories.realms.findById(client.realmId);
  const policy = resolveEnvironmentPolicy(client, realm ?? null);
  if (!policy.staticApiKeysAllowed) {
    return null;
  }

  // Best-effort usage stamp — a failure here must not deny an otherwise valid
  // authentication.
  try {
    await fastify.repositories.apiKeys.touchLastUsed(apiKey.id);
  } catch (err) {
    fastify.log.warn({ err, apiKeyId: apiKey.id }, 'Failed to touch api_key.last_used_at');
  }

  return {
    clientId: client.id,
    clientClientId: client.clientId,
    apiKeyId: apiKey.id,
    developerId: apiKey.developerId,
  };
}
