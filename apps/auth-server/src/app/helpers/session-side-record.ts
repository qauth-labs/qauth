import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { REDIS_KEYS } from '../constants/redis-keys';

/**
 * The per-session values that are not part of the session (#488): a Redis
 * hash beside it, keyed by its realm and `sid`, that never reaches Postgres.
 *
 * The session service stores only the authentication. These values change
 * on every consent step, and a Postgres write for each would cost more than
 * they are worth: losing them costs the user one more screen (a consent form
 * submitted after the loss is refused and shown again), never a session.
 *
 * Each value is its own hash field, so a write sets only what it names: the
 * consent screen and the consent API do not overwrite each other's token.
 */
export interface SessionSideRecord {
  /**
   * The identifier of the credential the user signed in with (#230: its
   * `external_sub`), shown on the consent screen. Absent for a sign-in that
   * had none, and after the record is lost; the screen then shows the user id.
   */
  identifier?: string;
  /** Consent screen CSRF token (double-submit), burned on the consent POST. */
  csrfToken?: string;
  /**
   * CSRF token for the cookie-authed JSON API (e.g. `DELETE /consents/:id`).
   * Distinct from {@link csrfToken} (which the consent screen burns after use)
   * so the two flows don't invalidate each other. Long-lived per session —
   * minted lazily by the GET that lists consents, validated via the
   * `X-CSRF-Token` header on state-changing JSON requests. The custom header
   * forces a CORS preflight, so naive cross-site CSRF is blocked even before
   * the token comparison runs.
   */
  apiCsrfToken?: string;
  /**
   * The exact scope set rendered on the most recent consent screen for a given
   * client, keyed by `client_id`. The consent POST handler grants ONLY these
   * scopes — the hidden `scope` form field is attacker-controllable, so the
   * granted set is bound to what the user actually saw, not to what is POSTed.
   */
  consentScopes: Record<string, string[]>;
  /**
   * The RFC 8707 resources named on that same consent screen, keyed by
   * `client_id`. Bound for the same reason as {@link consentScopes}: a
   * `resource` becomes the token's `aud`, and the hidden `resource` form
   * fields are as attacker-controllable as the hidden `scope`. The consent
   * POST records and binds only these.
   */
  consentResources: Record<string, string[]>;
}

/** What {@link writeSessionSideRecord} sets; a field left out is kept. */
export interface SessionSideRecordUpdate {
  identifier?: string;
  csrfToken?: string;
  apiCsrfToken?: string;
  /** The scopes and resources one consent screen named, for its client. */
  consent?: { clientId: string; scopes: string[]; resources: string[] };
}

/** The hash fields. A client's binding is one field per `client_id`. */
const FIELD = {
  identifier: 'identifier',
  csrfToken: 'csrfToken',
  apiCsrfToken: 'apiCsrfToken',
  consentScopesPrefix: 'consentScopes:',
  consentResourcesPrefix: 'consentResources:',
} as const;

const stringList = z.array(z.string());

/** A stored list, or `undefined` when the field is not one. */
function parseList(raw: string): string[] | undefined {
  try {
    const parsed = stringList.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

function sideRecordKey(realmId: string, sid: string): string {
  return REDIS_KEYS.BROWSER_SESSION_SIDE_RECORD(realmId, sid);
}

/**
 * The session's side record. An absent record reads as an empty one; a field
 * that does not parse is left out, so a corrupt or foreign value never binds
 * a consent.
 */
export async function readSessionSideRecord(
  fastify: FastifyInstance,
  session: Pick<BrowserSession, 'realmId' | 'sid'>
): Promise<SessionSideRecord> {
  const fields = await fastify.redis.hgetall(sideRecordKey(session.realmId, session.sid));
  const record: SessionSideRecord = { consentScopes: {}, consentResources: {} };
  for (const [field, value] of Object.entries(fields ?? {})) {
    if (field === FIELD.identifier) record.identifier = value;
    else if (field === FIELD.csrfToken) record.csrfToken = value;
    else if (field === FIELD.apiCsrfToken) record.apiCsrfToken = value;
    else if (field.startsWith(FIELD.consentScopesPrefix)) {
      const scopes = parseList(value);
      if (scopes) record.consentScopes[field.slice(FIELD.consentScopesPrefix.length)] = scopes;
    } else if (field.startsWith(FIELD.consentResourcesPrefix)) {
      const resources = parseList(value);
      if (resources) {
        record.consentResources[field.slice(FIELD.consentResourcesPrefix.length)] = resources;
      }
    }
  }
  return record;
}

/**
 * Set the named values on the session's side record and make the record
 * expire with the session's absolute end, so it never outlives the session
 * and a write never extends it.
 */
export async function writeSessionSideRecord(
  fastify: FastifyInstance,
  session: Pick<BrowserSession, 'realmId' | 'sid' | 'expiresAt'>,
  update: SessionSideRecordUpdate
): Promise<void> {
  const fields: Record<string, string> = {};
  if (update.identifier !== undefined) fields[FIELD.identifier] = update.identifier;
  if (update.csrfToken !== undefined) fields[FIELD.csrfToken] = update.csrfToken;
  if (update.apiCsrfToken !== undefined) fields[FIELD.apiCsrfToken] = update.apiCsrfToken;
  if (update.consent !== undefined) {
    const { clientId, scopes, resources } = update.consent;
    fields[`${FIELD.consentScopesPrefix}${clientId}`] = JSON.stringify(scopes);
    fields[`${FIELD.consentResourcesPrefix}${clientId}`] = JSON.stringify(resources);
  }
  if (Object.keys(fields).length === 0) return;
  const key = sideRecordKey(session.realmId, session.sid);
  const results = await fastify.redis
    .multi()
    .hset(key, fields)
    .pexpireat(key, session.expiresAt)
    .exec();
  // A MULTI reports a failed command in its results, not by rejecting.
  const failed = results?.find(([error]) => error !== null);
  if (failed) throw failed[0];
}

/**
 * Burn the consent screen's CSRF token, so its form cannot be submitted
 * twice. A fresh one is minted on the next render.
 */
export async function burnConsentCsrfToken(
  fastify: FastifyInstance,
  session: Pick<BrowserSession, 'realmId' | 'sid'>
): Promise<void> {
  await fastify.redis.hdel(sideRecordKey(session.realmId, session.sid), FIELD.csrfToken);
}

/** Drop a session's side record, when the session ends. */
export async function deleteSessionSideRecord(
  fastify: FastifyInstance,
  realmId: string,
  sid: string
): Promise<void> {
  await fastify.redis.del(sideRecordKey(realmId, sid));
}
