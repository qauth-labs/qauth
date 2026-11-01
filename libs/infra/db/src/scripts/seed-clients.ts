/**
 * What `seed-oauth-clients.ts` does for one `clients` entry: insert the
 * client, or with `--rotate` rewrite it from the manifest, and record a change
 * of its first-party profile (#631). Kept apart from the script so it can be
 * tested against a database without running the script, like
 * `client-suspension.ts`.
 */
import { randomBytes } from 'node:crypto';

import { hash } from '@node-rs/argon2';
import { and, eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import { ownershipRefusalOf, recordFirstPartyChange } from '../lib/first-party/first-party-change';
import { oauthClients } from '../lib/schema';
import type { Database, DbTransaction } from '../types';
import { type ClientSpec, firstPartyColumnsOf } from './seed-manifest';

// Matches `DEFAULT_PASSWORD_CONFIG` in libs/server/password so hashes verify
// against the same settings the auth-server uses at runtime.
const ARGON2_OPTS = { memoryCost: 65536, timeCost: 3, parallelism: 4 } as const;

function generateClientSecret(): string {
  return randomBytes(32).toString('hex');
}

export type Action = 'created' | 'rotated' | 'skipped' | 'refused';
export type Issued = {
  clientId: string;
  secret: string;
  action: Action;
  /**
   * Why a `--rotate` entry was refused. Nothing was written.
   * - `developer_owned`, `dynamic`, `cimd` (#631): the entry sets a
   *   first-party profile on a row a developer, dynamic registration or a
   *   CIMD document wrote, which can never be first party.
   * - `client_credentials_scopes_dropped` (#891): the stored client narrows
   *   its `client_credentials` grant and the entry has no
   *   `client_credentials_scopes`, so the rewrite would lift the narrowing.
   */
  refusal?: 'developer_owned' | 'dynamic' | 'cimd' | 'client_credentials_scopes_dropped';
  /** Whether the write changed the client's first-party profile, policy or reason (#631). */
  firstPartyChanged?: boolean;
  /** How many refresh tokens removing the client's profile revoked (#631). */
  revokedTokenCount?: number;
};

/** The isolation the operator transaction runs at (see its call). */
const READ_COMMITTED = { isolationLevel: 'read committed' } as const;

/** Any drizzle node-postgres database, whatever schema generic it was built with. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OperatorDb = NodePgDatabase<any>;

/**
 * Provision a single client. The check-then-act is wrapped in a transaction
 * so that if two seeder instances ever raced, one would block on the
 * row-level lock acquired by the other's read (FOR UPDATE semantics are
 * implicit in an UPDATE under READ COMMITTED on the same row).
 *
 * argon2 hashing is deliberately done *inside* the transaction only after
 * we've decided we need a new hash — so the skip path incurs no CPU cost.
 */
export async function provisionClient(
  db: OperatorDb,
  realmId: string,
  spec: ClientSpec,
  rotate: boolean
): Promise<Issued> {
  // READ COMMITTED whatever the database's default: the token revocation
  // relies on its UPDATE taking a fresh snapshot after the client's token
  // lock is granted, so it sees every token committed while it waited.
  return db.transaction(async (tx) => {
    // FOR NO KEY UPDATE, not FOR UPDATE: removing a first-party profile then
    // waits for the client's token lock (`revokeAllForClient`), which a token
    // insert holds while its foreign-key check takes a key-share lock on this
    // row, and this mode does not block that (#631).
    const [existing] = await tx
      .select({
        id: oauthClients.id,
        firstPartyProfile: oauthClients.firstPartyProfile,
        firstPartyPolicy: oauthClients.firstPartyPolicy,
        firstPartyReason: oauthClients.firstPartyReason,
        developerId: oauthClients.developerId,
        dynamicRegisteredAt: oauthClients.dynamicRegisteredAt,
        metadata: oauthClients.metadata,
        clientCredentialsScopes: oauthClients.clientCredentialsScopes,
      })
      .from(oauthClients)
      .where(and(eq(oauthClients.realmId, realmId), eq(oauthClients.clientId, spec.client_id)))
      .limit(1)
      .for('no key update');

    if (existing && !rotate) {
      return { clientId: spec.client_id, secret: '', action: 'skipped' as const };
    }

    // A row the profile's CHECK would refuse is refused here, by name, before
    // a secret is issued: failing on the CHECK would abort the run after
    // earlier entries committed new secrets the report never printed (#631).
    const refusal =
      existing && spec.first_party_profile !== undefined ? ownershipRefusalOf(existing) : null;
    if (refusal !== null) {
      return { clientId: spec.client_id, secret: '', action: 'refused' as const, refusal };
    }

    // #891: a rotation rewrites every column from the entry, and an entry
    // without the list writes NULL, which lets `client_credentials` issue
    // every scope of `scopes` again. An operator who set the list by hand
    // and rotates with a manifest that never named it would lift it without
    // a word, so the entry is refused, by name, before a secret is issued.
    if (existing && dropsClientCredentialsScopes(existing, spec)) {
      return {
        clientId: spec.client_id,
        secret: '',
        action: 'refused' as const,
        refusal: 'client_credentials_scopes_dropped' as const,
      };
    }

    const plaintextSecret = generateClientSecret();
    const clientSecretHash = await hash(plaintextSecret, ARGON2_OPTS);
    const after = firstPartyColumnsOf(spec);

    let id: string;
    let action: 'created' | 'rotated';
    if (existing) {
      await tx
        .update(oauthClients)
        .set(buildUpdate(spec, clientSecretHash))
        .where(eq(oauthClients.id, existing.id));
      id = existing.id;
      action = 'rotated';
    } else {
      const [created] = await tx
        .insert(oauthClients)
        .values(buildInsert(realmId, spec, clientSecretHash))
        .returning({ id: oauthClients.id });
      id = created.id;
      action = 'created';
    }

    // ADR-017 Decision 2 (#631): a change of the profile, its policy or its
    // reason is recorded as an event, and removing the profile revokes every
    // refresh token of the client, both in this transaction. The tool's
    // database handle has a schema generic of its own; at run time it is the
    // same node-postgres database and transaction the helper takes.
    const change = await recordFirstPartyChange(
      db as unknown as Database,
      tx as unknown as DbTransaction,
      {
        realmId,
        id,
        clientId: spec.client_id,
        before: existing
          ? {
              profile: existing.firstPartyProfile,
              policy: existing.firstPartyPolicy,
              reason: existing.firstPartyReason,
            }
          : { profile: null, policy: null, reason: null },
        after,
      }
    );
    return {
      clientId: spec.client_id,
      secret: plaintextSecret,
      action,
      firstPartyChanged: change.changed,
      revokedTokenCount: change.revokedTokenCount,
    };
  }, READ_COMMITTED);
}

/* ------------------------------------------------------------------------ */
/*                              Row builders                                */
/* ------------------------------------------------------------------------ */

/**
 * Whether rewriting a stored client from `spec` would lift the narrowing of
 * its `client_credentials` grant (#891): the row holds a list and the entry
 * has none. To lift it on purpose, the operator clears the column by hand
 * (`client_credentials_scopes = NULL`) before rotating.
 */
export function dropsClientCredentialsScopes(
  stored: { clientCredentialsScopes: unknown },
  spec: ClientSpec
): boolean {
  return stored.clientCredentialsScopes !== null && spec.client_credentials_scopes === undefined;
}

/**
 * The `client_credentials_scopes` column of a client entry (#891): the
 * manifest's list without repeats, or NULL when the entry has none.
 */
function clientCredentialsScopesOf(spec: ClientSpec): string[] | null {
  const list = spec.client_credentials_scopes;
  return list === undefined ? null : Array.from(new Set(list));
}

/** The three first-party columns of a client entry (#631). */
function firstPartyRow(spec: ClientSpec) {
  const { profile, policy, reason } = firstPartyColumnsOf(spec);
  return { firstPartyProfile: profile, firstPartyPolicy: policy, firstPartyReason: reason };
}

/**
 * Row for a freshly-inserted client. Defaults here mirror the schema column
 * defaults (require_pkce = true, response_types = ['code']) so a client
 * created via seed behaves identically to one created via the dev portal.
 */
export function buildInsert(realmId: string, spec: ClientSpec, clientSecretHash: string) {
  return {
    realmId,
    clientId: spec.client_id,
    clientSecretHash,
    name: spec.name,
    description: spec.description ?? null,
    redirectUris: spec.redirect_uris ?? [],
    scopes: spec.scopes ?? [],
    // #891: the scopes `client_credentials` may issue, out of `scopes`; NULL =
    // any of them. De-duplicated like the passkey origins.
    clientCredentialsScopes: clientCredentialsScopesOf(spec),
    audience: spec.audience ?? null,
    // ADR-011 (#434) ID-JAG targets; `[]` = no ID-JAG mint or redemption.
    idJagTargets: spec.id_jag_targets ?? [],
    requirePkce: spec.require_pkce ?? true,
    tokenEndpointAuthMethod: spec.token_endpoint_auth_method ?? 'client_secret_basic',
    grantTypes: spec.grant_types,
    responseTypes: spec.response_types ?? ['code'],
    isAgent: spec.is_agent ?? false,
    // Operator-set agent scope-mode cap; null = deny-by-default (no agent mode).
    maxAgentMode: spec.max_agent_mode ?? null,
    // RFC 7591 §2 client JWKS for `private_key_jwt` (#384). Mutually exclusive
    // — the manifest validator rejects a spec that sets both.
    jwks: spec.jwks ?? null,
    jwksUri: spec.jwks_uri ?? null,
    // Operator-set passkey origins (#467), normalised by the manifest schema.
    webauthnAllowedOrigins: Array.from(new Set(spec.webauthn_allowed_origins ?? [])),
    // RFC 9449 §5.2 (#480): refuse this client's token requests without a
    // DPoP proof while DPOP_ENABLED is on. false = DPoP stays optional.
    dpopBoundAccessTokens: spec.dpop_bound_access_tokens ?? false,
    // ADR-019 Decision 6 (#593): the domain the screens show first, normalised
    // by the manifest schema. NULL = the screens say the app is unverified.
    verifiedDomain: spec.verified_domain ?? null,
    // ADR-017 Decision 2 (#631): the operator's first-party profile, a native
    // profile's policy with its defaults filled in, and the written reason.
    // NULL for all three = not first party.
    ...firstPartyRow(spec),
    enabled: true,
    // The operator wrote this client, redirect URIs included, so it is the one
    // kind that receives authorization errors by automatic redirect
    // (RFC 9700 §4.11.2, ANT-2026-O8U3P920).
    provisionedByOperator: true,
  } as const;
}

/**
 * Row for a rotation. Deliberately omits `enabled` so Drizzle doesn't emit
 * it in the SET clause — a client that was manually disabled in the DB
 * stays disabled after a secret rotation.
 */
export function buildUpdate(spec: ClientSpec, clientSecretHash: string) {
  return {
    clientSecretHash,
    name: spec.name,
    description: spec.description ?? null,
    redirectUris: spec.redirect_uris ?? [],
    scopes: spec.scopes ?? [],
    // Removed from the manifest ⇒ NULL ⇒ any scope of `scopes` again (#891).
    clientCredentialsScopes: clientCredentialsScopesOf(spec),
    audience: spec.audience ?? null,
    // ADR-011 (#434) ID-JAG targets; `[]` = no ID-JAG mint or redemption.
    idJagTargets: spec.id_jag_targets ?? [],
    requirePkce: spec.require_pkce ?? true,
    tokenEndpointAuthMethod: spec.token_endpoint_auth_method ?? 'client_secret_basic',
    grantTypes: spec.grant_types,
    responseTypes: spec.response_types ?? ['code'],
    isAgent: spec.is_agent ?? false,
    // Operator-set agent scope-mode cap; null = deny-by-default (no agent mode).
    maxAgentMode: spec.max_agent_mode ?? null,
    // Kept in lock-step with the manifest so a key rotation is a manifest edit
    // + re-run, exactly like the other document-derived fields above.
    jwks: spec.jwks ?? null,
    jwksUri: spec.jwks_uri ?? null,
    webauthnAllowedOrigins: Array.from(new Set(spec.webauthn_allowed_origins ?? [])),
    dpopBoundAccessTokens: spec.dpop_bound_access_tokens ?? false,
    // Removed from the manifest ⇒ cleared, like every other operator field.
    verifiedDomain: spec.verified_domain ?? null,
    // Removed from the manifest ⇒ cleared (#631); `provisionClient` then
    // revokes the client's refresh tokens and records the removal.
    ...firstPartyRow(spec),
    // A rotation rewrites every field from the manifest, redirect URIs
    // included, so the operator now vouches for the row as it stands
    // (ANT-2026-O8U3P920). This is also how an operator marks a client the
    // migration 0023 backfill could not attribute.
    provisionedByOperator: true,
    updatedAt: sql`(EXTRACT(EPOCH FROM now()) * 1000)::bigint`,
  } as const;
}
