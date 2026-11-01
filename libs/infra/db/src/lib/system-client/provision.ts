/**
 * The system client's provisioner (ADR-017 phase F0, issue #631).
 *
 * The system client (`SYSTEM_CLIENT_ID`, `system` by default, the same id in
 * every realm) is the developer portal's client. Until this release the auth
 * server created it on first use as a secret-based row nobody held the secret
 * of. From F0 it is a `private_key_jwt` client with the `web_redirect`
 * first-party profile and the portal's callback as its redirect URI, written
 * from the operator's configuration by two operator paths that share this
 * module: the `system_client` section of the `db:seed-oauth-clients` manifest,
 * and the migration runner (its `SYSTEM_CLIENT_*` environment).
 *
 * What it writes, and what it leaves alone:
 *
 * - the authentication method (`private_key_jwt`) and the portal's public
 *   keys (`jwks` or `jwks_uri`), the redirect URIs, the `authorization_code`
 *   and `refresh_token` grants, the `code` response type and PKCE;
 * - the `web_redirect` profile, no policy, and the written reason;
 * - `provisioned_by_operator`, since the operator now vouches for the redirect
 *   URIs.
 *
 * It never changes the row's name, description, scopes, audience, `enabled`
 * or `suspended`, so an operator's suspension and the audience the auth
 * server gives the system client survive a run. A row it creates gets that
 * audience from the start, the developer API's (#524), so the portal's first
 * token is accepted without waiting for the auth server's next boot. A row that the profile's
 * CHECKs would refuse (a developer's, an agent, a dynamic or CIMD
 * registration) is refused here first, by name, and left as it is.
 *
 * The module reaches only `pg`, `drizzle-orm`, the event contract and the
 * shared validation rules, so the migration runner bundles it
 * (`@qauth-labs/infra-db/system-client`).
 */
import { randomBytes } from 'node:crypto';

import {
  DEVELOPER_API_AUDIENCE,
  isLoopbackHost,
  redirectTarget,
} from '@qauth-labs/shared-validation';
import { and, eq, sql } from 'drizzle-orm';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { z } from 'zod';

import type { Database, DbTransaction } from '../../types';
import {
  canonicalJson,
  type FirstPartyColumns,
  firstPartyColumnsDiffer,
  ownershipRefusalOf,
  recordFirstPartyChange,
} from '../first-party/first-party-change';
import { oauthClients, realms } from '../schema/core';
import { publicJwkSchema } from './public-jwk';

/** The `client_id` the auth server uses when `SYSTEM_CLIENT_ID` is unset. */
export const DEFAULT_SYSTEM_CLIENT_ID = 'system';

/**
 * The written reason stored with the system client's profile when the
 * operator gives none: the portal is the server's own front-end.
 */
export const DEFAULT_SYSTEM_CLIENT_REASON =
  "QAuth's developer portal: the web front-end this deployment runs for its own developers.";

/** The grants the portal's redirect flow uses. */
const SYSTEM_CLIENT_GRANT_TYPES = ['authorization_code', 'refresh_token'] as const;

/**
 * The portal's callback: a URI the consent screen can describe, on `https`,
 * or on `http` only to a loopback address, for a portal run locally.
 */
const portalRedirectUriSchema = z.url().refine(
  (uri) => {
    if (redirectTarget(uri) === undefined) return false;
    const url = new URL(uri);
    if (url.hash !== '') return false;
    return url.protocol === 'https:' || (url.protocol === 'http:' && isLoopbackHost(url.hostname));
  },
  {
    error: (issue) =>
      `"${String(issue.input)}": the portal's callback must be an https URI, or an http URI on a loopback address, with no fragment`,
  }
);

/**
 * The system client as an operator configures it: the `system_client` section
 * of the seed manifest, and what the migration runner builds from its
 * environment.
 */
export const systemClientSpecSchema = z
  .object({
    client_id: z.string().min(1).max(255).default(DEFAULT_SYSTEM_CLIENT_ID),
    redirect_uris: z.array(portalRedirectUriSchema).min(1).max(20),
    jwks: z.object({ keys: z.array(publicJwkSchema).min(1).max(20) }).optional(),
    jwks_uri: z
      .url()
      .max(2048)
      .refine((uri) => new URL(uri).protocol === 'https:', {
        message: 'jwks_uri must be an https URL',
      })
      .optional(),
    first_party_reason: z.string().trim().min(1).max(1000).default(DEFAULT_SYSTEM_CLIENT_REASON),
  })
  .strict()
  .refine((spec) => Boolean(spec.jwks) !== Boolean(spec.jwks_uri), {
    message:
      "the system client authenticates with private_key_jwt: set exactly one of jwks and jwks_uri, the portal's public keys",
    path: ['jwks'],
  });

export type SystemClientSpec = z.output<typeof systemClientSpecSchema>;
export type SystemClientSpecInput = z.input<typeof systemClientSpecSchema>;

/** Why a row named by the system client's id cannot become the system client. */
export type SystemClientRefusal = 'developer_owned' | 'agent' | 'dynamic' | 'cimd';

export type SystemClientResult =
  | { readonly status: 'realm_not_found'; readonly realm: string }
  | {
      readonly status: 'refused';
      readonly realm: string;
      readonly clientId: string;
      readonly reason: SystemClientRefusal;
    }
  | {
      readonly status: 'created' | 'updated' | 'unchanged';
      readonly realm: string;
      readonly clientId: string;
      readonly id: string;
      /** Whether the profile or its reason changed, so an event was written. */
      readonly firstPartyChanged: boolean;
    };

/** The isolation the operator transaction runs at (see its call). */
const READ_COMMITTED = { isolationLevel: 'read committed' } as const;

/** Any drizzle node-postgres database, whatever schema generic it was built with. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OperatorDb = NodePgDatabase<any>;

/**
 * A value for the NOT NULL `client_secret_hash` that no secret can match,
 * shaped like an argon2id hash as the CIMD sentinel is. The client
 * authenticates with `private_key_jwt`, which the auth server checks before
 * any secret, so no secret exists for it.
 */
function unusableSecretHash(): string {
  const salt = randomBytes(16).toString('base64').replace(/=+$/, '');
  const digest = randomBytes(32).toString('base64').replace(/=+$/, '');
  return `$argon2id$v=19$m=65536,t=3,p=4$${salt}$${digest}`;
}

/** The columns this provisioner owns, as the spec sets them. */
function ownedColumns(spec: SystemClientSpec) {
  return {
    tokenEndpointAuthMethod: 'private_key_jwt' as const,
    jwks: (spec.jwks ?? null) as { keys: Record<string, unknown>[] } | null,
    jwksUri: spec.jwks_uri ?? null,
    redirectUris: [...spec.redirect_uris],
    grantTypes: [...SYSTEM_CLIENT_GRANT_TYPES],
    responseTypes: ['code' as const],
    requirePkce: true,
    firstPartyProfile: 'web_redirect' as const,
    firstPartyPolicy: null,
    firstPartyReason: spec.first_party_reason,
    provisionedByOperator: true,
  };
}

type OwnedColumns = ReturnType<typeof ownedColumns>;

/** Why the row cannot carry a first-party profile, or `null` when it can. */
function refusalOf(row: {
  developerId: string | null;
  isAgent: boolean;
  dynamicRegisteredAt: number | null;
  metadata: Record<string, unknown> | null;
}): SystemClientRefusal | null {
  if (row.developerId !== null) return 'developer_owned';
  if (row.isAgent) return 'agent';
  return ownershipRefusalOf(row);
}

/**
 * Provision the system client in the realm named `realm`: create it, or
 * rewrite the columns this module owns, in one transaction that also records
 * a change of its profile (`client.first_party_changed`). Idempotent: a row
 * that already matches is reported `unchanged` and nothing is written.
 *
 * The realm must exist. The auth server creates the default realm at its
 * first boot, so on a new deployment the migration runner, which runs first,
 * reports `realm_not_found` until it runs again after that boot.
 */
export async function provisionSystemClient(
  db: OperatorDb,
  realm: string,
  spec: SystemClientSpec
): Promise<SystemClientResult> {
  // READ COMMITTED whatever the database's default: the token revocation
  // relies on its UPDATE taking a fresh snapshot after the client's token
  // lock is granted, so it sees every token committed while it waited.
  return db.transaction(async (tx) => {
    const [realmRow] = await tx
      .select({ id: realms.id })
      .from(realms)
      .where(eq(realms.name, realm))
      .limit(1);
    if (!realmRow) return { status: 'realm_not_found' as const, realm };

    // FOR NO KEY UPDATE, as the seed takes it: a change of profile may wait
    // for the client's token lock (`recordFirstPartyChange`), which a token
    // insert holds while its foreign-key check takes a key-share lock on this
    // row, and this mode does not block that.
    const [existing] = await tx
      .select()
      .from(oauthClients)
      .where(and(eq(oauthClients.realmId, realmRow.id), eq(oauthClients.clientId, spec.client_id)))
      .limit(1)
      .for('no key update');

    const owned = ownedColumns(spec);
    const after: FirstPartyColumns = {
      profile: owned.firstPartyProfile,
      policy: owned.firstPartyPolicy,
      reason: owned.firstPartyReason,
    };
    const record = (id: string, before: FirstPartyColumns) =>
      recordFirstPartyChange(db as unknown as Database, tx as unknown as DbTransaction, {
        realmId: realmRow.id,
        id,
        clientId: spec.client_id,
        before,
        after,
      });

    if (!existing) {
      const [created] = await tx
        .insert(oauthClients)
        .values({
          realmId: realmRow.id,
          clientId: spec.client_id,
          clientSecretHash: unusableSecretHash(),
          name: 'System Client',
          // As the auth server's getOrCreateSystemClient creates it (#524):
          // the portal's token carries exactly the developer API's audience.
          audience: [DEVELOPER_API_AUDIENCE],
          developerId: null,
          isAgent: false,
          ...owned,
        })
        .returning({ id: oauthClients.id });
      const change = await record(created.id, { profile: null, policy: null, reason: null });
      return {
        status: 'created' as const,
        realm,
        clientId: spec.client_id,
        id: created.id,
        firstPartyChanged: change.changed,
      };
    }

    const refusal = refusalOf(existing);
    if (refusal !== null) {
      return { status: 'refused' as const, realm, clientId: spec.client_id, reason: refusal };
    }

    const before: FirstPartyColumns = {
      profile: existing.firstPartyProfile,
      policy: existing.firstPartyPolicy,
      reason: existing.firstPartyReason,
    };
    // The owned columns as the row holds them, compared with what the spec
    // sets: a run that would change nothing writes nothing.
    const current = Object.fromEntries(
      Object.keys(owned).map((key) => [key, existing[key as keyof OwnedColumns]])
    );
    if (
      canonicalJson(current) === canonicalJson(owned) &&
      !firstPartyColumnsDiffer(before, after)
    ) {
      return {
        status: 'unchanged' as const,
        realm,
        clientId: spec.client_id,
        id: existing.id,
        firstPartyChanged: false,
      };
    }

    await tx
      .update(oauthClients)
      .set({ ...owned, updatedAt: sql`(EXTRACT(EPOCH FROM now()) * 1000)::bigint` })
      .where(eq(oauthClients.id, existing.id));
    const change = await record(existing.id, before);
    return {
      status: 'updated' as const,
      realm,
      clientId: spec.client_id,
      id: existing.id,
      firstPartyChanged: change.changed,
    };
  }, READ_COMMITTED);
}

/**
 * {@link provisionSystemClient} on its own connection to `connectionString`,
 * closed afterwards: what the migration runner calls once the migrations are
 * applied.
 */
export async function provisionSystemClientAt(
  connectionString: string,
  realm: string,
  spec: SystemClientSpec
): Promise<SystemClientResult> {
  const pool = new Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: 10_000,
    application_name: 'qauth-migration-runner',
  });
  try {
    return await provisionSystemClient(drizzle(pool), realm, spec);
  } finally {
    await pool.end().catch(() => undefined);
  }
}

/** The environment keys the migration runner reads for the system client. */
export const SYSTEM_CLIENT_ENV = Object.freeze({
  redirectUri: 'SYSTEM_CLIENT_REDIRECT_URI',
  jwks: 'SYSTEM_CLIENT_JWKS',
  jwksUri: 'SYSTEM_CLIENT_JWKS_URI',
  clientId: 'SYSTEM_CLIENT_ID',
  realm: 'DEFAULT_REALM_NAME',
} as const);

/** The realm the auth server boots when `DEFAULT_REALM_NAME` is unset. */
export const DEFAULT_REALM_NAME = 'master';

/** What the migration runner reads from its environment. */
export type SystemClientEnvConfig =
  | { readonly configured: false }
  | { readonly configured: true; readonly realm: string; readonly spec: SystemClientSpec }
  | { readonly configured: 'invalid'; readonly problems: readonly string[] };

/** A set, non-blank environment value, or `undefined`. */
function envValue(env: Readonly<Record<string, string | undefined>>, name: string) {
  const value = env[name]?.trim();
  return value === undefined || value === '' ? undefined : value;
}

/**
 * Read the system client's configuration from the migration runner's
 * environment (#631):
 *
 * - `SYSTEM_CLIENT_REDIRECT_URI`: the portal's callback. Setting it turns
 *   provisioning on; unset, the runner leaves the system client alone.
 * - `SYSTEM_CLIENT_JWKS_URI` (an https URL) or `SYSTEM_CLIENT_JWKS` (a JSON
 *   JWK Set): the portal's public keys. Exactly one is required with it.
 * - `SYSTEM_CLIENT_ID` (default `system`) and `DEFAULT_REALM_NAME` (default
 *   `master`): the same values the auth server reads.
 *
 * A key of the system client set without the redirect URI is refused, so a
 * half-written configuration never passes silently.
 */
export function systemClientConfigFromEnv(
  env: Readonly<Record<string, string | undefined>>
): SystemClientEnvConfig {
  const redirectUri = envValue(env, SYSTEM_CLIENT_ENV.redirectUri);
  const jwksText = envValue(env, SYSTEM_CLIENT_ENV.jwks);
  const jwksUri = envValue(env, SYSTEM_CLIENT_ENV.jwksUri);

  if (redirectUri === undefined) {
    if (jwksText === undefined && jwksUri === undefined) return { configured: false };
    return {
      configured: 'invalid',
      problems: [
        `${SYSTEM_CLIENT_ENV.jwks} or ${SYSTEM_CLIENT_ENV.jwksUri} is set without ${SYSTEM_CLIENT_ENV.redirectUri}: set the portal's callback too, or neither`,
      ],
    };
  }

  let jwks: unknown;
  if (jwksText !== undefined) {
    try {
      jwks = JSON.parse(jwksText);
    } catch {
      return {
        configured: 'invalid',
        problems: [`${SYSTEM_CLIENT_ENV.jwks} is not JSON: write the JWK Set, {"keys": [...]}`],
      };
    }
  }

  const parsed = systemClientSpecSchema.safeParse({
    client_id: envValue(env, SYSTEM_CLIENT_ENV.clientId) ?? DEFAULT_SYSTEM_CLIENT_ID,
    redirect_uris: [redirectUri],
    ...(jwks === undefined ? {} : { jwks }),
    ...(jwksUri === undefined ? {} : { jwks_uri: jwksUri }),
  });
  if (!parsed.success) {
    const names: Record<string, string> = {
      client_id: SYSTEM_CLIENT_ENV.clientId,
      redirect_uris: SYSTEM_CLIENT_ENV.redirectUri,
      jwks: SYSTEM_CLIENT_ENV.jwks,
      jwks_uri: SYSTEM_CLIENT_ENV.jwksUri,
    };
    return {
      configured: 'invalid',
      problems: parsed.error.issues.map((issue) => {
        const key = typeof issue.path[0] === 'string' ? names[issue.path[0]] : undefined;
        return key === undefined ? issue.message : `${key}: ${issue.message}`;
      }),
    };
  }
  return {
    configured: true,
    realm: envValue(env, SYSTEM_CLIENT_ENV.realm) ?? DEFAULT_REALM_NAME,
    spec: parsed.data,
  };
}

/** One line saying what {@link provisionSystemClient} did, for an operator's terminal. */
export function describeSystemClientResult(result: SystemClientResult): string {
  switch (result.status) {
    case 'realm_not_found':
      return (
        `The system client was not provisioned: realm "${result.realm}" does not exist yet. ` +
        'The auth server creates it at its first boot; run this again after that boot.'
      );
    case 'refused':
      return (
        `The system client was not provisioned: client "${result.clientId}" in realm ` +
        `"${result.realm}" is ${REFUSAL_TEXT[result.reason]}, which can never be first party. ` +
        'Nothing was changed. Set SYSTEM_CLIENT_ID to an unused client id, on this tool and on the auth server alike.'
      );
    case 'created':
      return `Provisioned the system client "${result.clientId}" in realm "${result.realm}": private_key_jwt, first-party profile web_redirect.`;
    case 'updated':
      return `Re-provisioned the system client "${result.clientId}" in realm "${result.realm}": private_key_jwt, first-party profile web_redirect.`;
    case 'unchanged':
      return `The system client "${result.clientId}" in realm "${result.realm}" is already provisioned as configured.`;
  }
}

const REFUSAL_TEXT: Record<SystemClientRefusal, string> = {
  developer_owned: "a developer's client",
  agent: 'an agent',
  dynamic: 'a dynamically registered client',
  cimd: 'a CIMD client',
};
