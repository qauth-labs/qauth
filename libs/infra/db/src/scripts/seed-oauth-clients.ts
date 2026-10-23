/**
 * Idempotent OAuth-client provisioner.
 *
 * Reads a JSON manifest and inserts (or, with `--rotate`, updates) OAuth
 * clients in an existing realm. Plaintext `client_secret` values are
 * generated per client, printed once to STDOUT, and argon2id-hashed in the
 * database. Designed for bootstrapping machine (`client_credentials`)
 * clients outside the developer portal.
 *
 * Usage (from the repo root):
 *
 *   DATABASE_URL=postgresql://qauth:pw@host:5432/qauth \
 *     pnpm nx run infra-db:db:seed-oauth-clients -- \
 *     --manifest=/absolute/path/to/manifest.json [--rotate]
 *
 * Or directly:
 *
 *   cd libs/infra/db && \
 *     tsx src/scripts/seed-oauth-clients.ts \
 *     --manifest=/path/to/manifest.json [--rotate]
 *
 * Differences from `seed.ts`:
 * - `seed.ts` is a dev-fixture generator (uses `drizzle-seed`, calls
 *   `reset()`, wipes + replants the `realms` + `oauth_clients` tables).
 *   It's destructive and not safe for production.
 * - `seed-oauth-clients.ts` is additive and idempotent — existing clients
 *   are left alone by default, and `--rotate` only touches the listed
 *   client_ids. Uses plain `drizzle-orm` inserts because `drizzle-seed`'s
 *   faker-style API is awkward for "insert these exact rows."
 *
 * The target realm must already exist. The auth-server creates the default
 * realm (`DEFAULT_REALM_NAME`, with its issuer from `JWT_ISSUER`) when it
 * boots, so start it once against the migrated database before running this.
 *
 * The manifest's optional `cimd_clients` section grants scopes to CIMD
 * clients (#770). Each entry sets only the client's `scopes` and `audience`;
 * its metadata document supplies the rest. It has no secret, so `--rotate`
 * does not apply: an entry always converges the row on the manifest. See
 * `cimd-client-grants.ts`.
 */
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { hash } from '@node-rs/argon2';
import * as dotenv from 'dotenv';
import { and, eq, sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';

import { oauthClients, realms } from '../lib/schema';
import { applyCimdClientGrant, type CimdGrantResult } from './cimd-client-grants';
import { type ClientSpec, manifestSchema } from './seed-manifest';

dotenv.config({ path: '../../../.env' });

/* ------------------------------------------------------------------------ */
/*                                 Helpers                                  */
/* ------------------------------------------------------------------------ */

// Matches `DEFAULT_PASSWORD_CONFIG` in libs/server/password so hashes verify
// against the same settings the auth-server uses at runtime.
const ARGON2_OPTS = { memoryCost: 65536, timeCost: 3, parallelism: 4 } as const;

function generateClientSecret(): string {
  return randomBytes(32).toString('hex');
}

function fingerprint(secret: string): string {
  return createHash('sha256').update(secret).digest('hex').slice(0, 8);
}

function parseArgs(argv: string[]): { manifestPath: string; rotate: boolean } {
  const rest = argv.slice(2);
  const rotate = rest.includes('--rotate');
  let manifestPath: string | undefined;
  for (const a of rest) {
    if (a.startsWith('--manifest=')) manifestPath = a.slice('--manifest='.length);
    else if (!a.startsWith('--')) manifestPath = a;
  }
  if (!manifestPath) {
    console.error(
      'Usage: seed-oauth-clients.ts --manifest=<path> [--rotate]\n' +
        '       Set DATABASE_URL in the environment.'
    );
    process.exit(2);
  }
  return { manifestPath, rotate };
}

/* ------------------------------------------------------------------------ */
/*                                   Main                                   */
/* ------------------------------------------------------------------------ */

type Action = 'created' | 'rotated' | 'skipped';
type Issued = { clientId: string; secret: string; action: Action };

async function main(): Promise<void> {
  const { manifestPath, rotate } = parseArgs(process.argv);

  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    console.error('DATABASE_URL must be set in the environment.');
    process.exit(2);
  }

  const raw: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const manifest = manifestSchema.parse(raw);

  const db = drizzle(databaseUrl);

  try {
    const [realm] = await db.select().from(realms).where(eq(realms.name, manifest.realm)).limit(1);
    if (!realm) {
      console.error(
        `Realm "${manifest.realm}" not found. The auth-server creates the default realm, ` +
          `named by DEFAULT_REALM_NAME, when it boots: start it once against this database, ` +
          `or set "realm" in the manifest to an existing realm, before seeding clients.`
      );
      process.exit(1);
    }

    const issued: Issued[] = [];
    for (const spec of manifest.clients ?? []) {
      issued.push(await provisionClient(db, realm.id, spec, rotate));
    }

    // Print the secrets before anything else can fail: they are already
    // committed, and the database keeps only their hashes.
    if (issued.length > 0) report(manifest.realm, issued);

    const granted: CimdGrantResult[] = [];
    for (const spec of manifest.cimd_clients ?? []) {
      granted.push(await applyCimdClientGrant(db, realm.id, spec));
    }

    reportCimdGrants(manifest.realm, granted);

    if (granted.some((g) => g.status === 'not_cimd')) process.exitCode = 1;
  } finally {
    await db.$client.end();
  }
}

/**
 * Provision a single client. The check-then-act is wrapped in a transaction
 * so that if two seeder instances ever raced, one would block on the
 * row-level lock acquired by the other's read (FOR UPDATE semantics are
 * implicit in an UPDATE under READ COMMITTED on the same row).
 *
 * argon2 hashing is deliberately done *inside* the transaction only after
 * we've decided we need a new hash — so the skip path incurs no CPU cost.
 */
async function provisionClient(
  db: ReturnType<typeof drizzle>,
  realmId: string,
  spec: ClientSpec,
  rotate: boolean
): Promise<Issued> {
  return db.transaction(async (tx) => {
    const [existing] = await tx
      .select({ id: oauthClients.id })
      .from(oauthClients)
      .where(and(eq(oauthClients.realmId, realmId), eq(oauthClients.clientId, spec.client_id)))
      .limit(1);

    if (existing && !rotate) {
      return { clientId: spec.client_id, secret: '', action: 'skipped' as const };
    }

    const plaintextSecret = generateClientSecret();
    const clientSecretHash = await hash(plaintextSecret, ARGON2_OPTS);

    if (existing) {
      await tx
        .update(oauthClients)
        .set(buildUpdate(spec, clientSecretHash))
        .where(eq(oauthClients.id, existing.id));
      return { clientId: spec.client_id, secret: plaintextSecret, action: 'rotated' as const };
    }

    await tx.insert(oauthClients).values(buildInsert(realmId, spec, clientSecretHash));
    return { clientId: spec.client_id, secret: plaintextSecret, action: 'created' as const };
  });
}

/* ------------------------------------------------------------------------ */
/*                              Row builders                                */
/* ------------------------------------------------------------------------ */

/**
 * Row for a freshly-inserted client. Defaults here mirror the schema column
 * defaults (require_pkce = true, response_types = ['code']) so a client
 * created via seed behaves identically to one created via the dev portal.
 */
function buildInsert(realmId: string, spec: ClientSpec, clientSecretHash: string) {
  return {
    realmId,
    clientId: spec.client_id,
    clientSecretHash,
    name: spec.name,
    description: spec.description ?? null,
    redirectUris: spec.redirect_uris ?? [],
    scopes: spec.scopes ?? [],
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
function buildUpdate(spec: ClientSpec, clientSecretHash: string) {
  return {
    clientSecretHash,
    name: spec.name,
    description: spec.description ?? null,
    redirectUris: spec.redirect_uris ?? [],
    scopes: spec.scopes ?? [],
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
    // A rotation rewrites every field from the manifest, redirect URIs
    // included, so the operator now vouches for the row as it stands
    // (ANT-2026-O8U3P920). This is also how an operator marks a client the
    // migration 0023 backfill could not attribute.
    provisionedByOperator: true,
    updatedAt: sql`(EXTRACT(EPOCH FROM now()) * 1000)::bigint`,
  } as const;
}

/* ------------------------------------------------------------------------ */
/*                                 Report                                   */
/* ------------------------------------------------------------------------ */

function report(realm: string, issued: Issued[]): void {
  const created = issued.filter((i) => i.action === 'created');
  const rotated = issued.filter((i) => i.action === 'rotated');
  const skipped = issued.filter((i) => i.action === 'skipped');

  console.log(
    `\nSeeded realm "${realm}": ` +
      `${created.length} created, ${rotated.length} rotated, ${skipped.length} skipped.\n`
  );

  if (created.length + rotated.length > 0) {
    console.log(
      'Store these plaintext secrets securely — the DB only keeps argon2id hashes.\n' +
        '  (fingerprint = first 8 chars of sha256(secret), for cross-checking)\n'
    );
    for (const i of [...created, ...rotated]) {
      console.log(`  ${i.clientId}`);
      console.log(`    secret:      ${i.secret}`);
      console.log(`    fingerprint: ${fingerprint(i.secret)}`);
      console.log(`    action:      ${i.action}`);
    }
    console.log('');
  }

  if (skipped.length > 0) {
    console.log(
      `Skipped (already exist; pass --rotate to re-issue secrets):\n  ` +
        skipped.map((s) => s.clientId).join(', ') +
        '\n'
    );
  }
}

function reportCimdGrants(realm: string, granted: CimdGrantResult[]): void {
  if (granted.length === 0) return;

  console.log(`\nCIMD clients in realm "${realm}" (scopes and audience only; no secret):`);
  for (const g of granted) {
    console.log(`  ${g.clientId}: ${g.status === 'not_cimd' ? 'REFUSED' : g.status}`);
  }
  console.log('');

  const refused = granted.filter((g) => g.status === 'not_cimd');
  if (refused.length > 0) {
    console.error(
      'Refused, and left unchanged: a client with this client_id exists and is not a CIMD ' +
        'client. Provision it under "clients" instead:\n  ' +
        refused.map((r) => r.clientId).join(', ') +
        '\n'
    );
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? (err.stack ?? err.message) : err);
  process.exit(1);
});
