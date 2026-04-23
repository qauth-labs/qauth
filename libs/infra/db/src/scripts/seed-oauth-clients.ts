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
 * The target realm must already exist. Create it via migrations or the
 * default-realm helper before running this.
 */
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { hash } from '@node-rs/argon2';
import * as dotenv from 'dotenv';
import { and, eq, sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { z } from 'zod';

import { oauthClients, realms } from '../lib/schema';
import { grantTypeEnum, responseTypeEnum, tokenEndpointAuthMethodEnum } from '../lib/schema/enums';

dotenv.config({ path: '../../../.env' });

/* ------------------------------------------------------------------------ */
/*                       Manifest schema (zod)                              */
/* ------------------------------------------------------------------------ */

// Reuse pgEnum values to stay in lock-step with the database schema. If
// someone adds a grant type or auth method to the enum, the manifest
// validator picks it up automatically.
const grantTypeZ = z.enum(grantTypeEnum.enumValues);
const responseTypeZ = z.enum(responseTypeEnum.enumValues);
const tokenEndpointAuthMethodZ = z.enum(tokenEndpointAuthMethodEnum.enumValues);

const clientSpecSchema = z
  .object({
    client_id: z.string().min(1).max(255),
    name: z.string().min(1).max(255),
    description: z.string().max(2000).optional(),
    grant_types: z.array(grantTypeZ).min(1),
    response_types: z.array(responseTypeZ).optional(),
    scopes: z.array(z.string().min(1)).optional(),
    audience: z.array(z.string().min(1)).nullable().optional(),
    redirect_uris: z.array(z.string().url()).optional(),
    require_pkce: z.boolean().optional(),
    token_endpoint_auth_method: tokenEndpointAuthMethodZ.optional(),
  })
  .strict();

const manifestSchema = z
  .object({
    realm: z.string().min(1),
    clients: z.array(clientSpecSchema).min(1),
  })
  .strict();

type ClientSpec = z.infer<typeof clientSpecSchema>;

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
        `Realm "${manifest.realm}" not found. Create it first (via migrations or the ` +
          `default-realm helper) before seeding clients.`
      );
      process.exit(1);
    }

    const issued: Issued[] = [];
    for (const spec of manifest.clients) {
      issued.push(await provisionClient(db, realm.id, spec, rotate));
    }

    report(manifest.realm, issued);
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
    requirePkce: spec.require_pkce ?? true,
    tokenEndpointAuthMethod: spec.token_endpoint_auth_method ?? 'client_secret_basic',
    grantTypes: spec.grant_types,
    responseTypes: spec.response_types ?? ['code'],
    enabled: true,
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
    requirePkce: spec.require_pkce ?? true,
    tokenEndpointAuthMethod: spec.token_endpoint_auth_method ?? 'client_secret_basic',
    grantTypes: spec.grant_types,
    responseTypes: spec.response_types ?? ['code'],
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

main().catch((err) => {
  console.error(err instanceof Error ? (err.stack ?? err.message) : err);
  process.exit(1);
});
