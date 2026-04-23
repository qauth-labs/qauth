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
 * Manifest shape:
 *
 *   {
 *     "realm": "default",
 *     "clients": [
 *       {
 *         "client_id": "example-service",
 *         "name": "Example Service",
 *         "description": "A machine client that does things.",
 *         "grant_types": ["client_credentials"],
 *         "scopes": ["read:things"],
 *         "audience": ["https://api.example.com"],
 *         "redirect_uris": [],
 *         "response_types": [],
 *         "require_pkce": false,
 *         "token_endpoint_auth_method": "client_secret_basic"
 *       }
 *     ]
 *   }
 *
 * The target realm must already exist. Create it via migrations or the
 * default-realm helper before running this.
 */
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { hash } from '@node-rs/argon2';
import * as dotenv from 'dotenv';
import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';

import { oauthClients, realms } from '../lib/schema';
import type { GrantType, ResponseType } from '../lib/schema/enums';

dotenv.config({ path: '../../../.env' });

/* ------------------------------------------------------------------------ */
/*                             Manifest shape                               */
/* ------------------------------------------------------------------------ */

const VALID_GRANT_TYPES = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
] as const satisfies readonly GrantType[];

const VALID_AUTH_METHODS = [
  'client_secret_post',
  'client_secret_basic',
  'private_key_jwt',
  'none',
] as const;
type TokenEndpointAuthMethod = (typeof VALID_AUTH_METHODS)[number];

type ClientSpec = {
  client_id: string;
  name: string;
  description?: string;
  grant_types: GrantType[];
  response_types?: ResponseType[];
  scopes?: string[];
  audience?: string[] | null;
  redirect_uris?: string[];
  require_pkce?: boolean;
  token_endpoint_auth_method?: TokenEndpointAuthMethod;
};

type Manifest = {
  realm: string;
  clients: ClientSpec[];
};

function assertManifest(raw: unknown): asserts raw is Manifest {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Manifest must be a JSON object.');
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj['realm'] !== 'string' || obj['realm'].length === 0) {
    throw new Error('Manifest.realm must be a non-empty string.');
  }
  if (!Array.isArray(obj['clients']) || obj['clients'].length === 0) {
    throw new Error('Manifest.clients must be a non-empty array.');
  }
  for (const [i, c] of obj['clients'].entries()) {
    if (!c || typeof c !== 'object') {
      throw new Error(`clients[${i}] is not an object.`);
    }
    const spec = c as Record<string, unknown>;
    if (typeof spec['client_id'] !== 'string' || !spec['client_id']) {
      throw new Error(`clients[${i}].client_id must be a non-empty string.`);
    }
    if (typeof spec['name'] !== 'string' || !spec['name']) {
      throw new Error(`clients[${i}].name must be a non-empty string.`);
    }
    if (
      !Array.isArray(spec['grant_types']) ||
      spec['grant_types'].length === 0 ||
      !spec['grant_types'].every((g) => VALID_GRANT_TYPES.includes(g as GrantType))
    ) {
      throw new Error(
        `clients[${i}].grant_types must be a non-empty subset of ${VALID_GRANT_TYPES.join(', ')}.`
      );
    }
    if (
      spec['token_endpoint_auth_method'] !== undefined &&
      !VALID_AUTH_METHODS.includes(spec['token_endpoint_auth_method'] as TokenEndpointAuthMethod)
    ) {
      throw new Error(
        `clients[${i}].token_endpoint_auth_method must be one of ${VALID_AUTH_METHODS.join(', ')}.`
      );
    }
  }
}

/* ------------------------------------------------------------------------ */
/*                                 Helpers                                  */
/* ------------------------------------------------------------------------ */

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

async function main(): Promise<void> {
  const { manifestPath, rotate } = parseArgs(process.argv);

  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    console.error('DATABASE_URL must be set in the environment.');
    process.exit(2);
  }

  const raw: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'));
  assertManifest(raw);
  const manifest = raw;

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

    type Issued = { clientId: string; secret: string; action: 'created' | 'rotated' | 'skipped' };
    const issued: Issued[] = [];

    for (const spec of manifest.clients) {
      const [existing] = await db
        .select({ id: oauthClients.id })
        .from(oauthClients)
        .where(and(eq(oauthClients.realmId, realm.id), eq(oauthClients.clientId, spec.client_id)))
        .limit(1);

      if (existing && !rotate) {
        issued.push({ clientId: spec.client_id, secret: '', action: 'skipped' });
        continue;
      }

      const plaintextSecret = generateClientSecret();
      const clientSecretHash = await hash(plaintextSecret, ARGON2_OPTS);

      const row = {
        realmId: realm.id,
        clientId: spec.client_id,
        clientSecretHash,
        name: spec.name,
        description: spec.description ?? null,
        redirectUris: spec.redirect_uris ?? [],
        scopes: spec.scopes ?? [],
        audience: spec.audience ?? null,
        requirePkce: spec.require_pkce ?? false,
        tokenEndpointAuthMethod: spec.token_endpoint_auth_method ?? 'client_secret_basic',
        grantTypes: spec.grant_types,
        responseTypes: spec.response_types ?? [],
        enabled: true,
      } as const;

      if (existing) {
        await db.update(oauthClients).set(row).where(eq(oauthClients.id, existing.id));
        issued.push({ clientId: spec.client_id, secret: plaintextSecret, action: 'rotated' });
      } else {
        await db.insert(oauthClients).values(row);
        issued.push({ clientId: spec.client_id, secret: plaintextSecret, action: 'created' });
      }
    }

    /* ------------------------------ Report ------------------------------ */

    const created = issued.filter((i) => i.action === 'created');
    const rotated = issued.filter((i) => i.action === 'rotated');
    const skipped = issued.filter((i) => i.action === 'skipped');

    console.log(
      `\nSeeded realm "${manifest.realm}": ` +
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
  } finally {
    await db.$client.end();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? (err.stack ?? err.message) : err);
  process.exit(1);
});
