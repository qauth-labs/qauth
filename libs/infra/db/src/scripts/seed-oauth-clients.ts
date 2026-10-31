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
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import * as dotenv from 'dotenv';
import { eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';

import { realms } from '../lib/schema';
import { applyCimdClientGrant, type CimdGrantResult } from './cimd-client-grants';
import { type Issued, provisionClient } from './seed-clients';
import { type ClientSpec, firstPartyColumnsOf, manifestSchema } from './seed-manifest';

dotenv.config({ path: '../../../.env' });

/* ------------------------------------------------------------------------ */
/*                                 Helpers                                  */
/* ------------------------------------------------------------------------ */

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
    warnPkceOff(manifest.clients ?? []);

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

  const firstParty = issued.filter((i) => i.firstPartyChanged);
  if (firstParty.length > 0) {
    console.log('First-party profile changed (recorded as client.first_party_changed):');
    for (const i of firstParty) {
      console.log(
        `  ${i.clientId}` +
          (i.revokedTokenCount
            ? `: profile removed, ${i.revokedTokenCount} refresh tokens revoked`
            : '')
      );
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

/**
 * ADR-017 question 11: PKCE stays required at the authorization challenge
 * endpoint unless the operator switches it off for one client. Say so, by
 * name, every time the manifest does.
 */
function warnPkceOff(clients: readonly ClientSpec[]): void {
  for (const spec of clients) {
    if (firstPartyColumnsOf(spec).policy?.pkce_required === false) {
      console.warn(
        `WARNING: ${spec.client_id}: first_party_policy.pkce_required is false. Its native ` +
          'sign-in at the authorization challenge endpoint will not require PKCE. The ' +
          'redirect flow still does.'
      );
    }
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
