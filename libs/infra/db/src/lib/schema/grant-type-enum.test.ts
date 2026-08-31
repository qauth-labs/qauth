/**
 * The `grant_type` pg enum is not just a column type — it is the **seed
 * manifest's allowlist**. `scripts/seed-oauth-clients.ts` builds its validator
 * as `z.enum(grantTypeEnum.enumValues)`, so a URN missing from this list cannot
 * be provisioned by an operator no matter what the auth-server accepts.
 *
 * That is how #381 escaped: `POST /oauth/token` gated on
 * `client.grantTypes.includes(TOKEN_EXCHANGE_GRANT_TYPE)` and
 * `/.well-known/oauth-authorization-server` advertised the grant, while this
 * list — and the DCR and CIMD allowlists — omitted it, leaving the whole
 * ADR-007 §2 delegation surface reachable only by writing the
 * `oauth_clients.grant_types` JSONB column out of band.
 *
 * Each value is asserted with the reason it is present, so removing one fails
 * with an explanation rather than an opaque diff.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { grantTypeEnum } from './enums';

/**
 * The migrations directory, located from whichever cwd the runner used.
 *
 * The sibling `migration-000*.integration.test.ts` files hardcode
 * `resolve(process.cwd(), 'libs/infra/db/drizzle')` because they only ever run
 * through the root `vitest.integration.config.ts`, from the workspace root.
 * This is a UNIT test, so it also runs under `nx run infra-db:test`, where the
 * cwd is the project directory — one hardcoded path cannot serve both.
 * `import.meta.url` is not an option either: this lib typechecks under a module
 * setting that rejects it.
 */
const DRIZZLE_DIR = ['libs/infra/db/drizzle', 'drizzle']
  .map((candidate) => path.resolve(process.cwd(), candidate))
  .find(existsSync);

describe('grantTypeEnum — the seed manifest allowlist', () => {
  it('carries the five grants an operator may provision', () => {
    expect([...grantTypeEnum.enumValues].sort()).toEqual(
      [
        'authorization_code',
        'client_credentials',
        'refresh_token',
        // RFC 7523 assertion grant — ID-JAG consumption (ADR-011).
        'urn:ietf:params:oauth:grant-type:jwt-bearer',
        // RFC 8693 on-behalf-of delegation (ADR-007 §2, #381).
        'urn:ietf:params:oauth:grant-type:token-exchange',
      ].sort()
    );
  });

  it('carries the RFC 8693 token-exchange URN the token endpoint gates on (#381)', () => {
    expect(grantTypeEnum.enumValues).toContain('urn:ietf:params:oauth:grant-type:token-exchange');
  });

  /**
   * A pg enum value that exists only in TypeScript is worse than one that is
   * missing from both: the seed validator would accept the manifest and the
   * INSERT would then fail against a database whose type does not carry the
   * label. Assert the migration that widens the type is actually checked in.
   */
  it('every URN value is added to the database type by a checked-in migration', () => {
    // Non-vacuity: if the directory were not found, the loop below would pass
    // by reading nothing at all.
    expect(DRIZZLE_DIR, `no drizzle directory found from cwd ${process.cwd()}`).toBeDefined();
    const sql = readdirSync(DRIZZLE_DIR as string)
      .filter((f) => f.endsWith('.sql'))
      .map((f) => readFileSync(path.join(DRIZZLE_DIR as string, f), 'utf8'))
      .join('\n');

    for (const value of grantTypeEnum.enumValues) {
      if (!value.startsWith('urn:')) continue; // the three originals ship in 0000's CREATE TYPE
      expect(
        sql.includes(`ALTER TYPE "public"."grant_type" ADD VALUE '${value}'`),
        `no migration adds '${value}' to the grant_type database type`
      ).toBe(true);
    }
  });
});
