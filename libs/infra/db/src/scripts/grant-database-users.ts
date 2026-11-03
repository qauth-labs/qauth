/**
 * Give each service role's database user exactly the grants of its roles
 * (issue #498, ADR-019 Decisions 8 and 9). Idempotent: a second run gives the
 * same grants.
 *
 * Usage (from the repo root), as the owner of the tables:
 *
 *   DATABASE_URL=postgresql://qauth_owner:pw@host:5432/qauth \
 *   DB_USER_WEB=qauth_web DB_USER_API=qauth_api DB_USER_ADMIN=qauth_admin \
 *   DB_USER_SIGNER=qauth_signer DB_USER_DELIVERY=qauth_delivery \
 *     pnpm nx run infra-db:db:grants -- [--check | --print]
 *
 * QAuth creates no database user and sets no password: the operator creates
 * the users first. With none of the DB_USER_* variables set it does nothing.
 * The migration runner applies the same grants after its migrations when the
 * variables are set on it.
 *
 * It exits 0 when the grants are applied or current, 1 when they were
 * refused or, with --check, differ, 2 on a usage error and 3 when it could
 * not run ({@link DATABASE_USER_GRANTS_EXIT}). Nx turns every non-zero exit
 * into 1, so a script that tells them apart runs
 * `pnpm --dir libs/infra/db exec tsx src/scripts/grant-database-users.ts`.
 */
import * as dotenv from 'dotenv';

import { DATABASE_USER_GRANTS_EXIT, runDatabaseUserGrants } from './database-user-grants';

dotenv.config({ path: '../../../.env' });

runDatabaseUserGrants(process.argv, process.env, {
  out: (line) => console.log(line),
  err: (line) => console.error(line),
}).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    console.error(
      `The grants could not be applied: ${error instanceof Error ? error.message : String(error)}`
    );
    process.exitCode = DATABASE_USER_GRANTS_EXIT.cannotRun;
  }
);
