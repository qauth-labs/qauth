/**
 * The break-glass CLI (ADR-019 Decisions 7 and 9, issue #602), the way in
 * when no admin can act. Two commands and no other:
 * `enrol-admin` creates an admin account with no password, its grant and a
 * one-time enrolment URL; `retire-key` retires a token-signing key that may
 * be compromised.
 *
 * Run it on a host that holds the database credentials and the KEK, with the
 * server's own environment: `DATABASE_URL` (the owner's role, not one process
 * role's in a split deployment), the KEK (`KEK`, `KEK_PATH` or a key service
 * adapter's settings), and for `retire-key` Redis. It starts only when the
 * KEK opens a stored key, opens no listening port and makes no HTTP call of
 * its own.
 *
 * Run it with `tsx` directly, in an interactive shell, never as an Nx task:
 * Nx keeps every task's terminal output on disk, and `enrol-admin` prints a
 * live token, so it refuses to run under Nx.
 *
 * ```console
 * # From apps/auth-server in a checkout:
 * pnpm exec tsx src/break-glass.ts enrol-admin --realm operator --role security-admin
 * # In the auth-server image, from /app:
 * tsx src/break-glass.ts retire-key --realm <name> --kid <kid> --confirm
 * ```
 *
 * Every run that changes anything is recorded in the realm's admin audit log,
 * with the operating-system user and uid and the host name, and announced as
 * a critical `admin.break_glass_used` event, before the change. The runbook
 * is `operate/break-glass.md` on the docs site.
 */
import { runBreakGlassProcess } from './app/helpers/break-glass-host';
import { describeKeysRetireError } from './app/helpers/keys-retire';

runBreakGlassProcess(process.argv.slice(2), process.env, {
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
}).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`break-glass: ${describeKeysRetireError(error)}\n`);
    process.exitCode = 1;
  }
);
