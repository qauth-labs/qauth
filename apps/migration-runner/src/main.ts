/**
 * The QAuth migration runner (issue #474, ADR-018 §5).
 *
 * Every upgrade ends by running it: it applies the pending database
 * migrations to DATABASE_URL under a Postgres advisory lock, logs each one
 * with its duration and exits 0 once the database is current. A second
 * runner started beside it waits for the lock, then finds nothing to do.
 * `--check` reports the pending migrations and changes nothing.
 *
 * Built by `nx run migration-runner:build` into one file,
 * `dist/apps/migration-runner/main.js`, with the generated migrations in
 * `drizzle/` beside it; the image runs it with Node alone. The exit codes
 * are in `cli.ts` ({@link RUNNER_EXIT}).
 */
import * as path from 'node:path';

import { RUNNER_EXIT, runRunner } from './cli';

// As the image's PID 1, Node ignores a signal it has no handler for, so
// `docker stop` would wait out its grace period. Exit instead: the dropped
// connection rolls the migration transaction back.
for (const [signal, code] of [
  ['SIGINT', 130],
  ['SIGTERM', 143],
] as const) {
  process.on(signal, () => {
    process.stderr.write(`${signal} received: stopping. A migration in progress rolls back.\n`);
    process.exit(code);
  });
}

runRunner(process.argv, process.env, path.join(__dirname, 'drizzle'), {
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
}).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`The migration runner failed: ${String(error)}\n`);
    process.exitCode = RUNNER_EXIT.cannotRun;
  }
);
