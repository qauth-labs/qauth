import type { FastifyInstance } from 'fastify';

/**
 * CLOSING THE APP'S FURTHER LISTENERS TOGETHER (#496, #511).
 *
 * The admin listener and the internal listener each wait for their calls in
 * flight when the app closes, up to a grace period under the 10 s Fastify
 * gives a `preClose` hook. Two such hooks would run one after the other, so
 * a process with both listeners could take the sum of the two to stop. One
 * `preClose` hook per app closes them all at once instead: the slowest bounds
 * the whole.
 */

/** The closes each app runs in its one `preClose` hook. */
const closesByApp = new WeakMap<FastifyInstance, Array<() => Promise<void>>>();

/**
 * Close a further listener of `app` when `app` begins to close, before its
 * database and cache close, at the same time as every other listener closed
 * this way. The first error, if any, is thrown once every close has settled.
 */
export function closeWithApp(app: FastifyInstance, close: () => Promise<void>): void {
  const known = closesByApp.get(app);
  if (known !== undefined) {
    known.push(close);
    return;
  }
  const closes = [close];
  closesByApp.set(app, closes);
  app.addHook('preClose', async () => {
    const outcomes = await Promise.allSettled(closes.map(async (run) => run()));
    const failed = outcomes.find((outcome) => outcome.status === 'rejected');
    if (failed !== undefined) throw failed.reason;
  });
}
