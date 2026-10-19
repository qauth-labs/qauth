import type { FastifyInstance } from 'fastify';

/**
 * Work a request answers for but does not wait for.
 *
 * A route whose answer must not depend on account state cannot await work
 * that only some accounts trigger: a minimum response time only pads up, so a
 * mail delivery slower than the floor would show in the response time of the
 * one branch that sends. A task started here runs after the handler has moved
 * on. Its failure is logged and never reaches the caller.
 *
 * Unlike a plain fire-and-forget, every task still running is kept in a set
 * that an `onClose` hook drains. Fastify runs that hook after the HTTP server
 * has closed and the in-flight requests have finished, so a graceful shutdown
 * waits for the mail a request has already answered for instead of dropping
 * it. A task that never settles holds the shutdown, as an awaited send would.
 */
export interface BackgroundTasks {
  /**
   * Start `task` without waiting for it.
   *
   * @param task - The work. It starts on a later microtask, after `run` returns.
   * @param failureMessage - Logged at `error`, with the error, if `task` rejects.
   */
  run(task: () => Promise<unknown>, failureMessage: string): void;
}

/**
 * Create the background-task runner for one route plugin and register the
 * `onClose` hook that waits for its tasks.
 *
 * @param fastify - The (encapsulated) instance the route is registered on.
 */
export function createBackgroundTasks(fastify: FastifyInstance): BackgroundTasks {
  const pending = new Set<Promise<void>>();
  fastify.addHook('onClose', async () => {
    await Promise.allSettled(pending);
  });

  return {
    run(task, failureMessage) {
      const settled: Promise<void> = Promise.resolve()
        .then(task)
        .then(
          () => undefined,
          (error: unknown) => {
            fastify.log.error(error, failureMessage);
          }
        )
        .finally(() => {
          pending.delete(settled);
        });
      pending.add(settled);
    },
  };
}
