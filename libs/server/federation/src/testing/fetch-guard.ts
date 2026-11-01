import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * The contract test kit's guard on `fetch` (#599): while the kit runs a
 * method, the global `fetch` refuses and counts every call, so a method that
 * calls `fetch` instead of `context.egress` fails the kit. It never sends
 * anything. It sees only the global `fetch`: a method that imports
 * `node:https` or `undici`, or kept a `fetch` from before the run, gets past
 * it, and the `qauth/no-direct-network` lint rule is what refuses those in
 * QAuth's own code.
 *
 * It lives under `src/testing/`, test support, because it replaces a global
 * that server code must not touch (`qauth/no-direct-network`).
 *
 * @experimental
 */

/**
 * A disabled `fetch`, and the way back.
 *
 * @experimental
 */
export interface FetchGuard {
  /** Run `work` as this guard's run: the `fetch` calls it makes count here. */
  run<T>(work: () => Promise<T>): Promise<T>;
  /** How many times `fetch` was called by this guard's run. */
  calls(): number;
  /** Lower this guard. The original `fetch` comes back with the last guard. */
  restore(): void;
}

/** The run a `fetch` call belongs to, across its awaits. */
const runs = new AsyncLocalStorage<{ count: number }>();
/** The guards up now, and the `fetch` the first one replaced. */
let active = 0;
let saved: { readonly fetch: typeof fetch } | undefined;
const counters = new Set<{ count: number }>();

/**
 * Replace the global `fetch` with one that refuses and counts every call.
 * Guards nest, and overlapping runs each count only their own calls: a call
 * is counted against the run it was made in, or, when it belongs to none,
 * against every run that is up. The original `fetch` comes back when the
 * last guard is lowered.
 *
 * @experimental
 */
export function disableFetch(): FetchGuard {
  if (active === 0) {
    saved = { fetch: globalThis.fetch };
    globalThis.fetch = (() => {
      const current = runs.getStore();
      if (current !== undefined) current.count += 1;
      else for (const counter of counters) counter.count += 1;
      return Promise.reject(new Error('fetch is disabled: send through context.egress'));
    }) as typeof fetch;
  }
  active += 1;
  const counter = { count: 0 };
  counters.add(counter);
  let lowered = false;
  return {
    run: (work) => runs.run(counter, work),
    calls: () => counter.count,
    restore: () => {
      if (lowered) return;
      lowered = true;
      counters.delete(counter);
      active -= 1;
      if (active === 0 && saved !== undefined) {
        globalThis.fetch = saved.fetch;
        saved = undefined;
      }
    },
  };
}
