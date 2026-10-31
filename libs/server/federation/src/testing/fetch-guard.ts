/**
 * The contract test kit's guard on `fetch` (#599): while the kit runs a
 * method, the global `fetch` refuses and counts every call, so a method that
 * goes around `context.egress` fails the kit. It never sends anything.
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
  /** How many times the method called `fetch` since the guard went up. */
  calls(): number;
  /** Put the original `fetch` back. */
  restore(): void;
}

/**
 * Replace the global `fetch` with one that refuses and counts every call.
 *
 * @experimental
 */
export function disableFetch(): FetchGuard {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (() => {
    calls += 1;
    return Promise.reject(new Error('fetch is disabled: send through context.egress'));
  }) as typeof fetch;
  return {
    calls: () => calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}
