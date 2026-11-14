/**
 * READINESS CHECKS (ADR-019 Decision 8, issue #500).
 *
 * `GET /ready` answers whether this process can serve what its roles need:
 * each role registers the checks of what it depends on, and the route runs
 * them all. `GET /health` is liveness and runs none.
 *
 * - Every process: `database`, Postgres reachable.
 * - `web`, `api` and `admin`: `redis`, which still holds the rate limits and
 *   the single-use stores.
 * - `signer`: `kek`, the KEK unwraps a stored key.
 * - `delivery`: `outbox`, the event outbox is readable.
 * - A later issue registers the configuration digest (#499). The signer
 *   service is not a check of a process with a remote signer (#497): such a
 *   process stays ready while the signer is down, so its JWKS, token
 *   verification, userinfo and introspection keep serving, and what signs
 *   answers 503.
 *
 * A check is a promise that resolves when the dependency answers and rejects
 * when it does not. Its result is `ok`, or `fail` with a reason from a closed
 * set, `error` or `timeout`: the answer is served on any host, to any caller,
 * so it names the check and never the error. The error goes to the log, once
 * when a check starts failing, with its name and message.
 *
 * Any caller can ask, so a check runs at most once at a time: requests join
 * the run in flight, and one that stops waiting at its timeout leaves the run
 * going. A new run starts only once that one settled, so a dependency that
 * stalls holds one run of each check, never one per request.
 */

/** A check's name: lower case, as `/ready` reports it. */
export const READINESS_CHECK_NAME = /^[a-z][a-z0-9_]{0,31}$/;

/**
 * How long a check may take before it counts as failed. `/ready` answers
 * within it, whatever a dependency does: a probe's own timeout should be
 * longer.
 */
export const DEFAULT_READINESS_CHECK_TIMEOUT_MS = 2_000;

/** Why a check failed: it rejected, or it did not settle in time. */
export type ReadinessFailure = 'error' | 'timeout';

/** One check's result, as `/ready` reports it. */
export type ReadinessCheckResult =
  | { readonly status: 'ok' }
  | { readonly status: 'fail'; readonly reason: ReadinessFailure };

/** A check a role registers. */
export interface ReadinessCheck {
  /** Its name in the answer, such as `database`; see {@link READINESS_CHECK_NAME}. */
  readonly name: string;
  /** Resolves when the dependency answers; rejects when it does not. */
  readonly run: () => Promise<unknown>;
  /** How long it may take; {@link DEFAULT_READINESS_CHECK_TIMEOUT_MS} when unset. */
  readonly timeoutMs?: number;
  /**
   * How long a success stands before the check runs again, for a check that
   * costs a call to a paid or rate-limited service, such as a KMS.
   */
  readonly reuseSuccessMs?: number;
  /**
   * How long a failure stands before the check runs again, for the same
   * kind of check: a dependency that refuses at once would otherwise take a
   * call per request. Unset, a failure is not reused.
   */
  readonly reuseFailureMs?: number;
}

/** What `/ready` reports: whether every check passed, and each one's result. */
export interface ReadinessReport {
  readonly ready: boolean;
  /** Each check's result, in the order the checks were registered. */
  readonly checks: Readonly<Record<string, ReadinessCheckResult>>;
}

/** The registry of a process's readiness checks: `fastify.readiness`. */
export interface ReadinessRegistry {
  /**
   * Add a check.
   *
   * @throws Error for a name that {@link READINESS_CHECK_NAME} refuses, or one
   *   already registered
   */
  register(check: ReadinessCheck): void;
  /** The names of the registered checks, in registration order. */
  names(): readonly string[];
  /** Run every check, at once, each bounded by its timeout. */
  run(): Promise<ReadinessReport>;
}

/** Where the registry logs a check that starts failing, and one that recovers. */
export interface ReadinessLog {
  warn(details: Record<string, unknown>, message: string): void;
  info(details: Record<string, unknown>, message: string): void;
}

/** Options for {@link createReadinessRegistry}. */
export interface ReadinessRegistryOptions {
  readonly log?: ReadinessLog;
  /** The clock, for a test. */
  readonly now?: () => number;
}

/** What the registry keeps of one check between runs. */
interface CheckState {
  readonly check: ReadinessCheck;
  /**
   * The run in flight until it settles, whoever stopped waiting for it: a
   * request joins it rather than starting another. It never rejects.
   */
  running: Promise<ReadinessCheckResult> | undefined;
  /** The last run's result while it may be reused, and until when. */
  reused: { readonly result: ReadinessCheckResult; readonly until: number } | undefined;
  /** The last result reported, to log a change of state once. */
  last: ReadinessCheckResult['status'] | undefined;
}

const OK: ReadinessCheckResult = Object.freeze({ status: 'ok' });
const FAILED: ReadinessCheckResult = Object.freeze({ status: 'fail', reason: 'error' });
const TIMED_OUT: ReadinessCheckResult = Object.freeze({ status: 'fail', reason: 'timeout' });

class ReadinessTimeout extends Error {
  constructor(timeoutMs: number) {
    super(`did not answer within ${timeoutMs} ms`);
    this.name = 'ReadinessTimeout';
  }
}

/** `promise`, or a {@link ReadinessTimeout} after `timeoutMs`; the timer never holds the process. */
async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new ReadinessTimeout(timeoutMs)), timeoutMs);
    timer.unref();
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** A short, bounded description of what a check threw, for the log. */
function describeError(error: unknown): { name: string; message: string } {
  if (error instanceof Error) {
    return { name: error.name, message: error.message.slice(0, 512) };
  }
  return { name: typeof error, message: String(error).slice(0, 512) };
}

/** Build an empty readiness registry. */
export function createReadinessRegistry(options: ReadinessRegistryOptions = {}): ReadinessRegistry {
  const now = options.now ?? Date.now;
  const states = new Map<string, CheckState>();

  /** Log a change of state once: the first failure, with its error, and the recovery. */
  function report(state: CheckState, result: ReadinessCheckResult, error?: unknown): void {
    const { name } = state.check;
    if (result.status === 'ok') {
      if (state.last === 'fail') {
        options.log?.info({ check: name }, 'A readiness check passes again');
      }
    } else if (state.last !== 'fail') {
      options.log?.warn(
        { check: name, reason: result.reason, err: describeError(error) },
        'A readiness check fails: GET /ready answers 503 until it passes'
      );
    }
    state.last = result.status;
  }

  /** Start a run of the check; it settles with the check, however long that takes. */
  function start(state: CheckState): Promise<ReadinessCheckResult> {
    const { check } = state;
    // A check that throws before it returns a promise fails like one that rejects.
    return Promise.resolve()
      .then(check.run)
      .then(
        () => ({ result: OK, error: undefined }),
        (error: unknown) => ({ result: FAILED, error })
      )
      .then(({ result, error }) => {
        state.running = undefined;
        const reuseMs = result.status === 'ok' ? check.reuseSuccessMs : check.reuseFailureMs;
        state.reused =
          reuseMs !== undefined && reuseMs > 0 ? { result, until: now() + reuseMs } : undefined;
        report(state, result, error);
        return result;
      });
  }

  async function result(state: CheckState): Promise<ReadinessCheckResult> {
    if (state.reused !== undefined && now() < state.reused.until) return state.reused.result;
    const run = (state.running ??= start(state));
    const timeoutMs = state.check.timeoutMs ?? DEFAULT_READINESS_CHECK_TIMEOUT_MS;
    try {
      return await withTimeout(run, timeoutMs);
    } catch (error) {
      // Only the timeout rejects: the run goes on, and the next request joins it.
      report(state, TIMED_OUT, error);
      return TIMED_OUT;
    }
  }

  return Object.freeze({
    register(check: ReadinessCheck): void {
      if (!READINESS_CHECK_NAME.test(check.name)) {
        throw new Error(
          `A readiness check's name is lower case letters, digits and underscores, 1 to 32 characters, starting with a letter: ${JSON.stringify(check.name)}`
        );
      }
      if (states.has(check.name)) {
        throw new Error(`The readiness check ${check.name} is already registered`);
      }
      states.set(check.name, { check, running: undefined, reused: undefined, last: undefined });
    },

    names(): readonly string[] {
      return [...states.keys()];
    },

    async run(): Promise<ReadinessReport> {
      const entries = [...states.values()];
      const results = await Promise.all(entries.map(result));
      const checks: Record<string, ReadinessCheckResult> = {};
      entries.forEach((state, index) => {
        checks[state.check.name] = results[index] as ReadinessCheckResult;
      });
      return {
        ready: results.every((entry) => entry.status === 'ok'),
        checks,
      };
    },
  });
}
