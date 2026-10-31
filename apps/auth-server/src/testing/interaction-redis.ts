import { vi } from 'vitest';

/**
 * The Redis commands the interaction store (`helpers/interaction-record.ts`,
 * #592) sends, held in memory for unit tests: strings with an absolute
 * `PXAT` deadline, `GETDEL`, and the sorted set of the expiry index (`ZADD`
 * with its `NX` and `XX` flags).
 *
 * `base` lends its commands to the same object, so a test can add the
 * browser-session commands (`createMemorySessionRedis`) that authentication
 * sends; `multi()` queues any command of the combined object and runs the
 * queue in order on `exec()`, as Redis does, one result per command.
 *
 * Deadlines are read against `Date.now()`, so `vi.setSystemTime` moves them.
 * Each command awaits a microtask first, so two concurrent callers interleave
 * as two clients of a real server would.
 */
export interface MemoryInteractionRedis {
  readonly strings: Map<string, { value: string; deadline?: number }>;
  readonly sortedSets: Map<string, Map<string, number>>;
  /**
   * Run once, just before the next `GETDEL` of a key that `match` accepts:
   * another client's commands, landing between a request's read and its take.
   */
  beforeNextGetdel(match: (key: string) => boolean, action: () => Promise<void>): void;
  get(key: string): Promise<string | null>;
  getdel(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: (string | number)[]): Promise<'OK' | null>;
  del(...keys: string[]): Promise<number>;
  zadd(key: string, ...args: (string | number)[]): Promise<number>;
  zrem(key: string, member: string): Promise<number>;
  zrangebyscore(
    key: string,
    min: string | number,
    max: string | number,
    ...args: (string | number)[]
  ): Promise<string[]>;
  multi(): Record<string, (...args: unknown[]) => unknown> & {
    exec(): Promise<[Error | null, unknown][]>;
  };
}

/** Create a {@link MemoryInteractionRedis}, with `base`'s commands beside its own. */
export function createMemoryInteractionRedis<Base extends object>(
  base: Base = {} as Base
): MemoryInteractionRedis & Base {
  const strings = new Map<string, { value: string; deadline?: number }>();
  const sortedSets = new Map<string, Map<string, number>>();
  const tick = () => Promise.resolve();

  /** The live value of `key`, dropping it once its deadline has passed. */
  function live(key: string): string | null {
    const entry = strings.get(key);
    if (entry === undefined) return null;
    if (entry.deadline !== undefined && entry.deadline <= Date.now()) {
      strings.delete(key);
      return null;
    }
    return entry.value;
  }

  function bound(value: string | number, inclusive = true): (score: number) => boolean {
    if (value === '-inf') return () => true;
    if (value === '+inf') return () => true;
    const limit = Number(value);
    return inclusive ? (score) => score <= limit : (score) => score < limit;
  }

  const hooks: { match: (key: string) => boolean; action: () => Promise<void> }[] = [];

  const own = {
    strings,
    sortedSets,
    get: vi.fn(async (key: string) => {
      await tick();
      return live(key);
    }),
    beforeNextGetdel(match: (key: string) => boolean, action: () => Promise<void>) {
      hooks.push({ match, action });
    },
    getdel: vi.fn(async (key: string) => {
      await tick();
      const hook = hooks.findIndex((candidate) => candidate.match(key));
      if (hook !== -1) await hooks.splice(hook, 1)[0].action();
      const value = live(key);
      strings.delete(key);
      return value;
    }),
    set: vi.fn(async (key: string, value: string, ...args: (string | number)[]) => {
      await tick();
      const upper = args.map((arg) => (typeof arg === 'string' ? arg.toUpperCase() : arg));
      if (upper.includes('NX') && live(key) !== null) return null;
      if (upper.includes('XX') && live(key) === null) return null;
      const at = upper.indexOf('PXAT');
      const deadline = at === -1 ? undefined : Number(upper[at + 1]);
      if (deadline !== undefined && deadline <= Date.now()) {
        strings.delete(key);
        return 'OK' as const;
      }
      strings.set(key, { value, ...(deadline === undefined ? {} : { deadline }) });
      return 'OK' as const;
    }),
    del: vi.fn(async (...keys: string[]) => {
      await tick();
      let removed = 0;
      for (const key of keys) {
        if (strings.delete(key) || sortedSets.delete(key)) removed += 1;
      }
      return removed;
    }),
    zadd: vi.fn(async (key: string, ...args: (string | number)[]) => {
      await tick();
      const flags = new Set<string>();
      while (typeof args[0] === 'string' && /^(NX|XX)$/i.test(args[0])) {
        flags.add(String(args.shift()).toUpperCase());
      }
      const [score, member] = [Number(args[0]), String(args[1])];
      const set = sortedSets.get(key) ?? new Map<string, number>();
      const present = set.has(member);
      if ((flags.has('NX') && present) || (flags.has('XX') && !present)) return 0;
      set.set(member, score);
      sortedSets.set(key, set);
      return present ? 0 : 1;
    }),
    zrem: vi.fn(async (key: string, member: string) => {
      await tick();
      const set = sortedSets.get(key);
      if (set === undefined || !set.delete(member)) return 0;
      if (set.size === 0) sortedSets.delete(key);
      return 1;
    }),
    zrangebyscore: vi.fn(
      async (
        key: string,
        min: string | number,
        max: string | number,
        ...args: (string | number)[]
      ) => {
        await tick();
        const above = min === '-inf' ? () => true : (score: number) => score >= Number(min);
        const below = bound(max);
        const upper = args.map((arg) => (typeof arg === 'string' ? arg.toUpperCase() : arg));
        const withScores = upper.includes('WITHSCORES');
        const at = upper.indexOf('LIMIT');
        const offset = at === -1 ? 0 : Number(upper[at + 1]);
        const count = at === -1 ? Infinity : Number(upper[at + 2]);
        const sorted = [...(sortedSets.get(key) ?? new Map<string, number>()).entries()]
          .filter(([, score]) => above(score) && below(score))
          .sort(([a, x], [b, y]) => x - y || a.localeCompare(b))
          .slice(offset, offset + count);
        return sorted.flatMap(([member, score]) =>
          withScores ? [member, String(score)] : [member]
        );
      }
    ),
  };

  const combined = Object.assign(base, own) as unknown as MemoryInteractionRedis &
    Base &
    Record<string, (...args: unknown[]) => Promise<unknown>>;
  combined.multi = () => {
    const queue: [string, unknown[]][] = [];
    const block = new Proxy({} as Record<string, unknown>, {
      get(_target, name) {
        if (name === 'exec') {
          return async () => {
            const results: [Error | null, unknown][] = [];
            for (const [command, args] of queue) {
              try {
                results.push([null, await combined[command](...args)]);
              } catch (error) {
                results.push([error as Error, null]);
              }
            }
            return results;
          };
        }
        return (...args: unknown[]) => {
          queue.push([String(name), args]);
          return block;
        };
      },
    });
    return block as ReturnType<MemoryInteractionRedis['multi']>;
  };
  return combined;
}
