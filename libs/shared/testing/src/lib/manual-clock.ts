/**
 * The clock shape QAuth's background workers take: the job runner's
 * `JobClock` and the delivery role's `DeliveryClock`.
 */
export interface TestClock {
  /** Epoch milliseconds. */
  now(): number;
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(timer: unknown): void;
}

/**
 * TEST SUPPORT — a {@link TestClock} whose time moves only when a test moves it.
 *
 * Timers fire in due order while time advances, and the queue is drained
 * between them (`setImmediate`), so the async work a timer starts can run and
 * arm the next timer before time moves on. Work that waits on real I/O, such as
 * a query against a test container, is not waited for: a test waits for its
 * effect itself (`vi.waitFor`), since only it knows what to wait for.
 */
export interface ManualClock extends TestClock {
  /** Move time to `time`, firing every timer due on the way, in order. */
  advanceTo(time: number): Promise<void>;
  /** Move time forward by `ms`. */
  advanceBy(ms: number): Promise<void>;
  /** The due times of the timers that have not fired, earliest first. */
  pending(): number[];
}

interface ManualTimer {
  readonly id: number;
  readonly due: number;
  readonly callback: () => void;
}

/** Let queued microtasks and immediates run. */
function drain(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/** A manual clock starting at `start` epoch milliseconds. */
export function createManualClock(start = 0): ManualClock {
  let time = start;
  let nextId = 1;
  const timers = new Map<number, ManualTimer>();

  function earliestDue(limit: number): ManualTimer | undefined {
    let earliest: ManualTimer | undefined;
    for (const timer of timers.values()) {
      if (timer.due > limit) continue;
      if (
        earliest === undefined ||
        timer.due < earliest.due ||
        (timer.due === earliest.due && timer.id < earliest.id)
      ) {
        earliest = timer;
      }
    }
    return earliest;
  }

  const clock: ManualClock = {
    now: () => time,

    setTimeout(callback: () => void, delayMs: number): unknown {
      const id = nextId++;
      timers.set(id, { id, due: time + Math.max(0, delayMs), callback });
      return id;
    },

    clearTimeout(timer: unknown): void {
      if (typeof timer === 'number') timers.delete(timer);
    },

    async advanceTo(target: number): Promise<void> {
      if (target < time) throw new Error(`Cannot move the clock back from ${time} to ${target}`);
      await drain();
      for (let timer = earliestDue(target); timer; timer = earliestDue(target)) {
        timers.delete(timer.id);
        time = Math.max(time, timer.due);
        timer.callback();
        await drain();
      }
      time = target;
      await drain();
    },

    advanceBy(ms: number): Promise<void> {
      return clock.advanceTo(time + ms);
    },

    pending(): number[] {
      return [...timers.values()].map((timer) => timer.due).sort((a, b) => a - b);
    },
  };
  return clock;
}
