/**
 * A small in-process cache of promises with a lifetime and a size bound,
 * oldest entry out first. A method holds no cache handle (ADR-019
 * Decision 12), so what it keeps lives in its own process: each node fetches
 * a provider's documents itself, at most once per lifetime.
 *
 * Concurrent readers of a missing entry share one load. A load that rejects
 * is kept for `failureTtlMs` from when it failed, so while a provider is down
 * its readers share one failure instead of each starting a call; with
 * `failureTtlMs` 0 (the default) it is not kept at all.
 */
export class TtlCache<T> {
  readonly #entries = new Map<string, { readonly value: Promise<T>; readonly expiresAt: number }>();

  constructor(
    readonly ttlMs: number,
    readonly maxEntries: number,
    readonly failureTtlMs = 0
  ) {}

  /** The entry for `key`, or a new one from `load`. */
  get(key: string, load: () => Promise<T>): Promise<T> {
    const now = Date.now();
    const found = this.#entries.get(key);
    if (found !== undefined && found.expiresAt > now) return found.value;
    if (found !== undefined) this.#entries.delete(key);
    const value = load();
    this.#entries.set(key, { value, expiresAt: now + this.ttlMs });
    value.catch(() => {
      // Only the failed load itself: a newer entry for the key stays.
      if (this.#entries.get(key)?.value !== value) return;
      if (this.failureTtlMs > 0) {
        this.#entries.set(key, { value, expiresAt: Date.now() + this.failureTtlMs });
      } else {
        this.#entries.delete(key);
      }
    });
    while (this.#entries.size > this.maxEntries) {
      const oldest = this.#entries.keys().next().value as string;
      this.#entries.delete(oldest);
    }
    return value;
  }

  /** Drop the entry for `key`. */
  delete(key: string): void {
    this.#entries.delete(key);
  }

  /** How many entries are kept. */
  get size(): number {
    return this.#entries.size;
  }
}
