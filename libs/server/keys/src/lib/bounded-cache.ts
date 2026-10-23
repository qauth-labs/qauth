/**
 * A map with a size limit that drops its least recently used entry first.
 * Internal to the in-process signer.
 */
export class BoundedCache<K, V> {
  readonly #limit: number;
  readonly #entries = new Map<K, V>();
  readonly #onEvict: ((value: V) => void) | undefined;

  /**
   * @param limit - the most entries held at once; at least 1
   * @param onEvict - called with each entry the limit pushes out
   */
  constructor(limit: number, onEvict?: (value: V) => void) {
    if (!Number.isSafeInteger(limit) || limit < 1) {
      throw new RangeError('A cache limit is a positive integer');
    }
    this.#limit = limit;
    this.#onEvict = onEvict;
  }

  get size(): number {
    return this.#entries.size;
  }

  /** The entry for `key`, which becomes the most recently used. */
  get(key: K): V | undefined {
    if (!this.#entries.has(key)) return undefined;
    const value = this.#entries.get(key) as V;
    this.#entries.delete(key);
    this.#entries.set(key, value);
    return value;
  }

  /** Drop the entry for `key`, without calling `onEvict`. */
  delete(key: K): void {
    this.#entries.delete(key);
  }

  /** Store `value` as the most recently used entry, evicting the oldest past the limit. */
  set(key: K, value: V): void {
    this.#entries.delete(key);
    this.#entries.set(key, value);
    while (this.#entries.size > this.#limit) {
      const [oldestKey, oldest] = this.#entries.entries().next().value as [K, V];
      this.#entries.delete(oldestKey);
      this.#onEvict?.(oldest);
    }
  }
}
