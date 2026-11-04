import { type FileHandle, open } from 'node:fs/promises';
import { createInterface } from 'node:readline';

import { checkedSha1Hex, SHA1_BYTES } from './digest';
import { BreachListError } from './errors';

/**
 * The operator's local breach list (#635): the SHA-1 digests of breached
 * passwords, held as one sorted buffer of 20-byte digests without repeats and
 * searched by binary search. A list of ten million digests takes 200 MB, and
 * no string per digest.
 */
export interface LocalBreachList {
  /**
   * Whether the list holds `sha1Hex`, a SHA-1 digest of 40 hex characters in
   * either case. Compares the digest's 20 bytes.
   *
   * @throws TypeError when `sha1Hex` is not a SHA-1 digest
   */
  has(sha1Hex: string): boolean;
  /** How many distinct digests the list holds. */
  readonly size: number;
}

/**
 * A digest line: 40 hex characters, optionally followed by `:<count>`, the
 * `HASH:COUNT` form the Have I Been Pwned downloader writes.
 */
const DIGEST_LINE = /^[0-9A-Fa-f]{40}(?::[0-9]+)?$/;

/** Digests the first buffer holds; it doubles as the list grows. */
const INITIAL_CAPACITY = 4096;

/** The list over `digests`: sorted 20-byte digests without repeats. */
function sortedDigestList(digests: Buffer): LocalBreachList {
  const size = digests.length / SHA1_BYTES;
  return Object.freeze({
    size,
    has(sha1Hex: string): boolean {
      const target = Buffer.from(checkedSha1Hex(sha1Hex), 'hex');
      let low = 0;
      let high = size - 1;
      while (low <= high) {
        const middle = (low + high) >>> 1;
        const start = middle * SHA1_BYTES;
        // The sign of digests[middle] - target.
        const order = digests.compare(target, 0, SHA1_BYTES, start, start + SHA1_BYTES);
        if (order === 0) return true;
        if (order < 0) low = middle + 1;
        else high = middle - 1;
      }
      return false;
    },
  });
}

/**
 * Collects the digests of a list, line by line, into one growing buffer. It
 * notes whether the lines came in order: the Have I Been Pwned downloader's
 * output does, and is then neither copied into an index nor sorted again.
 */
class DigestCollector {
  #bytes = Buffer.alloc(INITIAL_CAPACITY * SHA1_BYTES);
  #count = 0;
  #sorted = true;

  /**
   * Take line `lineNumber` (1-based). A blank line, or one starting with `#`,
   * is skipped; a malformed one throws a {@link BreachListError} naming its
   * number, never its content.
   */
  add(rawLine: string, lineNumber: number): void {
    let line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
    if (lineNumber === 1 && line.startsWith('﻿')) line = line.slice(1);
    if (line.trim() === '' || line.startsWith('#')) return;
    if (!DIGEST_LINE.test(line)) {
      throw new BreachListError(
        `breach list line ${lineNumber} is not a SHA-1 digest: 40 hex characters, optionally followed by :count`,
        { lineNumber }
      );
    }
    const offset = this.#count * SHA1_BYTES;
    if (offset + SHA1_BYTES > this.#bytes.length) {
      const grown = Buffer.alloc(this.#bytes.length * 2);
      this.#bytes.copy(grown, 0, 0, offset);
      this.#bytes = grown;
    }
    this.#bytes.write(line.slice(0, 40), offset, SHA1_BYTES, 'hex');
    if (this.#count > 0) {
      const previous = offset - SHA1_BYTES;
      // The sign of this digest - the previous one.
      const order = this.#bytes.compare(this.#bytes, previous, offset, offset, offset + SHA1_BYTES);
      // A repeat of the line before is dropped here; other repeats, after the sort.
      if (order === 0) return;
      if (order < 0) this.#sorted = false;
    }
    this.#count += 1;
  }

  /** The list of the digests taken. */
  finish(): LocalBreachList {
    const bytes = this.#bytes;
    const count = this.#count;
    if (this.#sorted) {
      // A copy of the exact size, so the buffer's spare room is freed.
      return sortedDigestList(Buffer.from(bytes.subarray(0, count * SHA1_BYTES)));
    }
    const order = new Uint32Array(count);
    for (let index = 0; index < count; index += 1) order[index] = index;
    order.sort((a, b) =>
      // The sign of digest a - digest b.
      bytes.compare(
        bytes,
        b * SHA1_BYTES,
        (b + 1) * SHA1_BYTES,
        a * SHA1_BYTES,
        (a + 1) * SHA1_BYTES
      )
    );
    const sorted = Buffer.alloc(count * SHA1_BYTES);
    let written = 0;
    for (const index of order) {
      const start = index * SHA1_BYTES;
      if (
        written > 0 &&
        bytes.compare(
          sorted,
          (written - 1) * SHA1_BYTES,
          written * SHA1_BYTES,
          start,
          start + SHA1_BYTES
        ) === 0
      ) {
        continue;
      }
      bytes.copy(sorted, written * SHA1_BYTES, start, start + SHA1_BYTES);
      written += 1;
    }
    return sortedDigestList(
      written === count ? sorted : Buffer.from(sorted.subarray(0, written * SHA1_BYTES))
    );
  }
}

/**
 * Parse a breach list held in memory, in the format {@link loadLocalBreachList}
 * reads. For tests and small lists; a file is read as a stream.
 *
 * @throws BreachListError naming the line number of the first malformed line
 */
export function parseLocalBreachList(text: string): LocalBreachList {
  const collector = new DigestCollector();
  const lines = text.split(/\r\n|\n|\r/);
  for (let index = 0; index < lines.length; index += 1) {
    collector.add(lines[index] ?? '', index + 1);
  }
  return collector.finish();
}

/**
 * Read and parse the operator's breach list file (`BREACHED_PASSWORD_LIST_PATH`,
 * #635), as a stream, line by line, so a list of millions of digests is never
 * held as text.
 *
 * The format: one SHA-1 per line, 40 hex characters in either case,
 * optionally followed by `:<count>` (the Have I Been Pwned downloader's
 * `HASH:COUNT` form, whose count is ignored); blank lines and lines starting
 * with `#` are skipped; CRLF line ends are accepted. Anything else is
 * malformed and fails the whole load. The lines need not be sorted, and
 * repeats are kept once.
 *
 * @throws BreachListError when the file cannot be read, or naming the line
 *   number, never the content, of the first malformed line
 */
export async function loadLocalBreachList(path: string): Promise<LocalBreachList> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, 'r');
    if (!(await handle.stat()).isFile()) {
      throw new BreachListError('the breach list is not a regular file');
    }
  } catch (error) {
    await handle?.close();
    if (error instanceof BreachListError) throw error;
    throw new BreachListError(`the breach list could not be read (${errorCode(error)})`, {
      cause: error,
    });
  }
  const stream = handle.createReadStream({ encoding: 'utf8' });
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  const collector = new DigestCollector();
  let lineNumber = 0;
  try {
    for await (const line of lines) {
      lineNumber += 1;
      collector.add(line, lineNumber);
    }
  } catch (error) {
    if (error instanceof BreachListError) throw error;
    throw new BreachListError(`the breach list could not be read (${errorCode(error)})`, {
      cause: error,
    });
  } finally {
    lines.close();
    stream.destroy();
    await handle.close().catch(() => undefined);
  }
  return collector.finish();
}

/** The `code` of a Node.js system error, such as `ENOENT`, or `unknown error`. */
function errorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : 'unknown error';
}

/** The outcome of {@link ReloadableBreachList.reload}. */
export type BreachListReloadResult =
  | { readonly loaded: true; readonly size: number }
  | { readonly loaded: false; readonly error: Error };

/** The local list of a deployment, which the operator can replace without a restart. */
export interface ReloadableBreachList {
  /** The list in use, or `null` while none has loaded. */
  current(): LocalBreachList | null;
  /**
   * Load the file again. The new list replaces the one in use only when it
   * loaded whole; a load that fails keeps the list in use (or none, before
   * the first success) and says why. Never rejects.
   *
   * Calls made while a load runs share that load and its result, so a burst
   * of changes to the file reads it once.
   */
  reload(): Promise<BreachListReloadResult>;
}

/**
 * The reloadable local list at `path`. Nothing is read until the first
 * {@link ReloadableBreachList.reload}: the auth server calls it at boot, and
 * again when the file changes.
 */
export function createReloadableBreachList(path: string): ReloadableBreachList {
  let list: LocalBreachList | null = null;
  let loading: Promise<BreachListReloadResult> | null = null;

  const load = async (): Promise<BreachListReloadResult> => {
    try {
      const next = await loadLocalBreachList(path);
      list = next;
      return { loaded: true, size: next.size };
    } catch (error) {
      return {
        loaded: false,
        error: error instanceof Error ? error : new BreachListError('the breach list did not load'),
      };
    } finally {
      loading = null;
    }
  };

  return Object.freeze({
    current: () => list,
    reload(): Promise<BreachListReloadResult> {
      loading ??= load();
      return loading;
    },
  });
}
