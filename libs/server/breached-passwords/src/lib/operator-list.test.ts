import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { passwordSha1 } from './digest';
import { BreachListError } from './errors';
import {
  createReloadableBreachList,
  loadLocalBreachList,
  type LocalBreachList,
  parseLocalBreachList,
} from './operator-list';

const A = passwordSha1('password');
const B = passwordSha1('123456');
const C = passwordSha1('qwerty');
const ABSENT = passwordSha1('a password on no list at all');

/** `digests` in ascending order, as the Have I Been Pwned downloader writes them. */
const ascending = (...digests: string[]) => [...digests].sort();

function expectHolds(list: LocalBreachList, digests: readonly string[]): void {
  for (const digest of digests) {
    expect(list.has(digest), digest).toBe(true);
    expect(list.has(digest.toLowerCase()), digest).toBe(true);
  }
}

let directory: string;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'qauth-breach-list-'));
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

let fileCount = 0;
async function listFile(text: string | Buffer): Promise<string> {
  fileCount += 1;
  const path = join(directory, `list-${fileCount}.txt`);
  await writeFile(path, text);
  return path;
}

describe('parseLocalBreachList: the format', () => {
  it('reads bare digests and HASH:COUNT lines, in either case', () => {
    const list = parseLocalBreachList([A, `${B.toLowerCase()}:24230577`, `${C}:0`].join('\n'));
    expect(list.size).toBe(3);
    expectHolds(list, [A, B, C]);
    expect(list.has(ABSENT)).toBe(false);
  });

  it('skips blank lines and comment lines, and accepts CRLF and a byte order mark', () => {
    const list = parseLocalBreachList(
      [
        '﻿# breached passwords, exported 2026-11-01',
        '',
        A,
        '   ',
        '# another comment',
        `${B}:3`,
        '',
      ].join('\r\n')
    );
    expect(list.size).toBe(2);
    expectHolds(list, [A, B]);
  });

  it('is empty for an empty text or one of comments only', () => {
    expect(parseLocalBreachList('').size).toBe(0);
    expect(parseLocalBreachList('# nothing yet\n').size).toBe(0);
    expect(parseLocalBreachList('').has(A)).toBe(false);
  });

  it('refuses a malformed line, naming its number and never its content', () => {
    const cases: [string, number][] = [
      [`${A}\nhunter2\n${B}`, 2],
      [`${A}\n${B.slice(0, 39)}`, 2],
      [`${A}\r\n\r\n${B}0`, 3],
      [`${A}:`, 1],
      [`${A}:12x`, 1],
      [`${A} :1`, 1],
      [` ${A}`, 1],
      [`${A.slice(0, 39)}G`, 1],
      [`# ok\n${A};1`, 2],
    ];
    for (const [text, lineNumber] of cases) {
      let caught: unknown;
      try {
        parseLocalBreachList(text);
      } catch (error) {
        caught = error;
      }
      expect(caught, text).toBeInstanceOf(BreachListError);
      const error = caught as BreachListError;
      expect(error.lineNumber).toBe(lineNumber);
      expect(error.message).toContain(`line ${lineNumber}`);
      expect(error.message).not.toContain('hunter2');
      expect(error.message).not.toContain(A.slice(0, 20));
      expect(error.message).not.toContain(B.slice(0, 20));
    }
  });

  it('refuses a value that is not a SHA-1 digest when searched', () => {
    const list = parseLocalBreachList(A);
    for (const value of ['password', A.slice(0, 39), `${A}0`, '']) {
      expect(() => list.has(value)).toThrow(TypeError);
    }
  });
});

describe('parseLocalBreachList: order and repeats', () => {
  it('finds every digest of a sorted list, and none in between', () => {
    const digests = ascending(
      ...Array.from({ length: 2000 }, (_, index) => passwordSha1(`sorted-${index}`))
    );
    const list = parseLocalBreachList(digests.join('\n'));
    expect(list.size).toBe(2000);
    expectHolds(list, digests);
    for (let index = 0; index < 200; index += 1) {
      expect(list.has(passwordSha1(`absent-${index}`))).toBe(false);
    }
  });

  it('finds every digest of an unsorted list, past the first buffer', () => {
    // More than the 4096 the first buffer holds, so it grows, in hash order.
    const digests = Array.from({ length: 5000 }, (_, index) => passwordSha1(`unsorted-${index}`));
    const list = parseLocalBreachList(digests.join('\n'));
    expect(list.size).toBe(5000);
    expectHolds(list, digests);
    expect(list.has(ABSENT)).toBe(false);
  });

  it('keeps a repeated digest once, adjacent or not, whatever its case or count', () => {
    const sorted = parseLocalBreachList(
      ascending(A, B, C)
        .flatMap((digest) => [digest, `${digest.toLowerCase()}:2`])
        .join('\n')
    );
    expect(sorted.size).toBe(3);
    expectHolds(sorted, [A, B, C]);

    const unsorted = parseLocalBreachList([C, A, B, A, `${C}:9`, B.toLowerCase()].join('\n'));
    expect(unsorted.size).toBe(3);
    expectHolds(unsorted, [A, B, C]);
  });

  it('finds the first and the last digest of the order', () => {
    const lowest = '0'.repeat(40);
    const highest = 'F'.repeat(40);
    const list = parseLocalBreachList([highest, A, lowest].join('\n'));
    expectHolds(list, [lowest, highest, A]);
    expect(list.has(`${'0'.repeat(39)}1`)).toBe(false);
    expect(list.has(`${'F'.repeat(39)}E`)).toBe(false);
  });
});

describe('loadLocalBreachList', () => {
  it('reads a file as the text parser does, sorted or not', async () => {
    const digests = Array.from({ length: 3000 }, (_, index) => passwordSha1(`file-${index}`));
    const unsorted = await loadLocalBreachList(
      await listFile(`# header\r\n${digests.map((digest) => `${digest}:1`).join('\r\n')}\r\n`)
    );
    expect(unsorted.size).toBe(3000);
    expectHolds(unsorted, digests);

    const sorted = await loadLocalBreachList(await listFile(ascending(...digests).join('\n')));
    expect(sorted.size).toBe(3000);
    expectHolds(sorted, digests);
    expect(sorted.has(ABSENT)).toBe(false);
  });

  it('refuses a malformed line by its number, never its content', async () => {
    const path = await listFile(`${A}\n${B}\nletmein\n${C}\n`);
    await expect(loadLocalBreachList(path)).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof BreachListError &&
        error.lineNumber === 3 &&
        error.message.includes('line 3') &&
        !error.message.includes('letmein')
    );
  });

  it('refuses a file that is missing or not a regular file', async () => {
    await expect(loadLocalBreachList(join(directory, 'missing.txt'))).rejects.toThrow(
      /could not be read \(ENOENT\)/
    );
    await expect(loadLocalBreachList(directory)).rejects.toThrow(BreachListError);
  });
});

describe('createReloadableBreachList', () => {
  it('holds no list until the first reload, then the list it loaded', async () => {
    const path = await listFile([A, B].join('\n'));
    const reloadable = createReloadableBreachList(path);
    expect(reloadable.current()).toBeNull();

    expect(await reloadable.reload()).toEqual({ loaded: true, size: 2 });
    expectHolds(reloadable.current() as LocalBreachList, [A, B]);
  });

  it('replaces the list when the file loads whole', async () => {
    const path = await listFile(A);
    const reloadable = createReloadableBreachList(path);
    await reloadable.reload();

    await writeFile(path, [B, C].join('\n'));
    expect(await reloadable.reload()).toEqual({ loaded: true, size: 2 });
    const list = reloadable.current() as LocalBreachList;
    expect(list.has(A)).toBe(false);
    expectHolds(list, [B, C]);
  });

  it('keeps the list in use when a reload fails, and says why', async () => {
    const path = await listFile([A, B].join('\n'));
    const reloadable = createReloadableBreachList(path);
    await reloadable.reload();
    const before = reloadable.current();

    await writeFile(path, `${C}\nnot a digest\n`);
    const result = await reloadable.reload();
    expect(result.loaded).toBe(false);
    expect(!result.loaded && result.error).toBeInstanceOf(BreachListError);
    expect(reloadable.current()).toBe(before);
    expect(reloadable.current()?.has(C)).toBe(false);

    await rm(path);
    expect((await reloadable.reload()).loaded).toBe(false);
    expect(reloadable.current()).toBe(before);
  });

  it('holds no list while every load has failed', async () => {
    const reloadable = createReloadableBreachList(join(directory, 'never-written.txt'));
    const result = await reloadable.reload();
    expect(result.loaded).toBe(false);
    expect(reloadable.current()).toBeNull();
  });

  it('lets concurrent reloads share one load, and starts a new one after it', async () => {
    const path = await listFile(A);
    const reloadable = createReloadableBreachList(path);

    const first = reloadable.reload();
    const second = reloadable.reload();
    expect(second).toBe(first);
    expect(await Promise.all([first, second])).toEqual([
      { loaded: true, size: 1 },
      { loaded: true, size: 1 },
    ]);

    await writeFile(path, [A, B].join('\n'));
    const third = reloadable.reload();
    expect(third).not.toBe(first);
    expect(await third).toEqual({ loaded: true, size: 2 });
  });
});
