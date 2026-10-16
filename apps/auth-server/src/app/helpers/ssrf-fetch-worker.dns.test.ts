import { beforeEach, describe, expect, it, vi } from 'vitest';

/*
 * How a fetch worker resolves the host it is asked to fetch. Both resolvers
 * are replaced here, so these tests say which one runs and what it is given;
 * `guardedGet` is called on the test's own thread.
 */

const { lookup, resolve4, resolve6, cancel, resolverOptions } = vi.hoisted(() => ({
  lookup: vi.fn(),
  resolve4: vi.fn(),
  resolve6: vi.fn(),
  cancel: vi.fn(),
  resolverOptions: [] as unknown[],
}));

vi.mock('node:dns', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:dns')>()),
  lookup,
}));

vi.mock('node:dns/promises', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:dns/promises')>()),
  Resolver: class {
    resolve4 = resolve4;
    resolve6 = resolve6;
    cancel = cancel;
    constructor(options?: unknown) {
      resolverOptions.push(options);
    }
  },
}));

import { guardedGet } from './ssrf-fetch-worker';

const errno = (code: string) => Object.assign(new Error(`query ${code}`), { code });
const never = () => new Promise<never>(() => undefined);

const get = (url: string, allowPrivateAddresses = false) =>
  guardedGet({ url, timeoutMs: 300, maxBytes: 4096, allowPrivateAddresses });

beforeEach(() => {
  vi.clearAllMocks();
  resolverOptions.length = 0;
});

// Regression (ANT-2026-MY1V8XOQ): the host was resolved with dns.lookup(), a
// blocking getaddrinfo(3) on the libuv thread pool, which the process shares
// and runs only a few of at a time. Nothing could cancel one, so names whose
// name server never answers held those threads long after their fetches had
// timed out, and every other lookup in the process queued behind them.
describe('guardedGet — name resolution', () => {
  it('resolves a caller-named host with c-ares, never with getaddrinfo', async () => {
    resolve4.mockResolvedValue(['127.0.0.1']);
    resolve6.mockRejectedValue(errno('ENODATA'));

    await expect(get('https://internal.example/cimd.json')).resolves.toEqual({
      kind: 'blocked',
      message: 'CIMD host resolves to a non-public address (127.0.0.1)',
    });
    expect(resolve4).toHaveBeenCalledWith('internal.example');
    expect(resolve6).toHaveBeenCalledWith('internal.example');
    expect(lookup).not.toHaveBeenCalled();
  });

  it('gives each query a timeout of its own, within the fetch deadline', async () => {
    resolve4.mockRejectedValue(errno('ENOTFOUND'));
    resolve6.mockRejectedValue(errno('ENOTFOUND'));

    await get('https://nowhere.example/cimd.json');

    expect(resolverOptions).toHaveLength(1);
    const options = resolverOptions[0] as { timeout: number; tries: number };
    expect(options.timeout).toBeGreaterThan(0);
    expect(options.timeout).toBeLessThanOrEqual(300);
    expect(options.tries).toBeGreaterThan(0);
  });

  it('drops the queries of a silent name server when the deadline passes', async () => {
    resolve4.mockImplementation(never);
    resolve6.mockImplementation(never);

    const started = performance.now();
    await expect(get('https://silent.example/cimd.json')).resolves.toEqual({
      kind: 'failed',
      message: 'CIMD fetch timed out',
    });
    expect(performance.now() - started).toBeLessThan(1000);
    expect(cancel).toHaveBeenCalled();
    expect(lookup).not.toHaveBeenCalled();
  });

  it('refuses a name when any of its A/AAAA records is non-public', async () => {
    resolve4.mockResolvedValue(['203.0.113.10']);
    resolve6.mockResolvedValue(['::1']);

    await expect(get('https://rebind.example/cimd.json')).resolves.toMatchObject({
      kind: 'blocked',
    });
  });

  it('reports a name that does not resolve as a failure, not as blocked', async () => {
    resolve4.mockRejectedValue(errno('ENOTFOUND'));
    resolve6.mockRejectedValue(errno('ENOTFOUND'));

    await expect(get('https://nowhere.example/cimd.json')).resolves.toMatchObject({
      kind: 'failed',
    });
  });

  it('keeps getaddrinfo for local fixtures, which /etc/hosts may name', async () => {
    lookup.mockImplementation(
      (_hostname: string, _options: unknown, callback: (err: Error) => void) =>
        callback(errno('ENOTFOUND'))
    );

    await expect(get('https://fixture.test/cimd.json', true)).resolves.toMatchObject({
      kind: 'failed',
    });
    expect(lookup).toHaveBeenCalledWith('fixture.test', { all: true }, expect.any(Function));
    expect(resolve4).not.toHaveBeenCalled();
  });
});
