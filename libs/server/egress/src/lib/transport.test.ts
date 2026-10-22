import { type AddressInfo, createServer, type Server, type Socket } from 'node:net';

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

/*
 * The two network edges the client uses outside tests, which the client tests
 * replace: name resolution and dialling.
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

import { dialPinned, resolveWithCares } from './transport';

const errno = (code: string) => Object.assign(new Error(`query ${code}`), { code });

beforeEach(() => {
  vi.clearAllMocks();
  resolverOptions.length = 0;
});

describe('resolveWithCares', () => {
  const resolve = (hostname: string, timeoutMs = 300, signal = new AbortController().signal) =>
    resolveWithCares(hostname, { timeoutMs, signal });

  it('returns every A and AAAA record, from c-ares and never from getaddrinfo', async () => {
    resolve4.mockResolvedValue(['93.184.215.14', '93.184.215.15']);
    resolve6.mockResolvedValue(['2606:2800:21f:cb07:6820:80da:af6b:8b2c']);

    await expect(resolve('example.com')).resolves.toEqual([
      { address: '93.184.215.14', family: 4 },
      { address: '93.184.215.15', family: 4 },
      { address: '2606:2800:21f:cb07:6820:80da:af6b:8b2c', family: 6 },
    ]);
    expect(resolve4).toHaveBeenCalledWith('example.com');
    expect(resolve6).toHaveBeenCalledWith('example.com');
    expect(lookup).not.toHaveBeenCalled();
  });

  it('accepts a host with one family only', async () => {
    resolve4.mockResolvedValue(['93.184.215.14']);
    resolve6.mockRejectedValue(errno('ENODATA'));
    await expect(resolve('v4only.example')).resolves.toEqual([
      { address: '93.184.215.14', family: 4 },
    ]);

    resolve4.mockRejectedValue(errno('ENODATA'));
    resolve6.mockResolvedValue(['2606:4700:4700::1111']);
    await expect(resolve('v6only.example')).resolves.toEqual([
      { address: '2606:4700:4700::1111', family: 6 },
    ]);
  });

  it('rejects when neither family answers', async () => {
    resolve4.mockRejectedValue(errno('ENOTFOUND'));
    resolve6.mockRejectedValue(errno('ENOTFOUND'));
    await expect(resolve('nowhere.example')).rejects.toMatchObject({ code: 'ENOTFOUND' });
  });

  it('gives each query a timeout of its own, within the call', async () => {
    resolve4.mockResolvedValue([]);
    resolve6.mockResolvedValue([]);
    await resolve('example.com', 300);
    expect(resolverOptions).toEqual([{ timeout: 300, tries: expect.any(Number) }]);

    await resolve('example.com', 60_000);
    expect((resolverOptions[1] as { timeout: number }).timeout).toBeLessThanOrEqual(2000);
  });

  it('cancels its queries when the call is aborted', async () => {
    const pending = new Promise<never>(() => undefined);
    resolve4.mockReturnValue(pending);
    resolve6.mockReturnValue(pending);
    const controller = new AbortController();
    void resolve('silent.example', 300, controller.signal);
    controller.abort();
    expect(cancel).toHaveBeenCalledTimes(1);
  });
});

describe('dialPinned', () => {
  let server: Server;
  let port: number;
  const accepted: Socket[] = [];

  beforeAll(async () => {
    server = createServer((socket) => {
      accepted.push(socket);
      socket.resume();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    for (const socket of accepted) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const connected = (socket: Socket): Promise<string | undefined> =>
    new Promise((resolve, reject) => {
      socket.once('connect', () => {
        const address = socket.remoteAddress;
        socket.destroy();
        resolve(address);
      });
      socket.once('error', reject);
    });

  it('dials the checked address without resolving the host name', async () => {
    // `.test` names never resolve; reaching the server proves the pinned
    // address was dialled.
    const socket = dialPinned('pinned.egress.test', [{ address: '127.0.0.1', family: 4 }], port);
    await expect(connected(socket)).resolves.toBe('127.0.0.1');
    expect(lookup).not.toHaveBeenCalled();
    expect(resolve4).not.toHaveBeenCalled();
  });

  it('tries the next checked address when one refuses', async () => {
    // Nothing listens on 127.0.0.2.
    const socket = dialPinned(
      'pinned.egress.test',
      [
        { address: '127.0.0.2', family: 4 },
        { address: '127.0.0.1', family: 4 },
      ],
      port
    );
    await expect(connected(socket)).resolves.toBe('127.0.0.1');
  });

  it('dials an IP literal as it is', async () => {
    const socket = dialPinned('127.0.0.1', [{ address: '127.0.0.1', family: 4 }], port);
    await expect(connected(socket)).resolves.toBe('127.0.0.1');
    expect(lookup).not.toHaveBeenCalled();
  });
});
