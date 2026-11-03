import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  logUnshowableRedirectUris,
  UNSHOWABLE_REDIRECT_URI_CLIENTS_NAMED,
  UNSHOWABLE_REDIRECT_URI_COMMAND,
  UNSHOWABLE_REDIRECT_URI_SCAN_BUDGET_MS,
  UNSHOWABLE_REDIRECT_URI_WAIT_MS,
  unshowableRedirectUriWarning,
} from './unshowable-redirect-uris';

type UnshowableRedirectUriScan = Awaited<
  ReturnType<FastifyInstance['repositories']['oauthClients']['findUnshowableRedirectUris']>
>;

function entry(index: number) {
  return {
    id: `id-${index}`,
    realmId: 'r1',
    realmName: 'master',
    clientId: `client-${index}`,
    source: 'dynamic' as const,
    redirectUris: [{ uri: `https://bad_${index}.example.com/cb`, reason: 'host' as const }],
  };
}

function run(result: UnshowableRedirectUriScan | Error) {
  const warn = vi.fn();
  const findUnshowableRedirectUris = vi.fn(async () => {
    if (result instanceof Error) throw result;
    return result;
  });
  const done = logUnshowableRedirectUris({
    clients: { findUnshowableRedirectUris },
    log: { warn },
    now: () => 10_000,
  });
  return { done, warn, findUnshowableRedirectUris };
}

describe('logUnshowableRedirectUris (#914)', () => {
  it('names each client with a redirect URI the consent screen cannot show, and the command', async () => {
    const { done, warn, findUnshowableRedirectUris } = run({
      clients: [entry(1), { ...entry(2), realmName: 'acme', realmId: 'r2', source: 'cimd' }],
      scanned: 9,
      complete: true,
    });
    await done;

    // Bounded: the scan gets a deadline, so a large table never holds the boot.
    expect(findUnshowableRedirectUris).toHaveBeenCalledWith({
      deadline: 10_000 + UNSHOWABLE_REDIRECT_URI_SCAN_BUDGET_MS,
    });
    expect(warn.mock.calls).toEqual([
      [
        {
          realm: 'master',
          realmId: 'r1',
          clientId: 'client-1',
          registration: 'dynamic',
          redirectUris: [{ uri: 'https://bad_1.example.com/cb', reason: 'host' }],
        },
        unshowableRedirectUriWarning('master', 'client-1'),
      ],
      [
        {
          realm: 'acme',
          realmId: 'r2',
          clientId: 'client-2',
          registration: 'cimd',
          redirectUris: [{ uri: 'https://bad_2.example.com/cb', reason: 'host' }],
        },
        unshowableRedirectUriWarning('acme', 'client-2'),
      ],
    ]);
    expect(unshowableRedirectUriWarning('master', 'client-1')).toBe(
      `the client "client-1" of the realm "master" has a redirect URI the consent screen cannot show, which the screen refuses with invalid_request (#593); \`${UNSHOWABLE_REDIRECT_URI_COMMAND}\` lists every such client and how to replace its URIs`
    );
  });

  it('says nothing when every client’s redirect URIs can be shown', async () => {
    const { done, warn } = run({ clients: [], scanned: 40, complete: true });
    await done;
    expect(warn).not.toHaveBeenCalled();
  });

  it('names at most a fixed number of clients and counts the rest', async () => {
    const total = UNSHOWABLE_REDIRECT_URI_CLIENTS_NAMED + 3;
    const { done, warn } = run({
      clients: Array.from({ length: total }, (_, i) => entry(i)),
      scanned: total,
      complete: true,
    });
    await done;

    expect(warn).toHaveBeenCalledTimes(UNSHOWABLE_REDIRECT_URI_CLIENTS_NAMED + 1);
    expect(warn.mock.calls.at(-1)).toEqual([
      { clients: total, named: UNSHOWABLE_REDIRECT_URI_CLIENTS_NAMED },
      `3 more clients have a redirect URI the consent screen cannot show; \`${UNSHOWABLE_REDIRECT_URI_COMMAND}\` lists them all`,
    ]);
  });

  it('says the check is incomplete when the deadline stopped it', async () => {
    const { done, warn } = run({ clients: [entry(1)], scanned: 1500, complete: false });
    await done;

    expect(warn).toHaveBeenCalledTimes(2);
    expect(warn.mock.calls[1]).toEqual([
      { scanned: 1500, budgetMs: UNSHOWABLE_REDIRECT_URI_SCAN_BUDGET_MS },
      `the boot's check of the clients' redirect URIs stopped after 1500 clients; \`${UNSHOWABLE_REDIRECT_URI_COMMAND}\` checks every client`,
    ]);
  });

  it('logs a failed scan and lets the boot go on', async () => {
    const { done, warn } = run(new TypeError('connection lost'));
    await expect(done).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalledWith(
      { error: 'TypeError' },
      expect.stringContaining(UNSHOWABLE_REDIRECT_URI_COMMAND)
    );
  });

  it('quotes a client id or realm name a stored row carries, C0 control characters escaped', () => {
    const message = unshowableRedirectUriWarning('ma\nster', 'evil\u001b[2J');
    expect(message).not.toContain('\u001b');
    expect(message).not.toContain('\n');
    expect(message).toContain('"evil\\u001b[2J"');
  });
});

describe('logUnshowableRedirectUris when a page of clients waits (#914 review)', () => {
  it('stops waiting after its bound, says so and lets the boot go on', async () => {
    vi.useFakeTimers();
    try {
      const warn = vi.fn();
      // A page that never answers, as one queued behind a migration's lock.
      const findUnshowableRedirectUris = vi.fn(() => new Promise<never>(() => undefined));
      const done = logUnshowableRedirectUris({
        clients: { findUnshowableRedirectUris },
        log: { warn },
        now: () => 0,
      });

      await vi.advanceTimersByTimeAsync(UNSHOWABLE_REDIRECT_URI_WAIT_MS - 1);
      expect(warn).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      await expect(done).resolves.toBeUndefined();

      expect(warn.mock.calls).toEqual([
        [
          { waitedMs: UNSHOWABLE_REDIRECT_URI_WAIT_MS },
          `the boot's check of the clients' redirect URIs did not finish within ${UNSHOWABLE_REDIRECT_URI_WAIT_MS} ms; \`${UNSHOWABLE_REDIRECT_URI_COMMAND}\` checks every client`,
        ],
      ]);
      // Bounded well inside Fastify's 10 s onReady limit.
      expect(UNSHOWABLE_REDIRECT_URI_WAIT_MS).toBeLessThan(10_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it('ignores a scan that fails after the boot stopped waiting', async () => {
    vi.useFakeTimers();
    try {
      let fail: (error: Error) => void = () => undefined;
      const findUnshowableRedirectUris = vi.fn(
        () => new Promise<never>((_, reject) => (fail = reject))
      );
      const done = logUnshowableRedirectUris({
        clients: { findUnshowableRedirectUris },
        log: { warn: vi.fn() },
        now: () => 0,
      });
      await vi.advanceTimersByTimeAsync(UNSHOWABLE_REDIRECT_URI_WAIT_MS);
      await done;
      // Rejecting now raises no unhandled rejection.
      fail(new Error('pool closed'));
      await vi.advanceTimersByTimeAsync(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
