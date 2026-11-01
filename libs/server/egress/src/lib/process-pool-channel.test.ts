import type * as ChildProcessModule from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { Socket } from 'node:net';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type ExchangeJob,
  type ExchangeOutcome,
  FETCH_PROCESS_CHANNEL_FD,
  FRAME,
  FRAME_HEADER_BYTES,
  MAX_FAILURE_PAYLOAD_BYTES,
  MAX_RESPONSE_FIELDS_BYTES,
} from './exchange';
import { createProcessPool, type ProcessPool } from './process-pool';

/*
 * Fetch processes a host has taken over, which send the pool whatever they
 * like over the channel (issue #857). The pool must stay up and bounded: it
 * refuses a frame from its header, kills the process and fails its call.
 *
 * The hostile program below replaces the real one when the pool spawns a
 * process; the rest of the start (flags, empty environment, descriptors) is
 * the pool's own. Each job's host name picks what the process does.
 */

const hostile = vi.hoisted(() => ({
  /** The program the next fetch processes run instead of `exchange.ts`. */
  program: undefined as string | undefined,
  /** Every process the pool started in this test. */
  children: [] as ChildProcess[],
}));

vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof ChildProcessModule>();
  const spawn = (
    command: string,
    args: readonly string[],
    options: ChildProcessModule.SpawnOptions
  ): ChildProcess => {
    const swapped = args.map((arg, i) =>
      i > 0 && args[i - 1] === '--eval' && hostile.program !== undefined ? hostile.program : arg
    );
    const child = actual.spawn(command, swapped, options);
    hostile.children.push(child);
    return child;
  };
  return { ...actual, spawn };
});

/**
 * A fetch process gone bad. It reads the pool's frames as the real one does,
 * then answers the exchange as its host name says.
 */
const HOSTILE_PROGRAM = `
import { Socket } from 'node:net';
const channel = new Socket({ fd: ${FETCH_PROCESS_CHANNEL_FD}, readable: true, writable: true });
channel.on('error', () => process.exit(1));
channel.on('end', () => process.exit(0));
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const frame = (type, payload = Buffer.alloc(0), length = payload.length) => {
  const header = Buffer.alloc(${FRAME_HEADER_BYTES});
  header.writeUInt8(type, 0);
  header.writeUInt32BE(length, 1);
  return Buffer.concat([header, payload]);
};
const ready = () => channel.write(frame(${FRAME.ready}));
const secured = (id) => channel.write(frame(${FRAME.secured}, u32(id)));
const failure = (id, host) => {
  const message = Buffer.from('egress to ' + host + ' failed: refused');
  return frame(${FRAME.failure}, Buffer.concat([u32(id), Buffer.from([1]), u16(message.length), message]));
};
// Bytes as fast as the pool takes them, until the process is killed.
const flood = () => {
  const chunk = Buffer.alloc(64 * 1024, 0x61);
  const pump = () => {
    while (channel.write(chunk));
    channel.once('drain', pump);
  };
  pump();
};
const behave = {
  // A response announced at the frame's largest length, then streamed.
  'huge.hostile.test': (id) => {
    ready();
    secured(id);
    channel.write(frame(${FRAME.response}, Buffer.alloc(0), 0xffffffff));
    flood();
  },
  // A response header one byte above the job's cap, and no payload at all.
  'over.hostile.test': (id, job) => {
    ready();
    secured(id);
    channel.write(frame(${FRAME.response}, Buffer.alloc(0), ${MAX_RESPONSE_FIELDS_BYTES} + job.maxResponseBytes + 1));
  },
  // A ready frame with a payload, which it never has.
  'ready.hostile.test': () => channel.write(frame(${FRAME.ready}, Buffer.alloc(16))),
  // A failure one byte above its cap.
  'failure.hostile.test': () => {
    ready();
    channel.write(frame(${FRAME.failure}, Buffer.alloc(0), ${MAX_FAILURE_PAYLOAD_BYTES + 1}));
  },
  // A response before the TLS handshake was reported.
  'early.hostile.test': (id) => {
    ready();
    channel.write(frame(${FRAME.response}, Buffer.concat([u32(id), u16(200), u16(0), Buffer.from([0]), Buffer.from('ok')])));
  },
  // A well-formed answer, then a frame while idle.
  'idle.hostile.test': (id, job) => {
    ready();
    secured(id);
    channel.write(failure(id, job.hostname));
    setTimeout(() => secured(id), 100);
  },
};
let pending = Buffer.alloc(0);
channel.on('data', (chunk) => {
  pending = Buffer.concat([pending, chunk]);
  while (pending.length >= 5 && pending.length >= 5 + pending.readUInt32BE(1)) {
    const type = pending.readUInt8(0);
    const payload = pending.subarray(5, 5 + pending.readUInt32BE(1));
    pending = pending.subarray(5 + payload.length);
    if (type !== ${FRAME.exchange}) continue;
    const head = JSON.parse(payload.toString('utf8', 4, 4 + payload.readUInt32BE(0)));
    behave[head.job.hostname](head.id, head.job);
  }
});
`;

/** The time a call gets: far more than a refusal takes, as CI runs every suite at once. */
const CALL_MS = 15_000;

const PROCESS_TEST = { timeout: 60_000 };

const job = (hostname: string): ExchangeJob => ({
  hostname,
  port: 443,
  literalFamily: 0,
  path: '/',
  addresses: [{ address: '127.0.0.1', family: 4 }],
  method: 'GET',
  headers: {},
  body: undefined,
  // Far away: a call that ends before it was refused, not timed out.
  connectTimeoutMs: 30_000,
  maxResponseBytes: 64 * 1024,
});

let pools: ProcessPool[] = [];

const pool = (): ProcessPool => {
  const created = createProcessPool();
  pools.push(created);
  return created;
};

afterEach(async () => {
  await Promise.all(pools.map((p) => p.close()));
  pools = [];
  for (const child of hostile.children) {
    expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
  }
  hostile.children = [];
  hostile.program = undefined;
});

/** Resolves once `check` holds, polling every 10 ms for up to 15 s. */
async function until(check: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!check()) {
    if (Date.now() > deadline) throw new Error('condition not met in time');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/**
 * That the pool killed `child`, and it has exited. Not its `signalCode`: the
 * pool destroys the channel and sends SIGKILL together, and the hostile
 * program exits on its own when its channel ends, so either may end the
 * process first. `killed` is set only when the pool's `kill('SIGKILL')`
 * reached a process that had not been reaped yet, which the pool's call
 * right after the destroy always does: a pool that stopped killing leaves it
 * `false`.
 */
function expectKilledByPool(child: ChildProcess): void {
  expect(child.killed).toBe(true);
  expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
}

/** The pool's end of the channel to `child`. */
const channelOf = (child: ChildProcess): Socket => {
  const channel = child.stdio[FETCH_PROCESS_CHANNEL_FD];
  if (!(channel instanceof Socket)) throw new Error('no channel');
  return channel;
};

const refused = (host: string, what: string): ExchangeOutcome => ({
  kind: 'failed',
  reason: 'network',
  message: `egress to ${host} failed: ${what}`,
});

const OVERSIZED = 'the fetch process sent a frame above its size cap';
const INVALID = 'the fetch process sent an invalid answer';

/** The bytes of the `ready` and `secured` frames a process sends first. */
const OPENING_BYTES = FRAME_HEADER_BYTES + FRAME_HEADER_BYTES + 4;

describe(
  'a fetch process that sends the pool what it likes (integration: real processes)',
  PROCESS_TEST,
  () => {
    it('refuses a frame whose length is above its cap from the header alone, kills the process and fails the call', async () => {
      hostile.program = HOSTILE_PROGRAM;
      const fetches = pool();
      await expect(
        fetches.exchange(job('over.hostile.test'), AbortSignal.timeout(CALL_MS))
      ).resolves.toEqual(refused('over.hostile.test', OVERSIZED));
      const [child] = hostile.children;
      // The process sent the header and no payload: the refusal came from the
      // header, without waiting for a byte of the frame.
      expect(channelOf(child).bytesRead).toBe(OPENING_BYTES + FRAME_HEADER_BYTES);
      await until(() => fetches.stats().processes === 0);
      expectKilledByPool(child);
      expect(fetches.stats().deadlineKills).toBe(0);
    });

    it('stops reading a frame announced at 4 GiB at the header, while the process streams it', async () => {
      hostile.program = HOSTILE_PROGRAM;
      const fetches = pool();
      await expect(
        fetches.exchange(job('huge.hostile.test'), AbortSignal.timeout(CALL_MS))
      ).resolves.toEqual(refused('huge.hostile.test', OVERSIZED));
      await until(() => fetches.stats().processes === 0);
      const [child] = hostile.children;
      expectKilledByPool(child);
      // What the pool read from the process: the frames before the header and,
      // at most, the rest of the one read (64 KiB) the header arrived in. The
      // process kept writing until it was killed; nothing of that was read or
      // kept, and the frame's cap here is the job's 64 KiB and the fixed fields.
      expect(channelOf(child).bytesRead).toBeLessThanOrEqual(
        OPENING_BYTES + FRAME_HEADER_BYTES + 64 * 1024
      );
    });

    it.each([
      ['a ready frame with a payload', 'ready.hostile.test', OVERSIZED],
      ['a failure above its cap', 'failure.hostile.test', OVERSIZED],
      ['a response before the TLS handshake was reported', 'early.hostile.test', INVALID],
    ])('kills a process that sends %s, and fails its call', async (_case, host, what) => {
      hostile.program = HOSTILE_PROGRAM;
      const fetches = pool();
      await expect(fetches.exchange(job(host), AbortSignal.timeout(CALL_MS))).resolves.toEqual(
        refused(host, what)
      );
      await until(() => fetches.stats().processes === 0);
      expectKilledByPool(hostile.children[0]);
    });

    it('kills a process that sends a frame while it runs no exchange', async () => {
      hostile.program = HOSTILE_PROGRAM;
      const fetches = pool();
      // Its answer is well formed, and taken.
      await expect(
        fetches.exchange(job('idle.hostile.test'), AbortSignal.timeout(CALL_MS))
      ).resolves.toEqual(refused('idle.hostile.test', 'refused'));
      // Then it speaks out of turn, and is killed long before its idle minute.
      await until(() => fetches.stats().processes === 0);
      expectKilledByPool(hostile.children[0]);
      expect(fetches.stats().deadlineKills).toBe(0);
    });
  }
);
