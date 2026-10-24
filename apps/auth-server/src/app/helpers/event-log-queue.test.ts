import { ExportResultCode } from '@opentelemetry/core';
import type { LogRecordExporter, ReadableLogRecord, SdkLogRecord } from '@opentelemetry/sdk-logs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  DEFAULT_EVENT_LOG_QUEUE_LIMITS,
  DropOldestLogRecordProcessor,
  type DroppedLogReason,
  type EventLogQueueLimits,
} from './event-log-queue';

/**
 * The bounded queue in front of the OTLP exporter (issue #541): it drops its
 * oldest record when full, exports one batch at a time, counts every record
 * it could not export, and never waits on the network for its caller.
 */

/** A record that only needs to be told apart from the others. */
const record = (n: number) => ({ body: `event-${n}` }) as unknown as SdkLogRecord;
const bodies = (batch: readonly ReadableLogRecord[]) => batch.map((r) => r.body);

/** An exporter whose exports wait until the test settles them. */
function scriptedExporter() {
  const batches: ReadableLogRecord[][] = [];
  const pending: Array<(code: ExportResultCode) => void> = [];
  const exporter: LogRecordExporter = {
    export: (logs, done) => {
      batches.push([...logs]);
      pending.push((code) => done({ code }));
    },
    shutdown: vi.fn(() => Promise.resolve()),
    forceFlush: () => Promise.resolve(),
  };
  return {
    exporter,
    batches,
    /** Settle the oldest export still out. */
    settle(code: ExportResultCode = ExportResultCode.SUCCESS) {
      const next = pending.shift();
      if (next === undefined) throw new Error('no export is out');
      next(code);
    },
    get out() {
      return pending.length;
    },
  };
}

function queue(limits: Partial<EventLogQueueLimits>, exporter: LogRecordExporter) {
  const dropped: Array<[number, DroppedLogReason]> = [];
  const processor = new DropOldestLogRecordProcessor(
    exporter,
    { ...DEFAULT_EVENT_LOG_QUEUE_LIMITS, ...limits },
    (count, reason) => dropped.push([count, reason])
  );
  return { processor, dropped };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('DropOldestLogRecordProcessor', () => {
  it('sends a batch once it is full, and a smaller one after the schedule delay', async () => {
    const script = scriptedExporter();
    const { processor, dropped } = queue(
      { maxExportBatchSize: 3, scheduleDelayMillis: 100 },
      script.exporter
    );

    for (const n of [1, 2, 3]) processor.onEmit(record(n));
    expect(script.batches.map(bodies)).toEqual([['event-1', 'event-2', 'event-3']]);
    script.settle();
    await vi.advanceTimersByTimeAsync(0);

    processor.onEmit(record(4));
    expect(script.batches).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(99);
    expect(script.batches).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(script.batches.map(bodies)).toEqual([['event-1', 'event-2', 'event-3'], ['event-4']]);
    expect(dropped).toEqual([]);
  });

  it('keeps one export out at a time and holds the rest within the cap, dropping the oldest', async () => {
    const script = scriptedExporter();
    const { processor, dropped } = queue(
      { maxQueueSize: 3, maxExportBatchSize: 2, scheduleDelayMillis: 10 },
      script.exporter
    );

    for (let n = 1; n <= 9; n += 1) {
      processor.onEmit(record(n));
      expect(processor.queueLength).toBeLessThanOrEqual(3);
    }
    // 1 and 2 went out; 3 to 9 arrived while they were out.
    expect(script.out).toBe(1);
    expect(script.batches.map(bodies)).toEqual([['event-1', 'event-2']]);
    expect(dropped).toEqual([
      [1, 'queue_full'],
      [1, 'queue_full'],
      [1, 'queue_full'],
      [1, 'queue_full'],
    ]);

    script.settle();
    await vi.advanceTimersByTimeAsync(0);
    // What waited, newest kept, goes out next as a full batch.
    expect(script.batches.map(bodies).at(-1)).toEqual(['event-7', 'event-8']);
    script.settle();
    await vi.advanceTimersByTimeAsync(10);
    expect(script.batches.map(bodies).at(-1)).toEqual(['event-9']);
  });

  it('counts a refused batch as dropped, by its size', async () => {
    const script = scriptedExporter();
    const { processor, dropped } = queue({ maxExportBatchSize: 2 }, script.exporter);

    processor.onEmit(record(1));
    processor.onEmit(record(2));
    script.settle(ExportResultCode.FAILED);
    await vi.advanceTimersByTimeAsync(0);

    expect(dropped).toEqual([[2, 'export_failed']]);
  });

  it('gives up a batch whose export never reports, and ignores a late answer', async () => {
    const script = scriptedExporter();
    const { processor, dropped } = queue(
      { maxExportBatchSize: 1, exportTimeoutMillis: 1000 },
      script.exporter
    );

    processor.onEmit(record(1));
    processor.onEmit(record(2));
    await vi.advanceTimersByTimeAsync(1000);
    expect(dropped).toEqual([[1, 'export_failed']]);
    // The next batch went out once the first was given up.
    expect(script.batches.map(bodies)).toEqual([['event-1'], ['event-2']]);

    script.settle(ExportResultCode.FAILED);
    await vi.advanceTimersByTimeAsync(0);
    expect(dropped).toEqual([[1, 'export_failed']]);
  });

  it('counts a batch whose exporter throws as dropped, and goes on', async () => {
    const exporter: LogRecordExporter = {
      export: () => {
        throw new Error('exporter broke');
      },
      shutdown: () => Promise.resolve(),
      forceFlush: () => Promise.resolve(),
    };
    const { processor, dropped } = queue({ maxExportBatchSize: 1 }, exporter);

    expect(() => processor.onEmit(record(1))).not.toThrow();
    await vi.advanceTimersByTimeAsync(0);
    expect(dropped).toEqual([[1, 'export_failed']]);
  });

  it('forceFlush sends every queued record and waits for the exports', async () => {
    const script = scriptedExporter();
    const { processor } = queue({ maxExportBatchSize: 2 }, script.exporter);

    for (const n of [1, 2, 3]) processor.onEmit(record(n));
    let flushed = false;
    const flushing = processor.forceFlush().then(() => {
      flushed = true;
    });
    script.settle();
    await vi.advanceTimersByTimeAsync(0);
    expect(flushed).toBe(false);
    script.settle();
    await flushing;

    expect(script.batches.map(bodies)).toEqual([['event-1', 'event-2'], ['event-3']]);
    expect(processor.queueLength).toBe(0);
  });

  it('close sends what is queued and stops the exporter', async () => {
    const script = scriptedExporter();
    const { processor } = queue({ scheduleDelayMillis: 1000 }, script.exporter);

    processor.onEmit(record(1));
    const closing = processor.close();
    await vi.advanceTimersByTimeAsync(0);
    script.settle();
    expect(await closing).toBe(0);
    expect(script.batches.map(bodies)).toEqual([['event-1']]);
    expect(script.exporter.shutdown).toHaveBeenCalledOnce();

    processor.onEmit(record(2));
    await vi.advanceTimersByTimeAsync(5000);
    expect(script.batches).toHaveLength(1);
  });

  it('close gives up after its time against a collector that never answers, and says how many were left', async () => {
    const script = scriptedExporter();
    const { processor } = queue(
      { maxExportBatchSize: 2, shutdownTimeoutMillis: 500 },
      script.exporter
    );

    for (const n of [1, 2, 3]) processor.onEmit(record(n));
    const closing = processor.close();
    await vi.advanceTimersByTimeAsync(500);

    // Two were being sent and one waited.
    expect(await closing).toBe(3);
    expect(processor.queueLength).toBe(0);
  });
});
