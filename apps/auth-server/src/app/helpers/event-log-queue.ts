import { context } from '@opentelemetry/api';
import { ExportResultCode, suppressTracing } from '@opentelemetry/core';
import type {
  LogRecordExporter,
  LogRecordProcessor,
  ReadableLogRecord,
  SdkLogRecord,
} from '@opentelemetry/sdk-logs';

/**
 * The queue between the event log records and the OTLP exporter (issue
 * #541). The SDK's BatchLogRecordProcessor drops the NEWEST record when its
 * queue is full and counts nothing; this one drops the oldest, so a collector
 * that comes back receives what happened last, and reports every drop.
 *
 * Nothing here works on the caller's behalf beyond queueing: `onEmit` only
 * adds the record and sets a timer, and even a full batch is serialized and
 * sent on a later turn of the event loop, never on the stack of the request
 * whose commit filled it. One batch is exported at a time; while it is out,
 * new records wait in the queue, which never holds more than `maxQueueSize`.
 * Only a batch given up at `exportTimeoutMillis` can leave its request still
 * open in the exporter while the next one goes out.
 */

/** Why a record was not exported. */
export type DroppedLogReason = 'queue_full' | 'export_failed';

/** The queue's sizes and times. */
export interface EventLogQueueLimits {
  /** The most records the queue holds; at that size each new record drops the oldest. */
  readonly maxQueueSize: number;
  /** The most records one export sends. */
  readonly maxExportBatchSize: number;
  /** How long a record waits for a full batch before a smaller one is sent, in milliseconds. */
  readonly scheduleDelayMillis: number;
  /**
   * How long an export may run before its batch counts as failed, in
   * milliseconds. A guard against an export that never reports: the
   * exporter's own timeout (OTEL_EXPORTER_OTLP_TIMEOUT) ends it first.
   */
  readonly exportTimeoutMillis: number;
  /** How long shutdown may spend sending what is queued, in milliseconds. */
  readonly shutdownTimeoutMillis: number;
}

/**
 * The defaults: the OpenTelemetry batch processor's own queue and batch sizes,
 * delay and export timeout, and the 5 seconds a stopping server gives its jobs.
 */
export const DEFAULT_EVENT_LOG_QUEUE_LIMITS: EventLogQueueLimits = Object.freeze({
  maxQueueSize: 2048,
  maxExportBatchSize: 512,
  scheduleDelayMillis: 1000,
  exportTimeoutMillis: 30_000,
  shutdownTimeoutMillis: 5000,
});

/** A log record processor with a bounded queue that drops its oldest record when full. */
export class DropOldestLogRecordProcessor implements LogRecordProcessor {
  private readonly queue: ReadableLogRecord[] = [];
  private timer: NodeJS.Timeout | undefined;
  /** When the pending timer fires, in epoch milliseconds. */
  private timerDue = 0;
  /** When the oldest queued record arrived, while any is queued. */
  private queuedSince = 0;
  private exporting: Promise<void> | undefined;
  /** The size of the batch being sent, or 0. */
  private sending = 0;
  private stopped = false;

  /**
   * @param exporter - sends a batch; it reports through its callback
   * @param limits - the queue's sizes and times
   * @param onDropped - told how many records were dropped, and why
   */
  constructor(
    private readonly exporter: LogRecordExporter,
    private readonly limits: EventLogQueueLimits,
    private readonly onDropped: (count: number, reason: DroppedLogReason) => void
  ) {}

  /** How many records wait to be exported, the batch being sent excluded. */
  get queueLength(): number {
    return this.queue.length;
  }

  onEmit(record: SdkLogRecord): void {
    if (this.stopped) return;
    if (this.queue.length === 0) this.queuedSince = Date.now();
    this.queue.push(record);
    if (this.queue.length > this.limits.maxQueueSize) {
      this.queue.shift();
      this.onDropped(1, 'queue_full');
    }
    // A full batch leaves on the next turn of the event loop: the exporter
    // serializes it synchronously, and the caller is a request's commit.
    this.scheduleDrain(
      this.queue.length >= this.limits.maxExportBatchSize ? 0 : this.limits.scheduleDelayMillis
    );
  }

  /** Export every queued record, one batch at a time, and wait for the last one. */
  async forceFlush(): Promise<void> {
    while (this.exporting !== undefined || this.queue.length > 0) {
      this.drain();
      await this.exporting;
    }
  }

  /** The SDK's shutdown: {@link close}. */
  async shutdown(): Promise<void> {
    await this.close();
  }

  /**
   * Send what is queued, within `shutdownTimeoutMillis`, then stop the
   * exporter.
   *
   * @returns how many records were still queued or being sent when the time
   *   ran out; they are not exported
   */
  async close(): Promise<number> {
    if (this.stopped) return 0;
    this.clearTimer();
    let timeout: NodeJS.Timeout | undefined;
    const outOfTime = new Promise<'timeout'>((resolve) => {
      timeout = setTimeout(() => resolve('timeout'), this.limits.shutdownTimeoutMillis);
    });
    try {
      const flushed = await Promise.race([
        this.forceFlush().then(() => 'flushed' as const),
        outOfTime,
      ]);
      this.stopped = true;
      const left = flushed === 'timeout' ? this.queue.length + this.sending : 0;
      this.queue.length = 0;
      // The exporter waits for a request still out; the same deadline bounds it.
      await Promise.race([this.exporter.shutdown().catch(() => undefined), outOfTime]);
      return left;
    } finally {
      clearTimeout(timeout);
    }
  }

  private clearTimer(): void {
    if (this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
  }

  /** Drain after `delayMillis`, unless a drain is already due no later than that. */
  private scheduleDrain(delayMillis: number): void {
    const due = Date.now() + delayMillis;
    if (this.timer !== undefined && this.timerDue <= due) return;
    this.clearTimer();
    this.timerDue = due;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.drain();
    }, delayMillis);
    // A pending batch never keeps the process alive; close() sends it.
    this.timer.unref();
  }

  /** Start the next export unless one is out or nothing is queued. */
  private drain(): void {
    if (this.exporting !== undefined || this.queue.length === 0) return;
    this.clearTimer();
    const batch = this.queue.splice(0, this.limits.maxExportBatchSize);
    if (this.queue.length > 0) this.queuedSince = Date.now();
    this.sending = batch.length;
    this.exporting = this.send(batch).finally(() => {
      this.exporting = undefined;
      this.sending = 0;
      // What arrived during the export goes out as a full batch now, or once
      // the oldest of it has waited the schedule delay. This runs in the
      // exporter's callback, not in a request.
      if (this.stopped || this.queue.length === 0) return;
      if (this.queue.length >= this.limits.maxExportBatchSize) {
        this.drain();
      } else {
        const waited = Date.now() - this.queuedSince;
        this.scheduleDrain(Math.max(0, this.limits.scheduleDelayMillis - waited));
      }
    });
  }

  /** Export one batch; a batch that fails or times out is counted as dropped. */
  private send(batch: ReadableLogRecord[]): Promise<void> {
    return new Promise<void>((resolve) => {
      let settled = false;
      const settle = (exported: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(guard);
        if (!exported) this.onDropped(batch.length, 'export_failed');
        resolve();
      };
      const guard = setTimeout(() => settle(false), this.limits.exportTimeoutMillis);
      guard.unref();
      try {
        // Suppressed tracing keeps the export's own HTTP request out of the
        // operator's traces, as the SDK's processors do.
        context.with(suppressTracing(context.active()), () => {
          this.exporter.export(batch, (result) => settle(result.code === ExportResultCode.SUCCESS));
        });
      } catch {
        settle(false);
      }
    });
  }
}
