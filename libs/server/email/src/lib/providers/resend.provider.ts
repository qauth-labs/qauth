import * as crypto from 'node:crypto';

import type { CreateEmailOptions, CreateEmailResponse } from 'resend';
import { Resend } from 'resend';

import type { EmailOptions, EmailProvider, EmailResult, ResendProviderConfig } from '../../types';

/** How many times a send is tried again after a transient failure. */
const MAX_RETRIES = 3;

/** The wait before retry `n` is `2^n` times this: 2 s, 4 s, 8 s. */
const BACKOFF_UNIT_MS = 1000;

/**
 * The longest wait a `Retry-After` header may ask for before a retry. An
 * answer that asks for longer is final: the send does not hold a mail that
 * long, and retrying sooner than Resend asks would only spend the account's
 * rate limit.
 */
const RETRY_AFTER_CEILING_MS = 10_000;

/** How long one attempt may take, its answer read to the end. */
const ATTEMPT_TIMEOUT_MS = 10_000;

/** Resend's error names are snake_case tokens; anything else is not reported. */
const ERROR_NAME = /^[a-z][a-z0-9_]{0,63}$/;

/** A thrown error's class name, the only part of it reported. */
const THROWN_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

/**
 * The parts of a Resend failure the provider reads: its status (`null` when no
 * answer came, `undefined` when the answer did not say one) and its name. Its
 * `message` is never read: it can quote an address.
 */
interface Failure {
  readonly statusCode: number | null | undefined;
  readonly name: string | undefined;
}

/** How one attempt ended. */
type Attempt =
  | { readonly kind: 'sent'; readonly messageId: string | undefined }
  | { readonly kind: 'transient'; readonly reason: string; readonly retryAfterMs?: number }
  | { readonly kind: 'final'; readonly reason: string };

/**
 * The status and name of the error `send` resolved with. The SDK hands back the
 * answer's JSON body as it came, so neither is trusted to have its type.
 */
function failureOf(error: unknown): Failure {
  if (typeof error !== 'object' || error === null) {
    return { statusCode: undefined, name: undefined };
  }
  const { statusCode, name } = error as Record<string, unknown>;
  return {
    statusCode:
      statusCode === null
        ? null
        : typeof statusCode === 'number' && Number.isInteger(statusCode)
          ? statusCode
          : undefined,
    name: typeof name === 'string' && ERROR_NAME.test(name) ? name : undefined,
  };
}

/** A failure as the provider reports it: status and name, never Resend's message. */
function describeFailure(failure: Failure): string {
  const status =
    failure.statusCode === null ? 'none' : (failure.statusCode?.toString() ?? 'unknown');
  return `status ${status}, ${failure.name ?? 'unknown'}`;
}

/**
 * Whether a failure may pass if the same send is tried again: no answer
 * (`statusCode: null`), any 5xx, the per-second rate limit and an earlier
 * attempt with the same idempotency key still in progress. Every other answer
 * is final, the daily and monthly quotas (429 `daily_quota_exceeded`,
 * `monthly_quota_exceeded`) among them: no wait of seconds lifts them.
 */
function isTransient(failure: Failure): boolean {
  const { statusCode, name } = failure;
  if (statusCode === null) return true;
  if (statusCode === undefined) return false;
  if (statusCode >= 500 && statusCode <= 599) return true;
  if (statusCode === 429) return name === 'rate_limit_exceeded';
  if (statusCode === 409) return name === 'concurrent_idempotent_requests';
  return false;
}

/**
 * The wait, in milliseconds, an answer's `Retry-After` header asks for
 * (RFC 9110 §10.2.3: a number of seconds or an HTTP date), or `undefined` when
 * it has none the provider can read.
 */
function retryAfterOf(headers: CreateEmailResponse['headers'], now: number): number | undefined {
  if (headers === null || typeof headers !== 'object') return undefined;
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === 'retry-after');
  const value = typeof entry?.[1] === 'string' ? entry[1].trim() : '';
  if (value === '') return undefined;
  if (/^\d+$/.test(value)) return Number(value) * 1000;
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, at - now);
}

/** The class name of something `send` threw, if it is one the provider may report. */
function thrownName(error: unknown): string {
  const name = error instanceof Error ? error.name : undefined;
  return name !== undefined && THROWN_NAME.test(name) ? name : 'unknown';
}

/** Resolves after `ms` milliseconds. */
function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Resend email provider implementation.
 *
 * A send that fails for a reason that may pass (no answer, a 5xx, the
 * per-second rate limit, a concurrent request with the same idempotency key)
 * is tried again up to {@link MAX_RETRIES} times, after 2 s, 4 s and 8 s or
 * the longer wait an answer's `Retry-After` asks for, and always with the same
 * idempotency key, so Resend sends the mail at most once. Each attempt has
 * {@link ATTEMPT_TIMEOUT_MS} to finish.
 */
export class ResendEmailProvider implements EmailProvider {
  private readonly resend: Resend;
  private readonly defaultFrom?: string;

  constructor(config: ResendProviderConfig) {
    this.resend = new Resend(config.apiKey);
    this.defaultFrom = config.fromAddress;
  }

  /**
   * Generate a content-based idempotency key
   *
   * This ensures the same email content produces the same key,
   * preventing duplicate sends during retries.
   */
  private generateIdempotencyKey(options: EmailOptions, from: string): string {
    const content = `${from}-${options.to}-${options.subject}-${options.html || ''}-${options.text || ''}`;
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 32);
  }

  /** The request body of a send. */
  private payloadOf(options: EmailOptions, from: string): CreateEmailOptions {
    return {
      from,
      to: options.to,
      subject: options.subject,
      ...(options.html && { html: options.html }),
      ...(options.text && { text: options.text }),
      ...(options.inlineImages !== undefined && options.inlineImages.length > 0
        ? {
            // A content ID makes each an inline part the HTML names through `cid:`.
            attachments: options.inlineImages.map((image) => ({
              filename: image.filename,
              content: image.content,
              contentType: image.contentType,
              contentId: image.contentId,
            })),
          }
        : {}),
    } as CreateEmailOptions;
  }

  /**
   * One attempt at a send. The SDK answers every HTTP and network failure as
   * `result.error` rather than throw, so the decision reads that; a throw is
   * an attempt this provider aborted for taking too long (transient), or a
   * fault of the request itself (final).
   */
  private async attempt(payload: CreateEmailOptions, idempotencyKey: string): Promise<Attempt> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ATTEMPT_TIMEOUT_MS);
    try {
      const result = await this.resend.emails.send(payload, {
        idempotencyKey,
        signal: controller.signal,
      });
      if (result.error === null || result.error === undefined) {
        return { kind: 'sent', messageId: result.data?.id };
      }
      const failure = failureOf(result.error);
      const reason = controller.signal.aborted
        ? `${describeFailure(failure)}, no answer within ${ATTEMPT_TIMEOUT_MS / 1000} s`
        : describeFailure(failure);
      if (!isTransient(failure)) return { kind: 'final', reason };
      const retryAfterMs = retryAfterOf(result.headers, Date.now());
      return retryAfterMs === undefined
        ? { kind: 'transient', reason }
        : { kind: 'transient', reason, retryAfterMs };
    } catch (error) {
      if (controller.signal.aborted) {
        return {
          kind: 'transient',
          reason: `no answer within ${ATTEMPT_TIMEOUT_MS / 1000} s`,
        };
      }
      return { kind: 'final', reason: `the send threw ${thrownName(error)}` };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Send an email via Resend API
   *
   * @param options - Email options
   * @returns Promise resolving to email result; a failure's `error` names
   *   Resend's status and error name, never its message
   */
  async sendEmail(options: EmailOptions): Promise<EmailResult> {
    const from = options.from || this.defaultFrom;
    if (!from) {
      return {
        success: false,
        error: 'From address is required. Set it in options or provider config.',
      };
    }

    // Validate that at least html or text is provided
    if (!options.html && !options.text) {
      return {
        success: false,
        error: 'Either html or text content must be provided',
      };
    }

    const payload = this.payloadOf(options, from);
    // Content-based, and the same on every attempt: if an earlier attempt did
    // reach Resend, a retry returns its result instead of sending again.
    const idempotencyKey = this.generateIdempotencyKey(options, from);

    let outcome = await this.attempt(payload, idempotencyKey);
    for (let retry = 1; outcome.kind === 'transient' && retry <= MAX_RETRIES; retry++) {
      const { retryAfterMs } = outcome;
      if (retryAfterMs !== undefined && retryAfterMs > RETRY_AFTER_CEILING_MS) {
        return {
          success: false,
          error: `Failed to send email via Resend: it asked for a wait of more than ${RETRY_AFTER_CEILING_MS / 1000} s before a retry (${outcome.reason})`,
        };
      }
      await wait(Math.max(Math.pow(2, retry) * BACKOFF_UNIT_MS, retryAfterMs ?? 0));
      outcome = await this.attempt(payload, idempotencyKey);
    }

    switch (outcome.kind) {
      case 'sent':
        return { success: true, messageId: outcome.messageId };
      case 'final':
        return { success: false, error: `Failed to send email via Resend (${outcome.reason})` };
      case 'transient':
        return {
          success: false,
          error: `Failed to send email via Resend after ${MAX_RETRIES} retries (${outcome.reason})`,
        };
    }
  }
}
