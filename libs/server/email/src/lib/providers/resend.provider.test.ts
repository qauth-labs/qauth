import { Resend } from 'resend';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { EmailOptions, ResendProviderConfig } from '../../types';
import { ResendEmailProvider } from './resend.provider';

// Mock Resend
const mockSend = vi.hoisted(() => vi.fn());

vi.mock('resend', () => {
  return {
    Resend: vi.fn().mockImplementation(function (this: Resend) {
      return {
        emails: {
          send: mockSend,
        },
      };
    }),
  };
});

describe('ResendEmailProvider', () => {
  let config: ResendProviderConfig;

  beforeEach(() => {
    config = {
      apiKey: 're_test123',
      fromAddress: 'noreply@example.com',
    };

    // Clear all mocks before each test
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('sendEmail', () => {
    it('should send an email successfully', async () => {
      const provider = new ResendEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
        html: '<p>Test body</p>',
      };

      mockSend.mockResolvedValueOnce({
        data: { id: 'msg_123' },
        error: null,
      });

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('msg_123');
      expect(mockSend).toHaveBeenCalledWith(
        {
          from: config.fromAddress,
          to: emailOptions.to,
          subject: emailOptions.subject,
          html: emailOptions.html,
          text: emailOptions.text,
        },
        expect.objectContaining({
          idempotencyKey: expect.any(String),
        })
      );
    });

    it('sends inline images as attachments with a content ID', async () => {
      const provider = new ResendEmailProvider(config);
      const content = Buffer.from([137, 80, 78, 71]);
      mockSend.mockResolvedValueOnce({ data: { id: 'msg_124' }, error: null });

      await provider.sendEmail({
        to: 'user@example.com',
        subject: 'Test Subject',
        html: '<img src="cid:logo@qauth.mail">',
        inlineImages: [
          { contentId: 'logo@qauth.mail', filename: 'logo.png', contentType: 'image/png', content },
        ],
      });

      expect(mockSend).toHaveBeenCalledWith(
        expect.objectContaining({
          attachments: [
            {
              filename: 'logo.png',
              content,
              contentType: 'image/png',
              contentId: 'logo@qauth.mail',
            },
          ],
        }),
        expect.anything()
      );
    });

    it('should use from address from options if provided', async () => {
      const provider = new ResendEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
        from: 'custom@example.com',
      };

      mockSend.mockResolvedValueOnce({
        data: { id: 'msg_123' },
        error: null,
      });

      await provider.sendEmail(emailOptions);

      expect(mockSend).toHaveBeenCalledWith(
        expect.objectContaining({
          from: 'custom@example.com',
        }),
        expect.any(Object)
      );
    });

    it('should return error if from address is missing', async () => {
      const provider = new ResendEmailProvider({ apiKey: 're_test123' }); // No fromAddress
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('From address is required');
    });

    it('should generate same idempotency key for same content', async () => {
      const provider = new ResendEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      mockSend.mockResolvedValue({
        data: { id: 'msg_123' },
        error: null,
      });

      await provider.sendEmail(emailOptions);
      await provider.sendEmail(emailOptions);

      const calls = mockSend.mock.calls;
      const key1 = calls[0]?.[1]?.idempotencyKey;
      const key2 = calls[1]?.[1]?.idempotencyKey;

      expect(key1).toBeDefined();
      expect(key2).toBeDefined();
      // Same content should produce same idempotency key
      expect(key1).toBe(key2);
    });

    it('should generate different idempotency keys for different content', async () => {
      const provider = new ResendEmailProvider(config);

      mockSend.mockResolvedValue({
        data: { id: 'msg_123' },
        error: null,
      });

      await provider.sendEmail({
        to: 'user@example.com',
        subject: 'Test Subject 1',
        text: 'Test body',
      });
      await provider.sendEmail({
        to: 'user@example.com',
        subject: 'Test Subject 2',
        text: 'Test body',
      });

      const calls = mockSend.mock.calls;
      const key1 = calls[0]?.[1]?.idempotencyKey;
      const key2 = calls[1]?.[1]?.idempotencyKey;

      expect(key1).toBeDefined();
      expect(key2).toBeDefined();
      // Different content should produce different idempotency keys
      expect(key1).not.toBe(key2);
    });

    it('should return error if html and text are both missing', async () => {
      const provider = new ResendEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
      };

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Either html or text content must be provided');
    });
  });

  /**
   * The Resend SDK never throws for an HTTP or network failure: `send`
   * resolves `{ data: null, error: { statusCode, name, message }, headers }`,
   * with `statusCode: null` and no headers when no answer came. These tests
   * mock it that way.
   */
  describe('failures as the SDK reports them', () => {
    const emailOptions: EmailOptions = {
      to: 'user@example.com',
      subject: 'Test Subject',
      text: 'Test body',
    };

    /** A failure as `send` resolves it; its message quotes the address, as Resend's can. */
    function failed(
      statusCode: number | null,
      name: string,
      headers: Record<string, string> | null = statusCode === null ? null : {}
    ) {
      return {
        data: null,
        error: { statusCode, name, message: `The address ${emailOptions.to} was refused` },
        headers,
      };
    }

    const sent = { data: { id: 'msg_123' }, error: null, headers: {} };

    /** The idempotency key of every attempt, in order. */
    function keysSent(): unknown[] {
      return mockSend.mock.calls.map((call) => call[1]?.idempotencyKey);
    }

    /** Send `emailOptions`, running every wait and attempt timeout to its end. */
    async function sendWithTimers(provider: ResendEmailProvider) {
      const promise = provider.sendEmail(emailOptions);
      await vi.runAllTimersAsync();
      return promise;
    }

    beforeEach(() => {
      vi.useFakeTimers();
    });

    it('sends once more with the same idempotency key after a 429 rate_limit_exceeded', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend
        .mockResolvedValueOnce(failed(429, 'rate_limit_exceeded'))
        .mockResolvedValueOnce(sent);

      const result = await sendWithTimers(provider);

      expect(result).toEqual({ success: true, messageId: 'msg_123' });
      expect(mockSend).toHaveBeenCalledTimes(2);
      const keys = keysSent();
      expect(keys[0]).toEqual(expect.any(String));
      expect(keys[1]).toBe(keys[0]);
    });

    it.each([
      [500, 'internal_server_error'],
      [503, 'application_error'],
      [409, 'concurrent_idempotent_requests'],
      [null, 'application_error'],
    ] as const)(
      'tries again after a resolved %s %s, with the same idempotency key',
      async (statusCode, name) => {
        const provider = new ResendEmailProvider(config);
        mockSend.mockResolvedValueOnce(failed(statusCode, name)).mockResolvedValueOnce(sent);

        const result = await sendWithTimers(provider);

        expect(result.success).toBe(true);
        expect(mockSend).toHaveBeenCalledTimes(2);
        expect(keysSent()[1]).toBe(keysSent()[0]);
      }
    );

    it('reports failure after three retries of a resolved 503, every attempt with the same key', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend.mockResolvedValue(failed(503, 'application_error'));

      const result = await sendWithTimers(provider);

      expect(result.success).toBe(false);
      expect(result.error).toContain('after 3 retries');
      expect(result.error).toContain('status 503, application_error');
      expect(mockSend).toHaveBeenCalledTimes(4); // the first attempt and three retries
      expect(new Set(keysSent()).size).toBe(1);
    });

    it('waits 2 s, 4 s and 8 s between the attempts', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend.mockResolvedValue(failed(503, 'application_error'));

      const start = Date.now();
      const promise = provider.sendEmail(emailOptions);
      for (const [at, calls] of [
        [0, 1],
        [1999, 1],
        [2000, 2],
        [5999, 2],
        [6000, 3],
        [13_999, 3],
        [14_000, 4],
      ] as const) {
        await vi.advanceTimersByTimeAsync(at - (Date.now() - start));
        expect(mockSend).toHaveBeenCalledTimes(calls);
      }
      await expect(promise).resolves.toMatchObject({ success: false });
    });

    it.each([
      [422, 'validation_error'],
      [429, 'daily_quota_exceeded'],
      [429, 'monthly_quota_exceeded'],
      [409, 'invalid_idempotent_request'],
      [403, 'invalid_api_key'],
      [400, 'invalid_attachment'],
    ] as const)('does not retry a resolved %s %s', async (statusCode, name) => {
      const provider = new ResendEmailProvider(config);
      mockSend.mockResolvedValue(failed(statusCode, name));

      const result = await sendWithTimers(provider);

      expect(result.success).toBe(false);
      expect(result.error).toContain(`status ${statusCode}, ${name}`);
      expect(result.error).not.toContain('retries');
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it("reports a failure's status and error name, never Resend's message", async () => {
      const provider = new ResendEmailProvider(config);
      mockSend.mockResolvedValue(failed(422, 'validation_error'));

      const result = await sendWithTimers(provider);

      expect(result).toEqual({
        success: false,
        error: 'Failed to send email via Resend (status 422, validation_error)',
      });
      expect(result.error).not.toContain(emailOptions.to);
    });

    it('reports a failure with no answer as status none, and after the retries', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend.mockResolvedValue(failed(null, 'application_error'));

      const result = await sendWithTimers(provider);

      expect(result.error).toBe(
        'Failed to send email via Resend after 3 retries (status none, application_error)'
      );
    });

    it('does not report an error name that is not a Resend error code', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend.mockResolvedValue({
        data: null,
        error: { statusCode: 400, name: emailOptions.to, message: 'x' },
        headers: {},
      });

      const result = await sendWithTimers(provider);

      expect(result.error).toBe('Failed to send email via Resend (status 400, unknown)');
    });

    it('does not retry an answer that names no status', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend.mockResolvedValue({ data: null, error: { message: 'Bad gateway' }, headers: {} });

      const result = await sendWithTimers(provider);

      expect(result.error).toBe('Failed to send email via Resend (status unknown, unknown)');
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('waits as long as a Retry-After in seconds asks when it is longer than the backoff', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend
        .mockResolvedValueOnce(failed(429, 'rate_limit_exceeded', { 'retry-after': '6' }))
        .mockResolvedValueOnce(sent);

      const promise = provider.sendEmail(emailOptions);
      await vi.advanceTimersByTimeAsync(5999);
      expect(mockSend).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(mockSend).toHaveBeenCalledTimes(2);
      await expect(promise).resolves.toEqual({ success: true, messageId: 'msg_123' });
    });

    it('reads a Retry-After that is an HTTP date', async () => {
      vi.setSystemTime(new Date('2026-11-15T00:00:00.000Z'));
      const provider = new ResendEmailProvider(config);
      mockSend
        .mockResolvedValueOnce(
          failed(503, 'application_error', { 'Retry-After': 'Sun, 15 Nov 2026 00:00:05 GMT' })
        )
        .mockResolvedValueOnce(sent);

      const promise = provider.sendEmail(emailOptions);
      await vi.advanceTimersByTimeAsync(4999);
      expect(mockSend).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(mockSend).toHaveBeenCalledTimes(2);
      await expect(promise).resolves.toMatchObject({ success: true });
    });

    it('keeps the backoff when a Retry-After asks for less', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend
        .mockResolvedValueOnce(failed(429, 'rate_limit_exceeded', { 'retry-after': '1' }))
        .mockResolvedValueOnce(sent);

      const promise = provider.sendEmail(emailOptions);
      await vi.advanceTimersByTimeAsync(1999);
      expect(mockSend).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(mockSend).toHaveBeenCalledTimes(2);
      await expect(promise).resolves.toMatchObject({ success: true });
    });

    it('gives up at once when a Retry-After asks for more than the ceiling', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend.mockResolvedValue(failed(429, 'rate_limit_exceeded', { 'retry-after': '60' }));

      const result = await sendWithTimers(provider);

      expect(result.success).toBe(false);
      expect(result.error).toContain('status 429, rate_limit_exceeded');
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('aborts an attempt after 10 s and tries again with the same key', async () => {
      const provider = new ResendEmailProvider(config);
      // As the SDK does: an aborted request resolves as no answer.
      mockSend
        .mockImplementationOnce(
          (_payload: unknown, { signal }: { signal: AbortSignal }) =>
            new Promise((resolve) =>
              signal.addEventListener('abort', () => resolve(failed(null, 'application_error')), {
                once: true,
              })
            )
        )
        .mockResolvedValueOnce(sent);

      const promise = provider.sendEmail(emailOptions);
      await vi.advanceTimersByTimeAsync(9999);
      expect(mockSend.mock.calls[0]?.[1]?.signal.aborted).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(mockSend.mock.calls[0]?.[1]?.signal.aborted).toBe(true);
      await vi.runAllTimersAsync();

      await expect(promise).resolves.toEqual({ success: true, messageId: 'msg_123' });
      expect(mockSend).toHaveBeenCalledTimes(2);
      expect(keysSent()[1]).toBe(keysSent()[0]);
      expect(mockSend.mock.calls[1]?.[1]?.signal.aborted).toBe(false);
    });

    it('tries again when an aborted attempt is thrown rather than resolved', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend
        .mockImplementationOnce(
          (_payload: unknown, { signal }: { signal: AbortSignal }) =>
            new Promise((_resolve, reject) =>
              signal.addEventListener('abort', () => reject(signal.reason), { once: true })
            )
        )
        .mockResolvedValueOnce(sent);

      const result = await sendWithTimers(provider);

      expect(result.success).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(2);
    });

    it('does not retry a send that throws for another reason, and reports no message', async () => {
      const provider = new ResendEmailProvider(config);
      mockSend.mockRejectedValue(new TypeError(`Cannot send to ${emailOptions.to}`));

      const result = await sendWithTimers(provider);

      expect(result).toEqual({
        success: false,
        error: 'Failed to send email via Resend (the send threw TypeError)',
      });
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
  });
});
