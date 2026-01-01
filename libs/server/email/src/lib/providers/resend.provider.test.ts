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

    it('should handle Resend API errors', async () => {
      const provider = new ResendEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      mockSend.mockResolvedValueOnce({
        data: null,
        error: { message: 'Invalid API key' },
      });

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid API key');
    });

    it('should retry on network errors', async () => {
      const provider = new ResendEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      // First call fails with network error
      mockSend.mockRejectedValueOnce(new Error('network timeout')).mockResolvedValueOnce({
        data: { id: 'msg_123' },
        error: null,
      });

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(2);
    });

    it('should retry on rate limit errors', async () => {
      const provider = new ResendEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      // First call fails with rate limit
      mockSend.mockRejectedValueOnce(new Error('rate limit exceeded')).mockResolvedValueOnce({
        data: { id: 'msg_123' },
        error: null,
      });

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(2);
    });

    it('should fail after max retries', async () => {
      vi.useFakeTimers();
      const provider = new ResendEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      // All retries fail
      mockSend.mockRejectedValue(new Error('network timeout'));

      const promise = provider.sendEmail(emailOptions);

      // Fast-forward time to skip all retry delays
      await vi.runAllTimersAsync();

      const result = await promise;

      expect(result.success).toBe(false);
      expect(result.error).toContain('Failed to send email after 3 retries');
      expect(mockSend).toHaveBeenCalledTimes(4); // Initial + 3 retries
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
});
