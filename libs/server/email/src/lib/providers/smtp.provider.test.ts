import nodemailer from 'nodemailer';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { EmailOptions, SmtpProviderConfig } from '../../types';
import { SmtpEmailProvider } from './smtp.provider';

// Mock nodemailer
vi.mock('nodemailer', () => {
  const mockSendMail = vi.fn();
  const mockCreateTransport = vi.fn(() => ({
    sendMail: mockSendMail,
  }));

  return {
    default: {
      createTransport: mockCreateTransport,
    },
  };
});

describe('SmtpEmailProvider', () => {
  let config: SmtpProviderConfig;
  let mockSendMail: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    config = {
      host: 'smtp.example.com',
      port: 587,
      secure: false,
      auth: {
        user: 'user@example.com',
        pass: 'password123',
      },
      fromAddress: 'noreply@example.com',
    };

    const nodemailerMock = nodemailer as unknown as {
      createTransport: ReturnType<typeof vi.fn>;
    };
    mockSendMail = vi.fn();
    nodemailerMock.createTransport.mockReturnValue({
      sendMail: mockSendMail,
    });
  });

  it('should create an SMTP provider', () => {
    const provider = new SmtpEmailProvider(config);
    expect(provider).toHaveProperty('sendEmail');
    expect(nodemailer.createTransport).toHaveBeenCalledWith({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.auth,
      requireTLS: undefined,
      ignoreTLS: undefined,
    });
  });

  it('should create transport with TLS options', () => {
    const configWithTls: SmtpProviderConfig = {
      ...config,
      options: {
        requireTLS: true,
        ignoreTLS: false,
      },
    };

    new SmtpEmailProvider(configWithTls);

    expect(nodemailer.createTransport).toHaveBeenCalledWith(
      expect.objectContaining({
        requireTLS: true,
        ignoreTLS: false,
      })
    );
  });

  describe('sendEmail', () => {
    it('should send an email successfully', async () => {
      const provider = new SmtpEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
        html: '<p>Test body</p>',
      };

      mockSendMail.mockResolvedValueOnce({
        messageId: 'smtp-msg-123',
      });

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('smtp-msg-123');
      expect(mockSendMail).toHaveBeenCalledWith({
        from: config.fromAddress,
        to: emailOptions.to,
        subject: emailOptions.subject,
        text: emailOptions.text,
        html: emailOptions.html,
      });
    });

    it('should use from address from options if provided', async () => {
      const provider = new SmtpEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
        from: 'custom@example.com',
      };

      mockSendMail.mockResolvedValueOnce({
        messageId: 'smtp-msg-123',
      });

      await provider.sendEmail(emailOptions);

      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          from: 'custom@example.com',
        })
      );
    });

    it('should return error if from address is missing', async () => {
      const provider = new SmtpEmailProvider({
        ...config,
        fromAddress: undefined,
      });
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('From address is required');
    });

    it('should handle connection errors', async () => {
      const provider = new SmtpEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      mockSendMail.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('SMTP connection error');
      expect(result.error).toContain('ECONNREFUSED');
    });

    it('should handle authentication errors', async () => {
      const provider = new SmtpEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      mockSendMail.mockRejectedValueOnce(new Error('Invalid login'));

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('SMTP connection error');
    });

    it('should handle timeout errors', async () => {
      const provider = new SmtpEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      mockSendMail.mockRejectedValueOnce(new Error('ETIMEDOUT'));

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(false);
      expect(result.error).toContain('SMTP connection error');
    });

    it('should handle generic errors', async () => {
      const provider = new SmtpEmailProvider(config);
      const emailOptions: EmailOptions = {
        to: 'user@example.com',
        subject: 'Test Subject',
        text: 'Test body',
      };

      mockSendMail.mockRejectedValueOnce(new Error('Unknown error'));

      const result = await provider.sendEmail(emailOptions);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Unknown error');
    });

    it('should return error if html and text are both missing', async () => {
      const provider = new SmtpEmailProvider(config);
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
