import { beforeEach, describe, expect, it } from 'vitest';

import type { EmailService } from '../types';
import { createEmailService } from './email-service';
import { MockEmailProvider } from './providers/mock.provider';

describe('createEmailService', () => {
  it('should create an email service', () => {
    const provider = new MockEmailProvider();
    const service = createEmailService(provider);
    expect(service).toHaveProperty('sendVerificationEmail');
  });

  it('should create an email service with config', () => {
    const provider = new MockEmailProvider();
    const service = createEmailService(provider, {
      defaultFrom: 'noreply@example.com',
      baseUrl: 'https://example.com',
    });
    expect(service).toHaveProperty('sendVerificationEmail');
  });
});

describe('EmailService', () => {
  let service: EmailService;
  let mockProvider: MockEmailProvider;

  beforeEach(() => {
    mockProvider = new MockEmailProvider();
    service = createEmailService(mockProvider);
  });

  describe('sendVerificationEmail', () => {
    it('should send a verification email', async () => {
      const result = await service.sendVerificationEmail('user@example.com', 'token123');
      expect(result.success).toBe(true);
      expect(result.messageId).toBeDefined();
    });

    it('should include token in email', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123');

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails).toHaveLength(1);
      expect(sentEmails[0]?.to).toBe('user@example.com');
      expect(sentEmails[0]?.text).toContain('token123');
      expect(sentEmails[0]?.html).toContain('token123');
    });

    it('should use default subject if not provided', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123');

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.subject).toBe('Verify your email address');
    });

    it('should use custom subject if provided', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123', {
        subject: 'Custom Subject',
      });

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.subject).toBe('Custom Subject');
    });

    it('should include verification URL when baseUrl is configured', async () => {
      const customProvider = new MockEmailProvider();
      const customService = createEmailService(customProvider, {
        baseUrl: 'https://example.com',
      });
      await customService.sendVerificationEmail('user@example.com', 'token123');

      const sentEmails = customProvider.getSentEmails();
      expect(sentEmails[0]?.text).toContain('https://example.com/auth/verify?token=token123');
      expect(sentEmails[0]?.html).toContain('https://example.com/auth/verify?token=token123');
    });

    it('should include token in text when baseUrl is not configured', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123');

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.text).toContain('#token=token123');
    });

    it('should use defaultFrom from config', async () => {
      const customProvider = new MockEmailProvider();
      const customService = createEmailService(customProvider, {
        defaultFrom: 'noreply@example.com',
      });
      await customService.sendVerificationEmail('user@example.com', 'token123');

      const sentEmails = customProvider.getSentEmails();
      expect(sentEmails[0]?.from).toBe('noreply@example.com');
    });

    it('should use custom from if provided in options', async () => {
      const customProvider = new MockEmailProvider();
      const customService = createEmailService(customProvider, {
        defaultFrom: 'noreply@example.com',
      });
      await customService.sendVerificationEmail('user@example.com', 'token123', {
        from: 'custom@example.com',
      });

      const sentEmails = customProvider.getSentEmails();
      expect(sentEmails[0]?.from).toBe('custom@example.com');
    });

    it('should use custom text if provided', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123', {
        text: 'Custom text',
      });

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.text).toBe('Custom text');
    });

    it('should use custom html if provided', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123', {
        html: '<p>Custom HTML</p>',
      });

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.html).toBe('<p>Custom HTML</p>');
    });
  });
});
