import { beforeEach, describe, expect, it } from 'vitest';

import {
  createEmailService,
  createMockEmailProvider,
  type EmailOptions,
  type EmailService,
} from './email-service';

describe('createEmailService', () => {
  it('should create an email service', () => {
    const provider = createMockEmailProvider();
    const service = createEmailService(provider);
    expect(service).toHaveProperty('sendVerificationEmail');
  });

  it('should create an email service with config', () => {
    const provider = createMockEmailProvider();
    const service = createEmailService(provider, {
      defaultFrom: 'noreply@example.com',
      baseUrl: 'https://example.com',
    });
    expect(service).toHaveProperty('sendVerificationEmail');
  });
});

describe('EmailService', () => {
  let service: EmailService;
  let mockProvider: ReturnType<typeof createMockEmailProvider>;

  beforeEach(() => {
    mockProvider = createMockEmailProvider();
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
      const customProvider = createMockEmailProvider();
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
      expect(sentEmails[0]?.text).toContain('Use token: token123');
    });

    it('should use defaultFrom from config', async () => {
      const customProvider = createMockEmailProvider();
      const customService = createEmailService(customProvider, {
        defaultFrom: 'noreply@example.com',
      });
      await customService.sendVerificationEmail('user@example.com', 'token123');

      const sentEmails = customProvider.getSentEmails();
      expect(sentEmails[0]?.from).toBe('noreply@example.com');
    });

    it('should use custom from if provided in options', async () => {
      const customProvider = createMockEmailProvider();
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

describe('MockEmailProvider', () => {
  let provider: ReturnType<typeof createMockEmailProvider>;

  beforeEach(() => {
    provider = createMockEmailProvider();
  });

  it('should send an email', async () => {
    const options: EmailOptions = {
      to: 'user@example.com',
      subject: 'Test Subject',
      text: 'Test body',
    };

    const result = await provider.sendEmail(options);
    expect(result.success).toBe(true);
    expect(result.messageId).toBeDefined();
  });

  it('should store sent emails', async () => {
    const options: EmailOptions = {
      to: 'user@example.com',
      subject: 'Test Subject',
      text: 'Test body',
    };

    await provider.sendEmail(options);
    const sentEmails = provider.getSentEmails();
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0]).toEqual(options);
  });

  it('should store multiple sent emails', async () => {
    await provider.sendEmail({
      to: 'user1@example.com',
      subject: 'Subject 1',
      text: 'Body 1',
    });
    await provider.sendEmail({
      to: 'user2@example.com',
      subject: 'Subject 2',
      text: 'Body 2',
    });

    const sentEmails = provider.getSentEmails();
    expect(sentEmails).toHaveLength(2);
  });

  it('should clear sent emails', async () => {
    await provider.sendEmail({
      to: 'user@example.com',
      subject: 'Test',
      text: 'Body',
    });

    expect(provider.getSentEmails()).toHaveLength(1);
    provider.clearSentEmails();
    expect(provider.getSentEmails()).toHaveLength(0);
  });

  it('should return a copy of sent emails', async () => {
    await provider.sendEmail({
      to: 'user@example.com',
      subject: 'Test',
      text: 'Body',
    });

    const emails1 = provider.getSentEmails();
    const emails2 = provider.getSentEmails();
    expect(emails1).not.toBe(emails2); // Different array instances
    expect(emails1).toEqual(emails2); // Same content
  });

  it('should handle HTML emails', async () => {
    const options: EmailOptions = {
      to: 'user@example.com',
      subject: 'Test',
      html: '<p>HTML body</p>',
    };

    await provider.sendEmail(options);
    const sentEmails = provider.getSentEmails();
    expect(sentEmails[0]?.html).toBe('<p>HTML body</p>');
  });

  it('should handle emails with from address', async () => {
    const options: EmailOptions = {
      to: 'user@example.com',
      subject: 'Test',
      text: 'Body',
      from: 'sender@example.com',
    };

    await provider.sendEmail(options);
    const sentEmails = provider.getSentEmails();
    expect(sentEmails[0]?.from).toBe('sender@example.com');
  });
});
