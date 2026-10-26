import { beforeEach, describe, expect, it } from 'vitest';

import type { EmailService } from '../types';
import { createEmailService } from './email-service';
import { MockEmailProvider } from './providers/mock.provider';

/** Where the verification links of these mails point: the realm's issuer. */
const LINK = { baseUrl: 'https://auth.example.com' };

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
      const result = await service.sendVerificationEmail('user@example.com', 'token123', LINK);
      expect(result.success).toBe(true);
      expect(result.messageId).toBeDefined();
    });

    it('should include token in email', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123', LINK);

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails).toHaveLength(1);
      expect(sentEmails[0]?.to).toBe('user@example.com');
      expect(sentEmails[0]?.text).toContain('token123');
      expect(sentEmails[0]?.html).toContain('token123');
    });

    it('should use default subject if not provided', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123', LINK);

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.subject).toBe('Verify your email address');
    });

    it('should use custom subject if provided', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123', LINK, {
        subject: 'Custom Subject',
      });

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.subject).toBe('Custom Subject');
    });

    it('should include the verification URL on the base the mail is given', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123', LINK);

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.text).toContain('https://auth.example.com/auth/verify?token=token123');
      expect(sentEmails[0]?.html).toContain('https://auth.example.com/auth/verify?token=token123');
    });

    it('should link each mail to its own base, as realms on one server need (#490)', async () => {
      await service.sendVerificationEmail('a@example.com', 'token-a', LINK);
      await service.sendVerificationEmail('b@example.com', 'token-b', {
        baseUrl: 'https://b.example.com',
      });

      const [first, second] = mockProvider.getSentEmails();
      expect(first?.text).toContain('https://auth.example.com/auth/verify?token=token-a');
      expect(second?.text).toContain('https://b.example.com/auth/verify?token=token-b');
      expect(second?.text).not.toContain('auth.example.com');
      expect(second?.html).not.toContain('auth.example.com');
    });

    it('should use defaultFrom from config', async () => {
      const customProvider = new MockEmailProvider();
      const customService = createEmailService(customProvider, {
        defaultFrom: 'noreply@example.com',
      });
      await customService.sendVerificationEmail('user@example.com', 'token123', LINK);

      const sentEmails = customProvider.getSentEmails();
      expect(sentEmails[0]?.from).toBe('noreply@example.com');
    });

    it('should use custom from if provided in options', async () => {
      const customProvider = new MockEmailProvider();
      const customService = createEmailService(customProvider, {
        defaultFrom: 'noreply@example.com',
      });
      await customService.sendVerificationEmail('user@example.com', 'token123', LINK, {
        from: 'custom@example.com',
      });

      const sentEmails = customProvider.getSentEmails();
      expect(sentEmails[0]?.from).toBe('custom@example.com');
    });

    it('should use custom text if provided', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123', LINK, {
        text: 'Custom text',
      });

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.text).toBe('Custom text');
    });

    it('should use custom html if provided', async () => {
      await service.sendVerificationEmail('user@example.com', 'token123', LINK, {
        html: '<p>Custom HTML</p>',
      });

      const sentEmails = mockProvider.getSentEmails();
      expect(sentEmails[0]?.html).toBe('<p>Custom HTML</p>');
    });

    describe('expiry copy (#334)', () => {
      it('should state 24 hours when no expiry is configured', async () => {
        await service.sendVerificationEmail('user@example.com', 'token123', LINK);

        const sentEmails = mockProvider.getSentEmails();
        expect(sentEmails[0]?.text).toContain('expire in 24 hours');
        expect(sentEmails[0]?.html).toContain('24 hours');
      });

      it('should reflect a non-default configured expiry', async () => {
        const customProvider = new MockEmailProvider();
        const customService = createEmailService(customProvider, {
          verificationTokenExpiry: 3600,
        });
        await customService.sendVerificationEmail('user@example.com', 'token123', LINK);

        const sentEmails = customProvider.getSentEmails();
        expect(sentEmails[0]?.text).toContain('expire in 1 hour');
        expect(sentEmails[0]?.html).toContain('1 hour');
        expect(sentEmails[0]?.text).not.toContain('24 hours');
        expect(sentEmails[0]?.html).not.toContain('24 hours');
      });

      it('should render the default expiry copy unchanged when 86400 is configured', async () => {
        const customProvider = new MockEmailProvider();
        const customService = createEmailService(customProvider, {
          verificationTokenExpiry: 86400,
        });
        await customService.sendVerificationEmail('user@example.com', 'token123', LINK);

        const sentEmails = customProvider.getSentEmails();
        expect(sentEmails[0]?.text).toContain('expire in 24 hours');
      });

      it('should humanize an expiry that is not a whole number of hours', async () => {
        const customProvider = new MockEmailProvider();
        const customService = createEmailService(customProvider, {
          verificationTokenExpiry: 5400,
        });
        await customService.sendVerificationEmail('user@example.com', 'token123', LINK);

        const sentEmails = customProvider.getSentEmails();
        expect(sentEmails[0]?.text).toContain('expire in 1 hour and 30 minutes');
      });

      it('should express multi-day expiries in days', async () => {
        const customProvider = new MockEmailProvider();
        const customService = createEmailService(customProvider, {
          verificationTokenExpiry: 259200,
        });
        await customService.sendVerificationEmail('user@example.com', 'token123', LINK);

        const sentEmails = customProvider.getSentEmails();
        expect(sentEmails[0]?.text).toContain('expire in 3 days');
      });
    });
  });

  describe('sendAccountExistsEmail', () => {
    it('sends the notice to the address with its own subject', async () => {
      const result = await service.sendAccountExistsEmail('owner@example.com');

      expect(result.success).toBe(true);
      const sent = mockProvider.getSentEmails();
      expect(sent).toHaveLength(1);
      expect(sent[0]?.to).toBe('owner@example.com');
      expect(sent[0]?.subject).toBe('Someone tried to register with your email address');
      expect(sent[0]?.text).toContain('You already have an account');
      expect(sent[0]?.html).toContain('You already have an account');
    });

    it('carries no link, so nothing in it can act on the account', async () => {
      const customProvider = new MockEmailProvider();
      const customService = createEmailService(customProvider);
      await customService.sendAccountExistsEmail('owner@example.com');

      const sent = customProvider.getSentEmails();
      expect(sent[0]?.html).not.toContain('href=');
      expect(sent[0]?.text).not.toContain('https://');
    });

    it('uses the default sender and honours overrides', async () => {
      const customProvider = new MockEmailProvider();
      const customService = createEmailService(customProvider, {
        defaultFrom: 'noreply@example.com',
      });
      await customService.sendAccountExistsEmail('owner@example.com', { subject: 'Custom' });

      const sent = customProvider.getSentEmails();
      expect(sent[0]?.from).toBe('noreply@example.com');
      expect(sent[0]?.subject).toBe('Custom');
    });
  });
});
