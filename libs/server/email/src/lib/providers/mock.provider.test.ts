import { beforeEach, describe, expect, it } from 'vitest';

import type { EmailOptions } from '../../types';
import { MockEmailProvider } from './mock.provider';

describe('MockEmailProvider', () => {
  let provider: MockEmailProvider;

  beforeEach(() => {
    provider = new MockEmailProvider();
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
    expect(result.messageId).toMatch(/^mock-/);
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
    expect(sentEmails[0]?.to).toBe('user1@example.com');
    expect(sentEmails[1]?.to).toBe('user2@example.com');
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

  it('should generate unique message IDs', async () => {
    const options: EmailOptions = {
      to: 'user@example.com',
      subject: 'Test',
      text: 'Body',
    };

    const result1 = await provider.sendEmail(options);
    await new Promise((resolve) => setTimeout(resolve, 10)); // Small delay
    const result2 = await provider.sendEmail(options);

    expect(result1.messageId).toBeDefined();
    expect(result2.messageId).toBeDefined();
    expect(result1.messageId).not.toBe(result2.messageId);
  });
});
