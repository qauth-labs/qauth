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

/** A public address for `smtp.example.com`, as a resolver would answer. */
const PUBLIC_ADDRESS = '93.184.216.34';

describe('SmtpEmailProvider', () => {
  let config: SmtpProviderConfig;
  let mockSendMail: ReturnType<typeof vi.fn>;
  let lookup: ReturnType<typeof vi.fn<(hostname: string) => Promise<{ address: string }[]>>>;
  const createTransport = () =>
    (nodemailer as unknown as { createTransport: ReturnType<typeof vi.fn> }).createTransport;

  const message: EmailOptions = { to: 'user@example.com', subject: 'Hi', text: 'Body' };

  beforeEach(() => {
    lookup = vi.fn<(hostname: string) => Promise<{ address: string }[]>>(async () => [
      { address: PUBLIC_ADDRESS },
    ]);
    config = {
      host: 'smtp.example.com',
      port: 587,
      secure: false,
      auth: {
        user: 'user@example.com',
        pass: 'password123',
      },
      fromAddress: 'noreply@example.com',
      connection: { allowPlaintext: false, allowedHosts: new Set(), lookup },
    };

    mockSendMail = vi.fn(async () => ({ messageId: 'smtp-msg-1' }));
    createTransport().mockClear();
    createTransport().mockReturnValue({
      sendMail: mockSendMail,
    });
  });

  it('should create an SMTP provider without connecting', () => {
    const provider = new SmtpEmailProvider(config);
    expect(provider).toHaveProperty('sendEmail');
    expect(createTransport()).not.toHaveBeenCalled();
  });

  it('dials the address the host resolved to, checks the certificate against the host name, and requires STARTTLS', async () => {
    const provider = new SmtpEmailProvider(config);

    expect((await provider.sendEmail(message)).success).toBe(true);

    expect(lookup).toHaveBeenCalledWith('smtp.example.com');
    expect(createTransport()).toHaveBeenCalledWith({
      host: PUBLIC_ADDRESS,
      port: 587,
      secure: false,
      auth: config.auth,
      requireTLS: true,
      servername: 'smtp.example.com',
      tls: { rejectUnauthorized: true, servername: 'smtp.example.com' },
    });
  });

  it('sends without STARTTLS only when the operator allows a plaintext relay', async () => {
    await new SmtpEmailProvider({
      ...config,
      connection: { ...config.connection!, allowPlaintext: true },
    }).sendEmail(message);
    expect(createTransport()).toHaveBeenLastCalledWith(
      expect.objectContaining({ requireTLS: false })
    );

    // Implicit TLS needs no STARTTLS.
    await new SmtpEmailProvider({ ...config, secure: true, port: 465 }).sendEmail(message);
    expect(createTransport()).toHaveBeenLastCalledWith(
      expect.objectContaining({ secure: true, requireTLS: false })
    );
  });

  it('is strict without a connection policy: STARTTLS required, public addresses only', async () => {
    const strict: SmtpProviderConfig = { ...config, host: '10.0.0.25' };
    delete strict.connection;
    const provider = new SmtpEmailProvider(strict);

    const result = await provider.sendEmail(message);

    expect(result.success).toBe(false);
    expect(result.error).toContain('The SMTP host 10.0.0.25 is refused');
    expect(createTransport()).not.toHaveBeenCalled();
  });

  it.each([
    ['a private address', '10.0.0.25'],
    ['a loopback address', '127.0.0.1'],
    ['a link-local address', '169.254.10.10'],
    ['a unique-local address', 'fd12:3456::25'],
    ['a cloud metadata address', '169.254.169.254'],
  ])('refuses a name that resolves only to %s, before it connects', async (_kind, address) => {
    lookup.mockResolvedValue([{ address }]);

    const result = await new SmtpEmailProvider(config).sendEmail(message);

    expect(result.success).toBe(false);
    expect(result.error).toContain('resolves to no public address');
    expect(result.error).not.toContain('password123');
    expect(createTransport()).not.toHaveBeenCalled();
  });

  it('dials the public address of a name that resolves to a private one too', async () => {
    lookup.mockResolvedValue([{ address: '10.0.0.25' }, { address: PUBLIC_ADDRESS }]);

    await new SmtpEmailProvider(config).sendEmail(message);

    expect(createTransport()).toHaveBeenCalledWith(
      expect.objectContaining({ host: PUBLIC_ADDRESS })
    );
  });

  it("reaches a private address of a host on the operator's list, never a metadata one", async () => {
    const allowed = {
      ...config,
      host: 'Relay.Internal.',
      connection: { ...config.connection!, allowedHosts: new Set(['relay.internal', '127.0.0.1']) },
    };
    lookup.mockResolvedValue([{ address: '10.0.0.25' }]);
    expect((await new SmtpEmailProvider(allowed).sendEmail(message)).success).toBe(true);
    expect(createTransport()).toHaveBeenLastCalledWith(
      expect.objectContaining({ host: '10.0.0.25', servername: 'relay.internal' })
    );

    // A listed IP literal is dialled as it is, with no TLS server name.
    expect(
      (await new SmtpEmailProvider({ ...allowed, host: '127.0.0.1' }).sendEmail(message)).success
    ).toBe(true);
    expect(createTransport()).toHaveBeenLastCalledWith(
      expect.objectContaining({ host: '127.0.0.1', tls: { rejectUnauthorized: true } })
    );

    createTransport().mockClear();
    lookup.mockResolvedValue([{ address: '169.254.169.254' }]);
    expect((await new SmtpEmailProvider(allowed).sendEmail(message)).success).toBe(false);
    expect(createTransport()).not.toHaveBeenCalled();
  });

  it('refuses localhost unless the operator lists it', async () => {
    const local = { ...config, host: 'localhost' };
    expect((await new SmtpEmailProvider(local).sendEmail(message)).error).toContain(
      'The SMTP host localhost is refused'
    );
    expect(lookup).not.toHaveBeenCalled();

    lookup.mockResolvedValue([{ address: '127.0.0.1' }]);
    const listed = {
      ...local,
      connection: { ...config.connection!, allowedHosts: new Set(['localhost']) },
    };
    expect((await new SmtpEmailProvider(listed).sendEmail(message)).success).toBe(true);
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
