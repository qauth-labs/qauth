import { render } from '@react-email/components';
import * as React from 'react';
import { describe, expect, it } from 'vitest';

import { VerifyEmail, type VerifyEmailProps } from './verification-email';

describe('VerifyEmail', () => {
  const defaultProps: VerifyEmailProps = {
    verificationUrl: 'https://example.com/auth/verify?token=abc123',
    expiresIn: '24 hours',
  };

  it('should render with required props', async () => {
    const template = React.createElement(VerifyEmail, defaultProps);
    const html = await render(template);

    expect(html).toBeDefined();
    expect(html).toContain('Verify Your Email Address');
    expect(html).toContain(defaultProps.verificationUrl);
    expect(html).toContain(defaultProps.expiresIn);
  });

  it('should include verification URL in the rendered HTML', async () => {
    const template = React.createElement(VerifyEmail, defaultProps);
    const html = await render(template);

    expect(html).toContain(defaultProps.verificationUrl);
    expect(html).toContain('href=');
  });

  it('should include expiration time in the rendered HTML', async () => {
    const template = React.createElement(VerifyEmail, defaultProps);
    const html = await render(template);

    // Account for HTML comments inserted by React Email
    expect(html).toContain('expire in');
    expect(html).toContain('24 hours');
  });

  it('should render with different expiration times', async () => {
    const props: VerifyEmailProps = {
      verificationUrl: 'https://example.com/auth/verify?token=abc123',
      expiresIn: '1 hour',
    };

    const template = React.createElement(VerifyEmail, props);
    const html = await render(template);

    // Account for HTML comments inserted by React Email
    expect(html).toContain('expire in');
    expect(html).toContain('1 hour');
  });

  it('should include verify button', async () => {
    const template = React.createElement(VerifyEmail, defaultProps);
    const html = await render(template);

    expect(html).toContain('Verify Email');
    expect(html).toContain('button');
  });

  it('should include preview text', async () => {
    const template = React.createElement(VerifyEmail, defaultProps);
    const html = await render(template);

    expect(html).toContain('Verify your email address to complete your registration');
  });

  it('should render with different verification URLs', async () => {
    const props: VerifyEmailProps = {
      verificationUrl: 'https://different.com/verify?token=xyz789',
      expiresIn: '24 hours',
    };

    const template = React.createElement(VerifyEmail, props);
    const html = await render(template);

    expect(html).toContain('https://different.com/verify?token=xyz789');
  });
});
