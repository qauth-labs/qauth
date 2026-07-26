import { render } from '@react-email/render';
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

  // The components below are vendored rather than imported from the deprecated
  // `@react-email/components` barrel (#333). These assertions pin the markup
  // those primitives produce, so a change to the vendored source shows up here
  // instead of in someone's inbox.
  describe('rendered markup', () => {
    it('should produce a table-based layout with the expected structure', async () => {
      const template = React.createElement(VerifyEmail, defaultProps);
      const html = await render(template);

      expect(html).toContain('<!DOCTYPE html');
      expect(html).toContain('lang="en"');
      expect(html).toContain('content="text/html; charset=UTF-8"');
      expect(html).toContain('x-apple-disable-message-reformatting');
      expect(html).toContain('role="presentation"');
      expect(html).toContain('max-width:37.5em');
      // Outlook conditional padding hack emitted by the Button primitive.
      expect(html).toContain('<!--[if mso]>');
      expect(html).toContain('mso-font-width:');
    });

    it('should keep the brand styling of the call-to-action button', async () => {
      const template = React.createElement(VerifyEmail, defaultProps);
      const html = await render(template);

      expect(html).toContain('background-color:#2563eb');
      expect(html).toContain('padding-top:12px');
      expect(html).toContain('padding-left:24px');
    });

    it('should render a readable plain-text version', async () => {
      const template = React.createElement(VerifyEmail, defaultProps);
      const text = await render(template, { plainText: true });

      expect(text).toContain('Verify Your Email Address');
      expect(text).toContain('Thank you for registering with QAuth');
      expect(text).toContain(defaultProps.verificationUrl);
      expect(text).toContain(`This verification link will expire in ${defaultProps.expiresIn}.`);
      // Plain text must not leak markup or the hidden preview padding.
      expect(text).not.toContain('<');
      expect(text).not.toMatch(/\u200C/);
    });
  });
});
