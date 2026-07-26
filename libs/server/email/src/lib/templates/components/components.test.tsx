import { render } from '@react-email/render';
import * as React from 'react';
import { describe, expect, it } from 'vitest';

import { Body, Button, Container, Head, Html, Preview, Section, Text } from './index';

/**
 * These components are vendored from resend/react-email (#333). Upstream's own
 * test suite does not come with them, so these tests pin the behaviour our
 * templates depend on — table-based layout, the Outlook padding hack, margin
 * resets — so a future edit to the vendored source cannot silently change what
 * lands in a mailbox.
 */
async function renderFragment(element: React.ReactElement): Promise<string> {
  return render(element);
}

describe('vendored react-email components', () => {
  describe('Html', () => {
    it('should default to lang="en" and dir="ltr"', async () => {
      const html = await renderFragment(React.createElement(Html, {}, 'hello'));

      expect(html).toContain('lang="en"');
      expect(html).toContain('dir="ltr"');
    });

    it('should allow lang and dir to be overridden', async () => {
      const html = await renderFragment(
        React.createElement(Html, { lang: 'tr', dir: 'rtl' }, 'merhaba')
      );

      expect(html).toContain('lang="tr"');
      expect(html).toContain('dir="rtl"');
    });
  });

  describe('Head', () => {
    it('should emit the charset and Apple reformatting meta tags', async () => {
      const html = await renderFragment(React.createElement(Html, {}, React.createElement(Head)));

      expect(html).toContain('content="text/html; charset=UTF-8"');
      expect(html).toContain('x-apple-disable-message-reformatting');
    });
  });

  describe('Body', () => {
    it('should wrap children in a presentation table for Yahoo/AOL', async () => {
      const html = await renderFragment(
        React.createElement(Body, {}, React.createElement('span', {}, 'content'))
      );

      expect(html).toContain('<body');
      expect(html).toContain('role="presentation"');
      expect(html).toContain('content');
    });

    it('should move styles to the inner cell and reset body margins', async () => {
      const html = await renderFragment(
        React.createElement(Body, { style: { margin: '20px', backgroundColor: '#f6f9fc' } }, 'x')
      );

      // The declared margin is zeroed on <body> itself...
      expect(html).toMatch(/<body[^>]*style="[^"]*margin:0/);
      // ...and reapplied on the inner cell, which Yahoo/AOL preserve.
      expect(html).toMatch(/<td[^>]*style="[^"]*margin:20px/);
    });
  });

  describe('Container', () => {
    it('should apply the default max width and allow overriding it', async () => {
      const defaultHtml = await renderFragment(React.createElement(Container, {}, 'x'));
      expect(defaultHtml).toContain('max-width:37.5em');

      const overriddenHtml = await renderFragment(
        React.createElement(Container, { style: { maxWidth: '20em' } }, 'x')
      );
      expect(overriddenHtml).toContain('max-width:20em');
      expect(overriddenHtml).not.toContain('max-width:37.5em');
    });
  });

  describe('Section', () => {
    it('should render a full-width presentation table carrying the given style', async () => {
      const html = await renderFragment(
        React.createElement(Section, { style: { padding: '0 48px' } }, 'x')
      );

      expect(html).toContain('role="presentation"');
      expect(html).toContain('width="100%"');
      expect(html).toContain('padding:0 48px');
    });
  });

  describe('Text', () => {
    it('should apply default typography and margins', async () => {
      const html = await renderFragment(React.createElement(Text, {}, 'hello'));

      expect(html).toContain('font-size:14px');
      expect(html).toContain('line-height:24px');
      expect(html).toContain('margin-top:16px');
      expect(html).toContain('margin-bottom:16px');
    });

    it('should expand a shorthand margin into its four longhand properties', async () => {
      const html = await renderFragment(
        React.createElement(Text, { style: { margin: '8px 12px' } }, 'hello')
      );

      expect(html).toContain('margin-top:8px');
      expect(html).toContain('margin-bottom:8px');
      expect(html).toContain('margin-left:12px');
      expect(html).toContain('margin-right:12px');
    });
  });

  describe('Button', () => {
    it('should render an anchor targeting a new tab by default', async () => {
      const html = await renderFragment(
        React.createElement(Button, { href: 'https://example.com' }, 'Click')
      );

      expect(html).toContain('href="https://example.com"');
      expect(html).toContain('target="_blank"');
      expect(html).toContain('Click');
    });

    it('should emit the Outlook (mso) conditional padding hack', async () => {
      const html = await renderFragment(
        React.createElement(
          Button,
          { href: 'https://example.com', style: { padding: '12px 24px' } },
          'Click'
        )
      );

      expect(html).toContain('<!--[if mso]>');
      expect(html).toContain('mso-font-width:');
      expect(html).toContain('mso-text-raise:');
    });

    it('should convert em padding to pixels', async () => {
      const html = await renderFragment(
        React.createElement(Button, { href: 'https://example.com', style: { padding: '1em' } }, 'x')
      );

      expect(html).toContain('padding-top:16px');
    });
  });

  describe('Preview', () => {
    it('should render hidden preview text', async () => {
      const html = await renderFragment(React.createElement(Preview, { children: 'Preview copy' }));

      expect(html).toContain('Preview copy');
      expect(html).toContain('display:none');
      expect(html).toContain('max-height:0');
    });

    it('should pad short preview text with invisible characters', async () => {
      const html = await renderFragment(React.createElement(Preview, { children: 'short' }));

      // One zero-width non-joiner per padded character, up to the 150-char cap.
      const padding = html.match(/\u200C/g) ?? [];
      expect(padding).toHaveLength(150 - 'short'.length);
    });

    it('should truncate preview text at 150 characters and not pad it', async () => {
      const long = 'a'.repeat(200);
      const html = await renderFragment(React.createElement(Preview, { children: long }));

      expect(html).toContain('a'.repeat(150));
      expect(html).not.toContain('a'.repeat(151));
      expect(html).not.toMatch(/\u200C/);
    });
  });
});
