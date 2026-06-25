import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { clientErrorMessage } from './client-error';
import { SecretReveal } from './secret-reveal';

describe('SecretReveal component', () => {
  it('shows the one-time secret with a "won\'t be shown again" warning', () => {
    const html = renderToString(
      <SecretReveal
        title="Client created"
        clientId="client-uuid"
        clientSecret={'a'.repeat(64)}
        onDone={vi.fn()}
      />
    );
    expect(html).toContain('Client created');
    expect(html).toContain('client-uuid');
    expect(html).toContain('a'.repeat(64));
    expect(html).toContain('not');
    expect(html).toContain('shown again');
  });

  it('omits the secret block for a public client (no secret)', () => {
    const html = renderToString(
      <SecretReveal title="Client created" clientId="client-uuid" onDone={vi.fn()} />
    );
    expect(html).toContain('client-uuid');
    expect(html).toContain('public client');
    expect(html).toContain('Client ID');
    expect(html).not.toContain('Client secret');
  });
});

describe('clientErrorMessage', () => {
  it('explains a 404 as not-found / not-owned', () => {
    expect(clientErrorMessage({ code: 'NOT_FOUND', message: '', status: 404 })).toContain(
      'not found'
    );
  });

  it('joins validation detail arrays', () => {
    expect(
      clientErrorMessage({
        code: 'VALIDATION_ERROR',
        message: 'bad',
        details: ['Redirect URI must be https.', 'Name is required.'],
        status: 400,
      })
    ).toBe('Redirect URI must be https. Name is required.');
  });

  it('maps rate limiting to a wait-and-retry message', () => {
    expect(clientErrorMessage({ code: 'RATE_LIMITED', message: '', status: 429 })).toContain(
      'Too many requests'
    );
  });
});
