import { renderToString } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { ClientForm, parseRedirectUris, parseScopes } from './client-form';

describe('parseRedirectUris', () => {
  it('splits on newlines and commas, trimming and dropping blanks', () => {
    expect(parseRedirectUris('https://a.com/cb\n  https://b.com/cb \n\n,https://c.com/cb')).toEqual(
      ['https://a.com/cb', 'https://b.com/cb', 'https://c.com/cb']
    );
  });

  it('returns an empty array for blank input', () => {
    expect(parseRedirectUris('   \n  ')).toEqual([]);
  });
});

describe('parseScopes', () => {
  it('splits on whitespace and commas', () => {
    expect(parseScopes('openid profile, email')).toEqual(['openid', 'profile', 'email']);
  });
});

describe('ClientForm component', () => {
  it('renders a blank create form with the submit label', () => {
    const html = renderToString(<ClientForm submitLabel="Create client" onSubmit={vi.fn()} />);
    expect(html).toContain('Create client');
    expect(html).toContain('Redirect URIs');
    expect(html).toContain('Token endpoint auth method');
  });

  it('pre-fills values in edit mode', () => {
    const html = renderToString(
      <ClientForm
        submitLabel="Save changes"
        onSubmit={vi.fn()}
        initial={{
          name: 'My App',
          redirectUris: ['https://app.example.com/cb'],
          scopes: ['openid', 'profile'],
        }}
      />
    );
    expect(html).toContain('My App');
    expect(html).toContain('https://app.example.com/cb');
    expect(html).toContain('openid profile');
    expect(html).toContain('Save changes');
  });

  it('surfaces a top-level error', () => {
    const html = renderToString(
      <ClientForm submitLabel="Create client" onSubmit={vi.fn()} error="Invalid redirect URI" />
    );
    expect(html).toContain('Invalid redirect URI');
  });
});
