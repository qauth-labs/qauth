import { render } from '@react-email/render';
import * as React from 'react';
import { describe, expect, it } from 'vitest';

import { AccountExistsEmail } from './account-exists-email';

describe('AccountExistsEmail', () => {
  it('tells the owner an account already exists and nothing changed', async () => {
    const text = await render(React.createElement(AccountExistsEmail), { plainText: true });

    expect(text).toContain('You already have an account');
    expect(text).toContain('no new account was created');
    expect(text).toContain('sign in with your existing password');
  });

  it('renders no link or button', async () => {
    const html = await render(React.createElement(AccountExistsEmail));

    expect(html).not.toContain('href=');
  });

  it('includes preview text', async () => {
    const html = await render(React.createElement(AccountExistsEmail));

    expect(html).toContain('Someone tried to create an account with your email address');
  });
});
