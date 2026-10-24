import { describe, expect, it } from 'vitest';

import { verificationTokenIn } from './mail';

const TOKEN = 'a3'.repeat(32);

describe('verificationTokenIn', () => {
  it('finds the token of the verification link every release sends', () => {
    expect(
      verificationTokenIn(`Verify your email:\nhttp://localhost:3000/auth/verify?token=${TOKEN}\n`)
    ).toBe(TOKEN);
  });

  it('finds it in an HTML href, after another parameter', () => {
    expect(
      verificationTokenIn(`<a href="https://id.example/verify?lang=en&token=${TOKEN}">Verify</a>`)
    ).toBe(TOKEN);
  });

  it('ignores a token of the wrong length and a mail without a link', () => {
    expect(verificationTokenIn(`/auth/verify?token=${TOKEN.slice(2)}`)).toBeUndefined();
    expect(verificationTokenIn(`/auth/verify?token=${TOKEN}ff`)).toBeUndefined();
    expect(verificationTokenIn('Welcome to QAuth.')).toBeUndefined();
  });
});
