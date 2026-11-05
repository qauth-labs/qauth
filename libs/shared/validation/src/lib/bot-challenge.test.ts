import { describe, expect, it } from 'vitest';

import {
  BOT_CHALLENGE_SITE_KEY_PATTERN,
  botChallengeProviderNameProblem,
  botChallengeVerifyUrlProblem,
} from './bot-challenge';

describe('the hosted bot challenge’s settings (#643)', () => {
  it('takes a provider name the captcha step can send, and never pow', () => {
    for (const name of ['turnstile', 'hcaptcha', 'recaptcha_v3', 'a', `a${'b'.repeat(31)}`]) {
      expect(botChallengeProviderNameProblem(name), name).toBeUndefined();
    }
    for (const name of ['pow', 'Turnstile', '1captcha', '', `a${'b'.repeat(32)}`, 'two words']) {
      expect(botChallengeProviderNameProblem(name), name).toBeDefined();
    }
  });

  it('takes a site key of letters, digits, dots, dashes and underscores', () => {
    expect(BOT_CHALLENGE_SITE_KEY_PATTERN.test('0x4AAAAAAABkMYinukE8nzY')).toBe(true);
    expect(BOT_CHALLENGE_SITE_KEY_PATTERN.test('a key')).toBe(false);
    expect(BOT_CHALLENGE_SITE_KEY_PATTERN.test('')).toBe(false);
  });

  it('takes an https verify URL with no credentials, query or fragment', () => {
    expect(
      botChallengeVerifyUrlProblem('https://challenges.cloudflare.com/turnstile/v0/siteverify')
    ).toBeUndefined();
    for (const url of [
      'http://example.com/siteverify',
      'https://user:pass@example.com/siteverify',
      'https://example.com/siteverify?x=1',
      'https://example.com/siteverify?',
      'https://example.com/siteverify#x',
      '/siteverify',
      'not a url',
    ]) {
      expect(botChallengeVerifyUrlProblem(url), url).toBeDefined();
    }
  });
});
