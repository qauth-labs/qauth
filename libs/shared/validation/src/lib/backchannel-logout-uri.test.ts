import { describe, expect, it } from 'vitest';

import {
  BACKCHANNEL_LOGOUT_URI_MAX_LENGTH,
  backchannelLogoutUriProblem,
} from './backchannel-logout-uri';

describe('backchannelLogoutUriProblem (OpenID Connect Back-Channel Logout 1.0 §2.2, #624)', () => {
  it.each([
    'https://app.example/logout',
    'https://app.example:8443/auth/backchannel?tenant=a&x=1',
    'https://xn--bcher-kva.example/logout',
  ])('accepts %s', (uri) => {
    expect(backchannelLogoutUriProblem(uri)).toBeUndefined();
  });

  it.each([
    ['http://app.example/logout', 'must use https'],
    ['https://app.example/logout#frag', 'must not include a fragment'],
    ['https://app.example/logout#', 'must not include a fragment'],
    ['https://user:pass@app.example/logout', 'must not carry a user name or password'],
    ['https://user@app.example/logout', 'must not carry a user name or password'],
    ['/logout', 'is not an absolute URI'],
    ['javascript:alert(1)', 'must use https'],
    ['https://app.example/log\tout', 'must be printable ASCII, with no space, tab or line break'],
    ['https://app.example/ logout', 'must be printable ASCII, with no space, tab or line break'],
    ['https://bücher.example/logout', 'must be printable ASCII, with no space, tab or line break'],
    ['', `must be 1 to ${BACKCHANNEL_LOGOUT_URI_MAX_LENGTH} characters`],
  ])('refuses %j: %s', (uri, problem) => {
    expect(backchannelLogoutUriProblem(uri)).toBe(problem);
  });

  it('refuses a URI over the length bound and accepts one at it', () => {
    const base = 'https://app.example/';
    const at = base + 'a'.repeat(BACKCHANNEL_LOGOUT_URI_MAX_LENGTH - base.length);
    expect(backchannelLogoutUriProblem(at)).toBeUndefined();
    expect(backchannelLogoutUriProblem(`${at}a`)).toBe(
      `must be 1 to ${BACKCHANNEL_LOGOUT_URI_MAX_LENGTH} characters`
    );
  });
});
