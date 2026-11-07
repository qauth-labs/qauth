import { describe, expect, it } from 'vitest';

import type { AccountOverview } from './account-changes';
import {
  ACCOUNT_NOTICES,
  ACCOUNT_PAGE_PATH,
  accountMessagePage,
  accountPage,
  newRecoveryCodesPage,
  passwordChangePage,
  reauthenticatePage,
} from './account-pages';

const CSRF = 'csrf-token-of-the-session';
const NONCE = 'style-nonce';
const PASSKEY_ID = '00000000-0000-4000-8000-0000000000a1';
const SID = '00000000-0000-4000-8000-0000000000c1';
const OTHER_SID = '00000000-0000-4000-8000-0000000000c2';
const LINKED_ID = '00000000-0000-4000-8000-0000000000d1';

/** An account with every method, so the overview draws every form. */
function overview(overrides: Partial<AccountOverview> = {}): AccountOverview {
  return {
    password: { set: true, address: 'ada@example.com' },
    passkeys: [
      {
        id: PASSKEY_ID,
        nickname: 'Laptop <script>alert(1)</script>',
        createdAt: Date.UTC(2026, 10, 1),
        lastUsedAt: null,
        backedUp: true,
        disabled: false,
      },
    ],
    totp: { set: true },
    recoveryCodes: { issued: true, unused: 9 },
    linkedAccounts: [
      { id: LINKED_ID, provider: 'acme', providerName: 'Acme', createdAt: Date.UTC(2026, 10, 2) },
    ],
    linkable: [{ provider: 'globex', name: 'Globex "SSO"' }],
    sessions: [
      {
        sid: SID,
        current: true,
        createdAt: Date.UTC(2026, 10, 3),
        lastSeenAt: Date.UTC(2026, 10, 3),
        userAgent: 'Firefox',
        ipAddress: '192.0.2.1',
        clients: [],
      },
      {
        sid: OTHER_SID,
        current: false,
        createdAt: Date.UTC(2026, 10, 4),
        lastSeenAt: Date.UTC(2026, 10, 4),
        userAgent: '<img src=x onerror=alert(1)>',
        ipAddress: null,
        clients: ['Photos'],
      },
    ],
    requiredFactor: 'pop',
    ...overrides,
  };
}

/** Every `<form …>…</form>` of a page. */
function formsOf(page: string): string[] {
  return page.match(/<form\b[\s\S]*?<\/form>/g) ?? [];
}

/** Every form posts to the account pages with the session's CSRF value, and the page runs no script. */
function expectPlainForms(page: string, expected: number): void {
  const forms = formsOf(page);
  expect(forms).toHaveLength(expected);
  for (const form of forms) {
    expect(form).toMatch(/^<form method="post" action="\/ui\/account[^"]*"/);
    expect(form).toContain(`<input type="hidden" name="csrf" value="${CSRF}" />`);
  }
  expect(page).not.toMatch(/<script\b/i);
  expect(page).not.toMatch(/<[^>]*\son[a-z]+=/i);
}

describe('accountPage (#844)', () => {
  it('draws every action as a plain form that carries the CSRF value', () => {
    const page = accountPage({
      cspNonce: NONCE,
      csrf: CSRF,
      overview: overview(),
      passkeysOn: true,
    });
    // Rename + remove the passkey, add one, turn TOTP off, regenerate the
    // codes, unlink, link, end each of two sessions, sign out everywhere.
    expectPlainForms(page, 10);
    for (const action of [
      `${ACCOUNT_PAGE_PATH}/passkeys/${PASSKEY_ID}/rename`,
      `${ACCOUNT_PAGE_PATH}/passkeys/${PASSKEY_ID}/remove`,
      `${ACCOUNT_PAGE_PATH}/passkeys/add`,
      `${ACCOUNT_PAGE_PATH}/totp/remove`,
      `${ACCOUNT_PAGE_PATH}/recovery-codes/regenerate`,
      `${ACCOUNT_PAGE_PATH}/linked-accounts/${LINKED_ID}/unlink`,
      `${ACCOUNT_PAGE_PATH}/linked-accounts/link`,
      `${ACCOUNT_PAGE_PATH}/sessions/${SID}/end`,
      `${ACCOUNT_PAGE_PATH}/sessions/${OTHER_SID}/end`,
      `${ACCOUNT_PAGE_PATH}/sessions/end-all`,
    ]) {
      expect(page).toContain(`action="${action}"`);
    }
    expect(page).toContain(`href="${ACCOUNT_PAGE_PATH}/password"`);
    expect(page).toContain(`nonce="${NONCE}"`);
  });

  it('escapes what the person, a browser or an operator wrote', () => {
    const page = accountPage({
      cspNonce: NONCE,
      csrf: CSRF,
      overview: overview(),
      passkeysOn: true,
    });
    expect(page).toContain('Laptop &lt;script&gt;alert(1)&lt;/script&gt;');
    expect(page).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(page).toContain('Globex &quot;SSO&quot;');
    expect(page).not.toContain('<script>alert(1)');
  });

  it('offers to set up what the account lacks, and no passkey form while passkeys are off', () => {
    const page = accountPage({
      cspNonce: NONCE,
      csrf: CSRF,
      overview: overview({
        passkeys: [],
        totp: { set: false },
        recoveryCodes: { issued: false, unused: 0 },
        linkedAccounts: [],
        linkable: [],
        sessions: [],
        requiredFactor: 'pwd',
      }),
      passkeysOn: false,
    });
    expect(page).toContain(`action="${ACCOUNT_PAGE_PATH}/totp/setup"`);
    expect(page).not.toContain(`action="${ACCOUNT_PAGE_PATH}/passkeys/add"`);
    expect(page).not.toContain(`action="${ACCOUNT_PAGE_PATH}/totp/remove"`);
    for (const form of formsOf(page)) expect(form).toContain(`name="csrf" value="${CSRF}"`);
  });

  it('shows a known notice', () => {
    const page = accountPage({
      cspNonce: NONCE,
      csrf: CSRF,
      overview: overview(),
      passkeysOn: true,
      notice: 'password_changed',
    });
    expect(page).toContain(ACCOUNT_NOTICES.password_changed);
  });
});

describe('the other account pages (#844)', () => {
  it('the password form carries the CSRF value and shows the policy’s messages escaped', () => {
    const page = passwordChangePage({
      cspNonce: NONCE,
      csrf: CSRF,
      address: 'ada@example.com',
      errors: ['Add another word or two. Uncommon words are better.', '<b>bold</b>'],
    });
    expectPlainForms(page, 1);
    expect(page).toContain('Add another word or two. Uncommon words are better.');
    expect(page).toContain('&lt;b&gt;bold&lt;/b&gt;');
    expect(page).toContain('name="current_password"');
    expect(page).toContain('name="new_password"');
  });

  it('the new recovery codes are shown once, with the set to confirm', () => {
    const page = newRecoveryCodesPage({
      cspNonce: NONCE,
      csrf: CSRF,
      codes: ['AAAA-BBBB', 'CCCC-DDDD'],
      setId: 'set-1',
    });
    expectPlainForms(page, 1);
    expect(page).toContain('<code>AAAA-BBBB</code>');
    expect(page).toContain('<code>CCCC-DDDD</code>');
    expect(page).toContain('name="set_id" value="set-1"');
  });

  it('"confirm it’s you" names the factor and where to come back to', () => {
    const page = reauthenticatePage({
      cspNonce: NONCE,
      csrf: CSRF,
      requiredFactor: 'otp',
      returnTo: `${ACCOUNT_PAGE_PATH}/password`,
    });
    expectPlainForms(page, 1);
    expect(page).toContain('your authenticator app');
    expect(page).toContain(`name="return_to" value="${ACCOUNT_PAGE_PATH}/password"`);
  });

  it('a message page links back to the overview', () => {
    const page = accountMessagePage({ cspNonce: NONCE, title: 'Not found', message: 'Gone <now>' });
    expect(page).toContain(`href="${ACCOUNT_PAGE_PATH}"`);
    expect(page).toContain('Gone &lt;now&gt;');
    expect(formsOf(page)).toHaveLength(0);
  });
});
