// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../server/actions/current-user', () => ({
  currentUserFn: vi.fn(),
}));

vi.mock('../server/actions/register', () => ({
  registerFn: vi.fn(),
}));

vi.mock('../server/actions/resend-verification', () => ({
  resendVerificationFn: vi.fn(),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>();
  return {
    ...actual,
    Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  };
});

import { registerFn } from '../server/actions/register';
import { Route } from './register';

// Opt into React's act() environment so effects flush synchronously.
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const PageComponent = Route.options.component as NonNullable<typeof Route.options.component>;

/** The one answer `POST /auth/register` gives for every address. */
const ACCEPTED = {
  ok: true,
  data: { message: 'Registration received. Check your inbox for an email with the next step.' },
} as const;

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  vi.mocked(registerFn).mockReset();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

/** Type into a React-controlled input the way a user would. */
function typeInto(input: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event('input', { bubbles: true }));
}

async function signUp(email: string, password: string) {
  act(() => root.render(<PageComponent />));
  const emailInput = container.querySelector('input[type="email"]') as HTMLInputElement;
  const passwordInput = container.querySelector('input[type="password"]') as HTMLInputElement;
  act(() => {
    typeInto(emailInput, email);
    typeInto(passwordInput, password);
  });
  const form = container.querySelector('form') as HTMLFormElement;
  await act(async () => {
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });
}

describe('RegisterPage — the same answer for every address (ANT-2026-SPEMY9GU)', () => {
  it('shows the check-your-inbox screen with the address as typed', async () => {
    vi.mocked(registerFn).mockResolvedValue(ACCEPTED as never);

    await signUp(' dev@example.com ', 'Str0ng-Passw0rd!');

    expect(registerFn).toHaveBeenCalledWith({
      data: { email: 'dev@example.com', password: 'Str0ng-Passw0rd!' },
    });
    expect(container.textContent).toContain('Check your inbox');
    expect(container.textContent).toContain('dev@example.com');
    // The screen must hold for an address that already had an account too,
    // so it promises the next step, not an activation link.
    expect(container.textContent).toContain('If you already had an account with this address');
    expect(container.textContent).not.toContain('already registered');
    expect(container.textContent).toContain('Resend verification email');
  });

  it('keeps the form and shows the feedback for a weak password', async () => {
    vi.mocked(registerFn).mockResolvedValue({
      ok: false,
      error: {
        code: 'WEAK_PASSWORD',
        message: 'Password does not meet strength requirements',
        details: ['Add another word or two.'],
        status: 422,
      },
    } as never);

    await signUp('dev@example.com', 'weak');

    expect(container.textContent).toContain('Add another word or two.');
    expect(container.querySelector('form')).not.toBeNull();
  });
});
