import { Button, FormField, Input } from '@qauth-labs/ui';
import { createFileRoute, Link } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

import { resendVerificationFn } from '../server/actions/resend-verification';
import { verifyFn } from '../server/actions/verify';

// Auth-server enforces 64-char hex tokens — reject early to skip the round-trip.
const TOKEN_RE = /^[0-9a-f]{64}$/;

export const Route = createFileRoute('/verify')({
  validateSearch: (raw: Record<string, unknown>): { token: string } => {
    const token = raw['token'];
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
      throw new Error('Invalid or missing verification token');
    }
    return { token };
  },
  component: VerifyPage,
});

type VerifyState =
  | { stage: 'pending' }
  | { stage: 'success'; email: string }
  | { stage: 'already-verified' }
  | { stage: 'error'; message: string };

type ResendState = 'idle' | 'sending' | 'sent' | { error: string };

function VerifyPage() {
  const { token } = Route.useSearch();
  const [state, setState] = useState<VerifyState>({ stage: 'pending' });
  const [resendEmail, setResendEmail] = useState('');
  const [resendState, setResendState] = useState<ResendState>('idle');

  useEffect(() => {
    let cancelled = false;

    verifyFn({ data: { token } }).then((result) => {
      if (cancelled) return;

      if (result.ok) {
        setState({ stage: 'success', email: result.data.email });
        return;
      }

      const { code, message } = result.error;

      if (code === 'EMAIL_ALREADY_VERIFIED') {
        setState({ stage: 'already-verified' });
        return;
      }

      setState({ stage: 'error', message });
    });

    return () => {
      cancelled = true;
    };
    // token is stable for the lifetime of this page load — empty deps is intentional
  }, []);

  async function handleResend(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setResendState('sending');
    const result = await resendVerificationFn({ data: { email: resendEmail } });
    if (result.ok) {
      setResendState('sent');
    } else {
      setResendState({ error: result.error.message });
    }
  }

  if (state.stage === 'pending') {
    return (
      <main className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
        <p className="text-sm text-gray-500">Verifying your email...</p>
      </main>
    );
  }

  if (state.stage === 'success' || state.stage === 'already-verified') {
    return (
      <main className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
        <div className="w-full max-w-md space-y-4 rounded-lg border border-gray-200 bg-white p-8 shadow-sm">
          <h1 className="text-xl font-semibold">Email verified</h1>
          {state.stage === 'success' ? (
            <p className="text-sm text-gray-600">
              <span className="font-medium">{state.email}</span> has been verified. You can now log
              in.
            </p>
          ) : (
            <p className="text-sm text-gray-600">This email is already verified.</p>
          )}
          <Link to="/login">
            <Button type="button">Continue to login</Button>
          </Link>
        </div>
      </main>
    );
  }

  // Error state.
  return (
    <main className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-md space-y-4 rounded-lg border border-gray-200 bg-white p-8 shadow-sm">
        <h1 className="text-xl font-semibold">Verification failed</h1>
        <p role="alert" className="text-sm text-red-600">
          {state.message}
        </p>

        <p className="text-sm text-gray-600">
          Enter your email below to request a new verification link.
        </p>

        {resendState === 'sent' ? (
          <p className="text-sm text-green-700">Verification email sent. Check your inbox.</p>
        ) : (
          <form onSubmit={(e) => void handleResend(e)} className="space-y-3">
            <FormField label="Email" htmlFor="resend-email">
              <Input
                id="resend-email"
                name="email"
                type="email"
                autoComplete="email"
                required
                value={resendEmail}
                onChange={(e) => setResendEmail(e.target.value)}
              />
            </FormField>

            {typeof resendState === 'object' ? (
              <p className="text-sm text-red-600">{resendState.error}</p>
            ) : null}

            <Button type="submit" disabled={resendState === 'sending'}>
              {resendState === 'sending' ? 'Sending...' : 'Resend verification email'}
            </Button>
          </form>
        )}
      </div>
    </main>
  );
}
