import { FormField, Input } from '@qauth-labs/ui';
import { createFileRoute, Link, redirect } from '@tanstack/react-router';
import { useState } from 'react';

import { currentUserFn } from '../server/actions/current-user';
import { registerFn } from '../server/actions/register';
import { resendVerificationFn } from '../server/actions/resend-verification';

export const Route = createFileRoute('/register')({
  beforeLoad: async () => {
    const result = await currentUserFn();
    if (result !== null) {
      throw redirect({ to: '/dashboard' });
    }
  },
  component: RegisterPage,
});

type FormState =
  | { stage: 'idle' }
  | { stage: 'submitting' }
  | { stage: 'success'; email: string }
  | { stage: 'error'; fieldErrors: { email?: string; password?: string }; formError?: string };

type ResendState = 'idle' | 'sending' | 'sent' | { error: string };

function RegisterPage() {
  const [formState, setFormState] = useState<FormState>({ stage: 'idle' });
  const [resendState, setResendState] = useState<ResendState>('idle');

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const email = (fd.get('email') as string).trim();
    const password = fd.get('password') as string;

    setFormState({ stage: 'submitting' });

    const result = await registerFn({ data: { email, password } });

    if (result.ok) {
      setFormState({ stage: 'success', email: result.data.email });
      return;
    }

    const { code, message, details } = result.error;

    if (code === 'EMAIL_TAKEN') {
      setFormState({
        stage: 'error',
        fieldErrors: { email: 'Email already registered.' },
      });
      return;
    }

    if (code === 'WEAK_PASSWORD') {
      const feedback = Array.isArray(details) ? (details as string[]).join(' ') : message;
      setFormState({
        stage: 'error',
        fieldErrors: { password: feedback },
      });
      return;
    }

    setFormState({ stage: 'error', fieldErrors: {}, formError: message });
  }

  async function handleResend(email: string) {
    setResendState('sending');
    const result = await resendVerificationFn({ data: { email } });
    if (result.ok) {
      setResendState('sent');
    } else {
      setResendState({ error: result.error.message });
    }
  }

  if (formState.stage === 'success') {
    return (
      <main className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
        <div className="w-full max-w-md space-y-4 rounded-lg border border-gray-200 bg-white p-8 shadow-sm">
          <h1 className="text-xl font-semibold">Check your inbox</h1>
          <p className="text-sm text-gray-600">
            We sent a verification link to <span className="font-medium">{formState.email}</span>.
            Open it to activate your account.
          </p>

          {resendState === 'sent' ? (
            <p className="text-sm text-green-700">Verification email resent.</p>
          ) : typeof resendState === 'object' ? (
            <p className="text-sm text-red-600">{resendState.error}</p>
          ) : (
            /* Button primitive drops onClick/disabled — use native button here */
            <button
              type="button"
              disabled={resendState === 'sending'}
              onClick={() => void handleResend(formState.email)}
              className="rounded-md border border-gray-300 bg-white px-4 py-2 text-sm text-gray-800 hover:bg-gray-100 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {resendState === 'sending' ? 'Sending...' : 'Resend verification email'}
            </button>
          )}
        </div>
      </main>
    );
  }

  const fieldErrors = formState.stage === 'error' ? formState.fieldErrors : {};
  const formError = formState.stage === 'error' ? formState.formError : undefined;
  const isSubmitting = formState.stage === 'submitting';

  return (
    <main className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-md space-y-6 rounded-lg border border-gray-200 bg-white p-8 shadow-sm">
        <h1 className="text-xl font-semibold">Create your account</h1>

        {formError ? (
          <p role="alert" className="text-sm text-red-600">
            {formError}
          </p>
        ) : null}

        <form onSubmit={(e) => void handleSubmit(e)} noValidate className="space-y-4">
          <FormField label="Email" htmlFor="email" error={fieldErrors.email}>
            <Input
              id="email"
              name="email"
              type="email"
              autoComplete="email"
              required
              aria-invalid={fieldErrors.email ? 'true' : undefined}
            />
          </FormField>

          <FormField label="Password" htmlFor="password" error={fieldErrors.password}>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="new-password"
              required
              aria-invalid={fieldErrors.password ? 'true' : undefined}
            />
          </FormField>

          {/* Button primitive drops type/disabled — use native button for form submission */}
          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full rounded-md bg-blue-500 px-4 py-2 text-sm text-white hover:bg-blue-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isSubmitting ? 'Creating account...' : 'Create account'}
          </button>
        </form>

        <p className="text-center text-sm text-gray-500">
          Already have an account?{' '}
          <Link to="/login" className="text-blue-600 hover:underline">
            Log in
          </Link>
        </p>
      </div>
    </main>
  );
}
