import { Button, FormField, Input } from '@qauth-labs/ui';
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

    // The auth-server answers a free address and one that already has an
    // account the same way, so success shows the same "check your inbox"
    // screen for both, with the address as typed. Which mail went out (a
    // verification link, or a notice for an existing account) is for the
    // mailbox owner alone to see.
    if (result.ok) {
      setFormState({ stage: 'success', email });
      return;
    }

    const { code, message, details } = result.error;

    // A refused password (#634): a message for each reason it was refused
    // (too short, too long, a common word or this account's address, too
    // easy to guess), then any feedback, all under the password field.
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
      <main className="bg-background flex min-h-screen items-center justify-center px-4">
        <div className="rounded-surface border-border bg-card w-full max-w-md space-y-4 border p-8">
          <h1 className="text-foreground text-3xl leading-tight">Check your inbox</h1>
          <p className="text-body text-sm">
            We sent an email to <span className="font-medium">{formState.email}</span> with the next
            step. If it holds a verification link, open it and confirm with your password to
            activate your account. If you already had an account with this address, the email says
            so: log in with your existing password instead.
          </p>

          {resendState === 'sent' ? (
            <p className="text-success text-sm">Verification email resent.</p>
          ) : typeof resendState === 'object' ? (
            <p className="text-destructive text-sm">{resendState.error}</p>
          ) : (
            <Button
              variant="outline"
              type="button"
              disabled={resendState === 'sending'}
              onClick={() => void handleResend(formState.email)}
            >
              {resendState === 'sending' ? 'Sending...' : 'Resend verification email'}
            </Button>
          )}
        </div>
      </main>
    );
  }

  const fieldErrors = formState.stage === 'error' ? formState.fieldErrors : {};
  const formError = formState.stage === 'error' ? formState.formError : undefined;
  const isSubmitting = formState.stage === 'submitting';

  return (
    <main className="bg-background flex min-h-screen items-center justify-center px-4">
      <div className="rounded-surface border-border bg-card w-full max-w-md space-y-6 border p-8">
        <h1 className="text-foreground text-3xl leading-tight">Create your account</h1>

        {formError ? (
          <p role="alert" className="text-destructive text-sm">
            {formError}
          </p>
        ) : null}

        <form onSubmit={(e) => void handleSubmit(e)} noValidate className="space-y-4">
          {/* Marked for password managers (#634): the address is the account's
              username, and the password a new one, so a manager offers to
              generate it and saves it under that address. */}
          <FormField label="Email" htmlFor="email" error={fieldErrors.email}>
            <Input
              id="email"
              name="email"
              type="email"
              autoComplete="username"
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

          <Button type="submit" disabled={isSubmitting} className="w-full">
            {isSubmitting ? 'Creating account...' : 'Create account'}
          </Button>
        </form>

        <p className="text-muted-foreground text-center text-sm">
          Already have an account?{' '}
          <Link to="/login" className="text-primary-text underline-offset-4 hover:underline">
            Log in
          </Link>
        </p>
      </div>
    </main>
  );
}
