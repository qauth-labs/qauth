import { Button, FormField, Input } from '@qauth-labs/ui';
import { createFileRoute, Link, redirect, useRouter } from '@tanstack/react-router';
import { useState } from 'react';

import { currentUserFn } from '../server/actions/current-user';
import { loginFn } from '../server/actions/login';

export const Route = createFileRoute('/login')({
  beforeLoad: async () => {
    const result = await currentUserFn();
    if (result !== null) {
      throw redirect({ to: '/dashboard' });
    }
  },
  component: LoginPage,
});

type FormState = { stage: 'idle' } | { stage: 'submitting' } | { stage: 'error'; message: string };

/** The one message for every failed login, whatever the auth-server's reason. */
const LOGIN_FAILED_MESSAGE =
  'Invalid email or password. If you have just signed up, confirm your email address first with the link we sent you.';

function LoginPage() {
  const router = useRouter();
  const [formState, setFormState] = useState<FormState>({ stage: 'idle' });

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const email = (fd.get('email') as string).trim();
    const password = fd.get('password') as string;

    setFormState({ stage: 'submitting' });

    const result = await loginFn({ data: { email, password } });

    if (result.ok) {
      await router.navigate({ to: '/dashboard' });
      return;
    }

    // Generic message regardless of error code — anti-enumeration. The
    // auth-server refuses an account whose address is not verified yet with
    // the same 401 as a wrong password, so the one message names that case
    // too, for a developer who has just signed up.
    setFormState({ stage: 'error', message: LOGIN_FAILED_MESSAGE });
  }

  const errorMessage = formState.stage === 'error' ? formState.message : undefined;
  const isSubmitting = formState.stage === 'submitting';

  return (
    <main className="bg-background flex min-h-screen items-center justify-center px-4">
      <div className="rounded-surface border-border bg-card w-full max-w-md space-y-6 border p-8">
        <h1 className="text-foreground text-3xl leading-tight">Log in to your account</h1>

        {errorMessage ? (
          <p role="alert" className="text-destructive text-sm">
            {errorMessage}
          </p>
        ) : null}

        <form onSubmit={(e) => void handleSubmit(e)} noValidate className="space-y-4">
          <FormField label="Email" htmlFor="email">
            <Input id="email" name="email" type="email" autoComplete="username" required />
          </FormField>

          <FormField label="Password" htmlFor="password">
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </FormField>

          <p className="text-muted-foreground text-sm">Forgot password? Coming soon.</p>

          <Button type="submit" disabled={isSubmitting} className="w-full">
            {isSubmitting ? 'Logging in...' : 'Log in'}
          </Button>
        </form>

        <p className="text-muted-foreground text-center text-sm">
          Don&apos;t have an account?{' '}
          <Link to="/register" className="text-primary-text underline-offset-4 hover:underline">
            Register
          </Link>
        </p>
      </div>
    </main>
  );
}
