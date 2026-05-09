import { FormField, Input } from '@qauth-labs/ui';
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

    // Generic message regardless of error code — anti-enumeration.
    setFormState({ stage: 'error', message: 'Invalid email or password.' });
  }

  const errorMessage = formState.stage === 'error' ? formState.message : undefined;
  const isSubmitting = formState.stage === 'submitting';

  return (
    <main className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-md space-y-6 rounded-lg border border-gray-200 bg-white p-8 shadow-sm">
        <h1 className="text-xl font-semibold">Log in to your account</h1>

        {errorMessage ? (
          <p role="alert" className="text-sm text-red-600">
            {errorMessage}
          </p>
        ) : null}

        <form onSubmit={(e) => void handleSubmit(e)} noValidate className="space-y-4">
          <FormField label="Email" htmlFor="email">
            <Input id="email" name="email" type="email" autoComplete="email" required />
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

          <p className="text-sm text-gray-400">Forgot password? Coming soon.</p>

          {/* Button primitive drops type/disabled — use native button for form submission */}
          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full rounded-md bg-blue-500 px-4 py-2 text-sm text-white hover:bg-blue-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isSubmitting ? 'Logging in...' : 'Log in'}
          </button>
        </form>

        <p className="text-center text-sm text-gray-500">
          Don&apos;t have an account?{' '}
          <Link to="/register" className="text-blue-600 hover:underline">
            Register
          </Link>
        </p>
      </div>
    </main>
  );
}
