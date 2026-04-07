import { Input, Label } from '@qauth/ui';
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { z } from 'zod';

import { ApiRequestError, register } from '../api/auth';

export const Route = createFileRoute('/register')({
  component: RegisterPage,
});

const registrationSchema = z
  .object({
    email: z.string().email('Please enter a valid email address'),
    password: z.string().min(8, 'Password must be at least 8 characters'),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

type FormErrors = Partial<Record<'email' | 'password' | 'confirmPassword', string>>;

function RegisterPage() {
  const [form, setForm] = useState({ email: '', password: '', confirmPassword: '' });
  const [fieldErrors, setFieldErrors] = useState<FormErrors>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [registeredEmail, setRegisteredEmail] = useState<string | null>(null);

  if (registeredEmail) {
    return <SuccessView email={registeredEmail} />;
  }

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    // Clear field error on change
    if (fieldErrors[name as keyof FormErrors]) {
      setFieldErrors((prev) => ({ ...prev, [name]: undefined }));
    }
    if (formError) setFormError(null);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFieldErrors({});
    setFormError(null);

    const result = registrationSchema.safeParse(form);
    if (!result.success) {
      const errors: FormErrors = {};
      for (const issue of result.error.issues) {
        const field = issue.path[0] as keyof FormErrors;
        if (!errors[field]) errors[field] = issue.message;
      }
      setFieldErrors(errors);
      return;
    }

    setIsSubmitting(true);
    try {
      await register(form.email, form.password);
      setRegisteredEmail(form.email);
    } catch (err) {
      if (err instanceof ApiRequestError) {
        const { statusCode, body } = err;
        if (statusCode === 409) {
          setFieldErrors({ email: 'An account with this email already exists' });
        } else if (statusCode === 400 && body.code === 'WEAK_PASSWORD') {
          setFieldErrors({ password: body.feedback?.[0] ?? 'Password is too weak' });
        } else if (statusCode === 429) {
          setFormError('Too many attempts. Please try again later.');
        } else {
          setFormError('Something went wrong. Please try again.');
        }
      } else {
        setFormError('Unable to connect. Please check your connection and try again.');
      }
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#FAFAFA] px-4 py-12">
      <div className="w-full max-w-md rounded-xl border border-[#E5E5E5] bg-white p-8 shadow-sm">
        {/* Logo */}
        <div className="text-center">
          <svg
            viewBox="0 0 500 500"
            className="mx-auto h-10 w-10"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            aria-label="QAuth"
          >
            <circle cx="250" cy="250" r="200" stroke="#C05C38" strokeWidth="100" />
            <rect x="320" y="370" width="155" height="155" fill="#01CED1" />
            <path
              d="M384 377C397 356 402 330 398 306C394 282 382 261 363 245C344 230 320 222 296 223C272 225 249 235 232 252C215 269 205 292 204 316C203 340 211 364 226 383C241 403 263 416 287 420C311 424 335 419 355 407"
              stroke="#01CED1"
              strokeWidth="25"
            />
          </svg>
        </div>

        {/* Heading */}
        <h1 className="mt-6 text-center text-2xl font-bold text-[#171717]">
          Create Developer Account
        </h1>
        <p className="mt-2 text-center text-sm text-[#525252]">
          Register to access the QAuth developer portal
        </p>

        {/* Form-level error */}
        {formError && (
          <div className="mt-5 flex items-center gap-2 rounded-lg border border-[#DC2626]/20 bg-[#FEF2F2] px-4 py-3">
            <svg
              className="h-4 w-4 shrink-0 text-[#DC2626]"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              <path
                fillRule="evenodd"
                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-5a.75.75 0 01.75.75v4.5a.75.75 0 01-1.5 0v-4.5A.75.75 0 0110 5zm0 10a1 1 0 100-2 1 1 0 000 2z"
                clipRule="evenodd"
              />
            </svg>
            <p className="text-sm text-[#DC2626]">{formError}</p>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="mt-6 space-y-5" noValidate>
          {/* Email */}
          <div>
            <Label htmlFor="email" error={!!fieldErrors.email} className="mb-1.5">
              Email address
            </Label>
            <Input
              id="email"
              name="email"
              type="email"
              autoComplete="email"
              value={form.email}
              onChange={handleChange}
              variant={fieldErrors.email ? 'error' : 'default'}
              placeholder="you@company.com"
            />
            {fieldErrors.email && (
              <p className="mt-1.5 text-xs font-medium text-[#DC2626]">{fieldErrors.email}</p>
            )}
          </div>

          {/* Password */}
          <div>
            <Label htmlFor="password" error={!!fieldErrors.password} className="mb-1.5">
              Password
            </Label>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="new-password"
              value={form.password}
              onChange={handleChange}
              variant={fieldErrors.password ? 'error' : 'default'}
              placeholder="At least 8 characters"
            />
            {fieldErrors.password && (
              <p className="mt-1.5 text-xs font-medium text-[#DC2626]">{fieldErrors.password}</p>
            )}
          </div>

          {/* Confirm Password */}
          <div>
            <Label
              htmlFor="confirmPassword"
              error={!!fieldErrors.confirmPassword}
              className="mb-1.5"
            >
              Confirm password
            </Label>
            <Input
              id="confirmPassword"
              name="confirmPassword"
              type="password"
              autoComplete="new-password"
              value={form.confirmPassword}
              onChange={handleChange}
              variant={fieldErrors.confirmPassword ? 'error' : 'default'}
              placeholder="Repeat your password"
            />
            {fieldErrors.confirmPassword && (
              <p className="mt-1.5 text-xs font-medium text-[#DC2626]">
                {fieldErrors.confirmPassword}
              </p>
            )}
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={isSubmitting}
            className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg bg-[#C05C38] py-2.5 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#A84E2F] active:bg-[#934428] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isSubmitting && (
              <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                />
              </svg>
            )}
            {isSubmitting ? 'Creating account...' : 'Create Account'}
          </button>
        </form>

        {/* Footer */}
        <p className="mt-6 text-center text-sm text-[#525252]">
          Already have an account?{' '}
          <a
            href="/login"
            className="font-medium text-[#01CED1] transition-colors duration-150 hover:text-[#00B5B8]"
          >
            Sign in
          </a>
        </p>
      </div>
    </div>
  );
}

function SuccessView({ email }: { email: string }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[#FAFAFA] px-4 py-12">
      <div
        className="w-full max-w-md rounded-xl border border-[#E5E5E5] bg-white p-8 shadow-sm"
        style={{ animation: 'fade-in-up 400ms ease-out' }}
      >
        {/* Check icon */}
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-[#F0FDF4]">
          <svg
            className="h-6 w-6 text-[#059669]"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2.5}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
          </svg>
        </div>

        <h1 className="mt-6 text-center text-2xl font-bold text-[#171717]">Check your email</h1>
        <p className="mx-auto mt-3 max-w-xs text-center text-sm text-[#525252]">
          We've sent a verification link to{' '}
          <span className="font-medium text-[#171717]">{email}</span>. Click the link to verify your
          account.
        </p>

        <a
          href="/"
          className="mt-6 flex w-full items-center justify-center rounded-lg bg-[#C05C38] py-2.5 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#A84E2F] active:bg-[#934428]"
        >
          Go to home
        </a>

        <p className="mt-4 text-center text-xs text-[#A3A3A3]">
          Didn't receive it?{' '}
          <button className="font-medium text-[#01CED1] hover:text-[#00B5B8]" type="button">
            Resend email
          </button>
        </p>
      </div>
    </div>
  );
}
