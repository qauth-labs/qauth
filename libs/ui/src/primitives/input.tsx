import { forwardRef, type InputHTMLAttributes } from 'react';

import { cn } from '../lib/utils';

export type InputProps = InputHTMLAttributes<HTMLInputElement>;

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, 'aria-invalid': ariaInvalid, ...props }, ref) => {
    return (
      <input
        ref={ref}
        aria-invalid={ariaInvalid}
        className={cn(
          'flex h-9 w-full rounded-md border border-gray-300 bg-white px-3 py-1 text-sm shadow-sm transition-colors',
          'placeholder:text-gray-400',
          'focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none',
          'disabled:cursor-not-allowed disabled:opacity-50',
          ariaInvalid === 'true' && 'border-red-500 focus:ring-red-500',
          className
        )}
        {...props}
      />
    );
  }
);

Input.displayName = 'Input';
