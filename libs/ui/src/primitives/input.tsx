import { forwardRef, type InputHTMLAttributes } from 'react';

import { cn } from '../lib/utils';

export type InputProps = InputHTMLAttributes<HTMLInputElement>;

/**
 * A text field. Its edge is the `input` colour, 3:1 against the page as WCAG 1.4.11 asks of a
 * control's boundary. `aria-invalid="true"` turns the edge and the focus ring to the error colour.
 * The text is 16px on a phone, so the browser does not zoom in on focus.
 */
export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, 'aria-invalid': ariaInvalid, ...props }, ref) => {
    return (
      <input
        ref={ref}
        aria-invalid={ariaInvalid}
        className={cn(
          'rounded-control border-input text-foreground flex h-9 w-full min-w-0 border bg-transparent px-3 py-1 text-base md:text-sm',
          'transition-colors duration-(--duration-fast) ease-standard',
          'placeholder:text-muted-foreground',
          'focus-visible:border-ring focus-visible:ring-ring outline-none focus-visible:ring-1',
          'disabled:bg-muted disabled:cursor-not-allowed disabled:opacity-50',
          'aria-invalid:border-destructive aria-invalid:focus-visible:ring-destructive',
          'file:text-foreground file:border-0 file:bg-transparent file:text-sm file:font-medium',
          className
        )}
        {...props}
      />
    );
  }
);

Input.displayName = 'Input';
