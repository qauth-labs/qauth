import { type ClassValue, clsx } from 'clsx';
import { extendTailwindMerge } from 'tailwind-merge';

/**
 * tailwind-merge, told about the theme names the tokens add, so `cn('rounded-control',
 * 'rounded-full')` keeps only the last radius as it does for Tailwind's own names.
 */
const twMerge = extendTailwindMerge({
  extend: {
    theme: {
      radius: ['control', 'surface'],
      ease: ['standard'],
    },
  },
});

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
