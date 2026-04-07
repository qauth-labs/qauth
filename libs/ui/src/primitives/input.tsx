import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '../lib/utils';

export type InputProps = React.InputHTMLAttributes<HTMLInputElement> &
  VariantProps<typeof inputVariants>;

const inputVariants = cva(
  'w-full rounded-lg border bg-white px-3 py-2.5 text-sm transition-colors duration-150 placeholder:text-[#A3A3A3] focus:ring-2 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'border-[#E5E5E5] focus:border-[#C05C38] focus:ring-[#C05C38]/20',
        error: 'border-[#DC2626] focus:border-[#DC2626] focus:ring-[#DC2626]/20',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);

export const Input = ({ variant, className, ...props }: InputProps) => {
  return <input className={cn(inputVariants({ variant }), className)} {...props} />;
};
