import { cva } from 'class-variance-authority';

import { cn } from '../lib/utils';

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'outline' | 'ghost' | 'link';
  size?: 'default' | 'sm' | 'lg';
};

const buttonVariants = cva('rounded-md bg-blue-500 p-2 text-white hover:bg-blue-600', {
  variants: {
    variant: {
      default: 'bg-blue-500 hover:bg-blue-600',
      outline: 'border border-gray-300 bg-white text-gray-800 hover:bg-gray-100',
      ghost: 'bg-transparent text-gray-800 hover:bg-gray-100',
      link: 'text-blue-500 hover:underline',
    },
    size: {
      default: 'p-2',
      sm: 'p-1',
      lg: 'p-3',
    },
  },
  defaultVariants: {
    variant: 'default',
  },
});

export const Button = ({
  children,
  variant = 'default',
  size = 'default',
  className,
}: ButtonProps) => {
  return <button className={cn(buttonVariants({ variant, size }), className)}>{children}</button>;
};
