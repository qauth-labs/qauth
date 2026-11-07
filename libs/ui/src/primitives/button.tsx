import { cva } from 'class-variance-authority';

import { cn } from '../lib/utils';

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'secondary' | 'outline' | 'ghost' | 'destructive' | 'link';
  size?: 'default' | 'sm' | 'lg';
};

/**
 * The design system's button: square, flat, with the focus ring outside the edge. Every variant's
 * text meets 4.5:1 on its fill in light and dark (see the contrast rules in `tokens.json`).
 */
export const buttonVariants = cva(
  [
    'rounded-control inline-flex shrink-0 cursor-pointer items-center justify-center gap-1.5 border border-transparent font-medium whitespace-nowrap select-none',
    'ease-standard transition-colors duration-(--duration-fast)',
    'focus-visible:ring-ring focus-visible:ring-offset-background outline-none focus-visible:ring-2 focus-visible:ring-offset-2',
    'disabled:pointer-events-none disabled:opacity-50',
    "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  ],
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground hover:bg-primary-hover',
        secondary: 'bg-secondary text-secondary-foreground hover:bg-accent',
        outline: 'border-input bg-background text-foreground hover:bg-muted',
        ghost: 'text-foreground hover:bg-accent hover:text-accent-foreground',
        destructive:
          'bg-destructive-surface text-destructive border-destructive/30 hover:border-destructive',
        link: 'text-primary-text underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-9 px-4 text-sm',
        sm: 'h-8 px-3 text-xs',
        lg: 'h-10 px-5 text-sm',
      },
    },
    // A link-styled button keeps the text's own height and no side padding, at any size.
    compoundVariants: [{ variant: 'link', className: 'h-auto px-0' }],
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export const Button = ({
  children,
  variant = 'default',
  size = 'default',
  className,
  ...rest
}: ButtonProps) => {
  return (
    <button {...rest} className={cn(buttonVariants({ variant, size }), className)}>
      {children}
    </button>
  );
};
