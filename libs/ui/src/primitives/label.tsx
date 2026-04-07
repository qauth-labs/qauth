import { cn } from '../lib/utils';

export type LabelProps = React.LabelHTMLAttributes<HTMLLabelElement> & {
  error?: boolean;
};

export const Label = ({ error, className, ...props }: LabelProps) => {
  return (
    <label
      className={cn(
        'block text-sm font-medium',
        error ? 'text-[#DC2626]' : 'text-[#171717]',
        className
      )}
      {...props}
    />
  );
};
