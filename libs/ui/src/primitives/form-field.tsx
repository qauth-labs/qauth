import { type ReactNode } from 'react';

import { Label } from './label';

export interface FormFieldProps {
  label: string;
  htmlFor: string;
  error?: string;
  helperText?: string;
  children: ReactNode;
}

export const FormField = ({ label, htmlFor, error, helperText, children }: FormFieldProps) => {
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error ? (
        <p className="text-destructive text-sm">{error}</p>
      ) : helperText ? (
        <p className="text-muted-foreground text-sm">{helperText}</p>
      ) : null}
    </div>
  );
};
