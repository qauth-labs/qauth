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
    <div className="flex flex-col space-y-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error ? (
        <p className="text-sm text-red-600">{error}</p>
      ) : helperText ? (
        <p className="text-sm text-gray-500">{helperText}</p>
      ) : null}
    </div>
  );
};
