import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { FormField } from './form-field';
import { Input } from './input';

describe('FormField', () => {
  it('renders the label', () => {
    const html = renderToString(
      <FormField label="Email" htmlFor="email">
        <Input id="email" />
      </FormField>
    );
    expect(html).toContain('Email');
    expect(html).toContain('<label');
  });

  it('associates label with the input via htmlFor', () => {
    const html = renderToString(
      <FormField label="Email" htmlFor="email">
        <Input id="email" />
      </FormField>
    );
    expect(html).toContain('for="email"');
  });

  it('renders children', () => {
    const html = renderToString(
      <FormField label="Name" htmlFor="name">
        <Input id="name" placeholder="Enter name" />
      </FormField>
    );
    expect(html).toContain('placeholder="Enter name"');
  });

  it('shows error message when error is provided', () => {
    const html = renderToString(
      <FormField label="Email" htmlFor="email" error="Email is required">
        <Input id="email" />
      </FormField>
    );
    expect(html).toContain('Email is required');
    expect(html).toContain('text-red-600');
  });

  it('shows helperText when no error is provided', () => {
    const html = renderToString(
      <FormField label="Email" htmlFor="email" helperText="We will never share your email">
        <Input id="email" />
      </FormField>
    );
    expect(html).toContain('We will never share your email');
    expect(html).toContain('text-gray-500');
  });

  it('shows error instead of helperText when both are provided', () => {
    const html = renderToString(
      <FormField
        label="Email"
        htmlFor="email"
        error="Email is required"
        helperText="Enter your email"
      >
        <Input id="email" />
      </FormField>
    );
    expect(html).toContain('Email is required');
    expect(html).not.toContain('Enter your email');
  });

  it('renders no helper or error text when neither is provided', () => {
    const html = renderToString(
      <FormField label="Email" htmlFor="email">
        <Input id="email" />
      </FormField>
    );
    expect(html).not.toContain('text-red-600');
    expect(html).not.toContain('text-gray-500');
  });
});
