import { createRef } from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { Input } from './input';

describe('Input', () => {
  it('renders with default classes', () => {
    const html = renderToString(<Input />);
    expect(html).toContain('rounded-control');
    expect(html).toContain('border');
    expect(html).toContain('focus-visible:ring-ring');
  });

  it('merges className with defaults', () => {
    const html = renderToString(<Input className="custom-class" />);
    expect(html).toContain('custom-class');
    expect(html).toContain('rounded-control');
  });

  it('renders without error when ref is provided', () => {
    const ref = createRef<HTMLInputElement>();
    const html = renderToString(<Input ref={ref} />);
    expect(html).toBeDefined();
    expect(html).toContain('<input');
  });

  // The error styling is keyed to the attribute (`aria-invalid:`), so the attribute is the state.
  it('carries aria-invalid, which turns on the error styling', () => {
    const html = renderToString(<Input aria-invalid="true" />);
    expect(html).toContain('aria-invalid:border-destructive');
    expect(html).toContain('aria-invalid="true"');
  });

  it('renders no aria-invalid when it is not set', () => {
    const html = renderToString(<Input />);
    expect(html).not.toContain('aria-invalid=');
  });

  it('passes through standard input attributes', () => {
    const html = renderToString(<Input type="email" placeholder="Enter email" disabled />);
    expect(html).toContain('type="email"');
    expect(html).toContain('placeholder="Enter email"');
    expect(html).toContain('disabled');
  });
});
