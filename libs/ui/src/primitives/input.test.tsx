import { createRef } from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { Input } from './input';

describe('Input', () => {
  it('renders with default classes', () => {
    const html = renderToString(<Input />);
    expect(html).toContain('rounded-md');
    expect(html).toContain('border');
    expect(html).toContain('focus:ring-blue-500');
  });

  it('merges className with defaults', () => {
    const html = renderToString(<Input className="custom-class" />);
    expect(html).toContain('custom-class');
    expect(html).toContain('rounded-md');
  });

  it('renders without error when ref is provided', () => {
    const ref = createRef<HTMLInputElement>();
    const html = renderToString(<Input ref={ref} />);
    expect(html).toBeDefined();
    expect(html).toContain('<input');
  });

  it('adds error styling class when aria-invalid is true', () => {
    const html = renderToString(<Input aria-invalid="true" />);
    expect(html).toContain('border-red-500');
    expect(html).toContain('aria-invalid="true"');
  });

  it('does not add error styling class when aria-invalid is not set', () => {
    const html = renderToString(<Input />);
    expect(html).not.toContain('border-red-500');
  });

  it('passes through standard input attributes', () => {
    const html = renderToString(<Input type="email" placeholder="Enter email" disabled />);
    expect(html).toContain('type="email"');
    expect(html).toContain('placeholder="Enter email"');
    expect(html).toContain('disabled');
  });
});
