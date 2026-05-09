import { createRef } from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { Label } from './label';

describe('Label', () => {
  it('renders with default classes', () => {
    const html = renderToString(<Label>Email</Label>);
    expect(html).toContain('text-sm');
    expect(html).toContain('font-medium');
  });

  it('renders children', () => {
    const html = renderToString(<Label>Email address</Label>);
    expect(html).toContain('Email address');
  });

  it('merges className with defaults', () => {
    const html = renderToString(<Label className="custom-class">Name</Label>);
    expect(html).toContain('custom-class');
    expect(html).toContain('text-sm');
  });

  it('renders without error when ref is provided', () => {
    const ref = createRef<HTMLLabelElement>();
    const html = renderToString(<Label ref={ref}>Label text</Label>);
    expect(html).toBeDefined();
    expect(html).toContain('<label');
  });

  it('passes through htmlFor attribute', () => {
    const html = renderToString(<Label htmlFor="email-input">Email</Label>);
    expect(html).toContain('for="email-input"');
  });
});
