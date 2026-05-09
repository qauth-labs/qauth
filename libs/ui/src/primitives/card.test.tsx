import { createRef } from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './card';

describe('Card', () => {
  it('renders with default classes', () => {
    const html = renderToString(<Card />);
    expect(html).toContain('rounded-lg');
    expect(html).toContain('border');
    expect(html).toContain('shadow-sm');
  });

  it('merges className with defaults', () => {
    const html = renderToString(<Card className="custom-class" />);
    expect(html).toContain('custom-class');
    expect(html).toContain('rounded-lg');
  });

  it('renders without error when ref is provided', () => {
    const ref = createRef<HTMLDivElement>();
    const html = renderToString(<Card ref={ref} />);
    expect(html).toBeDefined();
    expect(html).toContain('<div');
  });

  it('renders children', () => {
    const html = renderToString(<Card>Card body</Card>);
    expect(html).toContain('Card body');
  });
});

describe('CardHeader', () => {
  it('renders with default classes', () => {
    const html = renderToString(<CardHeader />);
    expect(html).toContain('flex');
    expect(html).toContain('p-6');
  });

  it('merges className with defaults', () => {
    const html = renderToString(<CardHeader className="extra" />);
    expect(html).toContain('extra');
    expect(html).toContain('p-6');
  });

  it('renders without error when ref is provided', () => {
    const ref = createRef<HTMLDivElement>();
    const html = renderToString(<CardHeader ref={ref} />);
    expect(html).toBeDefined();
  });
});

describe('CardContent', () => {
  it('renders with default classes', () => {
    const html = renderToString(<CardContent />);
    expect(html).toContain('p-6');
  });

  it('merges className with defaults', () => {
    const html = renderToString(<CardContent className="extra" />);
    expect(html).toContain('extra');
    expect(html).toContain('p-6');
  });

  it('renders without error when ref is provided', () => {
    const ref = createRef<HTMLDivElement>();
    const html = renderToString(<CardContent ref={ref} />);
    expect(html).toBeDefined();
  });
});

describe('CardTitle', () => {
  it('renders as h3 with default classes', () => {
    const html = renderToString(<CardTitle>Title</CardTitle>);
    expect(html).toContain('<h3');
    expect(html).toContain('font-semibold');
    expect(html).toContain('Title');
  });
});

describe('CardDescription', () => {
  it('renders as p with default classes', () => {
    const html = renderToString(<CardDescription>Desc</CardDescription>);
    expect(html).toContain('<p');
    expect(html).toContain('text-gray-500');
    expect(html).toContain('Desc');
  });
});
