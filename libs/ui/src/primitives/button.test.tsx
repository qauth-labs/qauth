import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { Button } from './button';

describe('Button', () => {
  it('renders default variant classes', () => {
    const html = renderToString(<Button>click</Button>);
    expect(html).toContain('rounded-md');
    expect(html).toContain('bg-blue-500');
  });

  it('applies outline variant', () => {
    const html = renderToString(<Button variant="outline">click</Button>);
    expect(html).toContain('border-gray-300');
  });

  it('merges custom className with variant classes', () => {
    const html = renderToString(<Button className="custom-x">click</Button>);
    expect(html).toContain('custom-x');
  });

  it('forwards standard HTML button attributes', () => {
    const html = renderToString(
      <Button type="submit" disabled name="login" form="loginForm">
        click
      </Button>
    );
    expect(html).toContain('type="submit"');
    expect(html).toContain('disabled');
    expect(html).toContain('name="login"');
    expect(html).toContain('form="loginForm"');
  });

  it('forwards aria attributes', () => {
    const html = renderToString(
      <Button aria-label="logout" aria-busy="true">
        click
      </Button>
    );
    expect(html).toContain('aria-label="logout"');
    expect(html).toContain('aria-busy="true"');
  });
});
