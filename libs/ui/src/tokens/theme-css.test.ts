// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';

import { tailwindThemeCss, themeCss } from './theme-css';

/**
 * jsdom applies style rules but ignores `@media`. This answers a media query the way a browser
 * would for the given colour scheme: a matching block is unwrapped, any other is dropped.
 */
function underColorScheme(css: string, scheme: 'light' | 'dark'): string {
  let out = '';
  let i = 0;
  const marker = '@media (prefers-color-scheme: ';
  while (i < css.length) {
    const at = css.indexOf(marker, i);
    if (at === -1) {
      out += css.slice(i);
      break;
    }
    out += css.slice(i, at);
    const open = css.indexOf('{', at);
    let depth = 1;
    let j = open + 1;
    while (depth > 0) {
      if (css[j] === '{') depth++;
      if (css[j] === '}') depth--;
      j++;
    }
    const query = css.slice(at + marker.length, css.indexOf(')', at));
    if (query === scheme) out += css.slice(open + 1, j - 1);
    i = j;
  }
  return out;
}

function mount(css: string, attribute?: 'light' | 'dark') {
  document.head.innerHTML = `<style>${css}</style>`;
  if (attribute) document.documentElement.setAttribute('data-theme', attribute);
  else document.documentElement.removeAttribute('data-theme');
  const root = getComputedStyle(document.documentElement);
  return (name: string) => root.getPropertyValue(name).trim();
}

const LIGHT_BG = 'oklch(1 0 0)';
const DARK_BG = 'oklch(0.113 0.004 260)';

afterEach(() => {
  document.head.innerHTML = '';
  document.documentElement.removeAttribute('data-theme');
});

describe('the generated stylesheets', () => {
  it('match the checked-in files', async () => {
    await expect(themeCss()).toMatchFileSnapshot('../styles/theme.css');
    await expect(tailwindThemeCss()).toMatchFileSnapshot('../styles/tailwind-theme.css');
  });
});

describe('dark mode', () => {
  it('is light with no attribute and no system preference', () => {
    const v = mount(underColorScheme(themeCss(), 'light'));
    expect(v('--background')).toBe(LIGHT_BG);
    expect(v('color-scheme')).toBe('light');
  });

  it('switches with data-theme="dark"', () => {
    const v = mount(underColorScheme(themeCss(), 'light'), 'dark');
    expect(v('--background')).toBe(DARK_BG);
    expect(v('--muted-foreground')).toBe('oklch(0.62 0.008 90)');
  });

  it('follows a system that prefers dark when there is no attribute', () => {
    const v = mount(underColorScheme(themeCss(), 'dark'));
    expect(v('--background')).toBe(DARK_BG);
  });

  it('stays light under a dark system when the root says data-theme="light"', () => {
    const v = mount(underColorScheme(themeCss(), 'dark'), 'light');
    expect(v('--background')).toBe(LIGHT_BG);
  });

  it('fixes a subtree to one mode', () => {
    document.head.innerHTML = `<style>${underColorScheme(themeCss(), 'dark')}</style>`;
    document.body.innerHTML = '<section data-theme="light"><p>x</p></section>';
    const p = document.querySelector('p');
    if (!p) throw new Error('no paragraph');
    expect(getComputedStyle(p).getPropertyValue('--background').trim()).toBe(LIGHT_BG);
    document.body.innerHTML = '';
  });

  it('has no dark set with darkMode: false, whatever the system or the attribute says', () => {
    const css = themeCss({ darkMode: false });
    expect(css).not.toContain('prefers-color-scheme');
    expect(css).not.toContain(DARK_BG);
    expect(mount(underColorScheme(css, 'dark'))('--background')).toBe(LIGHT_BG);
    expect(mount(underColorScheme(css, 'dark'), 'dark')('--background')).toBe(LIGHT_BG);
  });

  it('stops motion under prefers-reduced-motion', () => {
    expect(themeCss()).toMatch(
      /@media \(prefers-reduced-motion: reduce\) \{\s*:root \{\s*--duration-fast: 0ms;\s*--duration-normal: 0ms;/
    );
  });
});
