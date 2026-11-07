import { describe, expect, it } from 'vitest';

import { applyBrand, BrandError } from './brand';
import { themeCss } from './theme-css';

function issues(input: unknown): readonly string[] {
  try {
    applyBrand(input);
  } catch (error) {
    if (error instanceof BrandError) return error.issues;
    throw error;
  }
  throw new Error('applyBrand accepted the input');
}

/** The declarations of the first block whose selector starts with `selector`. */
function blockOf(css: string, selector: string): string {
  const at = css.indexOf(`${selector}`);
  return css.slice(css.indexOf('{', at) + 1, css.indexOf('}', at));
}

describe('applyBrand', () => {
  it('returns the default theme for no settings', () => {
    expect(applyBrand({})).toBe(themeCss());
    expect(applyBrand(undefined)).toBe(themeCss());
  });

  it('applies a primary that reaches 4.5:1 with its text, in both modes', () => {
    const css = applyBrand({ primary: '#1d4ed8' });
    expect(blockOf(css, ':root,')).toContain('--primary: #1d4ed8;');
    expect(blockOf(css, "[data-theme='dark']")).toContain('--primary: #1d4ed8;');
    // Darker on hover, never lighter.
    expect(blockOf(css, ':root,')).toMatch(/--primary-hover: #1a45be;/);
  });

  it('uses the primary for links where it reads on the page, and the text colour where not', () => {
    const css = applyBrand({ primary: '#1d4ed8' });
    // #1d4ed8 is 6.7:1 on white, and 2.6:1 on the dark page.
    expect(blockOf(css, ':root,')).toContain('--primary-text: #1d4ed8;');
    expect(blockOf(css, "[data-theme='dark']")).not.toContain('--primary-text: #1d4ed8;');
  });

  it('refuses a primary its text cannot be read on', () => {
    expect(issues({ primary: '#7dd3fc' })).toEqual([
      expect.stringMatching(
        /^brand\.primary: primary-foreground on primary is 1\.\d\d:1 in light mode, below 4\.5:1$/
      ),
      expect.stringMatching(/primary-foreground on primary-hover .* in light mode/),
      expect.stringMatching(/primary-foreground on primary .* in dark mode/),
      expect.stringMatching(/primary-foreground on primary-hover .* in dark mode/),
    ]);
  });

  it('checks an accent in each mode it will have', () => {
    // A dark teal reads on white and not on the dark page.
    expect(issues({ accent: '#0f766e' }).every((i) => i.includes('dark mode'))).toBe(true);
    expect(applyBrand({ accent: { light: '#0f766e', dark: '#5eead4' } })).toContain(
      '--highlight: #5eead4;'
    );
    expect(applyBrand({ accent: '#0f766e', darkMode: false })).toContain('--highlight: #0f766e;');
  });

  it('refuses a font outside the list', () => {
    expect(issues({ font: 'Comic Sans MS' })).toEqual(['brand.font must be one of: qauth, system']);
    expect(issues({ font: 'toString' })).toEqual(['brand.font must be one of: qauth, system']);
  });

  it('sets the font for text and headings', () => {
    const css = blockOf(applyBrand({ font: 'system' }), ':root {');
    expect(css).toContain("--font-sans: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;");
    expect(css).toContain(
      "--font-display: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;"
    );
    expect(applyBrand({ font: 'qauth' })).toBe(themeCss());
  });

  it.each([
    ['url(', { primary: 'url(https://x.example/a.png)' }],
    [';', { primary: '#1d4ed8;color:red' }],
    ['{', { primary: '#1d4ed8{' }],
    ['}', { accent: { light: '}' } }],
    ['url(', { font: 'URL(x)' }],
  ])('refuses a value containing %s', (fragment, input) => {
    expect(issues(input)).toEqual(
      expect.arrayContaining([expect.stringContaining(`contains "${fragment}"`)])
    );
  });

  it('refuses a setting that is not one of the four', () => {
    expect(issues({ logo: '/a.png' })).toEqual(['brand.logo is not a brand setting']);
    expect(issues({ accent: { light: '#0f766e', hover: '#0f766e' } })).toContain(
      'brand.accent.hover is not a mode'
    );
  });

  it('refuses a colour not written #rrggbb', () => {
    expect(issues({ primary: 'blue' })).toEqual(['brand.primary must be a colour written #rrggbb']);
    expect(issues({ primary: 42 })).toEqual([
      'brand.primary must be a colour written #rrggbb, or { light, dark }',
    ]);
  });

  it('refuses settings that are not an object, and a darkMode that is not a boolean', () => {
    expect(issues('dark')).toEqual(['the brand settings must be an object']);
    expect(issues({ darkMode: 'no' })).toEqual(['brand.darkMode must be true or false']);
  });

  it('leaves out the dark set with darkMode: false', () => {
    const css = applyBrand({ darkMode: false });
    expect(css).not.toContain('prefers-color-scheme');
    expect(css).toContain("[data-theme='dark']");
    expect(blockOf(css, ':root,')).toContain('color-scheme: light;');
  });
});
