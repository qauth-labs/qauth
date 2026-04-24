/**
 * Tiny HTML escape + template helper for the server-rendered login/consent
 * pages (issue #150). We do this inline instead of pulling in a templating
 * dep because the pages are two static forms and the server already ships
 * server-rendered responses nowhere else.
 *
 * SECURITY: every interpolated value passes through `esc()`. The tag
 * function `html` handles that automatically; the only place callers are
 * allowed to bypass escaping is via `safe(...)` for pre-built trusted
 * fragments.
 */

export function esc(value: unknown): string {
  if (value === null || value === undefined) return '';
  const s = String(value);
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Marker wrapper for values that should NOT be HTML-escaped. */
export interface SafeHtml {
  readonly __safe: true;
  readonly value: string;
}

export function safe(value: string): SafeHtml {
  return { __safe: true, value };
}

function isSafe(x: unknown): x is SafeHtml {
  return typeof x === 'object' && x !== null && (x as SafeHtml).__safe === true;
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHtml {
  let out = '';
  strings.forEach((chunk, i) => {
    out += chunk;
    if (i < values.length) {
      const v = values[i];
      if (Array.isArray(v)) {
        for (const item of v) {
          out += isSafe(item) ? item.value : esc(item);
        }
      } else if (isSafe(v)) {
        out += v.value;
      } else {
        out += esc(v);
      }
    }
  });
  return safe(out);
}

export function render(fragment: SafeHtml): string {
  return fragment.value;
}
