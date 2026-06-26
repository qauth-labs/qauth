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

/**
 * Marker wrapper for values that should NOT be HTML-escaped.
 *
 * The marker is a module-private Symbol, not a plain string key: symbols
 * are not serialisable through JSON/form-parsing, so a user-controlled
 * request body cannot forge a { __safe: true, value: '<script>...' }
 * object that sneaks past `isSafe()`.
 */
const SAFE_MARKER: unique symbol = Symbol('qauth.SafeHtml');

export interface SafeHtml {
  readonly [SAFE_MARKER]: true;
  readonly value: string;
}

export function safe(value: string): SafeHtml {
  return { [SAFE_MARKER]: true, value };
}

function isSafe(x: unknown): x is SafeHtml {
  return (
    typeof x === 'object' && x !== null && (x as Record<symbol, unknown>)[SAFE_MARKER] === true
  );
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

/**
 * Schemes permitted in a user-facing hyperlink. `javascript:`, `data:`,
 * `vbscript:` and friends are deliberately excluded: HTML-escaping protects an
 * attribute *value* against breaking out of its quotes, but it does NOT stop a
 * `javascript:alert(1)` URL (which contains no quotes) from executing when the
 * link is clicked. Any href/src built from client-supplied data MUST pass
 * through `safeUrl()` first (issue #112).
 */
const SAFE_URL_SCHEMES = new Set(['http:', 'https:', 'mailto:']);

/**
 * Return `value` if it parses as an absolute URL with an allowlisted scheme,
 * otherwise `undefined`. Use for any href/src interpolated from
 * client-controlled metadata (e.g. an OAuth client's `homepage_uri`) so a
 * `javascript:`/`data:` URL cannot be rendered as a clickable link.
 *
 * Note: a relative URL is rejected (returns undefined) because it has no
 * parseable scheme — callers that need same-origin relative links should build
 * those from trusted server-side values, not from user input.
 */
export function safeUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return undefined;
  }
  return SAFE_URL_SCHEMES.has(parsed.protocol) ? value : undefined;
}
