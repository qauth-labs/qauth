/**
 * Reading an HTML form the way a browser submits it, so a test can sign in and
 * answer the consent screen without knowing which hidden fields the server
 * renders.
 *
 * Written for the server's own pages, which put each attribute value in double
 * quotes and escape it, so a regular-expression reader is enough. It is the
 * suite's own code and shares nothing with the server's templates: a field the
 * page stops rendering, or renders under another name, fails the flow here.
 */

/** One `name=value` pair, in document order. */
export type FormField = readonly [name: string, value: string];

export interface HtmlForm {
  /** Upper-case, `GET` when the form names none (HTML §4.10.18.6). */
  readonly method: string;
  /** The `action` attribute as written, entity-decoded. */
  readonly action: string;
  /**
   * What a browser submits without the user touching the form: every enabled
   * hidden, text-like or password input with its value, and every checked
   * checkbox or radio button. Buttons are left out; see {@link buttons}.
   */
  readonly fields: readonly FormField[];
  /** The `name=value` of every named submit button, one of which the user presses. */
  readonly buttons: readonly FormField[];
}

const FORM = /<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi;
const INPUT = /<input\b([^>]*?)\/?>/gi;
const BUTTON = /<button\b([^>]*)>/gi;
const ATTRIBUTE = /([^\s"'=<>`/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

/** Input types whose value is submitted as it stands. */
const VALUE_TYPES = new Set(['hidden', 'text', 'email', 'password', 'search', 'tel', 'url']);

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

/** Decode the character references an attribute value can hold. */
export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (reference, body: string) => {
    if (body.startsWith('#x') || body.startsWith('#X')) {
      return String.fromCodePoint(Number.parseInt(body.slice(2), 16));
    }
    if (body.startsWith('#')) return String.fromCodePoint(Number.parseInt(body.slice(1), 10));
    return NAMED_ENTITIES[body.toLowerCase()] ?? reference;
  });
}

/** The attributes of one start tag, names lower-cased, values decoded. */
function attributes(source: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const match of source.matchAll(ATTRIBUTE)) {
    const name = match[1].toLowerCase();
    if (result.has(name)) continue;
    result.set(name, decodeEntities(match[2] ?? match[3] ?? match[4] ?? ''));
  }
  return result;
}

/** Every form in a page, in document order. */
export function readForms(html: string): HtmlForm[] {
  const forms: HtmlForm[] = [];
  for (const [, formAttributes, content] of html.matchAll(FORM)) {
    const form = attributes(formAttributes);
    const fields: FormField[] = [];
    for (const [, inputAttributes] of content.matchAll(INPUT)) {
      const input = attributes(inputAttributes);
      const name = input.get('name');
      if (!name || input.has('disabled')) continue;
      const type = (input.get('type') ?? 'text').toLowerCase();
      if (VALUE_TYPES.has(type)) {
        fields.push([name, input.get('value') ?? '']);
      } else if ((type === 'checkbox' || type === 'radio') && input.has('checked')) {
        fields.push([name, input.get('value') ?? 'on']);
      }
    }
    const buttons: FormField[] = [];
    for (const [, buttonAttributes] of content.matchAll(BUTTON)) {
      const button = attributes(buttonAttributes);
      const name = button.get('name');
      const type = (button.get('type') ?? 'submit').toLowerCase();
      if (name && type === 'submit' && !button.has('disabled')) {
        buttons.push([name, button.get('value') ?? '']);
      }
    }
    forms.push({
      method: (form.get('method') ?? 'get').toUpperCase(),
      action: form.get('action') ?? '',
      fields,
      buttons,
    });
  }
  return forms;
}

/** The first form whose `action` is `action`, or undefined. */
export function findForm(html: string, action: string): HtmlForm | undefined {
  return readForms(html).find((form) => form.action === action);
}

export interface SubmitOptions {
  /**
   * Values the user typed or changed. Each replaces every field of that name,
   * or is added when the form has none. `null` unticks a checkbox: the field
   * is dropped.
   */
  readonly set?: Record<string, string | null>;
  /** The submit button pressed, by its `value`. It must exist in the form. */
  readonly press?: string;
}

/**
 * The body a browser sends for `form`, after the user filled in `set` and
 * pressed the button whose value is `press`.
 *
 * @throws when `press` names no button of the form
 */
export function formBody(form: HtmlForm, options: SubmitOptions = {}): URLSearchParams {
  const set = options.set ?? {};
  const body = new URLSearchParams();
  for (const [name, value] of form.fields) {
    if (Object.hasOwn(set, name)) continue;
    body.append(name, value);
  }
  for (const [name, value] of Object.entries(set)) {
    if (value !== null) body.append(name, value);
  }
  if (options.press !== undefined) {
    const button = form.buttons.find(([, value]) => value === options.press);
    if (!button) {
      throw new Error(
        `the form posting to ${form.action} has no button "${options.press}" ` +
          `(it has ${form.buttons.map(([, value]) => `"${value}"`).join(', ') || 'none'})`
      );
    }
    body.append(button[0], button[1]);
  }
  return body;
}
