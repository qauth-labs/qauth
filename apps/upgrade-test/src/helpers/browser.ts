/**
 * Just enough of a browser to sign in through the hosted pages of any QAuth
 * release: a cookie jar for one origin and a reader for the HTML forms the
 * login and consent pages render.
 *
 * The upgrade test drives the SAME flow against releases whose pages differ in
 * markup, so nothing here names a field beyond what the caller fills in: a form
 * is submitted with every input and the chosen button as the page rendered
 * them, the way a browser would.
 */

/**
 * The cookies one origin set. Every request of the test goes to the server
 * under test, so the jar keeps names and values only and honours deletion by
 * `Max-Age=0` or a past `Expires`. It does not enforce the `__Host-` prefix's
 * `Secure` rule: the CI servers run over plain http on localhost with
 * `SESSION_COOKIE_SECURE=false`.
 */
export class CookieJar {
  private readonly cookies = new Map<string, string>();

  /** Store every `Set-Cookie` header of a response. */
  storeFrom(response: Response): void {
    for (const header of response.headers.getSetCookie()) {
      this.store(header);
    }
  }

  /** Store one `Set-Cookie` header value. */
  store(setCookie: string, now: number = Date.now()): void {
    const [pair, ...attributes] = setCookie.split(';');
    const equals = pair.indexOf('=');
    if (equals <= 0) return;
    const name = pair.slice(0, equals).trim();
    const value = pair.slice(equals + 1).trim();
    let expired = false;
    for (const attribute of attributes) {
      const [key, ...rest] = attribute.split('=');
      const attributeValue = rest.join('=').trim();
      switch (key.trim().toLowerCase()) {
        case 'max-age':
          if (/^-?\d+$/.test(attributeValue) && Number(attributeValue) <= 0) expired = true;
          break;
        case 'expires': {
          const at = Date.parse(attributeValue);
          if (!Number.isNaN(at) && at <= now) expired = true;
          break;
        }
      }
    }
    if (expired) {
      this.cookies.delete(name);
    } else {
      this.cookies.set(name, value);
    }
  }

  /** The `Cookie` header, or undefined when the jar is empty. */
  header(): string | undefined {
    if (this.cookies.size === 0) return undefined;
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  }
}

/** A `<form>` as the page rendered it. */
export interface HtmlForm {
  /** The `action` attribute, as written (relative or absolute). */
  readonly action: string;
  /** Lower-case `method`; `get` when absent, as in HTML. */
  readonly method: string;
  /** Every named `<input>`, in document order, with its rendered value. */
  readonly inputs: ReadonlyArray<{
    readonly name: string;
    readonly type: string;
    readonly value: string;
  }>;
  /** Every named submit `<button>`, in document order. */
  readonly buttons: ReadonlyArray<{ readonly name: string; readonly value: string }>;
}

const ENTITIES: Readonly<Record<string, string>> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

/** Decode the character references an HTML attribute value may carry. */
export function decodeHtmlAttribute(value: string): string {
  return value.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, reference: string) => {
    if (reference[0] === '#') {
      const code =
        reference[1] === 'x' || reference[1] === 'X'
          ? Number.parseInt(reference.slice(2), 16)
          : Number.parseInt(reference.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : match;
    }
    return ENTITIES[reference.toLowerCase()] ?? match;
  });
}

/** The attributes of one start tag, names lower-cased. */
function attributesOf(tag: string): Map<string, string> {
  const attributes = new Map<string, string>();
  const pattern = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  // Skip the tag name itself.
  const body = tag.replace(/^<\s*[a-z]+/i, '').replace(/\/?>$/, '');
  for (const match of body.matchAll(pattern)) {
    const value = match[2] ?? match[3] ?? match[4] ?? '';
    attributes.set(match[1].toLowerCase(), decodeHtmlAttribute(value));
  }
  return attributes;
}

/** Every `<form>` of a page, in document order. */
export function parseForms(html: string): HtmlForm[] {
  const forms: HtmlForm[] = [];
  for (const match of html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)) {
    const formTag = /^<form\b[^>]*>/i.exec(match[0])?.[0] ?? '<form>';
    const formAttributes = attributesOf(formTag);
    const inner = match[1];
    const inputs: { name: string; type: string; value: string }[] = [];
    for (const input of inner.matchAll(/<input\b[^>]*>/gi)) {
      const attributes = attributesOf(input[0]);
      const name = attributes.get('name');
      if (!name) continue;
      const type = (attributes.get('type') ?? 'text').toLowerCase();
      // An unchecked box is not submitted (HTML §4.10.21.4).
      if ((type === 'checkbox' || type === 'radio') && !attributes.has('checked')) continue;
      inputs.push({
        name,
        type,
        value: attributes.get('value') ?? (type === 'checkbox' ? 'on' : ''),
      });
    }
    const buttons: { name: string; value: string }[] = [];
    for (const button of inner.matchAll(/<button\b[^>]*>/gi)) {
      const attributes = attributesOf(button[0]);
      const type = (attributes.get('type') ?? 'submit').toLowerCase();
      const name = attributes.get('name');
      if (type !== 'submit' || !name) continue;
      buttons.push({ name, value: attributes.get('value') ?? '' });
    }
    forms.push({
      action: formAttributes.get('action') ?? '',
      method: (formAttributes.get('method') ?? 'get').toLowerCase(),
      inputs,
      buttons,
    });
  }
  return forms;
}

/**
 * The body a browser sends for a form: every input as rendered, with `fields`
 * overriding or adding values, and the named submit button when one is given.
 *
 * @throws when `submitter` names a button the form does not have
 */
export function formBody(
  form: HtmlForm,
  fields: Readonly<Record<string, string>> = {},
  submitter?: { readonly name: string; readonly value: string }
): URLSearchParams {
  const body = new URLSearchParams();
  const overridden = new Set<string>();
  for (const input of form.inputs) {
    if (input.type === 'submit' || input.type === 'button') continue;
    if (Object.hasOwn(fields, input.name)) {
      if (!overridden.has(input.name)) body.append(input.name, fields[input.name]);
      overridden.add(input.name);
    } else {
      body.append(input.name, input.value);
    }
  }
  for (const [name, value] of Object.entries(fields)) {
    if (!overridden.has(name)) body.append(name, value);
  }
  if (submitter) {
    const button = form.buttons.find(
      (candidate) => candidate.name === submitter.name && candidate.value === submitter.value
    );
    if (!button) {
      throw new Error(
        `The form posting to ${form.action} has no ${submitter.name}=${submitter.value} button.`
      );
    }
    body.append(button.name, button.value);
  }
  return body;
}
