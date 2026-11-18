/**
 * A URL with a user name or password, its user information (RFC 3986
 * §3.2.1), carries a secret, and a realm file holds no secret value (#515).
 * No string of a file may be one: not a `jwks_uri`, a redirect URI, an
 * audience or a resource indicator, nor any other member. The parser reads a
 * string the way a URL parser does (WHATWG URL, as Node's `fetch` does), so it
 * also finds `https:/user:pass@host`; the published JSON Schema checks the
 * usual form, `scheme://user:pass@host`, with {@link URL_CREDENTIALS_PATTERN}.
 */

/**
 * The usual form of a URL with user information: a scheme, `://`, then an `@`
 * before the authority ends. Linear: one character class runs up to the `@`.
 */
export const URL_CREDENTIALS_PATTERN = '^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\s]*@';

const URL_CREDENTIALS = new RegExp(URL_CREDENTIALS_PATTERN, 'u');

/** What an issue at such a string says. It never quotes the string, which holds the secret. */
export const URL_CREDENTIALS_MESSAGE =
  'this URL carries a user name or password, which are secrets, and a realm file holds no secret value: write the URL without them';

/** Whether `value` is a URL that names a user or a password. */
export function hasUrlCredentials(value: string): boolean {
  if (!value.includes('@')) return false;
  if (URL_CREDENTIALS.test(value)) return true;
  if (!URL.canParse(value)) return false;
  const url = new URL(value);
  return url.username !== '' || url.password !== '';
}

interface Visit {
  readonly value: unknown;
  readonly parent: Visit | undefined;
  readonly key: string | number | undefined;
}

function pathOf(visit: Visit): (string | number)[] {
  const path: (string | number)[] = [];
  for (let at: Visit | undefined = visit; at?.key !== undefined; at = at.parent) {
    path.unshift(at.key);
  }
  return path;
}

/**
 * The path of every string of `raw`, at any depth, that is a URL with a user
 * name or password, in document order. A loop, not a recursion, so a deeply
 * nested input cannot overflow the stack; a path is built only for a string
 * found.
 */
export function urlCredentialPaths(raw: unknown): (string | number)[][] {
  const found: (string | number)[][] = [];
  const stack: Visit[] = [{ value: raw, parent: undefined, key: undefined }];
  while (stack.length > 0) {
    const visit = stack.pop() as Visit;
    const { value } = visit;
    if (typeof value === 'string') {
      if (hasUrlCredentials(value)) found.push(pathOf(visit));
    } else if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index--) {
        stack.push({ value: value[index], parent: visit, key: index });
      }
    } else if (typeof value === 'object' && value !== null) {
      const entries = Object.entries(value);
      for (let index = entries.length - 1; index >= 0; index--) {
        const [key, member] = entries[index];
        stack.push({ value: member, parent: visit, key });
      }
    }
  }
  return found;
}
