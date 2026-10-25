/**
 * QAuth's local Oxlint plugin: ESLint rules the workspace relies on that Oxlint
 * does not implement natively. `.oxlintrc.json` loads it through `jsPlugins`,
 * so its rules are named `qauth/<rule>`.
 *
 * Oxlint's JS-plugin API mirrors ESLint's rule API (`context.options`,
 * `context.report`, esquery selectors as visitor keys), which is what lets an
 * ESLint rule run here unchanged. That API is outside Oxlint's semver, so
 * `oxlint` is pinned exactly in the catalog and a bump is a reviewed change.
 *
 * This directory is its own Nx project (`oxlint-plugin`, see project.json):
 * @nx/oxlint makes every linted project depend on the project that holds a
 * local JS plugin, and that must not be the root project.
 */

/**
 * `no-restricted-syntax`, ported from ESLint 10 (`lib/rules/no-restricted-syntax.js`)
 * with the same options: each one is an esquery selector, or `{ selector,
 * message }`, and every node it matches is reported. Oxlint has no native
 * counterpart. The key custody guard (ADR-019 Decision 9) uses it for the
 * import forms `no-restricted-imports` does not see.
 */
const noRestrictedSyntax = {
  meta: {
    type: 'suggestion',
    docs: { description: 'Disallow specified syntax' },
    schema: {
      type: 'array',
      items: {
        oneOf: [
          { type: 'string' },
          {
            type: 'object',
            properties: { selector: { type: 'string' }, message: { type: 'string' } },
            required: ['selector'],
            additionalProperties: false,
          },
        ],
      },
      uniqueItems: true,
      minItems: 0,
    },
    messages: { restrictedSyntax: '{{message}}' },
  },
  create(context) {
    return context.options.reduce((visitor, selectorOrObject) => {
      const isStringFormat = typeof selectorOrObject === 'string';
      const selector = isStringFormat ? selectorOrObject : selectorOrObject.selector;
      const message =
        !isStringFormat && selectorOrObject.message
          ? selectorOrObject.message
          : `Using '${selector}' is not allowed.`;
      return Object.assign(visitor, {
        [selector](node) {
          context.report({ node, messageId: 'restrictedSyntax', data: { message } });
        },
      });
    }, {});
  },
};

/** The request objects of the auth server's handlers and hooks, by their usual names. */
const REQUEST_NAMES = new Set(['request', 'req']);

/** Request properties Fastify derives from the `Host` header or `X-Forwarded-*`. */
const AUTHORITY_PROPERTIES = new Set(['host', 'hostname', 'port', 'protocol']);

/** Header names that carry the request's authority, compared in lower case. */
const AUTHORITY_HEADERS = new Set(['host', ':authority']);

/** A header name of the `X-Forwarded-*` family, alone in its string. */
const FORWARDED_HEADER = /^x-forwarded-[a-z0-9-]*$/i;

/** The name a member expression or a pattern property reads, or undefined when computed from a non-literal. */
function propertyName(key, computed) {
  if (!computed && key.type === 'Identifier') return key.name;
  if (key.type === 'Literal' && typeof key.value === 'string') return key.value;
  return undefined;
}

/** `request`, `req`. */
function isRequest(node) {
  return node?.type === 'Identifier' && REQUEST_NAMES.has(node.name);
}

/** `headers`, or any `<x>.headers`, such as `request.headers` or `request.raw.headers`. */
function isHeaders(node) {
  if (node?.type === 'Identifier') return node.name === 'headers';
  return (
    node?.type === 'MemberExpression' && propertyName(node.property, node.computed) === 'headers'
  );
}

/** Whether reading `name` from `object` reads the request's authority. */
function readsAuthority(object, name) {
  if (name === undefined) return false;
  if (isRequest(object) && AUTHORITY_PROPERTIES.has(name)) return true;
  return isHeaders(object) && AUTHORITY_HEADERS.has(name.toLowerCase());
}

/**
 * `no-request-authority` (ADR-019 Decision 1, issue #490): no URL is built from
 * the request. The realm resolver is the one reader of the request's
 * authority; every other file takes the realm it resolved and builds URLs from
 * the realm row (`realmIssuer`, `buildRealmUrl`). Reported:
 *
 * - `request.host`, `request.hostname`, `request.port` and `request.protocol`
 *   (also on `req`, computed, or destructured from it);
 * - the `Host` header and `:authority` read from any `headers` object
 *   (`request.headers.host`, `headers['Host']`, `const { host } = headers`);
 * - any string that is an `X-Forwarded-*` header name, wherever it appears.
 *
 * Takes no options. `.oxlintrc.json` turns it on for the auth server and the
 * libraries it loads, outside the resolver and the tests, which send such
 * headers on purpose.
 */
const noRequestAuthority = {
  meta: {
    type: 'problem',
    docs: { description: "Disallow reading the request's authority outside the realm resolver" },
    schema: [],
    messages: {
      requestAuthority:
        "Build URLs from the realm row (ADR-019 Decision 1): realmIssuer(realm) or buildRealmUrl(realm, path). Only the realm resolver reads the request's Host, X-Forwarded-* or protocol.",
    },
  },
  create(context) {
    const report = (node) => context.report({ node, messageId: 'requestAuthority' });
    return {
      MemberExpression(node) {
        if (readsAuthority(node.object, propertyName(node.property, node.computed))) report(node);
      },
      VariableDeclarator(node) {
        if (node.id.type !== 'ObjectPattern') return;
        for (const property of node.id.properties) {
          if (property.type !== 'Property') continue;
          if (readsAuthority(node.init, propertyName(property.key, property.computed))) {
            report(property);
          }
        }
      },
      Literal(node) {
        if (typeof node.value === 'string' && FORWARDED_HEADER.test(node.value)) report(node);
      },
      TemplateElement(node) {
        if (FORWARDED_HEADER.test(node.value.raw)) report(node);
      },
    };
  },
};

export default {
  meta: { name: 'qauth' },
  rules: {
    'no-restricted-syntax': noRestrictedSyntax,
    'no-request-authority': noRequestAuthority,
  },
};
