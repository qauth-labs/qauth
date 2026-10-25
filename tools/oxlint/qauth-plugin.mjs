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

/** A request object by its usual names: `request`, `req`, and either with leading underscores. */
const REQUEST_NAME = /^_*(?:request|req)$/;

/** Type names whose value is a request, for a destructured parameter. */
const REQUEST_TYPES = new Set(['FastifyRequest', 'IncomingMessage']);

/** Request properties Fastify derives from the `Host` header or `X-Forwarded-*`. */
const AUTHORITY_PROPERTIES = new Set(['host', 'hostname', 'port', 'protocol']);

/** Header names that carry the request's authority, compared in lower case. */
const AUTHORITY_HEADERS = new Set(['host', ':authority', 'forwarded']);

/** A header name of the `X-Forwarded-*` family, alone in its string. */
const FORWARDED_HEADER = /^x-forwarded-[a-z0-9-]*$/i;

/** The name a member expression or a pattern property reads, or undefined when computed from a non-literal. */
function propertyName(key, computed) {
  if (!computed && key.type === 'Identifier') return key.name;
  if (key.type === 'Literal' && typeof key.value === 'string') return key.value;
  return undefined;
}

/**
 * A request: `request`, `req`, `_request`, or a member that names one, such as
 * `reply.request`, `this.request` or `ctx.req`.
 */
function isRequest(node) {
  if (node?.type === 'Identifier') return REQUEST_NAME.test(node.name);
  if (node?.type !== 'MemberExpression') return false;
  const name = propertyName(node.property, node.computed);
  return name !== undefined && REQUEST_NAME.test(name);
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

/** What a destructuring pattern unpacks: a request, its headers, or neither. */
function sourceOf(node) {
  if (isRequest(node)) return 'request';
  if (isHeaders(node)) return 'headers';
  return undefined;
}

/** The type name an annotated pattern declares, as in `({ hostname }: FastifyRequest)`. */
function annotatedTypeName(pattern) {
  const type = pattern.typeAnnotation?.typeAnnotation;
  return type?.type === 'TSTypeReference' && type.typeName?.type === 'Identifier'
    ? type.typeName.name
    : undefined;
}

/**
 * Report every property of an object pattern that unpacks the authority from
 * `source`, following nested patterns: `{ hostname }` and `{ headers: { host } }`
 * from a request, `{ host }` from headers. A default value (`{ host = '' }`) is
 * looked through.
 */
function checkPattern(pattern, source, report) {
  if (pattern?.type === 'AssignmentPattern') return checkPattern(pattern.left, source, report);
  if (pattern?.type !== 'ObjectPattern' || source === undefined) return;
  for (const property of pattern.properties) {
    if (property.type !== 'Property') continue;
    const name = propertyName(property.key, property.computed);
    if (name === undefined) continue;
    if (source === 'request' && AUTHORITY_PROPERTIES.has(name)) report(property);
    else if (source === 'headers' && AUTHORITY_HEADERS.has(name.toLowerCase())) report(property);
    else if (source === 'request' && name === 'headers') {
      checkPattern(property.value, 'headers', report);
    } else if (source === 'request' && name === 'raw') {
      checkPattern(property.value, 'request', report);
    }
  }
}

/**
 * `no-request-authority` (ADR-019 Decision 1, issue #490): no URL is built from
 * the request. The realm resolver is the one reader of the request's
 * authority; every other file takes the realm it resolved and builds URLs from
 * the realm row (`realmIssuer`, `buildRealmUrl`). Reported:
 *
 * - `request.host`, `request.hostname`, `request.port` and `request.protocol`,
 *   on `request`, `req` (with leading underscores too) or a member naming one
 *   (`reply.request`, `this.request`), computed or destructured, including a
 *   parameter typed `FastifyRequest` or `IncomingMessage`;
 * - the `Host`, `:authority` and `Forwarded` headers read from any `headers`
 *   object (`request.headers.host`, `headers['Host']`, `const { host } = headers`,
 *   `const { headers: { host } } = request`);
 * - any string that is an `X-Forwarded-*` header name, wherever it appears.
 *
 * A path rule like the key custody guard: it keeps honest code honest. An
 * alias (`const h = request.headers; h.host`) or a request under another name
 * passes; review and the tests of each URL hold the rest of the line.
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
        checkPattern(node.id, sourceOf(node.init), report);
      },
      AssignmentExpression(node) {
        checkPattern(node.left, sourceOf(node.right), report);
      },
      ObjectPattern(node) {
        if (REQUEST_TYPES.has(annotatedTypeName(node))) checkPattern(node, 'request', report);
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
