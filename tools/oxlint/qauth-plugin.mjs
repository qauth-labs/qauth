/**
 * QAuth's local Oxlint plugin: ESLint rules the workspace relies on that Oxlint
 * does not implement natively, and QAuth's own rules. `.oxlintrc.json` loads it through `jsPlugins`,
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

/**
 * The platform modules that open outbound connections, each with the exports
 * that do. `all` marks a module that is a network client as a whole: any
 * value imported from it is reported. Every other export (`STATUS_CODES`,
 * `isIP`, types) passes.
 */
const NETWORK_MODULE_EXPORTS = new Map(
  [
    ['http', new Set(['request', 'get'])],
    ['https', new Set(['request', 'get'])],
    ['http2', new Set(['connect'])],
    ['net', new Set(['connect', 'createConnection', 'Socket', 'Stream'])],
    ['tls', new Set(['connect', 'TLSSocket'])],
    ['undici', 'all'],
  ].flatMap(([name, exports]) =>
    name === 'undici'
      ? [[name, exports]]
      : [
          [name, exports],
          [`node:${name}`, exports],
        ]
  )
);

/** Whether `module` is one of {@link NETWORK_MODULE_EXPORTS}. */
function isNetworkModule(module) {
  return typeof module === 'string' && NETWORK_MODULE_EXPORTS.has(module);
}

/** Whether `name`, read from `module`, opens a connection. */
function opensConnection(module, name) {
  const exports = NETWORK_MODULE_EXPORTS.get(module);
  return exports === 'all' || (exports !== undefined && exports.has(name));
}

/** Whether every value of `module` is a network client. */
function isClientModule(module) {
  return NETWORK_MODULE_EXPORTS.get(module) === 'all';
}

/** Names of the global object, on which `fetch` is reachable as a property too. */
const GLOBAL_OBJECTS = new Set(['globalThis', 'global', 'window', 'self']);

/** The name of a non-computed or string-keyed member access, or `undefined`. */
function memberName(node) {
  if (!node.computed && node.property.type === 'Identifier') return node.property.name;
  if (
    node.computed &&
    node.property.type === 'Literal' &&
    typeof node.property.value === 'string'
  ) {
    return node.property.value;
  }
  return undefined;
}

/** The module a `require('…')` call names, or `undefined`. */
function requiredModule(node) {
  if (
    node?.type === 'CallExpression' &&
    node.callee.type === 'Identifier' &&
    node.callee.name === 'require' &&
    node.arguments.length === 1 &&
    node.arguments[0].type === 'Literal' &&
    typeof node.arguments[0].value === 'string'
  ) {
    return node.arguments[0].value;
  }
  return undefined;
}

/** The name an import specifier imports, `default` included. */
function importedName(specifier) {
  const { imported } = specifier;
  return imported.type === 'Identifier' ? imported.name : imported.value;
}

/**
 * `no-direct-network` (ADR-019 Decision 8, issue #481): server code makes its
 * outbound HTTP calls through the egress client, which checks every
 * destination, and never through the platform's own clients. Reports:
 *
 * - the global `fetch`, read in any way: `fetch(url)`, `const f = fetch`,
 *   `globalThis.fetch`. A local binding named `fetch` (a parameter) is not
 *   the global one and passes, and so does a property of another object;
 * - the exports of the platform's network modules that open a connection:
 *   `request` and `get` of `node:http` and `node:https`, `connect` of
 *   `node:http2`, `connect`, `createConnection` and `Socket` of `node:net`,
 *   `connect` and `TLSSocket` of `node:tls`: a named import or re-export of
 *   them, a read through the module object (`https.request`), however it was
 *   imported or required, and a destructuring of it;
 * - any value imported or required from `undici`, a network client as a whole;
 * - a dynamic `import()` of those modules, and `export *` from them.
 *
 * `.oxlintrc.json` turns it on for server code outside the egress library.
 * A module path assembled at run time still passes: this keeps honest code
 * honest. `apps/auth-server/src/app/egress-rule.test.ts` lints samples with
 * it.
 */
const noDirectNetwork = {
  meta: {
    type: 'problem',
    docs: { description: 'Disallow outbound HTTP calls that bypass the egress client' },
    schema: [],
    messages: {
      direct:
        '{{what}} bypasses the egress client. Server code makes outbound calls through `fastify.egress` (ADR-019 Decision 8), which checks every destination.',
    },
  },
  create(context) {
    /** Local names bound to a network module object, with the module each names. */
    const modules = new Map();
    const report = (node, what) => context.report({ node, messageId: 'direct', data: { what } });

    return {
      ImportDeclaration(node) {
        const source = node.source.value;
        if (node.importKind === 'type' || !isNetworkModule(source)) return;
        for (const specifier of node.specifiers) {
          if (specifier.type === 'ImportSpecifier' && specifier.importKind === 'type') continue;
          if (isClientModule(source)) {
            report(specifier, `An import from '${source}'`);
          } else if (
            specifier.type === 'ImportDefaultSpecifier' ||
            specifier.type === 'ImportNamespaceSpecifier' ||
            importedName(specifier) === 'default'
          ) {
            modules.set(specifier.local.name, source);
          } else if (opensConnection(source, importedName(specifier))) {
            report(specifier, `${importedName(specifier)} from '${source}'`);
          }
        }
      },
      ExportNamedDeclaration(node) {
        const source = node.source?.value;
        if (node.exportKind === 'type' || !isNetworkModule(source)) return;
        for (const specifier of node.specifiers) {
          const local =
            specifier.local.type === 'Identifier' ? specifier.local.name : specifier.local.value;
          if (specifier.exportKind !== 'type' && opensConnection(source, local)) {
            report(specifier, `${local} from '${source}'`);
          }
        }
      },
      ExportAllDeclaration(node) {
        if (node.exportKind !== 'type' && isNetworkModule(node.source.value)) {
          report(node, `export * from '${node.source.value}'`);
        }
      },
      CallExpression(node) {
        const required = requiredModule(node);
        if (required !== undefined && isClientModule(required)) {
          report(node, `require('${required}')`);
        }
      },
      ImportExpression(node) {
        if (node.source.type === 'Literal' && isNetworkModule(node.source.value)) {
          report(node, `A dynamic import of '${node.source.value}'`);
        }
      },
      VariableDeclarator(node) {
        const required = requiredModule(node.init);
        const source =
          required !== undefined && isNetworkModule(required)
            ? required
            : node.init?.type === 'Identifier'
              ? modules.get(node.init.name)
              : undefined;
        // A client module's require call is reported as a call.
        if (source === undefined || isClientModule(source)) return;
        if (node.id.type === 'Identifier') {
          if (required !== undefined) modules.set(node.id.name, source);
          return;
        }
        if (node.id.type !== 'ObjectPattern') return;
        for (const property of node.id.properties) {
          if (property.type !== 'Property') continue;
          const key = property.key.type === 'Identifier' ? property.key.name : property.key.value;
          if (opensConnection(source, key)) report(property, `${key} from '${source}'`);
        }
      },
      // As ESLint's `no-restricted-globals` finds a global: a reference that
      // no scope declares (the global scope's `through`), or one to a global
      // the configuration declares, which has no definition.
      'Program:exit'(node) {
        const globalScope = context.sourceCode.getScope(node);
        const declared = globalScope.set.get('fetch');
        const references = [
          ...(declared !== undefined && declared.defs.length === 0 ? declared.references : []),
          ...globalScope.through.filter((reference) => reference.identifier.name === 'fetch'),
        ];
        for (const reference of references) report(reference.identifier, 'The global fetch');
      },
      MemberExpression(node) {
        const name = memberName(node);
        if (name === undefined) return;
        const { object } = node;
        if (name === 'fetch' && object.type === 'Identifier' && GLOBAL_OBJECTS.has(object.name)) {
          report(node, `${object.name}.fetch`);
          return;
        }
        if (object.type === 'Identifier' && modules.has(object.name)) {
          if (opensConnection(modules.get(object.name), name)) {
            report(node, `${object.name}.${name}`);
          }
          return;
        }
        const source = requiredModule(object);
        // A client module's require call is reported as a call.
        if (source !== undefined && !isClientModule(source) && opensConnection(source, name)) {
          report(node, `require('${source}').${name}`);
        }
      },
    };
  },
};

/** A request object by its usual names: `request`, `req`, and either with leading underscores. */
const REQUEST_NAME = /^_*(?:request|req)$/;

/** Type names whose value is a request, for an annotated parameter, variable or assertion. */
const REQUEST_TYPES = new Set(['FastifyRequest', 'IncomingMessage']);

/**
 * Request properties Fastify derives from the `Host` header or `X-Forwarded-*`,
 * and Node's `rawHeaders`, which holds the `Host` header among the rest.
 */
const AUTHORITY_PROPERTIES = new Set(['host', 'hostname', 'port', 'protocol', 'rawHeaders']);

/** Header names that carry the request's authority, compared in lower case. */
const AUTHORITY_HEADERS = new Set(['host', ':authority', 'forwarded']);

/** A header name of the `X-Forwarded-*` family, alone in its string. */
const FORWARDED_HEADER = /^x-forwarded-[a-z0-9-]*$/i;

/** The members a request's socket is read through: `request.raw.socket`, `req.connection`. */
const SOCKET_NAMES = new Set(['socket', 'connection']);

/** Expressions that only retype or guard the value they wrap. */
const WRAPPERS = new Set([
  'TSAsExpression',
  'TSSatisfiesExpression',
  'TSNonNullExpression',
  'TSTypeAssertion',
  'ChainExpression',
  'ParenthesizedExpression',
]);

/**
 * The value an expression reads, through the wrappers that only retype or guard
 * it: `request as FastifyRequest`, `request satisfies X`, `headers!`,
 * `<FastifyRequest>request`, an optional chain, parentheses.
 */
function unwrap(node) {
  let current = node;
  while (current && WRAPPERS.has(current.type)) current = current.expression;
  return current;
}

/**
 * The name a member expression or a pattern property reads, or undefined when
 * computed from anything but a string literal or a template with no
 * substitutions (`` headers[`host`] ``).
 */
function propertyName(key, computed) {
  if (!computed && key.type === 'Identifier') return key.name;
  if (key.type === 'Literal' && typeof key.value === 'string') return key.value;
  if (key.type === 'TemplateLiteral' && key.expressions.length === 0) {
    return key.quasis[0]?.value.cooked ?? undefined;
  }
  return undefined;
}

/**
 * The type name a type annotation or assertion names, as in
 * `(request: FastifyRequest)`, `FastifyRequest<{ Body: X }>` or
 * `http.IncomingMessage`.
 */
function typeName(type) {
  if (type?.type !== 'TSTypeReference') return undefined;
  const name = type.typeName;
  if (name?.type === 'Identifier') return name.name;
  if (name?.type === 'TSQualifiedName') return name.right?.name;
  return undefined;
}

/** The type name an annotated identifier or pattern declares. */
function annotatedTypeName(node) {
  return typeName(node?.typeAnnotation?.typeAnnotation);
}

/** A retyping to a request type: `value as FastifyRequest`, `<IncomingMessage>value`. */
function isRequestAssertion(node) {
  return (
    (node?.type === 'TSAsExpression' ||
      node?.type === 'TSSatisfiesExpression' ||
      node?.type === 'TSTypeAssertion') &&
    REQUEST_TYPES.has(typeName(node.typeAnnotation))
  );
}

/**
 * The checks of one file. `requestNames` holds the identifiers the file
 * declares with a request type, as a parameter or a variable; they count as
 * requests by name for the rest of the file.
 */
function checksFor(requestNames) {
  /**
   * A request: `request`, `req`, `_request`, an identifier declared with a
   * request type, a value retyped to one, a member that names one (such as
   * `reply.request`, `this.request` or `ctx.req`), or the `raw` request of one.
   */
  function isRequest(node) {
    if (isRequestAssertion(node)) return true;
    const value = unwrap(node);
    if (isRequestAssertion(value)) return true;
    if (value?.type === 'Identifier') {
      return REQUEST_NAME.test(value.name) || requestNames.has(value.name);
    }
    if (value?.type !== 'MemberExpression') return false;
    const name = propertyName(value.property, value.computed);
    if (name === undefined) return false;
    return REQUEST_NAME.test(name) || (name === 'raw' && isRequest(value.object));
  }

  /** `headers`, or any `<x>.headers`, such as `request.headers` or `request.raw.headers`. */
  function isHeaders(node) {
    const value = unwrap(node);
    if (value?.type === 'Identifier') return value.name === 'headers';
    return (
      value?.type === 'MemberExpression' &&
      propertyName(value.property, value.computed) === 'headers'
    );
  }

  /** A request's socket: `socket`, `connection`, or any `<x>.socket` / `<x>.connection`. */
  function isSocket(node) {
    const value = unwrap(node);
    if (value?.type === 'Identifier') return SOCKET_NAMES.has(value.name);
    if (value?.type !== 'MemberExpression') return false;
    return SOCKET_NAMES.has(propertyName(value.property, value.computed));
  }

  /** Whether reading `name` from `object` reads the request's authority. */
  function readsAuthority(object, name) {
    if (name === undefined) return false;
    if (isRequest(object) && AUTHORITY_PROPERTIES.has(name)) return true;
    if (isSocket(object) && name === 'encrypted') return true;
    return isHeaders(object) && AUTHORITY_HEADERS.has(name.toLowerCase());
  }

  /** What a destructuring pattern unpacks: a request, its headers, its socket, or neither. */
  function sourceOf(node) {
    if (isRequest(node)) return 'request';
    if (isHeaders(node)) return 'headers';
    if (isSocket(node)) return 'socket';
    return undefined;
  }

  return { isRequest, readsAuthority, sourceOf };
}

/**
 * Report every property of an object pattern that unpacks the authority from
 * `source`, following nested patterns: `{ hostname }` and `{ headers: { host } }`
 * from a request, `{ host }` from headers, `{ encrypted }` from a socket. A
 * default value (`{ host = '' }`) is looked through.
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
    else if (source === 'socket' && name === 'encrypted') report(property);
    else if (source === 'request' && name === 'headers') {
      checkPattern(property.value, 'headers', report);
    } else if (source === 'request' && name === 'raw') {
      checkPattern(property.value, 'request', report);
    } else if (source === 'request' && SOCKET_NAMES.has(name)) {
      checkPattern(property.value, 'socket', report);
    }
  }
}

/**
 * `no-request-authority` (ADR-019 Decision 1, issue #490): no URL is built from
 * the request. The realm resolver is the one reader of the request's
 * authority; every other file takes the realm it resolved and builds URLs from
 * the realm row (`realmIssuer`, `buildRealmUrl`). Reported:
 *
 * - `request.host`, `request.hostname`, `request.port`, `request.protocol` and
 *   `request.rawHeaders`, computed or destructured, on a request: `request`,
 *   `req` (with leading underscores too), a member naming one (`reply.request`,
 *   `this.request`) or its `raw` request, an identifier declared as a
 *   `FastifyRequest` or `IncomingMessage` (a parameter, a variable or a
 *   destructured parameter), or a value retyped to one (`x as FastifyRequest`);
 * - the `Host`, `:authority` and `Forwarded` headers read from any `headers`
 *   object (`request.headers.host`, `headers['Host']`, `` headers[`host`] ``,
 *   `const { host } = headers`, `const { headers: { host } } = request`);
 * - `encrypted` on a request's socket (`request.raw.socket.encrypted`,
 *   `req.connection.encrypted`), which decides the scheme;
 * - any string that is an `X-Forwarded-*` header name, wherever it appears.
 *
 * A type assertion, a non-null assertion, `satisfies`, an optional chain or
 * parentheses around any of these are looked through.
 *
 * A path rule like the key custody guard: it keeps honest code honest. An
 * alias (`const h = request.headers; h.host`) or a request under another name
 * with no request type passes; review and the tests of each URL hold the rest
 * of the line.
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
    const requestNames = new Set();
    const { readsAuthority, sourceOf } = checksFor(requestNames);
    return {
      Identifier(node) {
        // A parameter or variable declared with a request type.
        if (REQUEST_TYPES.has(annotatedTypeName(node))) requestNames.add(node.name);
      },
      MemberExpression(node) {
        if (readsAuthority(node.object, propertyName(node.property, node.computed))) report(node);
      },
      VariableDeclarator(node) {
        if (node.id?.type === 'Identifier' && REQUEST_TYPES.has(annotatedTypeName(node.id))) {
          requestNames.add(node.id.name);
        }
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
    'no-direct-network': noDirectNetwork,
    'no-request-authority': noRequestAuthority,
  },
};
