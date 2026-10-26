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

/** The modules whose `request` and `get` open an outbound HTTP connection. */
const HTTP_MODULES = new Set(['http', 'https', 'node:http', 'node:https']);
/** The functions of those modules that send a request. */
const HTTP_REQUEST_FUNCTIONS = new Set(['request', 'get']);
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
 * - `request` and `get` of `node:http` and `node:https`: a named import of
 *   them, or a read through the module object (`https.request`), however it
 *   was imported or required.
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
    /** Local names bound to the `http` or `https` module object. */
    const modules = new Set();
    const report = (node, what) => context.report({ node, messageId: 'direct', data: { what } });

    return {
      ImportDeclaration(node) {
        if (node.importKind === 'type' || !HTTP_MODULES.has(node.source.value)) return;
        for (const specifier of node.specifiers) {
          if (
            specifier.type === 'ImportDefaultSpecifier' ||
            specifier.type === 'ImportNamespaceSpecifier'
          ) {
            modules.add(specifier.local.name);
          } else if (
            specifier.type === 'ImportSpecifier' &&
            specifier.importKind !== 'type' &&
            HTTP_REQUEST_FUNCTIONS.has(importedName(specifier))
          ) {
            report(specifier, `${importedName(specifier)} from '${node.source.value}'`);
          } else if (
            specifier.type === 'ImportSpecifier' &&
            importedName(specifier) === 'default'
          ) {
            modules.add(specifier.local.name);
          }
        }
      },
      VariableDeclarator(node) {
        const source = requiredModule(node.init);
        if (source === undefined || !HTTP_MODULES.has(source)) return;
        if (node.id.type === 'Identifier') {
          modules.add(node.id.name);
          return;
        }
        if (node.id.type !== 'ObjectPattern') return;
        for (const property of node.id.properties) {
          if (property.type !== 'Property') continue;
          const key = property.key.type === 'Identifier' ? property.key.name : property.key.value;
          if (HTTP_REQUEST_FUNCTIONS.has(key)) report(property, `${key} from '${source}'`);
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
        if (!HTTP_REQUEST_FUNCTIONS.has(name)) return;
        if (object.type === 'Identifier' && modules.has(object.name)) {
          report(node, `${object.name}.${name}`);
          return;
        }
        const source = requiredModule(object);
        if (source !== undefined && HTTP_MODULES.has(source)) {
          report(node, `require('${source}').${name}`);
        }
      },
    };
  },
};

export default {
  meta: { name: 'qauth' },
  rules: { 'no-restricted-syntax': noRestrictedSyntax, 'no-direct-network': noDirectNetwork },
};
