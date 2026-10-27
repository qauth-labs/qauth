/**
 * THE ROUTE MANIFEST AGAINST THE CODE (#495).
 *
 * The manifest says, for every route module, which roles register it, which
 * plugins its routes call and which repositories they read or write. A process
 * builds its plugin set and its repository list from those claims, so a claim
 * that falls short is a route that crashes on a node of that role, and a claim
 * that runs long is a repository a role loads without using it.
 *
 * This file reads the code instead of trusting the claims: for each module it
 * follows the relative imports from its file (type-only imports bring no code
 * and are skipped), collects every decorator a plugin provides and every
 * `repositories.<name>` the reached files read, and requires the entry to name
 * exactly those. The jobs, the app's own plugins and the plugin libraries the
 * roles load are held to their lists the same way.
 *
 * It also checks what the folder autoload used to decide: every module under
 * `routes/` with a default export is listed once, under the prefix the
 * autoload gave it (its directory, or its `autoPrefix`), which is also what
 * the docs site's endpoint-coverage guard assumes.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

import { REPOSITORY_NAMES, type RepositoryName } from '@qauth-labs/fastify-plugin-db';
import { SESSION_COOKIE_ROLES } from '@qauth-labs/server-config';
import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

import { SERVER_JOBS } from './jobs';
import { type RolePlugin, ROUTE_MANIFEST } from './route-manifest';
import {
  CORE_REPOSITORIES,
  PLUGIN_REPOSITORIES,
  pluginsFor,
  SERVICE_ROLE_DEFINITIONS,
  SERVICE_ROLE_NAMES,
} from './service-roles';

const APP_DIR = __dirname;
const ROUTES_DIR = join(APP_DIR, 'routes');
const REPO_ROOT = resolve(APP_DIR, '../../../..');

/** The decorators of the plugins a process registers by role, with their plugin. */
const DECORATOR_PLUGINS: Readonly<Record<string, RolePlugin>> = {
  dpop: 'dpop',
  jwtUtils: 'jwt',
  requireJwt: 'jwt',
  verifyRequestAccessToken: 'jwt',
  passwordHasher: 'password',
  passwordValidator: 'password',
  pkceUtils: 'pkce',
  providerRegistry: 'federation',
  emailService: 'email',
  emailVerificationTokenUtils: 'email',
  sessionService: 'sessions',
  ssf: 'ssf',
  egress: 'egress',
};

/** What the files reached from one module read. */
interface Reach {
  readonly files: ReadonlySet<string>;
  readonly plugins: ReadonlySet<RolePlugin>;
  readonly repositories: ReadonlySet<RepositoryName>;
}

function isRepositoryName(name: string): name is RepositoryName {
  return (REPOSITORY_NAMES as readonly string[]).includes(name);
}

/** The `.ts` file a relative specifier names, or `undefined` for a package. */
function resolveImport(from: string, specifier: string): string | undefined {
  if (!specifier.startsWith('.')) return undefined;
  const base = resolve(dirname(from), specifier);
  return [`${base}.ts`, join(base, 'index.ts')].find((candidate) => existsSync(candidate));
}

/** Whether an import or export declaration brings code, not only types. */
function bringsCode(node: ts.ImportDeclaration | ts.ExportDeclaration): boolean {
  if (ts.isExportDeclaration(node)) return !node.isTypeOnly;
  const clause = node.importClause;
  if (clause === undefined) return true;
  if (clause.isTypeOnly) return false;
  if (clause.name !== undefined) return true;
  const bindings = clause.namedBindings;
  if (bindings === undefined || ts.isNamespaceImport(bindings)) return true;
  return bindings.elements.length === 0 || bindings.elements.some((element) => !element.isTypeOnly);
}

/** Whether `node` is `repositories` or `<something>.repositories`. */
function isRepositoriesObject(node: ts.Expression): boolean {
  return (
    (ts.isIdentifier(node) && node.text === 'repositories') ||
    (ts.isPropertyAccessExpression(node) && node.name.text === 'repositories')
  );
}

/**
 * The places in a file that read `fastify.repositories` in a form this check
 * cannot follow: `repositories[name]`, a variable holding the object or
 * destructuring it, or a parameter of the whole type under another name.
 */
function opaqueRepositoryReads(file: string, text = readFileSync(file, 'utf8')): string[] {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const found: string[] = [];
  const where = (node: ts.Node): string =>
    `${relative(APP_DIR, file)}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`;
  const visit = (node: ts.Node): void => {
    if (ts.isElementAccessExpression(node) && isRepositoriesObject(node.expression)) {
      found.push(`${where(node)} indexes repositories`);
    }
    if (
      ts.isVariableDeclaration(node) &&
      node.initializer !== undefined &&
      isRepositoriesObject(node.initializer)
    ) {
      found.push(`${where(node)} holds or destructures repositories`);
    }
    if (
      ts.isParameter(node) &&
      node.type !== undefined &&
      /\['repositories'\]$/.test(node.type.getText(source)) &&
      node.name.getText(source) !== 'repositories'
    ) {
      found.push(`${where(node)} takes the repositories as ${node.name.getText(source)}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

/** One file's imports, decorator reads and repository reads. */
function scan(file: string): {
  imports: string[];
  plugins: Set<RolePlugin>;
  repositories: Set<RepositoryName>;
} {
  const source = ts.createSourceFile(
    file,
    readFileSync(file, 'utf8'),
    ts.ScriptTarget.Latest,
    true
  );
  const imports: string[] = [];
  const plugins = new Set<RolePlugin>();
  const repositories = new Set<RepositoryName>();

  const visit = (node: ts.Node): void => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier !== undefined &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      bringsCode(node)
    ) {
      const target = resolveImport(file, node.moduleSpecifier.text);
      if (target !== undefined) imports.push(target);
    }
    if (ts.isPropertyAccessExpression(node)) {
      if (Object.hasOwn(DECORATOR_PLUGINS, node.name.text)) {
        plugins.add(DECORATOR_PLUGINS[node.name.text]);
      }
      if (isRepositoriesObject(node.expression) && isRepositoryName(node.name.text)) {
        repositories.add(node.name.text);
      }
    }
    // `Pick<FastifyInstance['repositories'], 'a' | 'b'>`: a helper handed the
    // whole object, reading the named repositories.
    if (
      ts.isTypeReferenceNode(node) &&
      node.typeName.getText(source) === 'Pick' &&
      node.typeArguments !== undefined &&
      /(\['repositories'\]|^Repositories)$/.test(node.typeArguments[0].getText(source))
    ) {
      const keys = node.typeArguments[1];
      const literals = ts.isUnionTypeNode(keys) ? keys.types : [keys];
      for (const literal of literals) {
        if (ts.isLiteralTypeNode(literal) && ts.isStringLiteral(literal.literal)) {
          const name = literal.literal.text;
          if (isRepositoryName(name)) repositories.add(name);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { imports, plugins, repositories };
}

/** Everything the files reachable from `entry` read. */
function reach(entry: string): Reach {
  const files = new Set<string>();
  const plugins = new Set<RolePlugin>();
  const repositories = new Set<RepositoryName>();
  const pending = [entry];
  while (pending.length > 0) {
    const file = pending.pop() as string;
    if (files.has(file)) continue;
    files.add(file);
    const scanned = scan(file);
    scanned.plugins.forEach((plugin) => plugins.add(plugin));
    scanned.repositories.forEach((name) => repositories.add(name));
    pending.push(...scanned.imports);
  }
  return { files, plugins, repositories };
}

/** Every file of a directory tree but tests. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.name.endsWith('.ts') && !/\.(test|spec)\.ts$/.test(entry.name) ? [path] : [];
  });
}

/** The file of a manifest module. */
function moduleFile(module: string): string {
  const file = resolveImport(join(ROUTES_DIR, 'index.ts'), `./${module}`);
  if (file === undefined) throw new Error(`No route module at routes/${module}`);
  return file;
}

const sorted = <T extends string>(values: Iterable<T>): T[] => [...values].sort();

describe('the route manifest (#495)', () => {
  it('lists every route module under routes/ exactly once', () => {
    const modules = sourceFiles(ROUTES_DIR)
      .filter((file) => /^export default /m.test(readFileSync(file, 'utf8')))
      .map((file) =>
        relative(ROUTES_DIR, file)
          .split(sep)
          .join('/')
          .replace(/(\/index)?\.ts$/, '')
      );
    const listed = ROUTE_MANIFEST.map((entry) => entry.module);

    expect(sorted(listed)).toEqual(sorted(modules));
    expect(new Set(listed).size).toBe(listed.length);
  });

  it('keeps the order the folder autoload registered, which the OpenAPI paths follow', () => {
    // The files of a directory, alphabetically, then its subdirectories.
    const autoloadOrder = (dir: string, prefix: string): string[] => {
      const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
        a.name.localeCompare(b.name)
      );
      const files = entries
        .filter((entry) => entry.isFile() && entry.name.endsWith('.ts'))
        .filter((entry) => !/\.(test|spec)\.ts$/.test(entry.name))
        .filter((entry) => /^export default /m.test(readFileSync(join(dir, entry.name), 'utf8')))
        .map((entry) =>
          entry.name === 'index.ts' ? prefix.slice(0, -1) : prefix + entry.name.replace(/\.ts$/, '')
        );
      if (files.includes(prefix.slice(0, -1))) return files;
      return [
        ...files,
        ...entries
          .filter((entry) => entry.isDirectory())
          .flatMap((entry) => autoloadOrder(join(dir, entry.name), `${prefix}${entry.name}/`)),
      ];
    };
    expect(ROUTE_MANIFEST.map((entry) => entry.module)).toEqual(autoloadOrder(ROUTES_DIR, ''));
  });

  it('gives every module at least one role, and only known roles', () => {
    for (const entry of ROUTE_MANIFEST) {
      expect(entry.roles.length, entry.module).toBeGreaterThan(0);
      for (const role of entry.roles) {
        expect(SERVICE_ROLE_NAMES, entry.module).toContain(role);
      }
    }
  });

  it('registers each module under the prefix the folder autoload gave it', () => {
    for (const entry of ROUTE_MANIFEST) {
      const file = moduleFile(entry.module);
      const autoPrefix = /^export const autoPrefix = '([^']*)';$/m.exec(readFileSync(file, 'utf8'));
      const directory = relative(ROUTES_DIR, dirname(file)).split(sep).join('/');
      const expected =
        autoPrefix !== null ? autoPrefix[1] : directory === '' ? undefined : `/${directory}`;
      expect(entry.prefix, entry.module).toBe(expected);
    }
  });

  it.each(ROUTE_MANIFEST.map((entry) => [entry.module, entry] as const))(
    'names exactly the plugins and repositories %s reaches',
    (_module, entry) => {
      const reached = reach(moduleFile(entry.module));
      expect(sorted(entry.plugins)).toEqual(sorted(reached.plugins));
      expect(sorted(entry.repositories)).toEqual(sorted(reached.repositories));
    }
  );
});

describe('what the check can see (#495)', () => {
  it('finds every repository read of the app in a form it follows', () => {
    const opaque = sourceFiles(APP_DIR).flatMap((file) => opaqueRepositoryReads(file));
    expect(opaque).toEqual([]);
  });

  it.each([
    ['an index', 'fastify.repositories[name].findById(id);', 'indexes repositories'],
    [
      'a destructuring',
      'const { users } = fastify.repositories;',
      'holds or destructures repositories',
    ],
    ['an alias', 'const repos = fastify.repositories;', 'holds or destructures repositories'],
    [
      'a renamed parameter',
      "function f(repos: FastifyInstance['repositories']) {}",
      'takes the repositories as repos',
    ],
  ])('would report %s', (_label, code, finding) => {
    expect(opaqueRepositoryReads(join(APP_DIR, 'sample.ts'), code)).toEqual([
      `sample.ts:1 ${finding}`,
    ]);
  });

  it.each([
    ['dpop', 'dpop'],
    ['jwt', 'jwt'],
    ['password', 'password'],
    ['pkce', 'pkce'],
    ['federation', 'federation'],
    ['email', 'email'],
    ['sessions', 'sessions'],
    ['ssf', 'ssf'],
    ['egress', 'egress'],
  ] as const)('maps every decorator of the %s plugin library to its plugin', (lib, plugin) => {
    const decorated = new Set<string>();
    for (const file of sourceFiles(join(REPO_ROOT, 'libs/fastify/plugins', lib, 'src'))) {
      for (const match of readFileSync(file, 'utf8').matchAll(/\.decorate\(\s*'(\w+)'/g)) {
        decorated.add(match[1]);
      }
    }
    expect(decorated.size, lib).toBeGreaterThan(0);
    for (const name of decorated) {
      expect(DECORATOR_PLUGINS[name], `${lib}: ${name}`).toBe(plugin);
    }
  });
});

describe('what the roles load beside their routes (#495)', () => {
  it.each(SERVER_JOBS.map((job) => [job.name, job] as const))(
    'places the job %s with exactly the repositories it reads',
    (name, job) => {
      // What the job's module reads, and what its placement hands it.
      const read = new Set(reach(join(APP_DIR, 'jobs', `${name}.ts`)).repositories);
      for (const match of job.create.toString().matchAll(/repositories\.(\w+)/g)) {
        if (isRepositoryName(match[1])) read.add(match[1]);
      }
      expect(sorted(job.repositories)).toEqual(sorted(read));
    }
  );

  it('loads in every process the repositories of the plugins every process registers', () => {
    // The plugins every process registers; the jobs plugin builds the jobs of
    // the process's roles (checked above) and the metrics plugin is below.
    for (const plugin of [
      'realm-resolver',
      'default-realm',
      'error-handler',
      'rate-limit',
      'request-id',
      'security-headers',
    ]) {
      const reached = reach(join(APP_DIR, 'plugins', `${plugin}.ts`));
      for (const name of reached.repositories) {
        expect(CORE_REPOSITORIES, plugin).toContain(name);
      }
    }
  });

  it('gives the event store gauges of /metrics to the role that reads the store', () => {
    // The gauges are registered only where the repositories are loaded, so a
    // role without them simply has no gauge; delivery reads the store.
    const reached = reach(join(APP_DIR, 'plugins', 'metrics.ts'));
    for (const name of reached.repositories) {
      expect(SERVICE_ROLE_DEFINITIONS.delivery.repositories).toContain(name);
    }
  });

  it.each(['sessions', 'ssf'] as const)(
    'names the repositories the %s plugin library reads',
    (plugin) => {
      const libDir = join(REPO_ROOT, 'libs/fastify/plugins', plugin, 'src');
      const read = new Set<RepositoryName>();
      for (const file of sourceFiles(libDir)) {
        scan(file).repositories.forEach((name) => read.add(name));
      }
      expect(sorted(PLUGIN_REPOSITORIES[plugin] ?? [])).toEqual(sorted(read));
    }
  );

  it('asks for SESSION_COOKIE_SECRET on exactly the roles that read the session cookie', () => {
    // A role reads the cookie when one of its modules reaches the cookie
    // helper or it registers the session service; the production check
    // (`config/env-schema.ts`) refuses the development secret only there.
    const cookieHelper = join(APP_DIR, 'helpers', 'session-cookie.ts');
    const readers = SERVICE_ROLE_NAMES.filter(
      (role) =>
        pluginsFor([role]).has('sessions') ||
        ROUTE_MANIFEST.some(
          (entry) =>
            entry.roles.includes(role) && reach(moduleFile(entry.module)).files.has(cookieHelper)
        )
    );
    expect(sorted(readers)).toEqual(sorted(SESSION_COOKIE_ROLES));
  });

  it('leaves no other plugin library reading fastify.repositories', () => {
    const readers = readdirSync(join(REPO_ROOT, 'libs/fastify/plugins')).filter((plugin) => {
      if (plugin === 'db') return false;
      const libDir = join(REPO_ROOT, 'libs/fastify/plugins', plugin, 'src');
      return sourceFiles(libDir).some((file) => scan(file).repositories.size > 0);
    });
    expect(sorted(readers)).toEqual(sorted(Object.keys(PLUGIN_REPOSITORIES)));
  });
});
