import { toJSONSchema } from 'zod';

import type {
  AuthMethod,
  AuthMethodContext,
  AuthMethodEgressRequest,
  AuthMethodEgressResponse,
  AuthMethodParameters,
  AuthMethodRoute,
  UpstreamStart,
} from '../auth-method/auth-method.interface';
import { createAuthMethodContext } from '../auth-method/context';
import { completeUpstreamStep, startUpstreamStep } from '../auth-method/engine';
import { AuthMethodContractError } from '../auth-method/errors';
import { authMethodProblems } from '../auth-method/validate';
import { disableFetch } from './fetch-guard';

/**
 * The contract test kit (#599): one function a method's author calls, in any
 * test runner, to check the method against the AuthMethod contract. It is
 * test support, served from the `testing` entry point, never from the main
 * one, and it refuses to run under `NODE_ENV=production`: while it runs, it
 * replaces the global `fetch`.
 *
 * ```ts
 * import { checkAuthMethod } from '@qauth-labs/server-federation/testing';
 *
 * it('meets the AuthMethod contract', async () => {
 *   await checkAuthMethod(myMethod, {
 *     config: { clientId: 'kit', clientSecret: 'kit-secret' },
 *     egress: (request) => myFakeProvider.answer(request),
 *     callback: (authorizationRequest) => myFakeProvider.signIn(authorizationRequest),
 *   });
 * });
 * ```
 *
 * It resolves with the checks it ran, and rejects with an
 * {@link AuthMethodContractError} that lists every check the method failed.
 *
 * EXPERIMENTAL, like the contract it checks.
 *
 * @experimental
 */

/**
 * A request the provider sends the browser back with, to one of the method's
 * routes.
 *
 * @experimental
 */
export interface AuthMethodKitRequest {
  /** The route's path below the method's prefix: `/callback`. */
  readonly path: string;
  readonly method: 'GET' | 'POST';
  readonly query?: AuthMethodParameters;
  readonly form?: AuthMethodParameters;
}

/**
 * How the provider behaves in the kit's run: the method's author plays it.
 *
 * @experimental
 */
export interface AuthMethodKitScenario {
  /** A config for one realm, which the method's `configSchema` accepts. */
  readonly config: unknown;
  /**
   * Answer the method's outbound calls as the provider would. Without it,
   * every call the method makes is refused.
   */
  egress?(
    request: AuthMethodEgressRequest
  ): AuthMethodEgressResponse | Promise<AuthMethodEgressResponse>;
  /**
   * The request the browser comes back with once the person signed in at the
   * provider, for the authorization request `start()` sent it to. Each call
   * signs the same person in.
   */
  callback(authorizationRequest: URL): AuthMethodKitRequest | Promise<AuthMethodKitRequest>;
  /**
   * The request the browser comes back with when the person declines at the
   * provider (`error=access_denied`). Checked when given.
   */
  declined?(authorizationRequest: URL): AuthMethodKitRequest | Promise<AuthMethodKitRequest>;
}

/**
 * What a passing run checked, in order.
 *
 * @experimental
 */
export interface AuthMethodKitReport {
  readonly checks: readonly string[];
}

/** The kit's realm. */
const KIT_ORIGIN = 'https://realm.kit.invalid';

/** Inputs no method's `verify()` may accept: none is a result of its callback. */
const JUNK_RESULTS: readonly unknown[] = [
  undefined,
  null,
  '',
  'kit-forged',
  {},
  [],
  { externalSub: 'kit-forged', assuranceLevel: 'high', rawClaims: {} },
];

/** Ends a run that cannot go on; the problems so far are reported. */
class KitStop extends Error {}

/** One run's state: problems, checks, and the provider's call count. */
interface KitRun {
  readonly problems: string[];
  readonly checks: string[];
  readonly logLines: string[];
  egressCalls: number;
  fail(problem: string): void;
  stop(problem: string): never;
}

/**
 * Check `method` against the AuthMethod contract.
 *
 * Static checks first: the contract version, `type`, `id`, the display data,
 * the config schema (a Zod object schema that renders as JSON Schema and
 * accepts `scenario.config`), the steps and the routes (each inside the
 * method's prefix). Then a run against a fake realm, with the global `fetch`
 * disabled:
 *
 * 1. `start()` answers an `https` redirect with no credentials and no fragment,
 *    and a transaction of JSON data within its cap; two starts answer different
 *    transactions.
 * 2. The provider's callback, with its transaction, ends in an identity whose
 *    attributes carry the method's `type`; a second sign-in of the same person
 *    resolves the same `externalSub`.
 * 3. The callback carries a value of the authorization request (`state`) that
 *    binds it to its transaction. Without it, with it empty or repeated, and
 *    with another start's transaction, the callback never gives a result, and
 *    never calls the provider: it checks the binding before it spends the code.
 *    (A request with no transaction never reaches the method: the host
 *    answers it.)
 * 4. `verify()` rejects inputs that no callback produced, a well-formed
 *    identity, a copy of a real result and a result already used among them.
 * 5. When the scenario gives one, the declined callback ends as `declined`.
 * 6. The method called the global `fetch` nowhere, and no log line carries
 *    the value of a config member marked `writeOnly` (a secret), in a field,
 *    a message or an error.
 *
 * @throws AuthMethodContractError listing every failed check
 * @throws Error when `NODE_ENV` is `production`
 * @experimental
 */
export async function checkAuthMethod(
  method: AuthMethod,
  scenario: AuthMethodKitScenario
): Promise<AuthMethodKitReport> {
  if (process.env['NODE_ENV'] === 'production') {
    throw new Error('checkAuthMethod is a test kit: it does not run with NODE_ENV=production');
  }
  const run: KitRun = {
    problems: [],
    checks: [],
    logLines: [],
    egressCalls: 0,
    fail(problem) {
      this.problems.push(problem);
    },
    stop(problem) {
      this.problems.push(problem);
      throw new KitStop(problem);
    },
  };

  const fetchGuard = disableFetch();
  let secrets: readonly string[] = [];
  try {
    const staticProblems = authMethodProblems(method);
    if (staticProblems.length > 0) {
      run.problems.push(...staticProblems);
      throw new KitStop('static');
    }
    run.checks.push('static');

    secrets = configSecrets(method, scenario.config, run);
    run.checks.push('config-schema');

    const context = kitContext(method, scenario, run);
    run.checks.push('context');

    await runChecks(method, scenario, context, run);
  } catch (error) {
    if (!(error instanceof KitStop)) run.problems.push(`the run threw: ${describe(error)}`);
  } finally {
    fetchGuard.restore();
  }

  if (fetchGuard.calls() > 0) {
    run.problems.push('the method called fetch: its outbound calls go through context.egress');
  }
  if (run.logLines.some((line) => secrets.some((secret) => line.includes(secret)))) {
    run.problems.push('a log line carries the value of a writeOnly config member');
  }
  if (run.problems.length > 0) {
    throw new AuthMethodContractError(
      `The AuthMethod ${String((method as { type?: unknown } | null)?.type)}`,
      run.problems
    );
  }
  run.checks.push('egress-only', 'secrets-not-logged');
  return Object.freeze({ checks: Object.freeze([...run.checks]) });
}

async function runChecks(
  method: AuthMethod,
  scenario: AuthMethodKitScenario,
  context: AuthMethodContext,
  run: KitRun
): Promise<void> {
  const first = await started(method, context, run);
  const second = await started(method, context, run);
  if (JSON.stringify(first.transaction) === JSON.stringify(second.transaction)) {
    run.fail('two starts answered the same transaction: its state must be fresh for each start');
  }
  run.checks.push('start');

  // The provider signs the person in, for the second start.
  const signIn = await scenario.callback(new URL(second.redirectTo));
  const happy = await callback(method, context, signIn, second.transaction, run);
  const completion = await completeUpstreamStep(method, happy).catch((error: unknown) =>
    run.stop(`the callback's outcome was refused: ${describe(error)}`)
  );
  if (completion.kind !== 'identity') {
    run.stop(`the provider's callback ended as ${describeOutcome(completion)}, not in an identity`);
  }
  const result = (happy as { result: unknown }).result;

  // The same person, a second time: the same subject.
  const third = await started(method, context, run);
  const again = await callback(
    method,
    context,
    await scenario.callback(new URL(third.redirectTo)),
    third.transaction,
    run
  );
  const repeated = await completeUpstreamStep(method, again).catch(() => undefined);
  if (
    repeated?.kind !== 'identity' ||
    repeated.identity.externalSub !== completion.identity.externalSub
  ) {
    run.fail('a second sign-in of the same person did not resolve the same externalSub');
  }
  run.checks.push('callback');

  await bindingChecks(method, context, run, { first, second, signIn });
  run.checks.push('transaction-binding');

  await verifyChecks(method, result, run);
  run.checks.push('verify-fails-closed');

  if (scenario.declined !== undefined) {
    const fourth = await started(method, context, run);
    const declinedRequest = await scenario.declined(new URL(fourth.redirectTo));
    const declined = await callback(method, context, declinedRequest, fourth.transaction, run);
    if ((declined as { kind?: unknown }).kind !== 'declined') {
      run.fail(`the declined callback answered ${describeOutcome(declined)}, not declined`);
    }
    run.checks.push('declined');
  }
}

/**
 * The callback must be bound to its transaction by a value of the
 * authorization request it carries back (`state`), and check that binding
 * before it calls the provider.
 */
async function bindingChecks(
  method: AuthMethod,
  context: AuthMethodContext,
  run: KitRun,
  starts: { first: UpstreamStart; second: UpstreamStart; signIn: AuthMethodKitRequest }
): Promise<void> {
  const { first, second, signIn } = starts;
  const authorizationValues = new Set(new URL(second.redirectTo).searchParams.values());
  const echoed = [
    ...echoedNames(signIn.query, authorizationValues).map((name) => ['query', name] as const),
    ...echoedNames(signIn.form, authorizationValues).map((name) => ['form', name] as const),
  ];
  if (echoed.length === 0) {
    run.fail(
      'the callback carries no value of the authorization request (such as state): nothing binds it to its transaction'
    );
  }

  const refused = async (label: string, request: AuthMethodKitRequest, transaction: unknown) => {
    const before = run.egressCalls;
    const outcome = await callback(method, context, request, transaction, run);
    if ((outcome as { kind?: unknown }).kind === 'result') {
      run.fail(`the callback gave a result ${label}: it must check state against its transaction`);
    } else if (run.egressCalls > before) {
      run.fail(
        `the callback called the provider ${label}: it must check state before it spends the code`
      );
    }
  };

  await refused("with another start's transaction", signIn, first.transaction);
  for (const [part, name] of echoed) {
    const changed = (value: string | readonly string[] | undefined) => {
      const parameters: Record<string, string | readonly string[]> = { ...(signIn[part] ?? {}) };
      if (value === undefined) delete parameters[name];
      else parameters[name] = value;
      return { ...signIn, [part]: parameters };
    };
    const original = String(signIn[part]?.[name]);
    await refused(`without ${name}`, changed(undefined), second.transaction);
    await refused(`with ${name} empty`, changed(''), second.transaction);
    await refused(`with ${name} repeated`, changed([original, original]), second.transaction);
  }
}

/** `verify()` rejects anything that is not a fresh result of its own callback. */
async function verifyChecks(method: AuthMethod, result: unknown, run: KitRun): Promise<void> {
  const accepts = (input: unknown) =>
    method.verify(input).then(
      () => true,
      () => false
    );
  for (const junk of JUNK_RESULTS) {
    if (await accepts(junk)) {
      run.fail(
        `verify() resolved for ${JSON.stringify(junk) ?? 'undefined'}, which no callback produced`
      );
    }
  }
  const copy = plainCopy(result);
  if (copy !== undefined && (await accepts(copy))) {
    run.fail(
      "verify() resolved for a copy of a callback's result: it must accept only its own results"
    );
  }
  if (await accepts(result)) {
    run.fail(
      'verify() resolved for a result it had already verified: a result signs one person in once'
    );
  }
}

/** The parameter names of `parameters` whose value appears in the authorization request. */
function echoedNames(
  parameters: AuthMethodParameters | undefined,
  authorizationValues: ReadonlySet<string>
): string[] {
  if (parameters === undefined) return [];
  return Object.entries(parameters)
    .filter(
      ([, value]) => typeof value === 'string' && value !== '' && authorizationValues.has(value)
    )
    .map(([name]) => name);
}

/** A structural copy of `value`, or `undefined` when it cannot be copied. */
function plainCopy(value: unknown): unknown {
  try {
    return structuredClone(value);
  } catch {
    try {
      return JSON.parse(JSON.stringify(value)) as unknown;
    } catch {
      return undefined;
    }
  }
}

async function started(
  method: AuthMethod,
  context: AuthMethodContext,
  run: KitRun
): Promise<UpstreamStart> {
  return startUpstreamStep(method, context, { uiLocales: ['en'] }).catch((error: unknown) =>
    run.stop(`start() failed: ${describe(error)}`)
  );
}

/** Run one request through the method's routes as the host would, following a bounce once. */
async function callback(
  method: AuthMethod,
  context: AuthMethodContext,
  request: AuthMethodKitRequest,
  transaction: unknown,
  run: KitRun
): Promise<unknown> {
  let route = findRoute(method.routes, request.method, request.path);
  if (route === undefined) {
    return run.stop(
      `the scenario's callback names ${request.method} ${request.path}, which is not a route of the method`
    );
  }
  let query = request.query ?? {};
  let form = request.form ?? {};
  if (route.kind === 'bounce') {
    const bounce: unknown = await route
      .handle({ method: route.method, query, form }, context)
      .catch((error: unknown) => run.stop(`the bounce route threw: ${describe(error)}`));
    const { to, query: carried } = (
      typeof bounce === 'object' && bounce !== null ? bounce : {}
    ) as { to?: unknown; query?: unknown };
    const target = method.routes.find(
      (candidate) =>
        candidate.kind === 'callback' && candidate.method === 'GET' && candidate.path === to
    );
    if (target === undefined) {
      return run.stop(
        `the bounce route sent the browser to ${String(to)}, which is not a GET callback route of the method`
      );
    }
    if (
      typeof carried !== 'object' ||
      carried === null ||
      !Object.values(carried).every((value) => typeof value === 'string')
    ) {
      return run.stop('the bounce route carried a query that is not a map of strings');
    }
    route = target;
    query = { ...(carried as Record<string, string>) };
    form = {};
  }
  if (route.kind !== 'callback') {
    return run.stop(`${route.method} ${route.path} is not a callback route`);
  }
  return route
    .handle({ method: route.method, query, form, transaction }, context)
    .catch((error: unknown) => run.stop(`the callback route threw: ${describe(error)}`));
}

function findRoute(
  routes: readonly AuthMethodRoute[],
  method: string,
  path: string
): AuthMethodRoute | undefined {
  return routes.find((route) => route.method === method && route.path === path);
}

/** The method's context in the kit's realm, over a fake egress, signer and logger. */
function kitContext(
  method: AuthMethod,
  scenario: AuthMethodKitScenario,
  run: KitRun
): AuthMethodContext {
  try {
    return createAuthMethodContext(method, {
      config: scenario.config,
      origin: KIT_ORIGIN,
      realmName: 'kit',
      realmId: '00000000-0000-4000-8000-000000000000',
      providerId: method.type,
      signerCaller: 'api',
      egress: {
        async request(request) {
          run.egressCalls += 1;
          if (!/^[a-z][a-z0-9_.:-]{0,63}$/.test(request.purpose)) {
            throw new Error('egress refused: purpose must be a fixed label');
          }
          if (new URL(request.url).protocol !== 'https:') {
            throw new Error('egress refused: the URL is not https');
          }
          if (scenario.egress === undefined) {
            throw new Error('egress refused: the scenario answers no outbound call');
          }
          const { realm: _realm, ...asMethodSent } = request;
          return scenario.egress(asMethodSent);
        },
      },
      signer: {
        async signClientAssertion() {
          return 'eyJhbGciOiJSUzI1NiJ9.eyJraXQiOnRydWV9.a2l0';
        },
        async getUpstreamJwks() {
          return { keys: [] };
        },
      },
      log: kitLogger(run.logLines),
    });
  } catch (error) {
    return run.stop(`the scenario's config does not pass configSchema: ${describe(error)}`);
  }
}

/** Check the config schema renders as an object schema; collect its writeOnly values. */
function configSecrets(method: AuthMethod, config: unknown, run: KitRun): readonly string[] {
  let schema: unknown;
  try {
    schema = toJSONSchema(method.configSchema);
  } catch (error) {
    run.fail(`configSchema does not render as JSON Schema: ${describe(error)}`);
    return [];
  }
  if ((schema as { type?: unknown }).type !== 'object') {
    run.fail('configSchema must be an object schema');
  }
  return writeOnlyValues(schema, config, 0);
}

/**
 * The string values of `config` at the members its schema marks `writeOnly`,
 * through `properties`, `additionalProperties`, `items` and the members of
 * `anyOf`, `oneOf` and `allOf`.
 */
function writeOnlyValues(schema: unknown, config: unknown, depth: number): string[] {
  if (typeof schema !== 'object' || schema === null || depth > 16) return [];
  const node = schema as Record<string, unknown>;
  if (node['writeOnly'] === true) {
    return typeof config === 'string' && config.length >= 4 ? [config] : [];
  }
  const found: string[] = [];
  for (const keyword of ['anyOf', 'oneOf', 'allOf']) {
    const members = node[keyword];
    if (Array.isArray(members)) {
      for (const member of members) found.push(...writeOnlyValues(member, config, depth + 1));
    }
  }
  if (Array.isArray(config)) {
    found.push(...config.flatMap((item) => writeOnlyValues(node['items'], item, depth + 1)));
    return found;
  }
  if (typeof config !== 'object' || config === null) return found;
  const properties = (
    typeof node['properties'] === 'object' && node['properties'] !== null ? node['properties'] : {}
  ) as Record<string, unknown>;
  for (const [key, value] of Object.entries(config)) {
    const child = Object.hasOwn(properties, key) ? properties[key] : node['additionalProperties'];
    found.push(...writeOnlyValues(child, value, depth + 1));
  }
  return found;
}

function kitLogger(lines: string[]) {
  const write = (fields: Record<string, unknown>, message: string): void => {
    lines.push(`${String(message)} ${serialised(fields)}`);
  };
  return { debug: write, info: write, warn: write, error: write };
}

/** JSON of a log line's fields, with each Error's message, stack and cause written out. */
function serialised(value: unknown): string {
  const seen = new WeakSet<object>();
  try {
    return (
      JSON.stringify(value, (_key, member: unknown) => {
        if (member instanceof Error) {
          return {
            name: member.name,
            message: member.message,
            stack: member.stack,
            cause: member.cause,
          };
        }
        if (typeof member === 'object' && member !== null) {
          if (seen.has(member)) return '[cycle]';
          seen.add(member);
        }
        return typeof member === 'bigint' ? member.toString() : member;
      }) ?? ''
    );
  } catch {
    return String(value);
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function describeOutcome(outcome: unknown): string {
  if (typeof outcome !== 'object' || outcome === null) return String(outcome);
  const { kind, reason } = outcome as Record<string, unknown>;
  return reason === undefined ? String(kind) : `${String(kind)} (${String(reason)})`;
}
