import { toJSONSchema } from 'zod';

import { disableFetch } from '../testing/fetch-guard';
import type {
  AuthMethod,
  AuthMethodContext,
  AuthMethodEgressRequest,
  AuthMethodEgressResponse,
  AuthMethodParameters,
  AuthMethodRoute,
  UpstreamStart,
} from './auth-method.interface';
import { createAuthMethodContext } from './context';
import { completeUpstreamStep, startUpstreamStep } from './engine';
import { AuthMethodContractError } from './errors';
import { authMethodProblems } from './validate';

/**
 * The contract test kit (#599): one function a method's author calls, in any
 * test runner, to check the method against the AuthMethod contract.
 *
 * ```ts
 * import { checkAuthMethod } from '@qauth-labs/server-federation';
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
   * provider, for the authorization request `start()` sent it to.
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

/** The origin the kit's realm is reached at. */
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

/**
 * Check `method` against the AuthMethod contract.
 *
 * Static checks first: the contract version, `type`, `id`, the display data,
 * the config schema (a Zod object schema that renders as JSON Schema and
 * accepts `scenario.config`), the steps and the routes (each inside the
 * method's prefix). Then a run against a fake realm, with `fetch` disabled so
 * that every outbound call must go through `context.egress`:
 *
 * 1. `start()` answers an `https` redirect with no credentials and no fragment,
 *    and a transaction of JSON data within its cap; a second start answers a
 *    different transaction, so its `state` cannot be guessed from the first.
 * 2. The provider's callback, with its transaction, ends in an identity: one
 *    `verify()` resolves, with an `externalSub`, an assurance level and raw
 *    claims, and attributes whose `source` is the method's `type`.
 * 3. The same callback with no transaction, and the callback of one start
 *    with the transaction of another, never end in an identity.
 * 4. `verify()` rejects inputs that no callback produced, a well-formed
 *    identity among them.
 * 5. When the scenario gives one, the declined callback ends as `declined`.
 * 6. No log line carries the value of a config member marked
 *    `writeOnly` (a secret).
 *
 * @throws AuthMethodContractError listing every failed check
 * @experimental
 */
export async function checkAuthMethod(
  method: AuthMethod,
  scenario: AuthMethodKitScenario
): Promise<AuthMethodKitReport> {
  const problems: string[] = [];
  const checks: string[] = [];
  const fail = (problem: string): void => {
    problems.push(problem);
  };
  const stop = (problem: string): never => {
    problems.push(problem);
    throw new KitStop(problem);
  };

  const fetchGuard = disableFetch();

  const logLines: string[] = [];
  let secrets: readonly string[] = [];
  try {
    const staticProblems = authMethodProblems(method);
    if (staticProblems.length > 0) {
      problems.push(...staticProblems);
      throw new KitStop('static');
    }
    checks.push('static');

    secrets = configSecrets(method, scenario.config, fail);
    checks.push('config-schema');

    let context: AuthMethodContext;
    try {
      context = createAuthMethodContext(method, {
        config: scenario.config,
        origin: KIT_ORIGIN,
        egress: kitEgress(scenario),
        signer: kitSigner(),
        log: kitLogger(logLines),
      });
    } catch (error) {
      return stop(`the scenario's config does not pass configSchema: ${describe(error)}`);
    }
    checks.push('context');

    const first = await started(method, context, stop);
    const second = await started(method, context, stop);
    if (JSON.stringify(first.transaction) === JSON.stringify(second.transaction)) {
      fail('two starts answered the same transaction: its state must be fresh for each start');
    }
    checks.push('start');

    // The provider signs the person in, for the second start.
    const secondRequest = await scenario.callback(new URL(second.redirectTo));
    const happy = await callback(method, context, secondRequest, second.transaction, stop);
    const completion = await completeUpstreamStep(method, happy).catch((error: unknown) =>
      stop(`the callback's outcome was refused: ${describe(error)}`)
    );
    if (completion.kind !== 'identity') {
      stop(
        `the provider's callback ended as ${describeCompletion(completion)}, not in an identity`
      );
    }
    checks.push('callback');

    // No transaction: another browser, or a replay after the first took it.
    const replay = await callback(method, context, secondRequest, undefined, stop);
    if (!isMismatch(replay)) {
      fail(
        `the callback with no transaction answered ${describeOutcome(replay)}, not failed with transaction_mismatch`
      );
    }
    // The callback of the second start, with the first start's transaction.
    const mixed = await callback(method, context, secondRequest, first.transaction, stop);
    if (
      typeof mixed === 'object' &&
      mixed !== null &&
      (mixed as { kind?: unknown }).kind === 'result'
    ) {
      fail("the callback accepted another start's transaction: it must check state against it");
    }
    checks.push('transaction-binding');

    for (const junk of JUNK_RESULTS) {
      const accepted = await method.verify(junk).then(
        () => true,
        () => false
      );
      if (accepted) {
        fail(
          `verify() resolved for ${JSON.stringify(junk) ?? 'undefined'}, which no callback produced`
        );
      }
    }
    checks.push('verify-fails-closed');

    if (scenario.declined !== undefined) {
      const thirdStart = await started(method, context, stop);
      const declinedRequest = await scenario.declined(new URL(thirdStart.redirectTo));
      const declined = await callback(
        method,
        context,
        declinedRequest,
        thirdStart.transaction,
        stop
      );
      if ((declined as { kind?: unknown }).kind !== 'declined') {
        fail(`the declined callback answered ${describeOutcome(declined)}, not declined`);
      }
      checks.push('declined');
    }
  } catch (error) {
    if (!(error instanceof KitStop)) problems.push(`the run threw: ${describe(error)}`);
  } finally {
    fetchGuard.restore();
  }

  if (fetchGuard.calls() > 0) {
    problems.push('the method called fetch: every outbound call must go through context.egress');
  }
  if (logLines.some((line) => secrets.some((secret) => line.includes(secret)))) {
    problems.push('a log line carries the value of a writeOnly config member');
  }
  if (problems.length > 0) {
    throw new AuthMethodContractError(
      `The AuthMethod ${String((method as { type?: unknown } | null)?.type)}`,
      problems
    );
  }
  checks.push('egress-only', 'secrets-not-logged');
  return Object.freeze({ checks: Object.freeze(checks) });
}

async function started(
  method: AuthMethod,
  context: AuthMethodContext,
  stop: (problem: string) => never
): Promise<UpstreamStart> {
  return startUpstreamStep(method, context, { uiLocales: ['en'] }).catch((error: unknown) =>
    stop(`start() failed: ${describe(error)}`)
  );
}

/** Run one request through the method's routes, following a bounce once. */
async function callback(
  method: AuthMethod,
  context: AuthMethodContext,
  request: AuthMethodKitRequest,
  transaction: unknown,
  stop: (problem: string) => never
): Promise<unknown> {
  let route = findRoute(method.routes, request.method, request.path);
  if (route === undefined) {
    return stop(
      `the scenario's callback names ${request.method} ${request.path}, which is not a route of the method`
    );
  }
  let query = request.query ?? {};
  let form = request.form ?? {};
  if (route.kind === 'bounce') {
    const bounce: unknown = await route
      .handle({ method: route.method, query, form }, context)
      .catch((error: unknown) => stop(`the bounce route threw: ${describe(error)}`));
    const { to, query: carried } = (
      typeof bounce === 'object' && bounce !== null ? bounce : {}
    ) as {
      to?: unknown;
      query?: unknown;
    };
    const target = typeof to === 'string' ? findRoute(method.routes, 'GET', to) : undefined;
    if (target === undefined) {
      return stop(
        `the bounce route sent the browser to ${String(to)}, which is not a GET route of the method`
      );
    }
    if (
      typeof carried !== 'object' ||
      carried === null ||
      !Object.values(carried).every((value) => typeof value === 'string')
    ) {
      return stop('the bounce route carried a query that is not a map of strings');
    }
    route = target;
    query = { ...(carried as Record<string, string>) };
    form = {};
  }
  if (route.kind !== 'callback') {
    return stop(`${route.method} ${route.path} is not a callback route`);
  }
  return route
    .handle({ method: route.method, query, form, transaction }, context)
    .catch((error: unknown) => stop(`the callback route threw: ${describe(error)}`));
}

function findRoute(
  routes: readonly AuthMethodRoute[],
  method: string,
  path: string
): AuthMethodRoute | undefined {
  return routes.find((route) => route.method === method && route.path === path);
}

function isMismatch(outcome: unknown): boolean {
  if (typeof outcome !== 'object' || outcome === null) return false;
  const { kind, reason } = outcome as Record<string, unknown>;
  return kind === 'failed' && reason === 'transaction_mismatch';
}

/** Check the config schema renders as an object schema; collect its writeOnly values. */
function configSecrets(
  method: AuthMethod,
  config: unknown,
  fail: (problem: string) => void
): readonly string[] {
  let schema: unknown;
  try {
    schema = toJSONSchema(method.configSchema);
  } catch (error) {
    fail(`configSchema does not render as JSON Schema: ${describe(error)}`);
    return [];
  }
  if ((schema as { type?: unknown }).type !== 'object') {
    fail('configSchema must be an object schema');
  }
  return writeOnlyValues(schema, config);
}

/** The string values of `config` at the members its schema marks `writeOnly`. */
function writeOnlyValues(schema: unknown, config: unknown): string[] {
  if (typeof schema !== 'object' || schema === null) return [];
  const node = schema as Record<string, unknown>;
  if (node['writeOnly'] === true) {
    return typeof config === 'string' && config.length >= 4 ? [config] : [];
  }
  const properties = node['properties'];
  if (typeof properties !== 'object' || properties === null) return [];
  if (typeof config !== 'object' || config === null) return [];
  return Object.entries(properties).flatMap(([key, child]) =>
    writeOnlyValues(child, (config as Record<string, unknown>)[key])
  );
}

function kitEgress(scenario: AuthMethodKitScenario) {
  return {
    async request(request: AuthMethodEgressRequest): Promise<AuthMethodEgressResponse> {
      if (!['operator', 'admin', 'remote_document'].includes(request.source)) {
        throw new Error(`egress refused: source ${String(request.source)}`);
      }
      if (!/^[a-z][a-z0-9_.:-]{0,63}$/.test(request.purpose)) {
        throw new Error('egress refused: purpose must be a fixed label');
      }
      if (new URL(request.url).protocol !== 'https:') {
        throw new Error('egress refused: the URL is not https');
      }
      if (scenario.egress === undefined) {
        throw new Error('egress refused: the scenario answers no outbound call');
      }
      return scenario.egress(request);
    },
  };
}

function kitSigner() {
  return {
    async signClientAssertion(): Promise<string> {
      return 'eyJhbGciOiJSUzI1NiJ9.eyJraXQiOnRydWV9.a2l0';
    },
    async getUpstreamJwks() {
      return { keys: [] };
    },
  };
}

function kitLogger(lines: string[]) {
  const write = (fields: Record<string, unknown>, message: string): void => {
    lines.push(`${message} ${safeJson(fields)}`);
  };
  return { debug: write, info: write, warn: write, error: write };
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? '';
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

function describeCompletion(completion: { kind: string; reason?: string }): string {
  return completion.reason === undefined
    ? completion.kind
    : `${completion.kind} (${completion.reason})`;
}
