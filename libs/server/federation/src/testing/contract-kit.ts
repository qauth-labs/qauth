import { createHash } from 'node:crypto';

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
import {
  completeUpstreamStep,
  presentedUpstreamBinding,
  startUpstreamStep,
  upstreamBindingMatches,
} from '../auth-method/engine';
import { AuthMethodContractError } from '../auth-method/errors';
import { authMethodParameters } from '../auth-method/parameters';
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
  /**
   * A config for one realm, which the method's `configSchema` accepts. Give
   * its `writeOnly` members realistic secrets (a dozen characters or more):
   * the kit looks for every one of them, however short, in every log line,
   * and a secret such as `abc` matches text that is no leak.
   */
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
  /** The bodies of the method's outbound calls, in order, as text. */
  readonly egressBodies: string[];
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
 *    a transaction of JSON data within its cap and a binding of 22 to 512
 *    base64url characters; two starts answer different transactions.
 * 2. Two starts answer different bindings, and each sends its binding to the
 *    provider, in the redirect or in a body it posted.
 * 3. The provider's callback carries the binding back in the callback
 *    route's `bindingParameter` (`state` by default): the kit, like the host,
 *    hands the handler the transaction only when it does. It ends in an
 *    identity whose attributes carry the method's `type`; a second sign-in of
 *    the same person resolves the same `externalSub`.
 * 4. When the authorization request asks for a code (`response_type=code`,
 *    in the redirect or a body the method posted), it carries
 *    `code_challenge_method=S256` and a `code_challenge` (RFC 7636; QAuth
 *    requires PKCE with S256), and every token request the callback makes
 *    (`grant_type=authorization_code`) carries the `code_verifier` whose S256
 *    is that challenge.
 * 5. `verify()` rejects inputs that no callback produced, a well-formed
 *    identity, a copy of a real result and a result already used among them.
 * 6. When the scenario gives one, the declined callback ends as `declined`.
 * 7. The method called the global `fetch` nowhere, and no log line carries
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
    egressBodies: [],
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
    await fetchGuard.run(async () => {
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
    });
  } catch (error) {
    if (!(error instanceof KitStop)) run.problems.push(`the run threw: ${describe(error)}`);
  } finally {
    fetchGuard.restore();
  }

  if (fetchGuard.calls() > 0) {
    run.problems.push('the method called fetch: its outbound calls go through context.egress');
  }
  const forms = secretForms(secrets, configStrings(scenario.config));
  if (run.logLines.some((line) => forms.some((form) => line.includes(form)))) {
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
  if (JSON.stringify(first.start.transaction) === JSON.stringify(second.start.transaction)) {
    run.fail('two starts answered the same transaction: its state must be fresh for each start');
  }
  run.checks.push('start');

  bindingChecks(first, second, run);
  run.checks.push('transaction-binding');

  // The provider signs the person in, for the second start.
  const signIn = await scenario.callback(new URL(second.start.redirectTo));
  const bodiesBefore = run.egressBodies.length;
  const happy = await callback(method, context, signIn, second.start, run);
  pkceChecks(second, run.egressBodies.slice(bodiesBefore), run);
  if (happy === HOST_REFUSED) {
    run.stop(
      "the provider's callback does not carry back the binding start() answered, in the callback route's bindingParameter (state by default): the host answers it as transaction_mismatch before the method runs"
    );
  }
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
    await scenario.callback(new URL(third.start.redirectTo)),
    third.start,
    run
  );
  const repeated = await completeUpstreamStep(method, again).catch(() => undefined);
  if (
    repeated?.kind !== 'identity' ||
    repeated.identity.externalSub !== completion.identity.externalSub
  ) {
    run.fail('a second sign-in of the same person did not resolve the same externalSub');
  }
  run.checks.push('callback', 'pkce');

  await verifyChecks(method, result, run);
  run.checks.push('verify-fails-closed');

  if (scenario.declined !== undefined) {
    const fourth = await started(method, context, run);
    const declinedRequest = await scenario.declined(new URL(fourth.start.redirectTo));
    const declined = await callback(method, context, declinedRequest, fourth.start, run);
    if ((declined as { kind?: unknown }).kind !== 'declined') {
      run.fail(`the declined callback answered ${describeOutcome(declined)}, not declined`);
    }
    run.checks.push('declined');
  }
}

/**
 * The binding `start()` answers is what the host checks a callback against
 * (the engine has already checked it is 22 to 512 base64url characters, the
 * length of 128 random bits; the kit cannot measure randomness). Two starts
 * must answer different bindings, and the start must send its binding to the
 * provider, in the redirect or in a body the method posted (a pushed
 * authorization request), or the provider cannot carry it back.
 */
function bindingChecks(first: KitStart, second: KitStart, run: KitRun): void {
  if (first.start.binding === second.start.binding) {
    run.fail('two starts answered the same binding: it must be fresh for each start');
  }
  if (!second.values.includes(second.start.binding)) {
    run.fail(
      'start() did not send its binding to the provider, in the redirect or in a body it posted: the provider cannot carry it back'
    );
  }
}

/** What a PKCE verifier may be (RFC 7636 §4.1): 43 to 128 unreserved characters. */
const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
/** What an S256 challenge is: the base64url SHA-256 of a verifier, 43 characters. */
const PKCE_S256_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

/**
 * PKCE with S256, as QAuth requires it of every authorization-code request
 * (RFC 7636): an authorization request that asks for a code carries
 * `code_challenge_method=S256` and a challenge, and every token request the
 * callback made carries the verifier whose S256 is that challenge.
 */
function pkceChecks(start: KitStart, callbackBodies: readonly string[], run: KitRun): void {
  const codeRequest = start.authorizationRequests.find(
    (parameters) => parameters.get('response_type') === 'code'
  );
  const challenge = codeRequest?.get('code_challenge') ?? undefined;
  if (
    codeRequest !== undefined &&
    (codeRequest.get('code_challenge_method') !== 'S256' ||
      challenge === undefined ||
      !PKCE_S256_CHALLENGE.test(challenge))
  ) {
    run.fail(
      'the authorization request asks for a code without PKCE: it must carry code_challenge_method=S256 and a code_challenge (RFC 7636)'
    );
  }
  const tokenRequests = callbackBodies
    .map((body) => new URLSearchParams(body))
    .filter((parameters) => parameters.get('grant_type') === 'authorization_code');
  for (const tokenRequest of tokenRequests) {
    const verifier = tokenRequest.get('code_verifier');
    if (
      verifier === null ||
      !PKCE_VERIFIER.test(verifier) ||
      challenge === undefined ||
      createHash('sha256').update(verifier, 'ascii').digest('base64url') !== challenge
    ) {
      run.fail(
        "the token request carries no code_verifier whose S256 is the start's code_challenge (RFC 7636 §4.5)"
      );
      return;
    }
  }
}

/** `verify()` rejects anything that is not a fresh result of its own callback. */
async function verifyChecks(method: AuthMethod, result: unknown, run: KitRun): Promise<void> {
  const accepts = (input: unknown) =>
    Promise.resolve()
      .then(() => method.verify(input))
      .then(
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

/** A start, and every value it sent the provider: the redirect's query and posted bodies. */
interface KitStart {
  readonly start: UpstreamStart;
  readonly values: readonly string[];
  /** The redirect's query and each form the start posted (a pushed request). */
  readonly authorizationRequests: readonly URLSearchParams[];
}

/** The values of a body the method posted: a form, or the strings of a JSON document. */
function bodyValues(body: string): string[] {
  const values = [...new URLSearchParams(body).values()];
  try {
    values.push(...stringLeaves(JSON.parse(body) as unknown, 0));
  } catch {
    // Not JSON: the form reading above is all there is.
  }
  return values;
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
): Promise<KitStart> {
  const before = run.egressBodies.length;
  const start = await startUpstreamStep(method, context, { uiLocales: ['en'] }).catch(
    (error: unknown) => run.stop(`start() failed: ${describe(error)}`)
  );
  const posted = run.egressBodies.slice(before);
  const values = [
    ...new URL(start.redirectTo).searchParams.values(),
    ...posted.flatMap(bodyValues),
  ];
  const authorizationRequests = [
    new URL(start.redirectTo).searchParams,
    ...posted.map((body) => new URLSearchParams(body)),
  ];
  return { start, values, authorizationRequests };
}

/** `work()`, with a synchronous throw read as a rejection, as the host's `await` reads it. */
function settled<T>(work: () => Promise<T>): Promise<T> {
  return Promise.resolve().then(work);
}

/**
 * What the kit's host answers a callback whose binding does not match, as the
 * route mount does: before the method runs.
 */
const HOST_REFUSED = Object.freeze({ kind: 'failed', reason: 'transaction_mismatch' } as const);

/**
 * Run one request through the method's routes as the host would, following a
 * bounce once: the callback's binding is compared with the start's before
 * the handler is called, and a mismatch answers {@link HOST_REFUSED}.
 */
async function callback(
  method: AuthMethod,
  context: AuthMethodContext,
  request: AuthMethodKitRequest,
  start: UpstreamStart,
  run: KitRun
): Promise<unknown> {
  let route = findRoute(method.routes, request.method, request.path);
  if (route === undefined) {
    return run.stop(
      `the scenario's callback names ${request.method} ${request.path}, which is not a route of the method`
    );
  }
  // The objects the host hands a handler: frozen, with no prototype, within
  // the caps (`authMethodParameters`); a GET has an empty form.
  let query = authMethodParameters(request.query);
  let form = authMethodParameters(request.method === 'POST' ? request.form : undefined);
  if (route.kind === 'bounce') {
    const bounceRoute = route;
    // A bounce is handed no context, as the host hands it none.
    const bounce: unknown = await settled(() =>
      bounceRoute.handle({ method: bounceRoute.method, query, form })
    ).catch((error: unknown) => run.stop(`the bounce route threw: ${describe(error)}`));
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
      Array.isArray(carried) ||
      (Object.getPrototypeOf(carried) !== Object.prototype &&
        Object.getPrototypeOf(carried) !== null) ||
      !Object.values(carried).every((value) => typeof value === 'string')
    ) {
      return run.stop('the bounce route carried a query that is not a plain object of strings');
    }
    route = target;
    // As the browser brings it back: through the URL the host redirects to.
    query = authMethodParameters(
      Object.fromEntries(new URLSearchParams(carried as Record<string, string>))
    );
    form = authMethodParameters(undefined);
  }
  if (route.kind !== 'callback') {
    return run.stop(`${route.method} ${route.path} is not a callback route`);
  }
  const callbackRoute = route;
  if (
    !upstreamBindingMatches(start.binding, presentedUpstreamBinding(callbackRoute, { query, form }))
  ) {
    return HOST_REFUSED;
  }
  const transaction = start.transaction;
  return settled(() =>
    callbackRoute.handle({ method: callbackRoute.method, query, form, transaction }, context)
  ).catch((error: unknown) => run.stop(`the callback route threw: ${describe(error)}`));
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
          if (request.body !== undefined) {
            run.egressBodies.push(
              typeof request.body === 'string'
                ? request.body
                : Buffer.from(request.body).toString('utf8')
            );
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
          // The scenario sees the call as the method sent it: no realm, and
          // `redirect: 'error'` for the zero redirect cap it asked for.
          const { realm: _realm, limits, ...rest } = request;
          return scenario.egress(
            limits?.maxRedirects === 0 ? { ...rest, redirect: 'error' } : rest
          );
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
  return writeOnlyValues(schema, schema, config, 0);
}

/**
 * The string values of `config` under the members its schema marks
 * `writeOnly`: every string leaf of such a member, whatever its shape. The
 * walk follows `properties`, `additionalProperties`, `items`, the members of
 * `anyOf`, `oneOf` and `allOf`, and local `$ref`s into `$defs`.
 */
function writeOnlyValues(root: unknown, schema: unknown, config: unknown, depth: number): string[] {
  if (typeof schema !== 'object' || schema === null || depth > 32) return [];
  const node = schema as Record<string, unknown>;
  const reference = node['$ref'];
  if (typeof reference === 'string') {
    return writeOnlyValues(root, resolveLocalRef(root, reference), config, depth + 1);
  }
  if (node['writeOnly'] === true) {
    // Every one, however short: a short secret is still a secret. A scenario
    // gives realistic ones, so a short one does not match by accident.
    return stringLeaves(config, 0);
  }
  const found: string[] = [];
  for (const keyword of ['anyOf', 'oneOf', 'allOf']) {
    const members = node[keyword];
    if (Array.isArray(members)) {
      for (const member of members) found.push(...writeOnlyValues(root, member, config, depth + 1));
    }
  }
  if (Array.isArray(config)) {
    found.push(...config.flatMap((item) => writeOnlyValues(root, node['items'], item, depth + 1)));
    return found;
  }
  if (typeof config !== 'object' || config === null) return found;
  const properties = (
    typeof node['properties'] === 'object' && node['properties'] !== null ? node['properties'] : {}
  ) as Record<string, unknown>;
  for (const [key, value] of Object.entries(config)) {
    const child = Object.hasOwn(properties, key) ? properties[key] : node['additionalProperties'];
    found.push(...writeOnlyValues(root, child, value, depth + 1));
  }
  return found;
}

/** The schema a local `#/...` reference names, or `undefined`. */
function resolveLocalRef(root: unknown, reference: string): unknown {
  if (!reference.startsWith('#/')) return undefined;
  let node: unknown = root;
  for (const segment of reference.slice(2).split('/')) {
    if (typeof node !== 'object' || node === null) return undefined;
    node = (node as Record<string, unknown>)[segment.replace(/~1/g, '/').replace(/~0/g, '~')];
  }
  return node;
}

/** Every string inside `value`, at any depth. */
function stringLeaves(value: unknown, depth: number): string[] {
  if (typeof value === 'string') return [value];
  if (typeof value !== 'object' || value === null || depth > 32) return [];
  return Object.values(value).flatMap((item) => stringLeaves(item, depth + 1));
}

/** Every string of the config, for the forms a secret takes beside another value. */
function configStrings(config: unknown): string[] {
  return stringLeaves(config, 0);
}

/**
 * The forms a secret can take in a log line: itself, base64 and base64url,
 * percent-encoded, and the HTTP Basic credentials it makes with any other
 * string of the config (`client_secret_basic`, RFC 6749 §2.3.1).
 */
function secretForms(secrets: readonly string[], strings: readonly string[]): string[] {
  const base64 = (text: string) => Buffer.from(text, 'utf8').toString('base64');
  const base64url = (text: string) => Buffer.from(text, 'utf8').toString('base64url');
  const forms = new Set<string>();
  for (const secret of secrets) {
    forms.add(secret);
    forms.add(base64(secret));
    forms.add(base64url(secret));
    forms.add(encodeURIComponent(secret));
    for (const other of strings) {
      if (other === secret) continue;
      forms.add(base64(`${other}:${secret}`));
      forms.add(base64(`${encodeURIComponent(other)}:${encodeURIComponent(secret)}`));
    }
  }
  // Only the empty string is left out: it is inside every line.
  return [...forms].filter((form) => form.length > 0);
}

function kitLogger(lines: string[]) {
  const write = (fields: Record<string, unknown>, message: string): void => {
    lines.push(`${String(message)} ${serialised(fields)}`);
  };
  return { debug: write, info: write, warn: write, error: write };
}

/**
 * JSON of a log line's fields. An Error is written out with its own fields
 * (as the server's error serializer copies them), its message, stack and
 * cause, and an AggregateError's errors.
 */
function serialised(value: unknown): string {
  const seen = new WeakSet<object>();
  try {
    return (
      JSON.stringify(value, (_key, member: unknown) => {
        if (member instanceof Error) {
          if (seen.has(member)) return '[cycle]';
          seen.add(member);
          return {
            ...member,
            name: member.name,
            message: member.message,
            stack: member.stack,
            cause: member.cause,
            ...(member instanceof AggregateError ? { errors: member.errors } : {}),
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
