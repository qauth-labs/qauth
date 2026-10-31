import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import {
  createSampleAuthMethod,
  SAMPLE_CONFIG,
  SAMPLE_SUBJECT,
  sampleProviderEgress,
  sampleScenario,
} from '../../testing/sample-auth-method.fixture';
import type {
  AuthMethod,
  AuthMethodCallbackRoute,
  AuthMethodRoute,
  UpstreamCallbackOutcome,
} from '../auth-method/auth-method.interface';
import { AuthMethodContractError } from '../auth-method/errors';
import { checkAuthMethod } from './contract-kit';

/** The problems the kit reports for `method`, or `[]` when it passes. */
async function kitProblems(
  method: unknown,
  scenario = sampleScenario()
): Promise<readonly string[]> {
  try {
    await checkAuthMethod(method as AuthMethod, scenario);
    return [];
  } catch (error) {
    expect(error).toBeInstanceOf(AuthMethodContractError);
    return (error as AuthMethodContractError).problems;
  }
}

type CallbackHandle = AuthMethodCallbackRoute['handle'];

/** The sample with its GET callback's handler replaced. */
function withCallback(wrap: (original: CallbackHandle) => CallbackHandle): AuthMethod {
  const method = createSampleAuthMethod();
  const routes = method.routes.map((route): AuthMethodRoute => {
    if (route.kind !== 'callback') return route;
    const original = route.handle.bind(route) as CallbackHandle;
    return { ...route, handle: wrap(original) } as AuthMethodRoute;
  });
  return { ...method, routes } as AuthMethod;
}

/**
 * A callback written the common wrong way, by hand: it redeems the code with
 * the provider, then decides by `check` whether the answer belongs to the
 * transaction.
 */
function handWritten(
  check: (presented: unknown, expected: string) => boolean,
  options: { spendFirst?: boolean } = {}
): AuthMethod {
  return withCallback((original) => async (request, context) => {
    const transaction = request.transaction as { state: string };
    const presented = request.query['state'];
    if (options.spendFirst) {
      // Spends the code before it looks at state.
      await context.egress.request({
        method: 'POST',
        url: SAMPLE_CONFIG.tokenEndpoint,
        body: `code=${String(request.query['code'])}&client_secret=${SAMPLE_CONFIG.clientSecret}`,
        purpose: 'upstream-token',
        source: 'admin',
      });
    }
    if (!check(presented, transaction.state)) {
      return { kind: 'failed', reason: 'transaction_mismatch' };
    }
    // Hand the original the transaction its own check accepted.
    return original({ ...request, query: { ...request.query, state: transaction.state } }, context);
  });
}

describe('checkAuthMethod, the contract test kit', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('passes for the sample method, listing what it checked', async () => {
    const report = await checkAuthMethod(createSampleAuthMethod(), sampleScenario());
    expect(report.checks).toEqual([
      'static',
      'config-schema',
      'context',
      'start',
      'callback',
      'transaction-binding',
      'verify-fails-closed',
      'declined',
      'egress-only',
      'secrets-not-logged',
    ]);
  });

  it('passes for the sample method with a form_post answer through its bounce route', async () => {
    await expect(
      checkAuthMethod(createSampleAuthMethod(), sampleScenario({ responseMode: 'form_post' }))
    ).resolves.toBeDefined();
  });

  it('puts fetch back after a run, passing or failing, and after overlapping runs', async () => {
    const original = globalThis.fetch;
    await checkAuthMethod(createSampleAuthMethod(), sampleScenario());
    await kitProblems({ ...createSampleAuthMethod(), contract: 'x' });
    expect(globalThis.fetch).toBe(original);
    await Promise.all([
      checkAuthMethod(createSampleAuthMethod(), sampleScenario()),
      checkAuthMethod(createSampleAuthMethod(), sampleScenario({ responseMode: 'form_post' })),
    ]);
    expect(globalThis.fetch).toBe(original);
  });

  it('refuses to run with NODE_ENV=production', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    await expect(checkAuthMethod(createSampleAuthMethod(), sampleScenario())).rejects.toThrow(
      'checkAuthMethod is a test kit: it does not run with NODE_ENV=production'
    );
  });

  describe('fails for a broken method', () => {
    it('one written against another contract version', async () => {
      expect(await kitProblems({ ...createSampleAuthMethod(), contract: 'qauth-auth-method/0' }))
        .toMatchInlineSnapshot(`
          [
            "it is written against the contract qauth-auth-method/0, and this server implements qauth-auth-method/1-rc.0",
          ]
        `);
    });

    it('one that mounts a route outside its prefix', async () => {
      const method = createSampleAuthMethod();
      const routes = [{ ...method.routes[0], path: '/../../oauth/token' }];
      expect(await kitProblems({ ...method, routes })).toMatchInlineSnapshot(`
        [
          "routes[0].path must be one to four lower-case segments, such as /callback: a route cannot leave the method's prefix",
        ]
      `);
    });

    it('one whose callback ignores its transaction', async () => {
      const method = handWritten(() => true);
      expect(await kitProblems(method)).toMatchInlineSnapshot(`
        [
          "the callback gave a result with another start's transaction: it must check state against its transaction",
          "the callback gave a result without state: it must check state against its transaction",
          "the callback gave a result with state empty: it must check state against its transaction",
          "the callback gave a result with state repeated: it must check state against its transaction",
        ]
      `);
    });

    it('one that compares state only when the callback carries one', async () => {
      const method = handWritten((presented, expected) =>
        presented === undefined ? true : presented === expected
      );
      expect(await kitProblems(method)).toMatchInlineSnapshot(`
        [
          "the callback gave a result without state: it must check state against its transaction",
        ]
      `);
    });

    it('one that spends the code before it checks state', async () => {
      const method = handWritten((presented, expected) => presented === expected, {
        spendFirst: true,
      });
      expect(await kitProblems(method)).toMatchInlineSnapshot(`
        [
          "the callback called the provider with another start's transaction: it must check state before it spends the code",
          "the callback called the provider without state: it must check state before it spends the code",
          "the callback called the provider with state empty: it must check state before it spends the code",
          "the callback called the provider with state repeated: it must check state before it spends the code",
        ]
      `);
    });

    it('one whose verify() accepts anything shaped like a result', async () => {
      const method = createSampleAuthMethod();
      const lenient = {
        ...method,
        verify: async (input: unknown) => {
          const result = input as { sub?: unknown; email?: unknown };
          if (typeof result?.sub !== 'string') throw new Error('not a result');
          return {
            externalSub: result.sub,
            assuranceLevel: 'low' as const,
            rawClaims: { sub: result.sub, email: result.email },
          };
        },
      };
      expect(await kitProblems(lenient)).toMatchInlineSnapshot(`
        [
          "verify() resolved for a copy of a callback's result: it must accept only its own results",
          "verify() resolved for a result it had already verified: a result signs one person in once",
        ]
      `);
    });

    it('one whose verify() accepts what no callback produced', async () => {
      const method = createSampleAuthMethod();
      const lenient = {
        ...method,
        verify: async (input: unknown) => {
          try {
            return await method.verify(input);
          } catch {
            return { externalSub: 'anyone', assuranceLevel: 'low' as const, rawClaims: {} };
          }
        },
      };
      expect(await kitProblems(lenient)).toMatchInlineSnapshot(`
        [
          "verify() resolved for undefined, which no callback produced",
          "verify() resolved for null, which no callback produced",
          "verify() resolved for "", which no callback produced",
          "verify() resolved for "kit-forged", which no callback produced",
          "verify() resolved for {}, which no callback produced",
          "verify() resolved for [], which no callback produced",
          "verify() resolved for {"externalSub":"kit-forged","assuranceLevel":"high","rawClaims":{}}, which no callback produced",
          "verify() resolved for a copy of a callback's result: it must accept only its own results",
          "verify() resolved for a result it had already verified: a result signs one person in once",
        ]
      `);
    });

    it('one that starts every transaction with the same state', async () => {
      const method = createSampleAuthMethod();
      const fixed = {
        ...method,
        start: async (context: Parameters<typeof method.start>[0]) => {
          const start = await method.start(context, { uiLocales: [] });
          const url = new URL(start.redirectTo);
          url.searchParams.set('state', 'fixed');
          return { redirectTo: url.href, transaction: { state: 'fixed' } };
        },
      };
      expect(await kitProblems(fixed)).toMatchInlineSnapshot(`
        [
          "two starts answered the same transaction: its state must be fresh for each start",
          "the callback gave a result with another start's transaction: it must check state against its transaction",
        ]
      `);
    });

    it('one whose start() sends no state, so nothing binds the callback', async () => {
      // A callback that binds nothing (no state, as a PKCE-only client would)
      // and a start that sends none.
      const loose = handWritten(() => true);
      const stateless = {
        ...loose,
        start: async (context: Parameters<typeof loose.start>[0]) => {
          const start = await loose.start(context, { uiLocales: [] });
          const url = new URL(start.redirectTo);
          url.searchParams.delete('state');
          return { redirectTo: url.href, transaction: start.transaction };
        },
      };
      expect(
        await kitProblems(stateless, {
          ...sampleScenario(),
          callback: () => ({
            path: '/callback',
            method: 'GET',
            query: { code: `code-for-${SAMPLE_SUBJECT}` },
          }),
          declined: undefined,
        })
      ).toMatchInlineSnapshot(`
        [
          "the callback carries no value of the authorization request (such as state): nothing binds it to its transaction",
          "the callback gave a result with another start's transaction: it must check state against its transaction",
        ]
      `);
    });

    it('one that resolves a new externalSub at each sign-in', async () => {
      const method = createSampleAuthMethod();
      let count = 0;
      const unstable = {
        ...method,
        verify: async (input: unknown) => {
          const identity = await method.verify(input);
          count += 1;
          return { ...identity, externalSub: `${identity.externalSub}-${count}` };
        },
      };
      expect(await kitProblems(unstable)).toMatchInlineSnapshot(`
        [
          "a second sign-in of the same person did not resolve the same externalSub",
        ]
      `);
    });

    it('one that calls fetch instead of the egress client', async () => {
      const method = withCallback((original) => async (request, context) => {
        await fetch('https://provider.example/token').catch(() => undefined);
        return original(request, context);
      });
      expect(await kitProblems(method)).toMatchInlineSnapshot(`
        [
          "the method called fetch: its outbound calls go through context.egress",
        ]
      `);
    });

    it('one that logs a secret of its config', async () => {
      const method = withCallback((original) => async (request, context) => {
        context.log.info(
          { secret: (context.config as typeof SAMPLE_CONFIG).clientSecret },
          'calling'
        );
        return original(request, context);
      });
      expect(await kitProblems(method)).toMatchInlineSnapshot(`
        [
          "a log line carries the value of a writeOnly config member",
        ]
      `);
    });

    it('one that logs a secret inside an error', async () => {
      const method = withCallback((original) => async (request, context) => {
        const secret = (context.config as typeof SAMPLE_CONFIG).clientSecret;
        context.log.warn({ err: new Error(`token call failed with ${secret}`) }, 'calling');
        return original(request, context);
      });
      expect(await kitProblems(method)).toMatchInlineSnapshot(`
        [
          "a log line carries the value of a writeOnly config member",
        ]
      `);
    });

    it('one that logs a secret held under a union in its config', async () => {
      const configSchema = z.object({
        authorizationEndpoint: z.url(),
        tokenEndpoint: z.url(),
        clientId: z.string(),
        clientSecret: z.string(),
        clientAuth: z.discriminatedUnion('method', [
          z.object({
            method: z.literal('client_secret_basic'),
            secret: z.string().meta({ writeOnly: true }),
          }),
          z.object({ method: z.literal('private_key_jwt') }),
        ]),
      });
      const leaky = withCallback((original) => async (request, context) => {
        const config = context.config as { clientAuth: { secret?: string } };
        context.log.info({ auth: config.clientAuth.secret }, 'calling');
        return original(request, context);
      });
      const scenario = {
        ...sampleScenario(),
        config: {
          ...SAMPLE_CONFIG,
          clientAuth: { method: 'client_secret_basic', secret: 'union-held-secret' },
        },
      };
      expect(await kitProblems({ ...leaky, configSchema } as unknown as AuthMethod, scenario))
        .toMatchInlineSnapshot(`
        [
          "a log line carries the value of a writeOnly config member",
        ]
      `);
    });

    it('one that answers a decline as a failure', async () => {
      const method = withCallback((original) => async (request, context) => {
        const outcome: UpstreamCallbackOutcome = await original(request, context);
        return outcome.kind === 'declined' ? { kind: 'failed', reason: 'provider_error' } : outcome;
      });
      expect(await kitProblems(method)).toMatchInlineSnapshot(`
        [
          "the declined callback answered failed (provider_error), not declined",
        ]
      `);
    });

    it('one whose callback never signs anyone in', async () => {
      const method = withCallback(() => async () => ({
        kind: 'failed',
        reason: 'invalid_response',
      }));
      expect(await kitProblems(method)).toMatchInlineSnapshot(`
        [
          "the provider's callback ended as failed (invalid_response), not in an identity",
        ]
      `);
    });

    it('one whose bounce sends the browser to a route that is not a callback', async () => {
      const method = createSampleAuthMethod();
      const routes: AuthMethodRoute[] = [
        ...method.routes.map((route) =>
          route.kind === 'bounce'
            ? { ...route, handle: async () => ({ to: '/loop', query: {} }) }
            : route
        ),
        {
          kind: 'bounce',
          method: 'GET',
          path: '/loop',
          handle: async () => ({ to: '/loop', query: {} }),
        },
      ];
      expect(
        await kitProblems({ ...method, routes }, sampleScenario({ responseMode: 'form_post' }))
      ).toMatchInlineSnapshot(`
        [
          "the bounce route sent the browser to /loop, which is not a GET callback route of the method",
        ]
      `);
    });

    it('one whose config schema refuses the scenario config', async () => {
      expect(
        await kitProblems(createSampleAuthMethod(), {
          ...sampleScenario(),
          config: { clientId: 'x' },
        })
      ).toMatchInlineSnapshot(`
        [
          "the scenario's config does not pass configSchema: AuthMethod oidc_sample: the config does not pass the method's schema",
        ]
      `);
    });

    it('one whose start() answers an http redirect', async () => {
      const method = createSampleAuthMethod();
      const insecure = {
        ...method,
        start: async () => ({ redirectTo: 'http://provider.example/authorize', transaction: {} }),
      };
      expect(await kitProblems(insecure)).toMatchInlineSnapshot(`
        [
          "start() failed: AuthMethod oidc_sample: start() answered a redirect that is not https",
        ]
      `);
    });
  });

  it('answers the provider through the scenario, without the realm the host adds', async () => {
    const seen: unknown[] = [];
    await checkAuthMethod(createSampleAuthMethod(), {
      ...sampleScenario(),
      egress: (request) => {
        seen.push(request);
        return sampleProviderEgress(request);
      },
    });
    expect(seen.length).toBeGreaterThan(0);
    for (const request of seen) expect(request).not.toHaveProperty('realm');
  });
});
