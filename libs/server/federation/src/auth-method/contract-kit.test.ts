import { describe, expect, it } from 'vitest';

import {
  createSampleAuthMethod,
  SAMPLE_CONFIG,
  sampleScenario,
} from '../../testing/sample-auth-method.fixture';
import type {
  AuthMethod,
  AuthMethodCallbackRoute,
  AuthMethodRoute,
  UpstreamCallbackOutcome,
} from './auth-method.interface';
import { checkAuthMethod } from './contract-kit';
import { AuthMethodContractError } from './errors';

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

/** The sample with its GET callback's handler wrapped. */
function withCallback(
  wrap: (original: AuthMethodCallbackRoute['handle']) => AuthMethodCallbackRoute['handle']
): AuthMethod {
  const method = createSampleAuthMethod();
  const routes = method.routes.map((route): AuthMethodRoute => {
    if (route.kind !== 'callback') return route;
    const original = route.handle.bind(route) as AuthMethodCallbackRoute['handle'];
    return { ...route, handle: wrap(original) } as AuthMethodRoute;
  });
  return { ...method, routes } as AuthMethod;
}

describe('checkAuthMethod, the contract test kit', () => {
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

  it('puts fetch back after a run, passing or failing', async () => {
    const original = globalThis.fetch;
    await checkAuthMethod(createSampleAuthMethod(), sampleScenario());
    await kitProblems({ ...createSampleAuthMethod(), contract: 'x' });
    expect(globalThis.fetch).toBe(original);
  });

  describe('fails for a broken method', () => {
    it('one written against another contract version', async () => {
      expect(
        await kitProblems({ ...createSampleAuthMethod(), contract: 'qauth-auth-method/0' })
      ).toEqual([
        'it is written against the contract qauth-auth-method/0, and this server implements qauth-auth-method/1-rc.0',
      ]);
    });

    it('one that mounts a route outside its prefix', async () => {
      const method = createSampleAuthMethod();
      const routes = [{ ...method.routes[0], path: '/../../oauth/token' }];
      expect(await kitProblems({ ...method, routes })).toEqual([
        "routes[0].path must be one to four lower-case segments, such as /callback: a route cannot leave the method's prefix",
      ]);
    });

    it('one whose callback does not check the transaction', async () => {
      const method = withCallback((original) => async (request, context) => {
        // Accepts any callback: hands its own state back as the transaction.
        const state = request.query['state'];
        return original({ ...request, transaction: { state: String(state) } }, context);
      });
      expect(await kitProblems(method)).toEqual([
        'the callback with no transaction answered result, not failed with transaction_mismatch',
        "the callback accepted another start's transaction: it must check state against it",
      ]);
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
      const problems = await kitProblems(lenient);
      expect(problems).toHaveLength(7);
      expect(problems[0]).toBe('verify() resolved for undefined, which no callback produced');
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
      expect(await kitProblems(fixed)).toEqual([
        'two starts answered the same transaction: its state must be fresh for each start',
        "the callback accepted another start's transaction: it must check state against it",
      ]);
    });

    it('one that calls fetch instead of the egress client', async () => {
      const method = withCallback((original) => async (request, context) => {
        await fetch('https://provider.example/token').catch(() => undefined);
        return original(request, context);
      });
      expect(await kitProblems(method)).toEqual([
        'the method called fetch: every outbound call must go through context.egress',
      ]);
    });

    it('one that logs a secret of its config', async () => {
      const method = withCallback((original) => async (request, context) => {
        context.log.info(
          { secret: (context.config as typeof SAMPLE_CONFIG).clientSecret },
          'calling'
        );
        return original(request, context);
      });
      expect(await kitProblems(method)).toEqual([
        'a log line carries the value of a writeOnly config member',
      ]);
    });

    it('one that answers a decline as a failure', async () => {
      const method = withCallback((original) => async (request, context) => {
        const outcome: UpstreamCallbackOutcome = await original(request, context);
        return outcome.kind === 'declined' ? { kind: 'failed', reason: 'provider_error' } : outcome;
      });
      expect(await kitProblems(method)).toEqual([
        'the declined callback answered failed (provider_error), not declined',
      ]);
    });

    it('one whose callback never signs anyone in', async () => {
      const method = withCallback(() => async () => ({
        kind: 'failed',
        reason: 'invalid_response',
      }));
      expect(await kitProblems(method)).toEqual([
        "the provider's callback ended as failed (invalid_response), not in an identity",
      ]);
    });

    it('one whose config schema refuses the scenario config', async () => {
      expect(
        await kitProblems(createSampleAuthMethod(), {
          ...sampleScenario(),
          config: { clientId: 'x' },
        })
      ).toEqual([
        "the scenario's config does not pass configSchema: AuthMethod oidc_sample: the config does not pass the method's schema",
      ]);
    });

    it('one whose start() answers an http redirect', async () => {
      const method = createSampleAuthMethod();
      const insecure = {
        ...method,
        start: async () => ({ redirectTo: 'http://provider.example/authorize', transaction: {} }),
      };
      expect(await kitProblems(insecure)).toEqual([
        'start() failed: AuthMethod oidc_sample: start() answered a redirect that is not https',
      ]);
    });
  });
});
