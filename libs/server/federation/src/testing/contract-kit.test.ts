import { createHash, randomBytes, randomUUID } from 'node:crypto';

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
 * A callback written by hand that decides by `check` whether the answer
 * belongs to the transaction, then hands it to the sample's own callback.
 */
function handWritten(check: (presented: unknown, expected: string) => boolean): AuthMethod {
  return withCallback((original) => async (request, context) => {
    const transaction = request.transaction as { state: string };
    if (!check(request.query['state'], transaction.state)) {
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
      'transaction-binding',
      'callback',
      'pkce',
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

    it('one whose callback route names a binding parameter the provider does not carry back', async () => {
      const method = createSampleAuthMethod();
      const routes = method.routes.map((route) =>
        route.kind === 'callback' ? { ...route, bindingParameter: 'session_state' } : route
      );
      expect(await kitProblems({ ...method, routes })).toMatchInlineSnapshot(`
        [
          "the provider's callback does not carry back the binding start() answered, in the callback route's bindingParameter (state by default): the host answers it as transaction_mismatch before the method runs",
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
          const value = 'fixed-fixed-fixed-fixed';
          url.searchParams.set('state', value);
          return {
            redirectTo: url.href,
            transaction: { ...start.transaction, state: value },
            binding: value,
          };
        },
      };
      expect(await kitProblems(fixed)).toMatchInlineSnapshot(`
        [
          "two starts answered the same binding: it must be fresh for each start",
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
          return { redirectTo: url.href, transaction: start.transaction, binding: start.binding };
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
          "start() did not send its binding to the provider, in the redirect or in a body it posted: the provider cannot carry it back",
          "the provider's callback does not carry back the binding start() answered, in the callback route's bindingParameter (state by default): the host answers it as transaction_mismatch before the method runs",
        ]
      `);
    });

    it('one that asks for a code without PKCE', async () => {
      const method = createSampleAuthMethod();
      const plain = {
        ...method,
        start: async (context: Parameters<typeof method.start>[0]) => {
          const start = await method.start(context, { uiLocales: [] });
          const url = new URL(start.redirectTo);
          url.searchParams.delete('code_challenge');
          url.searchParams.delete('code_challenge_method');
          return { ...start, redirectTo: url.href };
        },
      };
      expect(await kitProblems(plain)).toMatchInlineSnapshot(`
        [
          "the authorization request asks for a code without PKCE: it must carry code_challenge_method=S256 and a code_challenge (RFC 7636)",
          "the token request carries no code_verifier whose S256 is the start's code_challenge (RFC 7636 §4.5)",
        ]
      `);
    });

    it('one that uses the plain PKCE method', async () => {
      const method = createSampleAuthMethod();
      const plain = {
        ...method,
        start: async (context: Parameters<typeof method.start>[0]) => {
          const start = await method.start(context, { uiLocales: [] });
          const url = new URL(start.redirectTo);
          url.searchParams.set('code_challenge', start.transaction.codeVerifier);
          url.searchParams.set('code_challenge_method', 'plain');
          return { ...start, redirectTo: url.href };
        },
      };
      expect(await kitProblems(plain)).toMatchInlineSnapshot(`
        [
          "the authorization request asks for a code without PKCE: it must carry code_challenge_method=S256 and a code_challenge (RFC 7636)",
          "the token request carries no code_verifier whose S256 is the start's code_challenge (RFC 7636 §4.5)",
        ]
      `);
    });

    it("one whose token request carries a verifier that is not the start's", async () => {
      const method = withCallback(
        (original) => async (request, context) =>
          original(
            {
              ...request,
              transaction: {
                ...(request.transaction as object),
                codeVerifier: randomBytes(32).toString('base64url'),
              },
            },
            context
          )
      );
      expect(await kitProblems(method)).toMatchInlineSnapshot(`
        [
          "the token request carries no code_verifier whose S256 is the start's code_challenge (RFC 7636 §4.5)",
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

  describe('passes for a correct method', () => {
    it('whose callback leaves the binding to the host, which never runs it without one', async () => {
      // It hands the provider's answer on without comparing state: the host
      // compares the binding before the handler ever sees the transaction.
      await expect(
        checkAuthMethod(
          handWritten(() => true),
          sampleScenario()
        )
      ).resolves.toBeDefined();
    });

    it('whose provider echoes scope and prompt back beside state', async () => {
      const method = createSampleAuthMethod();
      const echoing = {
        ...method,
        start: async (context: Parameters<typeof method.start>[0]) => {
          const start = await method.start(context, { uiLocales: [] });
          const url = new URL(start.redirectTo);
          url.searchParams.set('scope', 'openid email');
          url.searchParams.set('prompt', 'login');
          return { redirectTo: url.href, transaction: start.transaction, binding: start.binding };
        },
      };
      const scenario = sampleScenario();
      await expect(
        checkAuthMethod(echoing, {
          ...scenario,
          callback: (authorizationRequest) => ({
            path: '/callback',
            method: 'GET',
            query: {
              code: `code-for-${SAMPLE_SUBJECT}`,
              state: authorizationRequest.searchParams.get('state') ?? '',
              scope: 'openid email',
              prompt: 'login',
            },
          }),
        })
      ).resolves.toBeDefined();
    });

    it('that pushes its authorization request, so state travels in a posted body', async () => {
      const method = createSampleAuthMethod();
      const pushedState = new Map<string, string>();
      const pushing = {
        ...method,
        start: async (context: Parameters<typeof method.start>[0]) => {
          const state = randomBytes(16).toString('base64url');
          const codeVerifier = randomBytes(32).toString('base64url');
          const answer = await context.egress.request({
            method: 'POST',
            url: 'https://provider.example/par',
            body: new URLSearchParams({
              response_type: 'code',
              client_id: context.config.clientId,
              state,
              redirect_uri: context.routeUrl('/callback'),
              code_challenge: createHash('sha256').update(codeVerifier).digest('base64url'),
              code_challenge_method: 'S256',
            }).toString(),
            purpose: 'upstream-par',
            source: 'admin',
          });
          const { request_uri: requestUri } = JSON.parse(Buffer.from(answer.body).toString()) as {
            request_uri: string;
          };
          const url = new URL(context.config.authorizationEndpoint);
          url.searchParams.set('client_id', context.config.clientId);
          url.searchParams.set('request_uri', requestUri);
          return { redirectTo: url.href, transaction: { state, codeVerifier }, binding: state };
        },
      };
      const scenario = sampleScenario();
      await expect(
        checkAuthMethod(pushing, {
          ...scenario,
          egress: (request) => {
            if (request.url !== 'https://provider.example/par')
              return sampleProviderEgress(request);
            const requestUri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`;
            pushedState.set(
              requestUri,
              new URLSearchParams(String(request.body)).get('state') ?? ''
            );
            return {
              status: 201,
              headers: {},
              body: Buffer.from(JSON.stringify({ request_uri: requestUri })),
              url: request.url,
            };
          },
          callback: (authorizationRequest) => ({
            path: '/callback',
            method: 'GET',
            query: {
              code: `code-for-${SAMPLE_SUBJECT}`,
              state:
                pushedState.get(authorizationRequest.searchParams.get('request_uri') ?? '') ?? '',
            },
          }),
          declined: undefined,
        })
      ).resolves.toBeDefined();
    });

    it('whose verify() throws, rather than rejects, on what it refuses', async () => {
      const method = createSampleAuthMethod();
      const throwing = {
        ...method,
        verify: (input: unknown) => {
          if (typeof input !== 'object' || input === null) throw new Error('not a result');
          return method.verify(input);
        },
      };
      await expect(checkAuthMethod(throwing, sampleScenario())).resolves.toBeDefined();
    });

    it('run beside a broken one: each run counts only its own fetch calls', async () => {
      const fetching = withCallback((original) => async (request, context) => {
        await fetch('https://provider.example/token').catch(() => undefined);
        return original(request, context);
      });
      const [correct, broken] = await Promise.all([
        kitProblems(createSampleAuthMethod()),
        kitProblems(fetching),
      ]);
      expect(correct).toEqual([]);
      expect(broken).toEqual([
        'the method called fetch: its outbound calls go through context.egress',
      ]);
    });
  });

  describe('fails for a method that leaks or guesses', () => {
    it('one whose state is a short counter', async () => {
      const method = createSampleAuthMethod();
      let count = 0;
      const counting = {
        ...method,
        start: async (context: Parameters<typeof method.start>[0]) => {
          const start = await method.start(context, { uiLocales: [] });
          count += 1;
          const state = String(count);
          const url = new URL(start.redirectTo);
          url.searchParams.set('state', state);
          return { redirectTo: url.href, transaction: { state }, binding: state };
        },
      };
      expect(await kitProblems(counting)).toMatchInlineSnapshot(`
        [
          "start() failed: AuthMethod oidc_sample: start() answered a binding that is not 22 to 512 base64url characters",
        ]
      `);
    });

    it.each([
      [
        'in an own field of an error',
        (secret: string) => ({
          err: Object.assign(new Error('token call failed'), {
            requestBody: `client_secret=${secret}`,
          }),
        }),
      ],
      [
        'as HTTP Basic credentials',
        (secret: string) => ({
          authorization: `Basic ${Buffer.from(`${SAMPLE_CONFIG.clientId}:${secret}`).toString('base64')}`,
        }),
      ],
    ])('one that logs a secret %s', async (_label, leak) => {
      const method = withCallback((original) => async (request, context) => {
        context.log.warn(leak((context.config as typeof SAMPLE_CONFIG).clientSecret), 'calling');
        return original(request, context);
      });
      expect(await kitProblems(method)).toEqual([
        'a log line carries the value of a writeOnly config member',
      ]);
    });

    it('one that logs a short secret', async () => {
      const configSchema = z.object({
        authorizationEndpoint: z.url(),
        tokenEndpoint: z.url(),
        clientId: z.string(),
        clientSecret: z.string(),
        pin: z.string().meta({ writeOnly: true }),
      });
      const leaky = withCallback((original) => async (request, context) => {
        context.log.info({ pin: (context.config as { pin: string }).pin }, 'calling');
        return original(request, context);
      });
      expect(
        await kitProblems({ ...leaky, configSchema } as unknown as AuthMethod, {
          ...sampleScenario(),
          config: { ...SAMPLE_CONFIG, pin: 'abc' },
        })
      ).toEqual(['a log line carries the value of a writeOnly config member']);
    });

    it('one that logs a secret held in a list, or behind a $ref', async () => {
      const shared = z.string().meta({ id: 'KitRefSecret599', writeOnly: true });
      const configSchema = z.object({
        authorizationEndpoint: z.url(),
        tokenEndpoint: z.url(),
        clientId: z.string(),
        clientSecret: z.string(),
        previousSecrets: z.array(z.string()).meta({ writeOnly: true }),
        signingSecret: shared,
        backupSigningSecret: shared,
      });
      const config = {
        ...SAMPLE_CONFIG,
        previousSecrets: ['rotated-out-secret'],
        signingSecret: 'referenced-secret',
        backupSigningSecret: 'other-referenced-secret',
      };
      for (const pick of [
        (c: typeof config) => c.previousSecrets[0],
        (c: typeof config) => c.signingSecret,
      ]) {
        const leaky = withCallback((original) => async (request, context) => {
          context.log.info({ value: pick(context.config as typeof config) }, 'calling');
          return original(request, context);
        });
        expect(
          await kitProblems({ ...leaky, configSchema } as unknown as AuthMethod, {
            ...sampleScenario(),
            config,
          })
        ).toEqual(['a log line carries the value of a writeOnly config member']);
      }
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

  it("shows the scenario a call's redirect: 'error' as the method sent it, not as a cap", async () => {
    const seen: Record<string, unknown>[] = [];
    // The sample's callback, with every outbound call asking for no redirect.
    const strict = withCallback(
      (original) => async (request, context) =>
        original(request, {
          ...context,
          egress: { request: (call) => context.egress.request({ ...call, redirect: 'error' }) },
        })
    );
    await checkAuthMethod(strict, {
      ...sampleScenario(),
      egress: (request) => {
        seen.push(request as unknown as Record<string, unknown>);
        return sampleProviderEgress(request);
      },
    });
    expect(seen.length).toBeGreaterThan(0);
    for (const request of seen) {
      expect(request['redirect']).toBe('error');
      expect(request).not.toHaveProperty('limits');
    }
  });
});
