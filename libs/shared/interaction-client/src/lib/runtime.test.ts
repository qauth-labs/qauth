import { describe, expect, expectTypeOf, it, vi } from 'vitest';

import {
  type AnswerRequest,
  createInteractionClient,
  type Interaction,
  type PasswordParams,
  type Problem,
  type Step,
} from '../index';
import { expandPath, UnexpectedStatusError } from './runtime';

const ID = 'aW50ZXJhY3Rpb24taWQtb2YtMzItcmFuZG9tLWJ5dGU';
const CSRF = 'cGVyLXN0ZXAtY3NyZi12YWx1ZS1vZi0zMi1ieXRlcyE';

function jsonResponse(status: number, body: unknown, contentType = 'application/json') {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': contentType } });
}

describe('the Interaction API client', () => {
  it('reads the current step on the configured origin, with no body', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => jsonResponse(200, { step: {} }));
    const client = createInteractionClient({ baseUrl: 'https://auth.example.com', fetch });
    const result = await client.interactionsGet({ interactionId: ID });
    expect(result.status).toBe(200);
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe(`https://auth.example.com/interaction/v1-rc.0/${ID}`);
    expect(init).toMatchObject({ method: 'GET', credentials: 'same-origin', redirect: 'manual' });
    expect(init?.body).toBeUndefined();
  });

  it('posts an answer as JSON, same-origin, without following a redirect', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      jsonResponse(200, { result: 'redirect', location: 'https://app.example.com/cb' })
    );
    const client = createInteractionClient({ fetch });
    const answer: AnswerRequest = {
      type: 'urn:qauth:ia:password:v1-rc.0',
      csrf: CSRF,
      password: 'correct horse battery staple x',
    };
    const result = await client.interactionsAnswer({ interactionId: ID }, answer);
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe(`/interaction/v1-rc.0/${ID}/answer`);
    expect(init?.method).toBe('POST');
    expect(init?.credentials).toBe('same-origin');
    expect(init?.redirect).toBe('manual');
    expect(init?.headers).toMatchObject({ 'content-type': 'application/json' });
    expect(JSON.parse(String(init?.body))).toEqual(answer);
    if (result.status === 200) {
      expectTypeOf(result.data).toEqualTypeOf<
        { result: 'step'; interaction: Interaction } | { result: 'redirect'; location: string }
      >();
    }
    expect(result.data).toEqual({ result: 'redirect', location: 'https://app.example.com/cb' });
  });

  it('reads a problem document as data, typed by its status', async () => {
    const problem = {
      type: 'about:blank',
      title: 'Gone',
      status: 410,
      code: 'interaction_expired',
      trace_id: 'req-1',
    };
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      jsonResponse(410, problem, 'application/problem+json')
    );
    const result = await createInteractionClient({ fetch }).interactionsPersonalGet({
      interactionId: ID,
    });
    expect(result).toMatchObject({ status: 410, data: problem });
    if (result.status === 410) expectTypeOf(result.data).toEqualTypeOf<Problem>();
  });

  it('refuses a status the document does not declare, such as a proxy’s 502', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(
      async () =>
        new Response('<html></html>', { status: 502, headers: { 'content-type': 'text/html' } })
    );
    const call = createInteractionClient({ fetch }).interactionsGet({ interactionId: ID });
    await expect(call).rejects.toBeInstanceOf(UnexpectedStatusError);
    await expect(call).rejects.toMatchObject({ status: 502 });
  });

  it('reads no body from a declared answer that is not JSON', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response(null, { status: 303 }));
    const result = await createInteractionClient({ fetch }).interactionsCancel(
      { interactionId: ID },
      { csrf: CSRF }
    );
    expect(result.status).toBe(303);
    expect(result.data).toBeUndefined();
  });

  it('encodes path parameters and refuses a missing one', () => {
    expect(expandPath('/interaction/v1-rc.0/{interactionId}', { interactionId: 'a/b?c' })).toBe(
      '/interaction/v1-rc.0/a%2Fb%3Fc'
    );
    expect(() => expandPath('/interaction/v1-rc.0/{interactionId}', {})).toThrow(TypeError);
  });

  it('narrows a step by its name to its params', () => {
    const narrow = (step: Step) => {
      if (step.type === 'urn:qauth:ia:password:v1-rc.0') {
        expectTypeOf(step.params).toEqualTypeOf<PasswordParams>();
        expectTypeOf(step.error).toEqualTypeOf<'invalid_credentials' | undefined>();
      }
      if (step.type === 'urn:qauth:ia:new_password:v1-rc.0') {
        expectTypeOf(step.params.purpose).toEqualTypeOf<'register' | 'reset' | 'update_required'>();
      }
    };
    expect(narrow).toBeTypeOf('function');
  });
});
